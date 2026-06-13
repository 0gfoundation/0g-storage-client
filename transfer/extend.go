package transfer

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/0gfoundation/0g-storage-client/contract"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
)

// ExtendOption controls an extend-storage operation.
type ExtendOption struct {
	TransactionOption // Submitter, Fee, Nonce, MaxGasPrice, NRetries, Step

	Method          string // node-selection method for availability checks ("random", "min", ...)
	ExpectedReplica uint   // expected replicas when selecting nodes via the indexer
	FullTrusted     bool   // whether to use full trusted nodes when selecting via the indexer
	BatchSize       uint   // submissions per batchSubmit tx (0 => defaultBatchSize)
}

// ExtendItem pairs a recovered file data root with the submission used to re-pay for it.
type ExtendItem struct {
	Root       common.Hash
	Submission contract.Submission
}

// ErrDataUnavailable is returned by ExtendStorage when one or more fragments are no
// longer stored on the network. No transaction is sent in this case.
type ErrDataUnavailable struct {
	Missing []common.Hash
}

func (e *ErrDataUnavailable) Error() string {
	roots := make([]string, len(e.Missing))
	for i, r := range e.Missing {
		roots[i] = r.Hex()
	}
	return fmt.Sprintf("data no longer available on storage for roots [%s]; please upload these again",
		strings.Join(roots, ", "))
}

// ErrSubmitEventNotFound is returned when a given tx hash has no receipt or carries no
// Flow Submit event, so its submission cannot be recovered.
type ErrSubmitEventNotFound struct {
	TxHash common.Hash
}

func (e *ErrSubmitEventNotFound) Error() string {
	return fmt.Sprintf("no Flow submit event found for tx %s", e.TxHash.Hex())
}

// isRootAvailable reports whether a storage node's FileInfo means the data root is still
// stored and usable: present, finalized, and not pruned.
func isRootAvailable(info *node.FileInfo) bool {
	return info != nil && info.Finalized && !info.Pruned
}

// parseSubmissions extracts every Flow Submit event from the given (go-ethereum) logs and
// returns one ExtendItem per distinct data root, where the root is derived from the
// submission's own nodes via Submission.Root().
func parseSubmissions(flow *contract.FlowContract, logs []*ethtypes.Log) ([]ExtendItem, error) {
	seen := make(map[common.Hash]struct{})
	items := make([]ExtendItem, 0, len(logs))
	for _, log := range logs {
		ev, err := flow.ParseSubmit(*log)
		if err != nil {
			continue // not a Submit log
		}
		sub := contract.Submission{Data: ev.Submission}
		// The data root is derived from the submission's own nodes (Submission.Root()
		// == core.MerkleTree(data).Root() == the key storage nodes/indexer use). We do
		// NOT compare against the event's indexed `identity`: on-chain `identity` is a
		// different digest, not the bare data root, so matching against it would wrongly
		// drop every valid submission.
		root := sub.Root()
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		items = append(items, ExtendItem{Root: root, Submission: sub})
	}
	return items, nil
}

// feeForSubmissions sums the protocol fee for the given submissions at the given price.
func feeForSubmissions(items []ExtendItem, pricePerSector *big.Int) *big.Int {
	total := big.NewInt(0)
	for _, it := range items {
		total = new(big.Int).Add(total, it.Submission.Fee(pricePerSector))
	}
	return total
}

// RecoverSubmissions fetches the receipt for each submit-tx hash and recovers the
// submissions from its Flow Submit events. Roots are de-duplicated across all tx hashes.
// A tx whose receipt carries no Submit event yields *ErrSubmitEventNotFound.
func (uploader *Uploader) RecoverSubmissions(ctx context.Context, submitTxHashes []common.Hash) ([]ExtendItem, error) {
	seen := make(map[common.Hash]struct{})
	all := make([]ExtendItem, 0, len(submitTxHashes))
	for _, txHash := range submitTxHashes {
		receipt, err := uploader.flow.WaitForReceipt(ctx, txHash, false)
		if err != nil || receipt == nil {
			return nil, &ErrSubmitEventNotFound{TxHash: txHash}
		}
		ethLogs := make([]*ethtypes.Log, 0, len(receipt.Logs))
		for _, l := range receipt.Logs {
			ethLogs = append(ethLogs, l.ToEthLog())
		}
		items, err := parseSubmissions(uploader.flow, ethLogs)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return nil, &ErrSubmitEventNotFound{TxHash: txHash}
		}
		for _, it := range items {
			if _, ok := seen[it.Root]; ok {
				continue
			}
			seen[it.Root] = struct{}{}
			all = append(all, it)
		}
	}
	return all, nil
}

// checkAvailability returns the subset of roots that are NOT currently stored (finalized,
// not pruned) on any of the uploader's selected nodes.
func (uploader *Uploader) checkAvailability(ctx context.Context, roots []common.Hash) []common.Hash {
	clients := append(append([]*node.ZgsClient{}, uploader.clients.Trusted...), uploader.clients.Discovered...)
	var missing []common.Hash
	for _, root := range roots {
		available := false
		for _, client := range clients {
			info, err := client.GetFileInfo(ctx, root, true)
			if err != nil {
				continue
			}
			if isRootAvailable(info) {
				available = true
				break
			}
		}
		if !available {
			missing = append(missing, root)
		}
	}
	return missing
}

// Resubmit re-submits the given submissions to the Flow contract to pay the storage fee
// again, batched by opt.BatchSize. It performs NO segment upload. The submitter is set to
// opt.Submitter (or the flow's default signer). Returns the new submit tx hashes.
func (uploader *Uploader) Resubmit(ctx context.Context, items []ExtendItem, opt ExtendOption) ([]common.Hash, error) {
	if len(items) == 0 {
		return nil, errors.New("no submissions to extend")
	}
	batchSize := int(opt.BatchSize)
	if batchSize <= 0 {
		batchSize = int(defaultBatchSize)
	}

	submitter := opt.Submitter
	if submitter == (common.Address{}) {
		s, err := uploader.flow.GetSubmitterAddress()
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to get submitter address from flow contract")
		}
		submitter = s
	}

	pricePerSector, err := uploader.market.PricePerSector(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to read price per sector")
	}

	singleBatch := len(items) <= batchSize
	txHashes := make([]common.Hash, 0)
	for l := 0; l < len(items); l += batchSize {
		r := min(l+batchSize, len(items))
		batch := items[l:r]

		subs := make([]contract.Submission, 0, len(batch))
		for _, it := range batch {
			s := it.Submission
			s.Submitter = submitter
			subs = append(subs, s)
		}

		opts, err := uploader.flow.CreateTransactOpts(ctx)
		if err != nil {
			return txHashes, errors.WithMessage(err, "Failed to create transact opts")
		}
		if opt.Nonce != nil && l == 0 {
			opts.Nonce = opt.Nonce
		}
		if opt.Fee != nil && singleBatch {
			opts.Value = opt.Fee
		} else {
			opts.Value = feeForSubmissions(batch, pricePerSector)
		}
		uploader.logger.WithField("fee(neuron)", opts.Value).Info("extend submit with fee")

		retryOpt := &contract.TxRetryOption{
			MaxGasPrice:      opt.MaxGasPrice,
			MaxNonGasRetries: opt.NRetries,
			Step:             opt.Step,
		}

		method := "batchSubmit"
		params := []any{subs}
		if len(subs) == 1 {
			method = "submit"
			params = []any{subs[0]}
		}

		receipt, err := contract.TransactWithGasAdjustment(uploader.flow, method, opts, retryOpt, opt.OnSubmitted, params...)
		if err != nil {
			return txHashes, errors.WithMessage(err, "Failed to re-submit for extend")
		}
		txHashes = append(txHashes, receipt.TransactionHash)
	}
	return txHashes, nil
}

// ExtendStorage re-pays the storage fee for data already stored on the network, identified
// by the original Flow.submit tx hashes, without re-uploading bytes. Availability is checked
// against the uploader's own nodes. Returns the new submit tx hashes, or *ErrDataUnavailable
// if any fragment is no longer stored (in which case no transaction is sent).
func (uploader *Uploader) ExtendStorage(ctx context.Context, submitTxHashes []common.Hash, opt ExtendOption) ([]common.Hash, error) {
	items, err := uploader.RecoverSubmissions(ctx, submitTxHashes)
	if err != nil {
		return nil, err
	}
	roots := make([]common.Hash, len(items))
	for i, it := range items {
		roots[i] = it.Root
	}
	if missing := uploader.checkAvailability(ctx, roots); len(missing) > 0 {
		return nil, &ErrDataUnavailable{Missing: missing}
	}
	uploader.logger.WithField("fragments", len(items)).Info("All fragments available, extending storage period")
	return uploader.Resubmit(ctx, items, opt)
}
