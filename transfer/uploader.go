package transfer

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"time"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/parallel"
	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/0gfoundation/0g-storage-client/contract"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/core/merkle"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/openweb3/web3go"
	"github.com/openweb3/web3go/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// defaultTaskSize is the default number of data segments to upload in a single upload RPC request
const defaultTaskSize = uint(10)
const defaultBatchSize = uint(10)
const fastUploadMaxSize = int64(10 * 1024 * 1024)
const defaultLogEntryWaitTimeout = 10 * time.Minute

type FinalityRequirement uint

const (
	FileFinalized     FinalityRequirement = iota // wait for file finalization
	TransactionPacked                            // wait for transaction packed
)

// SelectedNodes holds the selected trusted and discovered nodes.
type SelectedNodes struct {
	Trusted    []*node.ZgsClient
	Discovered []*node.ZgsClient
}

// UploaderContractConfig optionally pins contract addresses to avoid fetching them from storage nodes.
type UploaderContractConfig struct {
	FlowAddress   *common.Address
	MarketAddress *common.Address
}

// UploadOption upload option for a file
type UploadOption struct {
	Tags             []byte              // transaction tags
	FinalityRequired FinalityRequirement // finality setting
	TaskSize         uint                // number of segment to upload in single rpc request
	ExpectedReplica  uint                // expected number of replications
	SkipTx           bool                // skip sending transaction on chain, this can set to true only if the data has already settled on chain before
	FastMode         bool                // skip waiting for receipt and upload segments by root (recommended for small files)
	Fee              *big.Int            // fee in neuron
	Nonce            *big.Int            // nonce for transaction
	MaxGasPrice      *big.Int            // max gas price for transaction
	NRetries         int                 // number of retries for uploading
	Step             int64               // step for uploading
	Method           string              // method for selecting nodes, can be "max", "random" or certain positive number in string
	FullTrusted      bool                // whether to use full trusted nodes
}

// SubmitLogEntryOption option for submitting log entry
type SubmitLogEntryOption struct {
	Fee         *big.Int
	Nonce       *big.Int
	MaxGasPrice *big.Int
	NRetries    int
	Step        int64
	WaitReceipt *bool
}

// Uploader uploader to upload file to 0g storage, send on-chain transactions and transfer data to storage nodes.
type Uploader struct {
	flow     *contract.FlowContract // flow contract instance
	market   *contract.Market       // market contract instance
	clients  *SelectedNodes         // 0g storage clients
	routines int                    // number of go routines for uploading
	logger   *logrus.Logger         // logger
}

func statusClient(clients *SelectedNodes) (*node.ZgsClient, error) {
	if len(clients.Trusted) > 0 {
		return clients.Trusted[0], nil
	}
	if len(clients.Discovered) > 0 {
		return clients.Discovered[0], nil
	}
	return nil, errors.New("Storage node not specified")
}

// NewUploader Initialize a new uploader.
func NewUploader(ctx context.Context, w3Client *web3go.Client, clients *SelectedNodes, opts ...zg_common.LogOption) (*Uploader, error) {
	return NewUploaderWithContractConfig(ctx, w3Client, clients, nil, opts...)
}

// NewUploaderWithContractConfig initializes a new uploader with optional contract addresses.
func NewUploaderWithContractConfig(ctx context.Context, w3Client *web3go.Client, clients *SelectedNodes, contractConfig *UploaderContractConfig, opts ...zg_common.LogOption) (*Uploader, error) {
	if len(clients.Trusted) == 0 && len(clients.Discovered) == 0 {
		return nil, errors.New("Storage node not specified")
	}

	var flowAddress common.Address
	if contractConfig != nil && contractConfig.FlowAddress != nil {
		flowAddress = *contractConfig.FlowAddress
	} else {
		statusNode, err := statusClient(clients)
		if err != nil {
			return nil, err
		}
		status, err := statusNode.GetStatus(context.Background())
		if err != nil {
			return nil, errors.WithMessagef(err, "Failed to get status from storage node %v", statusNode.URL())
		}

		chainId, err := w3Client.Eth.ChainId()
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to get chain ID from blockchain node")
		}

		if chainId != nil && *chainId != status.NetworkIdentity.ChainId {
			return nil, errors.Errorf("Chain ID mismatch, blockchain = %v, storage node = %v", *chainId, status.NetworkIdentity.ChainId)
		}
		flowAddress = status.NetworkIdentity.FlowContractAddress
	}

	flow, err := contract.NewFlowContract(flowAddress, w3Client)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to create flow contract")
	}

	var market *contract.Market
	if contractConfig != nil && contractConfig.MarketAddress != nil {
		backend, _ := w3Client.ToClientForContract()
		market, err = contract.NewMarket(*contractConfig.MarketAddress, backend)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to create market contract")
		}
	} else {
		market, err = flow.GetMarketContract(ctx)
		if err != nil {
			return nil, errors.WithMessagef(err, "Failed to get market contract from flow contract %v", flowAddress)
		}
	}

	uploader := &Uploader{
		clients: clients,
		logger:  zg_common.NewLogger(opts...),
		flow:    flow,
		market:  market,
	}

	return uploader, nil
}

func (uploader *Uploader) WithRoutines(routines int) *Uploader {
	uploader.routines = routines
	return uploader
}

// SplitableUpload submit data to 0g storage contract and large data will be splited to reduce padding cost.
func (uploader *Uploader) SplitableUpload(ctx context.Context, data core.IterableData, fragmentSize int64, option ...UploadOption) ([]common.Hash, []common.Hash, error) {
	if fragmentSize < core.DefaultChunkSize {
		fragmentSize = core.DefaultChunkSize
	}
	// align size of fragment to 2 power
	fragmentSize = int64(core.NextPow2(uint64(fragmentSize)))
	uploader.logger.Infof("fragment size: %v", fragmentSize)

	txHashes := make([]common.Hash, 0)
	rootHashes := make([]common.Hash, 0)
	if data.Size() <= fragmentSize {
		txHash, rootHash, err := uploader.Upload(ctx, data, option...)
		if err != nil {
			return txHashes, rootHashes, err
		}
		txHashes = append(txHashes, txHash)
		rootHashes = append(rootHashes, rootHash)
	} else {
		fragments := data.Split(fragmentSize)
		uploader.logger.Infof("splitted origin file into %v fragments, %v bytes each.", len(fragments), fragmentSize)
		var opt UploadOption
		if len(option) > 0 {
			opt = option[0]
		}
		for l := 0; l < len(fragments); l += int(defaultBatchSize) {
			r := min(l+int(defaultBatchSize), len(fragments))
			uploader.logger.Infof("batch submitting fragments %v to %v...", l, r)
			opts := BatchUploadOption{
				Fee:         nil,
				Nonce:       nil,
				MaxGasPrice: opt.MaxGasPrice,
				NRetries:    opt.NRetries,
				Step:        opt.Step,
				DataOptions: make([]UploadOption, 0),
				Method:      opt.Method,
				FullTrusted: opt.FullTrusted,
			}
			for i := l; i < r; i += 1 {
				opts.DataOptions = append(opts.DataOptions, opt)
			}
			txHash, roots, err := uploader.BatchUpload(ctx, fragments[l:r], opts)
			if err != nil {
				return txHashes, rootHashes, err
			}
			txHashes = append(txHashes, txHash)
			rootHashes = append(rootHashes, roots...)
		}
	}
	return txHashes, rootHashes, nil
}

// Upload submit data to 0g storage contract, then transfer the data to the storage nodes.
// returns the submission transaction hash and the hash will be zero if transaction is skipped.
func (uploader *Uploader) Upload(ctx context.Context, data core.IterableData, option ...UploadOption) (common.Hash, common.Hash, error) {
	stageTimer := time.Now()

	var opt UploadOption
	if len(option) > 0 {
		opt = option[0]
	}
	fastMode := opt.FastMode && data.Size() <= fastUploadMaxSize
	if opt.FastMode && !fastMode {
		uploader.logger.WithField("size", data.Size()).Info("Fast mode disabled for data size over limit")
	}

	uploader.logger.WithFields(logrus.Fields{
		"size":     data.Size(),
		"chunks":   data.NumChunks(),
		"segments": data.NumSegments(),
	}).Info("Data prepared to upload")

	// Calculate file merkle root.
	tree, err := core.MerkleTree(data)
	if err != nil {
		return common.Hash{}, common.Hash{}, errors.WithMessage(err, "Failed to create data merkle tree")
	}
	uploader.logger.WithField("root", tree.Root()).Info("Data merkle root calculated")

	// Check existence
	info, err := checkLogExistence(ctx, uploader.clients, tree.Root())
	if err != nil {
		return common.Hash{}, tree.Root(), errors.WithMessage(err, "Failed to check if skipped log entry available on storage node")
	}
	if fastMode {
		return uploader.uploadFast(ctx, data, tree, info, opt, stageTimer)
	}

	return uploader.uploadSlow(ctx, data, tree, info, opt, stageTimer)
}

func (uploader *Uploader) uploadFast(ctx context.Context, data core.IterableData, tree *merkle.Tree, info *node.FileInfo, opt UploadOption, stageTimer time.Time) (common.Hash, common.Hash, error) {
	txHash := common.Hash{}
	if !opt.SkipTx || info == nil {
		uploader.logger.WithField("root", tree.Root()).Info("Prepare to submit log entry")
		var err error
		txHash, err = uploader.submitLogEntryNoReceipt(ctx, data, opt)
		if err != nil {
			return txHash, tree.Root(), err
		}
	}

	if info == nil {
		if err := uploader.uploadFileByRoot(ctx, data, tree, opt.ExpectedReplica, opt.TaskSize, opt.Method); err != nil {
			return txHash, tree.Root(), errors.WithMessage(err, "Failed to upload file")
		}

		uploader.logger.WithField("duration", time.Since(stageTimer)).Info("upload took")
		return txHash, tree.Root(), nil
	}

	if err := uploader.uploadFile(ctx, info, data, tree, opt.ExpectedReplica, opt.TaskSize, opt.Method); err != nil {
		return txHash, tree.Root(), errors.WithMessage(err, "Failed to upload file")
	}

	uploader.logger.WithField("duration", time.Since(stageTimer)).Info("upload took")

	return txHash, tree.Root(), nil
}

func (uploader *Uploader) uploadSlow(ctx context.Context, data core.IterableData, tree *merkle.Tree, info *node.FileInfo, opt UploadOption, stageTimer time.Time) (common.Hash, common.Hash, error) {
	txHash := common.Hash{}
	if !opt.SkipTx || info == nil {
		if data.Size() <= fastUploadMaxSize && info == nil {
			uploader.logger.WithField("root", tree.Root()).Info("Upload/Transaction in parallel")
			txHash, err := uploader.uploadSlowParallel(ctx, data, tree, opt)
			if err != nil {
				return txHash, tree.Root(), err
			}
			uploader.logger.WithField("duration", time.Since(stageTimer)).Info("upload took")
			return txHash, tree.Root(), nil
		}

		uploader.logger.WithField("root", tree.Root()).Info("Prepare to submit log entry")
		var err error
		txHash, info, err = uploader.submitLogEntryAndWait(ctx, data, tree, opt)
		if err != nil {
			return txHash, tree.Root(), err
		}
	}

	if err := uploader.uploadFile(ctx, info, data, tree, opt.ExpectedReplica, opt.TaskSize, opt.Method); err != nil {
		return txHash, tree.Root(), errors.WithMessage(err, "Failed to upload file")
	}

	if _, err := uploader.waitForLogEntry(ctx, tree.Root(), opt.FinalityRequired, info.Tx.Seq); err != nil {
		return txHash, tree.Root(), errors.WithMessage(err, "Failed to wait for transaction finality on storage node")
	}

	uploader.logger.WithField("duration", time.Since(stageTimer)).Info("upload took")

	return txHash, tree.Root(), nil
}

func (uploader *Uploader) uploadSlowParallel(ctx context.Context, data core.IterableData, tree *merkle.Tree, opt UploadOption) (common.Hash, error) {
	txHash, err := uploader.submitLogEntryNoReceipt(ctx, data, opt)
	if err != nil {
		return txHash, err
	}

	uploadCtx, cancelUpload := context.WithCancel(ctx)
	defer cancelUpload()

	uploadCh := make(chan error, 1)
	receiptCh := make(chan error, 1)

	go func() {
		if err := uploader.uploadFileByRoot(uploadCtx, data, tree, opt.ExpectedReplica, opt.TaskSize, opt.Method); err != nil {
			uploadCh <- errors.WithMessage(err, "Failed to upload file")
			return
		}
		uploadCh <- uploader.waitForLogEntryByRoot(uploadCtx, tree.Root(), opt.FinalityRequired)
	}()

	go func() {
		_, err := uploader.flow.WaitForReceipt(uploadCtx, txHash, true)
		receiptCh <- err
	}()

	var afterReceiptTimer *time.Timer
	var afterReceiptC <-chan time.Time

	for {
		select {
		case err := <-uploadCh:
			if err != nil {
				cancelUpload()
				return txHash, err
			}
			if afterReceiptTimer != nil {
				afterReceiptTimer.Stop()
			}
			return txHash, nil
		case err := <-receiptCh:
			if err != nil {
				cancelUpload()
				return txHash, err
			}
			if afterReceiptTimer == nil {
				afterReceiptTimer = time.NewTimer(defaultLogEntryWaitTimeout)
				afterReceiptC = afterReceiptTimer.C
			}
		case <-afterReceiptC:
			cancelUpload()
			return txHash, errors.New("timeout waiting for upload and log entry after receipt")
		case <-ctx.Done():
			cancelUpload()
			return txHash, ctx.Err()
		}
	}
}

func (uploader *Uploader) submitLogEntryNoReceipt(ctx context.Context, data core.IterableData, opt UploadOption) (common.Hash, error) {
	waitReceipt := false
	receiptFlag := waitReceipt
	submitOpts := SubmitLogEntryOption{
		Fee:         opt.Fee,
		Nonce:       opt.Nonce,
		MaxGasPrice: opt.MaxGasPrice,
		NRetries:    opt.NRetries,
		Step:        opt.Step,
		WaitReceipt: &receiptFlag,
	}
	txHash, _, err := uploader.SubmitLogEntry(ctx, []core.IterableData{data}, [][]byte{opt.Tags}, submitOpts)
	if err != nil {
		return txHash, errors.WithMessage(err, "Failed to submit log entry")
	}
	return txHash, nil
}

func (uploader *Uploader) submitLogEntryAndWait(ctx context.Context, data core.IterableData, tree *merkle.Tree, opt UploadOption) (common.Hash, *node.FileInfo, error) {
	waitReceipt := true
	receiptFlag := waitReceipt
	submitOpts := SubmitLogEntryOption{
		Fee:         opt.Fee,
		Nonce:       opt.Nonce,
		MaxGasPrice: opt.MaxGasPrice,
		NRetries:    opt.NRetries,
		Step:        opt.Step,
		WaitReceipt: &receiptFlag,
	}

	txHash, receipt, err := uploader.SubmitLogEntry(ctx, []core.IterableData{data}, [][]byte{opt.Tags}, submitOpts)
	if err != nil {
		return txHash, nil, errors.WithMessage(err, "Failed to submit log entry")
	}
	if receipt == nil || receipt.Logs == nil || len(receipt.Logs) == 0 {
		return txHash, nil, errors.New("missing transaction receipt logs")
	}

	seqNums, err := uploader.ParseLogs(ctx, receipt.Logs)
	if err != nil {
		return txHash, nil, errors.WithMessage(err, "Failed to parse logs")
	}
	if len(seqNums) != 1 {
		return txHash, nil, errors.New("log entry event count mismatch")
	}

	info, err := uploader.waitForLogEntry(ctx, tree.Root(), TransactionPacked, seqNums[0])
	if err != nil {
		return txHash, nil, errors.WithMessage(err, "Failed to check if log entry available on storage node")
	}

	return txHash, info, nil
}

func (uploader *Uploader) waitForLogEntryByRoot(ctx context.Context, root common.Hash, finalityRequired FinalityRequirement) error {
	uploader.logger.WithFields(logrus.Fields{
		"root":     root,
		"finality": finalityRequired,
	}).Info("Wait for log entry on storage node by root")

	reminder := util.NewReminder(uploader.logger, time.Minute)
	clients := append(uploader.clients.Trusted, uploader.clients.Discovered...)
	txSeqOrRoot := node.TxSeqOrRoot{Root: root}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}

		ok := true
		for _, client := range clients {
			finalized, err := client.CheckFileFinalized(ctx, txSeqOrRoot)
			if err != nil {
				return err
			}
			if finalized == nil {
				fields := logrus.Fields{}
				if status, err := client.GetStatus(ctx); err == nil {
					fields["zgsNodeSyncHeight"] = status.LogSyncHeight
				}

				reminder.Remind("Log entry is unavailable yet", fields)
				ok = false
				break
			}

			if finalityRequired <= FileFinalized && !*finalized {
				reminder.Remind("Log entry is available, but not finalized yet", logrus.Fields{
					"root": root,
				})
				ok = false
				break
			}
		}

		if ok {
			return nil
		}
	}
}

func (uploader *Uploader) UploadFile(ctx context.Context, path string, option ...UploadOption) (txnHash common.Hash, rootHash common.Hash, err error) {
	file, err := core.Open(path)
	if err != nil {
		err = errors.WithMessagef(err, "failed to open file %s", path)
		return
	}
	defer file.Close()

	return uploader.Upload(ctx, file, option...)
}

// SubmitLogEntry submit the data to 0g storage contract by sending a transaction
func (uploader *Uploader) SubmitLogEntry(ctx context.Context, datas []core.IterableData, tags [][]byte, submitOption SubmitLogEntryOption) (common.Hash, *types.Receipt, error) {
	// Construct submission
	submissions := make([]contract.Submission, len(datas))
	for i := 0; i < len(datas); i++ {
		flow := core.NewFlow(datas[i], tags[i])
		submission, err := flow.CreateSubmission()
		if err != nil {
			return common.Hash{}, nil, errors.WithMessage(err, "Failed to create flow submission")
		}
		submissions[i] = *submission
	}

	// Submit log entry to smart contract.
	opts, err := uploader.flow.CreateTransactOpts(ctx)
	if err != nil {
		return common.Hash{}, nil, errors.WithMessage(err, "Failed to create opts to send transaction")
	}
	if submitOption.Nonce != nil {
		opts.Nonce = submitOption.Nonce
	}

	waitReceipt := true
	if submitOption.WaitReceipt != nil {
		waitReceipt = *submitOption.WaitReceipt
	}

	var receipt *types.Receipt
	pricePerSector, err := uploader.market.PricePerSector(&bind.CallOpts{Context: ctx})
	if err != nil {
		return common.Hash{}, nil, errors.WithMessage(err, "Failed to read price per sector")
	}
	var tx *types.Transaction
	isSingle := len(datas) == 1
	if submitOption.Fee != nil {
		opts.Value = submitOption.Fee
	} else {
		opts.Value = big.NewInt(0)
		for _, v := range submissions {
			opts.Value = new(big.Int).Add(opts.Value, v.Fee(pricePerSector))
		}
	}

	uploader.logger.WithField("fee(neuron)", opts.Value).Info("submit with fee")

	method := "batchSubmit"
	params := []any{submissions}
	if isSingle {
		method = "submit"
		params = []any{submissions[0]}
	}

	retryOpt := &contract.TxRetryOption{
		MaxGasPrice:      submitOption.MaxGasPrice,
		MaxNonGasRetries: submitOption.NRetries,
		Step:             submitOption.Step,
	}

	if waitReceipt {
		receipt, err = contract.TransactWithGasAdjustment(uploader.flow, method, opts, retryOpt, params...)
	} else {
		tx, err = contract.TransactWithGasAdjustmentNoReceipt(uploader.flow, method, opts, retryOpt, params...)
	}

	if err != nil {
		return common.Hash{}, nil, errors.WithMessage(err, "Failed to send transaction to append log entry")
	}

	var txHash common.Hash
	if tx != nil {
		txHash = tx.Hash()
	} else {
		txHash = receipt.TransactionHash
	}
	uploader.logger.WithField("hash", txHash.Hex()).Info("Succeeded to send transaction to append log entry")

	return txHash, receipt, err
}

// EstimateFee estimates the protocol fee (in Wei) for uploading a single data item with given tags.
// It uses the same Submission.Fee(pricePerSector) calculation as SubmitLogEntry.
func (uploader *Uploader) EstimateFee(ctx context.Context, data core.IterableData, tags []byte) (*big.Int, error) {
	flow := core.NewFlow(data, tags)
	submission, err := flow.CreateSubmission()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to create flow submission for fee estimation")
	}
	pricePerSector, err := uploader.market.PricePerSector(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to read price per sector for fee estimation")
	}
	fee := submission.Fee(pricePerSector)
	return fee, nil
}

// EstimateBatchFee estimates the total protocol fee (in Wei) for uploading multiple data items
// with corresponding tags. The lengths of datas and tags must match.
func (uploader *Uploader) EstimateBatchFee(ctx context.Context, datas []core.IterableData, tags [][]byte) (*big.Int, error) {
	if len(datas) != len(tags) {
		return nil, errors.New("datas and tags length mismatch")
	}
	pricePerSector, err := uploader.market.PricePerSector(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to read price per sector for batch fee estimation")
	}
	total := big.NewInt(0)
	for i := 0; i < len(datas); i++ {
		flow := core.NewFlow(datas[i], tags[i])
		submission, err := flow.CreateSubmission()
		if err != nil {
			return nil, errors.WithMessagef(err, "Failed to create flow submission for fee estimation at index %d", i)
		}
		fee := submission.Fee(pricePerSector)
		total = new(big.Int).Add(total, fee)
	}
	return total, nil
}

func (uploader *Uploader) ParseLogs(ctx context.Context, logs []*types.Log) ([]uint64, error) {
	submits := make([]uint64, 0)
	for _, log := range logs {
		submit, err := uploader.flow.ParseSubmit(*log.ToEthLog())
		if err != nil {
			continue
		}
		submits = append(submits, submit.SubmissionIndex.Uint64())
	}
	return submits, nil
}

// Wait for log entry ready on storage node.
func (uploader *Uploader) waitForLogEntry(ctx context.Context, root common.Hash, finalityRequired FinalityRequirement, txSeq uint64) (*node.FileInfo, error) {
	uploader.logger.WithFields(logrus.Fields{
		"root":     root,
		"finality": finalityRequired,
		"txSeq":    txSeq,
	}).Info("Wait for log entry on storage node")

	reminder := util.NewReminder(uploader.logger, time.Minute)

	var err error
	var info *node.FileInfo

	for {
		time.Sleep(time.Second)

		clients := append(uploader.clients.Trusted, uploader.clients.Discovered...)

		ok := true
		for _, client := range clients {
			info, err = client.GetFileInfoByTxSeq(ctx, txSeq)
			if err != nil {
				return nil, err
			}
			// log entry unavailable yet
			if info == nil {
				fields := logrus.Fields{}
				if status, err := client.GetStatus(ctx); err == nil {
					fields["zgsNodeSyncHeight"] = status.LogSyncHeight
				}

				reminder.Remind("Log entry is unavailable yet", fields)
				ok = false
				break
			}

			if finalityRequired <= FileFinalized && !info.Finalized {
				reminder.Remind("Log entry is available, but not finalized yet", logrus.Fields{
					"cached":           info.IsCached,
					"uploadedSegments": info.UploadedSegNum,
					"txSeq":            info.Tx.Seq,
				})
				ok = false
				break
			}
		}

		if ok {
			break
		}
	}

	return info, nil
}

func (uploader *Uploader) newSegmentUploaderWithRange(ctx context.Context, startSegmentIndex, endSegmentIndex uint64, txSeq uint64, useTxSeq bool, data core.IterableData, tree *merkle.Tree, expectedReplica, taskSize uint, method string) ([]*segmentUploader, error) {
	createUploader := func(clients []*node.ZgsClient) (*segmentUploader, error) {
		if len(clients) == 0 {
			return nil, nil
		}
		shardConfigs, err := getShardConfigs(ctx, clients)
		if err != nil {
			return nil, err
		}
		if !shard.CheckReplica(shardConfigs, expectedReplica, method) {
			return nil, fmt.Errorf("selected nodes cannot cover all shards")
		}
		clientTasks := make([][]*uploadTask, 0)
		for clientIndex, shardConfig := range shardConfigs {
			// skip finalized nodes
			info, _ := clients[clientIndex].GetFileInfo(ctx, tree.Root(), true)
			if info != nil && info.Finalized {
				continue
			}
			// create upload tasks
			// segIndex % NumShard = shardId (in flow)
			segIndex := shardConfig.NextSegmentIndex(startSegmentIndex)
			tasks := make([]*uploadTask, 0)
			for ; segIndex <= endSegmentIndex; segIndex += shardConfig.NumShard * uint64(taskSize) {
				tasks = append(tasks, &uploadTask{
					clientIndex: clientIndex,
					segIndex:    segIndex - startSegmentIndex,
					numShard:    shardConfig.NumShard,
				})
			}
			clientTasks = append(clientTasks, tasks)
		}
		sort.SliceStable(clientTasks, func(i, j int) bool {
			return len(clientTasks[i]) > len(clientTasks[j])
		})
		tasks := make([]*uploadTask, 0)
		if len(clientTasks) > 0 {
			for taskIndex := 0; taskIndex < len(clientTasks[0]); taskIndex += 1 {
				for i := 0; i < len(clientTasks) && taskIndex < len(clientTasks[i]); i += 1 {
					tasks = append(tasks, clientTasks[i][taskIndex])
				}
			}
		}

		return &segmentUploader{
			data:     data,
			tree:     tree,
			txSeq:    txSeq,
			useTxSeq: useTxSeq,
			clients:  clients,
			tasks:    tasks,
			taskSize: taskSize,
			logger:   uploader.logger,
		}, nil
	}

	trustedUploader, err := createUploader(uploader.clients.Trusted)
	if err != nil {
		return nil, err
	}
	discoveredUploader, err := createUploader(uploader.clients.Discovered)

	return []*segmentUploader{trustedUploader, discoveredUploader}, err
}

func (uploader *Uploader) newSegmentUploader(ctx context.Context, info *node.FileInfo, data core.IterableData, tree *merkle.Tree, expectedReplica, taskSize uint, method string) ([]*segmentUploader, error) {
	startSegmentIndex, endSegmentIndex := core.SegmentRange(info.Tx.StartEntryIndex, info.Tx.Size)
	return uploader.newSegmentUploaderWithRange(ctx, startSegmentIndex, endSegmentIndex, info.Tx.Seq, true, data, tree, expectedReplica, taskSize, method)
}

func (uploader *Uploader) newSegmentUploaderByRoot(ctx context.Context, data core.IterableData, tree *merkle.Tree, expectedReplica, taskSize uint, method string) ([]*segmentUploader, error) {
	startSegmentIndex, endSegmentIndex := core.SegmentRange(0, uint64(data.Size()))
	return uploader.newSegmentUploaderWithRange(ctx, startSegmentIndex, endSegmentIndex, 0, false, data, tree, expectedReplica, taskSize, method)
}

func (uploader *Uploader) uploadFile(ctx context.Context, info *node.FileInfo, data core.IterableData, tree *merkle.Tree, expectedReplica, taskSize uint, method string) error {
	stageTimer := time.Now()

	if taskSize == 0 {
		taskSize = defaultTaskSize
	}

	uploader.logger.WithFields(logrus.Fields{
		"segNum":   data.NumSegments(),
		"nodeNum":  len(uploader.clients.Discovered) + len(uploader.clients.Trusted),
		"sequence": info.Tx.Seq,
		"root":     tree.Root(),
	}).Info("Begin to upload file")

	segmentUploader, err := uploader.newSegmentUploader(ctx, info, data, tree, expectedReplica, taskSize, method)
	if err != nil && segmentUploader == nil {
		return err
	}

	if err != nil {
		return errors.Errorf("Discovered nodes create uploader error: %v", err)
	}

	opt := parallel.SerialOption{
		Routines: uploader.routines,
	}

	if segmentUploader[1] != nil {
		logrus.Infof("Uploading to %d discovered nodes", len(segmentUploader[1].clients))
		err = parallel.Serial(ctx, segmentUploader[1], len(segmentUploader[1].tasks), opt)
		if err != nil {
			return errors.Errorf("Discovered nodes upload error: %v", err)
		}
	}

	err = parallel.Serial(ctx, segmentUploader[0], len(segmentUploader[0].tasks), opt)
	if err != nil {
		return errors.Errorf("Trusted nodes upload error: %v", err)
	}

	uploader.logger.WithFields(logrus.Fields{
		"duration": time.Since(stageTimer),
		"segNum":   data.NumSegments(),
		"sequence": info.Tx.Seq,
		"root":     tree.Root(),
	}).Info("Completed to upload file")

	return nil
}

func (uploader *Uploader) uploadFileByRoot(ctx context.Context, data core.IterableData, tree *merkle.Tree, expectedReplica, taskSize uint, method string) error {
	stageTimer := time.Now()

	if taskSize == 0 {
		taskSize = defaultTaskSize
	}

	uploader.logger.WithFields(logrus.Fields{
		"segNum":  data.NumSegments(),
		"nodeNum": len(uploader.clients.Discovered) + len(uploader.clients.Trusted),
		"root":    tree.Root(),
	}).Info("Begin to upload file by root")

	segmentUploader, err := uploader.newSegmentUploaderByRoot(ctx, data, tree, expectedReplica, taskSize, method)
	if err != nil && segmentUploader == nil {
		return err
	}

	if err != nil {
		return errors.Errorf("Discovered nodes create uploader error: %v", err)
	}

	opt := parallel.SerialOption{
		Routines: uploader.routines,
	}

	if segmentUploader[1] != nil {
		logrus.Infof("Uploading to %d discovered nodes", len(segmentUploader[1].clients))
		err = parallel.Serial(ctx, segmentUploader[1], len(segmentUploader[1].tasks), opt)
		if err != nil {
			return errors.Errorf("Discovered nodes upload error: %v", err)
		}
	}

	err = parallel.Serial(ctx, segmentUploader[0], len(segmentUploader[0].tasks), opt)
	if err != nil {
		return errors.Errorf("Trusted nodes upload error: %v", err)
	}

	uploader.logger.WithFields(logrus.Fields{
		"duration": time.Since(stageTimer),
		"segNum":   data.NumSegments(),
		"root":     tree.Root(),
	}).Info("Completed to upload file by root")

	return nil
}
