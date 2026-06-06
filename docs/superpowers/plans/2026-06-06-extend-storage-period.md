# Extend Storage Period Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `ExtendStorage` operation that re-pays the storage fee for data already on the 0G network — identified by the original `Flow.submit` tx hash(es) — without re-uploading bytes, refusing (and asking the user to re-upload) if any fragment is no longer stored.

**Architecture:** Recover each `Submission` verbatim from its on-chain `Submit` event via the existing `flow.ParseSubmit` (fetched by tx-receipt, no chain scan, no original file). Verify every recovered root is still stored (indexer `GetFileLocations`, or node `GetFileInfo` in `--node` mode). If all present, re-submit via `Flow.submit`/`batchSubmit` paying the fee again, performing no segment transfer.

**Tech Stack:** Go 1.23, `cobra` CLI, `web3go`/go-ethereum contract bindings, `testify` for unit tests, the Python `ClientTestFramework` + `tests/go_tests/` harness for integration.

**Spec:** `docs/superpowers/specs/2026-06-05-extend-storage-period-design.md` · **Issue:** #153

---

## File Structure

- **Create** `transfer/extend.go` — `ExtendOption`, `ExtendItem`, typed errors, pure helpers (`isRootAvailable`, `parseSubmissions`, `feeForSubmissions`), and `Uploader` methods `RecoverSubmissions`, `Resubmit`, `checkAvailability`, `ExtendStorage`.
- **Create** `transfer/extend_test.go` — unit tests for the pure helpers and error types.
- **Create** `indexer/client_extend.go` — `Client.ExtendStorage` (indexer-based availability check).
- **Create** `cmd/extend.go` — the `extend` CLI subcommand.
- **Create** `tests/go_tests/extend_storage_test/main.go` — end-to-end driver.
- **Create** `tests/extend_storage_test.py` — Python integration test wrapping the driver.
- **Modify** `cli.md` — document the `extend` command.

All new Go symbols are defined in Task 1–7 before they are referenced.

---

### Task 1: Scaffolding — option, item, and typed errors

**Files:**
- Create: `transfer/extend.go`
- Test: `transfer/extend_test.go`

- [ ] **Step 1: Write the failing test**

```go
package transfer

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestErrDataUnavailable_Message(t *testing.T) {
	root := common.HexToHash("0x1234")
	err := &ErrDataUnavailable{Missing: []common.Hash{root}}
	assert.Contains(t, err.Error(), root.Hex())
	assert.Contains(t, err.Error(), "upload")

	var target *ErrDataUnavailable
	assert.True(t, errors.As(error(err), &target))
	assert.Equal(t, []common.Hash{root}, target.Missing)
}

func TestErrSubmitEventNotFound_Message(t *testing.T) {
	h := common.HexToHash("0xabcd")
	err := &ErrSubmitEventNotFound{TxHash: h}
	assert.Contains(t, err.Error(), h.Hex())

	var target *ErrSubmitEventNotFound
	assert.True(t, errors.As(error(err), &target))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./transfer/ -run 'TestErr' -v`
Expected: FAIL — `undefined: ErrDataUnavailable` / `ErrSubmitEventNotFound`.

- [ ] **Step 3: Write minimal implementation**

```go
package transfer

import (
	"fmt"
	"strings"

	"github.com/0gfoundation/0g-storage-client/contract"
	"github.com/ethereum/go-ethereum/common"
)

// ExtendOption controls an extend-storage operation.
type ExtendOption struct {
	TransactionOption // Submitter, Fee, Nonce, MaxGasPrice, NRetries, Step

	Method          string // node-selection method for availability checks ("random", "min", ...)
	ExpectedReplica uint    // expected replicas when selecting nodes via the indexer
	FullTrusted     bool    // whether to use full trusted nodes when selecting via the indexer
	BatchSize       uint    // submissions per batchSubmit tx (0 => defaultBatchSize)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./transfer/ -run 'TestErr' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add transfer/extend.go transfer/extend_test.go
git commit -m "transfer: add extend-storage option, item, and typed errors (#153)"
```

---

### Task 2: Availability predicate

**Files:**
- Modify: `transfer/extend.go`
- Test: `transfer/extend_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestIsRootAvailable(t *testing.T) {
	assert.False(t, isRootAvailable(nil))
	assert.False(t, isRootAvailable(&node.FileInfo{Finalized: false}))
	assert.False(t, isRootAvailable(&node.FileInfo{Finalized: true, Pruned: true}))
	assert.True(t, isRootAvailable(&node.FileInfo{Finalized: true, Pruned: false}))
}
```

Add the import `"github.com/0gfoundation/0g-storage-client/node"` to the test file's import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./transfer/ -run TestIsRootAvailable -v`
Expected: FAIL — `undefined: isRootAvailable`.

- [ ] **Step 3: Write minimal implementation**

Add to `transfer/extend.go` (and add `"github.com/0gfoundation/0g-storage-client/node"` to its imports):

```go
// isRootAvailable reports whether a storage node's FileInfo means the data root is still
// stored and usable: present, finalized, and not pruned.
func isRootAvailable(info *node.FileInfo) bool {
	return info != nil && info.Finalized && !info.Pruned
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./transfer/ -run TestIsRootAvailable -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add transfer/extend.go transfer/extend_test.go
git commit -m "transfer: add isRootAvailable predicate (#153)"
```

---

### Task 3: Parse submissions from receipt logs (root verification + dedupe)

**Files:**
- Modify: `transfer/extend.go`
- Test: `transfer/extend_test.go`

This is the crux: turn a tx receipt's logs into `ExtendItem`s, verifying the derived root equals the event identity. `flow.ParseSubmit` only ABI-unpacks (no network), so it is unit-testable with a hand-built log.

- [ ] **Step 1: Write the failing test**

```go
func buildSubmitLog(t *testing.T, sub contract.Submission) *types.Log {
	t.Helper()
	parsed, err := contract.FlowMetaData.GetAbi()
	require.NoError(t, err)
	ev := parsed.Events["Submit"]

	// non-indexed args: submissionIndex, startPos, length, submission
	data, err := ev.Inputs.NonIndexed().Pack(
		big.NewInt(0),                  // submissionIndex
		big.NewInt(0),                  // startPos
		sub.Data.Length,                // length
		sub.Data,                       // submission (struct)
	)
	require.NoError(t, err)

	identity := sub.Root() // indexed identity == data root
	return &types.Log{
		Topics: []common.Hash{
			ev.ID,                                   // event signature
			common.HexToHash("0x00"),                // indexed sender (zero)
			identity,                                // indexed identity
		},
		Data: data,
	}
}

func newTestSubmission(t *testing.T, sizeBytes int64) contract.Submission {
	t.Helper()
	data, err := core.NewDataInMemory(make([]byte, sizeBytes))
	require.NoError(t, err)
	sub, err := core.NewFlow(data, []byte{}).CreateSubmission(common.Address{})
	require.NoError(t, err)
	return *sub
}

func TestParseSubmissions_DedupesAndVerifiesRoot(t *testing.T) {
	flow := &contract.FlowContract{Flow: &contract.Flow{}}
	// give the embedded Flow a real ABI-bound contract so ParseSubmit can unpack
	bound, err := contract.NewFlow(common.Address{}, nil)
	require.NoError(t, err)
	flow.Flow = bound

	sub := newTestSubmission(t, 4096)
	log := buildSubmitLog(t, sub)

	items, err := parseSubmissions(flow, []*types.Log{log, log}) // duplicate => one item
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, sub.Root(), items[0].Root)
	assert.Equal(t, sub.Data.Length, items[0].Submission.Data.Length)
}

func TestParseSubmissions_NoSubmitLog(t *testing.T) {
	bound, err := contract.NewFlow(common.Address{}, nil)
	require.NoError(t, err)
	flow := &contract.FlowContract{Flow: bound}

	items, err := parseSubmissions(flow, []*types.Log{{Topics: []common.Hash{common.HexToHash("0xdead")}}})
	require.NoError(t, err)
	assert.Empty(t, items)
}
```

Add imports to the test file: `"math/big"`, `"github.com/0gfoundation/0g-storage-client/contract"`, `"github.com/0gfoundation/0g-storage-client/core"`, `"github.com/ethereum/go-ethereum/core/types"` (aliased `types`), and `"github.com/stretchr/testify/require"`.

> Note: receipt logs in production are `*web3go/types.Log`; `parseSubmissions` accepts the go-ethereum `*core/types.Log` that `(*web3go.Log).ToEthLog()` produces, so the conversion happens in `RecoverSubmissions` (Task 5) and this helper stays network-free and testable.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./transfer/ -run TestParseSubmissions -v`
Expected: FAIL — `undefined: parseSubmissions`.

- [ ] **Step 3: Write minimal implementation**

Add to `transfer/extend.go` (add imports `ethtypes "github.com/ethereum/go-ethereum/core/types"`):

```go
// parseSubmissions extracts every Flow Submit event from the given (go-ethereum) logs and
// returns one ExtendItem per distinct data root. Each submission's derived root is verified
// against the event's indexed identity; mismatches are skipped defensively.
func parseSubmissions(flow *contract.FlowContract, logs []*ethtypes.Log) ([]ExtendItem, error) {
	seen := make(map[common.Hash]struct{})
	items := make([]ExtendItem, 0, len(logs))
	for _, log := range logs {
		ev, err := flow.ParseSubmit(*log)
		if err != nil {
			continue // not a Submit log
		}
		sub := contract.Submission{Data: ev.Submission}
		root := sub.Root()
		if root != common.BytesToHash(ev.Identity[:]) {
			continue // identity mismatch; ignore
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		items = append(items, ExtendItem{Root: root, Submission: sub})
	}
	return items, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./transfer/ -run TestParseSubmissions -v`
Expected: PASS. (If `contract.NewFlow(addr, nil)` panics on nil backend, change the test to `bound, _ := contract.NewFlow(common.HexToAddress("0x1"), nil)`; `ParseSubmit` does not call the backend.)

- [ ] **Step 5: Commit**

```bash
git add transfer/extend.go transfer/extend_test.go
git commit -m "transfer: parse submissions from submit-tx receipt logs (#153)"
```

---

### Task 4: Fee computation for a set of submissions

**Files:**
- Modify: `transfer/extend.go`
- Test: `transfer/extend_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestFeeForSubmissions(t *testing.T) {
	sub := newTestSubmission(t, 4096)
	price := big.NewInt(7)

	// fee for the slice equals the sum of per-submission fees
	want := new(big.Int).Add(sub.Fee(price), sub.Fee(price))
	got := feeForSubmissions([]ExtendItem{{Submission: sub}, {Submission: sub}}, price)
	assert.Equal(t, want, got)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./transfer/ -run TestFeeForSubmissions -v`
Expected: FAIL — `undefined: feeForSubmissions`.

- [ ] **Step 3: Write minimal implementation**

Add to `transfer/extend.go` (add `"math/big"` to imports):

```go
// feeForSubmissions sums the protocol fee for the given submissions at the given price.
func feeForSubmissions(items []ExtendItem, pricePerSector *big.Int) *big.Int {
	total := big.NewInt(0)
	for _, it := range items {
		total = new(big.Int).Add(total, it.Submission.Fee(pricePerSector))
	}
	return total
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./transfer/ -run TestFeeForSubmissions -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add transfer/extend.go transfer/extend_test.go
git commit -m "transfer: add feeForSubmissions helper (#153)"
```

---

### Task 5: `RecoverSubmissions` and node-based `checkAvailability`

**Files:**
- Modify: `transfer/extend.go`

These call the network (`flow.WaitForReceipt`, `client.GetFileInfo`) and are exercised by the integration test in Task 9; no new unit test (they are thin wiring over Task 2/3 helpers). Keep them tiny.

- [ ] **Step 1: Add `RecoverSubmissions`**

Add to `transfer/extend.go`:

```go
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
```

Add imports `"context"` and (for `receipt.Logs` element type) nothing extra — `*web3go/types.Log` exposes `ToEthLog()`.

- [ ] **Step 2: Add `checkAvailability`**

```go
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
```

- [ ] **Step 3: Verify it compiles**

Run: `go build ./transfer/...`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add transfer/extend.go
git commit -m "transfer: recover submissions from receipts + node availability check (#153)"
```

---

### Task 6: `Resubmit` and `Uploader.ExtendStorage`

**Files:**
- Modify: `transfer/extend.go`

- [ ] **Step 1: Add `Resubmit`**

```go
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

		receipt, err := contract.TransactWithGasAdjustment(uploader.flow, method, opts, retryOpt, params...)
		if err != nil {
			return txHashes, errors.WithMessage(err, "Failed to re-submit for extend")
		}
		txHashes = append(txHashes, receipt.TransactionHash)
	}
	return txHashes, nil
}
```

Add imports `"github.com/ethereum/go-ethereum/accounts/abi/bind"` and `"github.com/pkg/errors"`.

- [ ] **Step 2: Add `ExtendStorage`**

```go
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
```

- [ ] **Step 3: Verify it compiles and all transfer unit tests pass**

Run: `go build ./transfer/... && go test ./transfer/ -run 'TestErr|TestIsRootAvailable|TestParseSubmissions|TestFeeForSubmissions' -v`
Expected: build OK, all PASS.

- [ ] **Step 4: Commit**

```bash
git add transfer/extend.go
git commit -m "transfer: add Uploader.Resubmit and ExtendStorage (#153)"
```

---

### Task 7: `indexer.Client.ExtendStorage` (indexer availability check)

**Files:**
- Create: `indexer/client_extend.go`

- [ ] **Step 1: Implement**

```go
package indexer

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/transfer"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/openweb3/web3go"
)

// ExtendStorage re-pays the storage fee for data already stored on the network, identified
// by the original Flow.submit tx hashes, without re-uploading bytes. Each recovered fragment
// root is checked for availability via the indexer's GetFileLocations (requiring full shard
// coverage). Returns the new submit tx hashes, or *transfer.ErrDataUnavailable if any fragment
// is no longer stored (in which case no transaction is sent).
func (c *Client) ExtendStorage(
	ctx context.Context, w3Client *web3go.Client,
	submitTxHashes []eth_common.Hash, opt transfer.ExtendOption,
) ([]eth_common.Hash, error) {
	expectedReplica := max(uint(1), opt.ExpectedReplica)

	uploader, err := c.NewUploaderFromIndexerNodes(ctx, 0, w3Client, expectedReplica, nil, opt.Method, opt.FullTrusted)
	if err != nil {
		return nil, err
	}

	items, err := uploader.RecoverSubmissions(ctx, submitTxHashes)
	if err != nil {
		return nil, err
	}

	var missing []eth_common.Hash
	for _, it := range items {
		locations, err := c.GetFileLocations(ctx, it.Root.Hex())
		if err != nil {
			c.logger.WithError(err).Debugf("fragment %v not located", it.Root.Hex())
			missing = append(missing, it.Root)
			continue
		}
		if _, covered := shard.Select(locations, 1, "random"); !covered {
			missing = append(missing, it.Root)
		}
	}
	if len(missing) > 0 {
		return nil, &transfer.ErrDataUnavailable{Missing: missing}
	}

	return uploader.Resubmit(ctx, items, opt)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./indexer/...`
Expected: no errors. (If `c.logger` is unexported and inaccessible here — it is in the same package, so OK. `max` is a Go 1.21+ builtin.)

- [ ] **Step 3: Commit**

```bash
git add indexer/client_extend.go
git commit -m "indexer: add Client.ExtendStorage with indexer availability check (#153)"
```

---

### Task 8: `extend` CLI subcommand

**Files:**
- Create: `cmd/extend.go`

- [ ] **Step 1: Implement** (mirrors `cmd/upload.go`'s structure)

```go
package cmd

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type extendArgument struct {
	transactionArgument

	txs []string // original Flow.submit tx hashes

	node    []string
	indexer string

	submitter       string
	expectedReplica uint
	method          string
	fullTrusted     bool
	batchSize       uint
	maxGasPrice     uint
	nRetries        int
	step            int64
	routines        int
	timeout         time.Duration

	flowAddress   string
	marketAddress string
}

func bindExtendFlags(cmd *cobra.Command, args *extendArgument) {
	cmd.Flags().StringSliceVar(&args.txs, "tx", []string{}, "Original Flow.submit tx hash(es) returned by upload (repeatable or comma-separated)")
	cmd.MarkFlagRequired("tx")

	cmd.Flags().StringSliceVar(&args.node, "node", []string{}, "ZeroGStorage storage node URL")
	cmd.Flags().StringVar(&args.indexer, "indexer", "", "ZeroGStorage indexer URL")
	cmd.MarkFlagsOneRequired("indexer", "node")
	cmd.MarkFlagsMutuallyExclusive("indexer", "node")

	cmd.Flags().StringVar(&args.submitter, "submitter", "", "Address to submit transaction from (optional, defaults to key owner)")
	cmd.Flags().UintVar(&args.expectedReplica, "expected-replica", 1, "expected number of replications to check/select")
	cmd.Flags().StringVar(&args.method, "method", "min", "method for selecting nodes: max, min, random, or positive number")
	cmd.Flags().BoolVar(&args.fullTrusted, "full-trusted", true, "whether to use full trusted nodes")
	cmd.Flags().UintVar(&args.batchSize, "batch-size", 10, "number of submissions to re-submit in a single on-chain transaction")
	cmd.Flags().UintVar(&args.maxGasPrice, "max-gas-price", 0, "max gas price to send transaction")
	cmd.Flags().IntVar(&args.nRetries, "n-retries", 0, "number of retries when it's not a gas price issue")
	cmd.Flags().Int64Var(&args.step, "step", 15, "step of gas price increasing, step / 10")
	cmd.Flags().DurationVar(&args.timeout, "timeout", 0, "cli task timeout, 0 for no timeout")
	cmd.Flags().StringVar(&args.flowAddress, "flow-address", "", "Flow contract address (skip storage node status call when set)")
	cmd.Flags().StringVar(&args.marketAddress, "market-address", "", "Market contract address (optional)")
}

var (
	extendArgs extendArgument

	extendCmd = &cobra.Command{
		Use:   "extend",
		Short: "Extend the storage period of already-stored data by re-paying, without re-uploading",
		Run:   extend,
	}
)

func init() {
	bindExtendFlags(extendCmd, &extendArgs)
	bindTransactionFlags(extendCmd, &extendArgs.transactionArgument)
	rootCmd.AddCommand(extendCmd)
}

func extend(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if extendArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, extendArgs.timeout)
		defer cancel()
	}

	if len(extendArgs.txs) == 0 {
		logrus.Fatal("at least one --tx is required")
	}
	txHashes := make([]common.Hash, 0, len(extendArgs.txs))
	for _, s := range extendArgs.txs {
		h := common.HexToHash(strings.TrimSpace(s))
		if h == (common.Hash{}) {
			logrus.Fatalf("invalid tx hash: %q", s)
		}
		txHashes = append(txHashes, h)
	}

	w3client := blockchain.MustNewWeb3(extendArgs.url, extendArgs.key, providerOption)
	defer w3client.Close()

	var submitter common.Address
	if extendArgs.submitter != "" {
		submitter = common.HexToAddress(extendArgs.submitter)
	}
	var nonce *big.Int
	if extendArgs.nonce > 0 {
		nonce = big.NewInt(int64(extendArgs.nonce))
	}
	var fee *big.Int
	if extendArgs.fee > 0 {
		feeInA0GI := big.NewFloat(extendArgs.fee)
		fee, _ = feeInA0GI.Mul(feeInA0GI, big.NewFloat(1e18)).Int(nil)
	}
	var maxGasPrice *big.Int
	if extendArgs.maxGasPrice > 0 {
		maxGasPrice = big.NewInt(int64(extendArgs.maxGasPrice))
	}

	opt := transfer.ExtendOption{
		TransactionOption: transfer.TransactionOption{
			Submitter:   submitter,
			Fee:         fee,
			Nonce:       nonce,
			MaxGasPrice: maxGasPrice,
			NRetries:    extendArgs.nRetries,
			Step:        extendArgs.step,
		},
		Method:          extendArgs.method,
		ExpectedReplica: extendArgs.expectedReplica,
		FullTrusted:     extendArgs.fullTrusted,
		BatchSize:       extendArgs.batchSize,
	}

	var txHashesOut []common.Hash
	var err error
	if extendArgs.indexer != "" {
		indexerClient, ierr := indexer.NewClient(extendArgs.indexer, indexer.IndexerClientOption{
			ProviderOption: providerOption,
			LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
			Routines:       extendArgs.routines,
			Contract: &transfer.ContractAddress{
				FlowAddress:   extendArgs.flowAddress,
				MarketAddress: extendArgs.marketAddress,
			},
		})
		if ierr != nil {
			logrus.WithError(ierr).Fatal("Failed to initialize indexer client")
		}
		defer indexerClient.Close()
		txHashesOut, err = indexerClient.ExtendStorage(ctx, w3client, txHashes, opt)
	} else {
		uploader, closer, uerr := transfer.NewUploaderFromConfig(ctx, w3client, transfer.UploaderConfig{
			Nodes:          extendArgs.node,
			ProviderOption: providerOption,
			LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
			Contact: &transfer.ContractAddress{
				FlowAddress:   extendArgs.flowAddress,
				MarketAddress: extendArgs.marketAddress,
			},
			Routines: extendArgs.routines,
		})
		if uerr != nil {
			logrus.WithError(uerr).Fatal("Failed to initialize uploader")
		}
		defer closer()
		txHashesOut, err = uploader.ExtendStorage(ctx, txHashes, opt)
	}

	var unavailable *transfer.ErrDataUnavailable
	if errors.As(err, &unavailable) {
		logrus.Errorf("storage period NOT extended: %v", unavailable.Error())
		logrus.Fatal("re-run `upload` for the missing data")
	}
	if err != nil {
		logrus.WithError(err).Fatal("Failed to extend storage period")
	}

	s := make([]string, len(txHashesOut))
	for i, h := range txHashesOut {
		s[i] = h.Hex()
	}
	logrus.Infof("storage period extended, submit tx = %v", strings.Join(s, ","))
}
```

- [ ] **Step 2: Verify it builds**

Run: `go build ./... && go run . extend --help`
Expected: build OK; help shows `--tx`, `--indexer/--node`, `--key`, `--url`, fee/gas flags.

- [ ] **Step 3: Commit**

```bash
git add cmd/extend.go
git commit -m "cmd: add 'extend' subcommand to renew storage period (#153)"
```

---

### Task 9: End-to-end integration test

**Files:**
- Create: `tests/go_tests/extend_storage_test/main.go`
- Create: `tests/extend_storage_test.py`

Mirror `tests/go_tests/batch_upload_test/main.go` and `tests/batch_upload_test.py`. Read both before writing.

- [ ] **Step 1: Write the Go driver** — `tests/go_tests/extend_storage_test/main.go`

It must, using the same arg convention as `batch_upload_test/main.go` (`os.Args[1:]` = priv key, blockchain URL, comma-separated node URLs, indexer URL):

1. create a `web3go` client and an in-memory file (`core.NewDataInMemory(randomBytes)`);
2. build a `transfer.Uploader` from the node URLs (`transfer.NewUploaderFromConfig`);
3. `txHash, root, err := uploader.Upload(ctx, data, transfer.UploadOption{FinalityRequired: transfer.FileFinalized, ExpectedReplica: 1, Method: "min"})`; assert finalized via `GetFileInfo`;
4. `extendTxs, err := uploader.ExtendStorage(ctx, []common.Hash{txHash}, transfer.ExtendOption{Method: "min"})`; assert `err == nil` and `len(extendTxs) == 1` and `extendTxs[0] != txHash`;
5. fetch the extend tx receipt and assert it contains a `Submit` event whose identity equals `root` (locks `identity == root` and "no re-upload" — proves pay-again worked with no segment transfer);
6. wrap `runTest` in `util.WaitUntil(..., 3*time.Minute)` exactly like `batch_upload_test/main.go:76-80`.

```go
// key assertions (full file follows batch_upload_test/main.go scaffolding):
if err != nil {
	panic(fmt.Sprintf("extend failed: %v", err))
}
if len(extendTxs) != 1 || extendTxs[0] == txHash {
	panic("expected exactly one NEW extend tx hash distinct from the original")
}
receipt, _ := uploader_flow_WaitForReceipt(...) // via a fresh transfer.Uploader's flow, or web3 client
// parse logs, assert a Submit event with Identity == root exists
```

- [ ] **Step 2: Write the Python test** — `tests/extend_storage_test.py`

Subclass `ClientTestFramework` like `tests/batch_upload_test.py`: `setup_params` with `num_blockchain_nodes=1`, `num_nodes=1`; `run_test` spawns `go run tests/go_tests/extend_storage_test/main.go <GENESIS_PRIV_KEY> <blockchain_url> <node_urls> <indexer_url>` and asserts exit 0. Add a second scenario after the happy path:

- stop the single storage node (`self.stop_storage_node(...)` per the framework), then run a small Go driver assertion that `ExtendStorage` returns an error containing "no longer available" (the `ErrDataUnavailable` path). If stopping a node is awkward in the harness, assert the unavailable path by extending a **random unknown tx hash** and expecting `ErrSubmitEventNotFound` instead — whichever the harness supports cleanly; document the choice in a comment.

- [ ] **Step 3: Run the integration test**

Run: `cd tests && python extend_storage_test.py` (requires the `zgs_node`/CLI binaries the harness expects, per `tests/client_test_framework`).
Expected: PASS — upload, extend (new Submit for same identity), and the unavailable scenario.

- [ ] **Step 4: Commit**

```bash
git add tests/go_tests/extend_storage_test/main.go tests/extend_storage_test.py
git commit -m "tests: end-to-end extend-storage integration test (#153)"
```

---

### Task 10: Document the command and finish

**Files:**
- Modify: `cli.md`

- [ ] **Step 1: Add an `extend` section to `cli.md`** near the `upload` docs:

```markdown
### extend

Extend the storage period of already-stored data by paying the protocol fee again,
without re-uploading the bytes. Identify the data by the `Flow.submit` tx hash(es)
returned when it was uploaded.

```
0g-storage-client extend \
  --url <BLOCKCHAIN_RPC> --key <PRIVATE_KEY> \
  --indexer <INDEXER_URL> \
  --tx <SUBMIT_TX_HASH>[,<SUBMIT_TX_HASH>...]
```

If any fragment is no longer stored, no transaction is sent and the command reports which
roots must be uploaded again. There is no client-readable expiry; decide when to extend
based on your own records of when the data was uploaded.
```

- [ ] **Step 2: Run the full build and unit suite**

Run: `go build ./... && go vet ./transfer/... ./indexer/... ./cmd/... && go test ./transfer/...`
Expected: build/vet clean; transfer unit tests PASS.

- [ ] **Step 3: Commit**

```bash
git add cli.md
git commit -m "docs: document the extend command (#153)"
```

- [ ] **Step 4: Push and open the PR**

```bash
git push -u origin feat/extend-storage-period
gh pr create --fill --base main \
  --title "feat: extend storage period without re-upload (#153)" \
  --body "Implements #153. See docs/superpowers/specs/2026-06-05-extend-storage-period-design.md and docs/superpowers/plans/2026-06-06-extend-storage-period.md."
```

---

## Self-Review

**Spec coverage:**
- Tx-hash input → Task 5/8. ✓
- Submission recovered verbatim from Submit event (no scan/file) → Task 3/5. ✓
- All-fragments availability via indexer (`GetFileLocations`) and node (`GetFileInfo`) → Task 6/7. ✓
- Stop-and-ask-to-re-upload (`ErrDataUnavailable`, no payment) → Task 6/7/8. ✓
- Pay-again via submit/batchSubmit, no transfer → Task 6. ✓
- SDK (`transfer` + `indexer`) + CLI surface → Task 6/7/8. ✓
- Typed errors → Task 1. ✓
- Unit + integration tests → Task 1–4, 9. ✓
- `identity == root` assumption locked by integration test → Task 9 step 1.5. ✓

**Placeholder scan:** Implementation/unit-test steps contain complete code. Task 9 (integration) intentionally references `batch_upload_test` scaffolding and shows the exact new calls/assertions, because the harness wiring must match the existing template verbatim — the executor reads that file rather than risk a divergent copy.

**Type consistency:** `ExtendOption`, `ExtendItem`, `ErrDataUnavailable{Missing}`, `ErrSubmitEventNotFound{TxHash}`, `parseSubmissions`, `feeForSubmissions`, `isRootAvailable`, `RecoverSubmissions`, `checkAvailability`, `Resubmit`, `ExtendStorage` are named identically across Tasks 1–8. `Resubmit` uses `defaultBatchSize`/`min` (already in `transfer`), `bind.CallOpts`, `contract.TransactWithGasAdjustment`, `contract.TxRetryOption` — all confirmed to exist.
