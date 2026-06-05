# Extend storage period — design

- **Date:** 2026-06-05
- **Issue:** [#153](https://github.com/0gfoundation/0g-storage-client/issues/153)
- **Status:** approved for planning

## Problem

Data uploaded to 0G storage is paid for a fixed period (~1 year) at upload time. There
is currently **no way to extend that period**. A user who wants to keep data alive past
its term has no choice but to upload the whole file again, re-paying *and* re-transferring
every byte.

We want an `ExtendStorage` operation: re-pay the storage fee for data that is **already on
the network**, *without* re-transferring the bytes. If the data is no longer stored, the
user is told to upload it again.

### What exists today (verified)

- **No extend/renew/topup capability** anywhere — not in the CLI, `transfer.Uploader`,
  `indexer.Client`, or `kv.Client`.
- **The client has no notion of storage duration.** The protocol fee is purely size-based:
  `Σ (2^nodeHeight) × pricePerSector` (`contract.Submission.Fee`, `contract/contract.go:377`).
  The "1 year" lifetime is a protocol/economic setting the client **cannot read**. There is
  no expiry/remaining-period field on `node.FileInfo`.

  Consequence: this is an **extend-now** operation. *When* to extend (e.g. near expiry) is
  the caller's responsibility; the client cannot compute or enforce a deadline.
- `Flow.submit` / `Flow.batchSubmit` are `payable` and accept a `Submission{Data{Length,
  Tags, Nodes[]}, Submitter}`. Re-calling them with the same content is **not** blocked by
  the contract (no on-chain dedup); only the storage node rejects re-uploading the *segments*
  of already-finalized data. So paying again on chain is allowed; we must just skip the byte
  transfer.
- `node.FileInfo.Pruned` (mutually exclusive with `Finalized`, `node/types.go:51`) is the
  "data root no longer available" signal.

## Key decisions

| Decision | Choice | Why |
| --- | --- | --- |
| What identifies the data | The original **`Flow.submit` tx hash(es)** returned by `upload` | A root alone cannot recover the `Submission` cheaply (see below). A submit tx hash recovers it with a single receipt fetch. One tx may batch several fragments, so a list of tx hashes covers a fragmented file. |
| Where the `Submission` comes from | **Verbatim from the on-chain `Submit` event**, parsed from the submit-tx receipt via the existing `flow.ParseSubmit` | We never recompute or "worry about" the merkle nodes — they come straight from chain. No original file needed. |
| Existence check | **Indexer** `GetFileLocations(root)` (indexer mode) / `GetFileInfo(root)` (node mode) | Reuses existing logic that resolves root → txSeq → holding nodes and only counts finalized, shard-covered data. |
| Fragment handling | All-or-nothing | A file is split into fragments, each its own root. Extend proceeds only if **every** fragment is still stored. |
| When data is gone | **Stop and ask to re-upload** (typed error, no payment) | Extend never silently performs an expensive full upload. |
| Surface area | **SDK + CLI** | `transfer.Uploader`, `indexer.Client`, and an `extend` subcommand. |

### Why not reconstruct the submission from a root

Recovering the `Submission` from a *root alone* requires finding the original `Submit`
event. Its indexed `identity` topic equals the data root, but `FilterSubmit(identity=root)`
needs a block range, and **nothing maps a root to its submit block**: `node.FileInfo.Tx`
carries only `Seq`/`StartEntryIndex`/`Size`/`DataMerkleRoot` (`node/types.go:36-43`); the
`admin_*` RPCs are sync/peer related; `getFlowRootByTxSeq` returns a root, not a block.

So the filter would default to `[deployBlock … latest]` — for data uploaded ~a year ago on
0G's fast blocks that is millions of blocks, and `eth_getLogs` is range-capped / timeout-prone
on most RPC providers. **Rejected as infeasible.** The submit tx hash avoids the scan entirely.

## Flow

Input: `submitTxHashes []common.Hash`, plus an `ExtendOption` (fee/gas/nonce, node-selection
method, indexer-vs-node, etc.).

1. **Recover submissions (no scan).** For each tx hash:
   - fetch the receipt (`flow.WaitForReceipt` / `eth_getTransactionReceipt`);
   - for each log, attempt `flow.ParseSubmit(*log.ToEthLog())` — same pattern as
     `Uploader.ParseLogs` (`transfer/uploader.go:690-700`);
   - from each parsed `FlowSubmit`, take `Submission{Data: ev.Submission}` verbatim and derive
     `root = Submission.Root()` (`contract/contract.go:117`); defensively assert `root ==
     ev.Identity`.
   - If a tx is not found or has no `Submit` log → `ErrSubmitEventNotFound{TxHash}`.
   - Result: a de-duplicated set of `(root, Submission)` pairs across all tx hashes.
2. **Check all fragments still stored.**
   - *Indexer mode:* for each root → `indexer.Client.GetFileLocations(root)`; require
     `shard.Select(locations, 1, method)` coverage.
   - *Node mode:* for each root → `GetFileInfo(root, true)` across selected nodes; require a
     non-nil, `Finalized`, non-`Pruned` result with shard coverage.
   - Collect every root that fails. If the set is non-empty → return
     `ErrDataUnavailable{Missing []common.Hash}` and **send no transaction**.
3. **Pay again, no transfer.** For every recovered submission:
   - set `Submission.Submitter` to the extending wallet (root is derived only from `Data`, so
     it is unchanged → any wallet may extend any data);
   - recompute total fee `Σ Submission.Fee(pricePerSector)` using `market.PricePerSector`;
   - re-submit via `Flow.submit` (single) / `Flow.batchSubmit` (batched by `BatchSize`),
     reusing the gas-adjustment machinery (`contract.TransactWithGasAdjustment`).
   - **No `uploadFile` / segment transfer is performed.**
   - Return the new submit tx hashes.

## Components & interfaces

### `transfer` package — new file `transfer/extend.go`

```go
// ExtendOption controls an extend-storage operation.
type ExtendOption struct {
    TransactionOption        // Submitter, Fee, Nonce, MaxGasPrice, NRetries, Step
    Method            string // node-selection method for availability checks ("random", "min", ...)
    BatchSize         uint   // submissions per batchSubmit tx (default defaultBatchSize)
}

// ExtendStorage re-pays the storage fee for data already stored on the network,
// identified by the original Flow.submit tx hashes, without re-uploading bytes.
// Availability is checked against the uploader's own nodes. Returns the new submit
// tx hashes. Returns *ErrDataUnavailable if any fragment is no longer stored
// (in which case no transaction is sent).
func (uploader *Uploader) ExtendStorage(
    ctx context.Context, submitTxHashes []common.Hash, opt ExtendOption,
) ([]common.Hash, error)
```

Internal helpers (shared, also used by the indexer layer):

```go
// recoverSubmissions fetches each submit-tx receipt and parses its Submit logs into
// (root, Submission) pairs, de-duplicated by root.
func (uploader *Uploader) recoverSubmissions(
    ctx context.Context, submitTxHashes []common.Hash,
) ([]extendItem, error)               // extendItem{ Root common.Hash; Submission contract.Submission }

// resubmit pays the fee again for the given submissions (no byte transfer) and
// returns the new tx hashes. Batches by opt.BatchSize.
func (uploader *Uploader) resubmit(
    ctx context.Context, items []extendItem, opt ExtendOption,
) ([]common.Hash, error)
```

The availability check is **pluggable** so both layers reuse `recoverSubmissions` + `resubmit`:
the transfer layer checks via its selected nodes' `GetFileInfo`; the indexer layer checks via
`GetFileLocations`.

### `indexer` package — new method on `Client` (e.g. `indexer/client_extend.go`)

```go
// ExtendStorage recovers submissions from the given submit-tx hashes, verifies every
// fragment is still stored using the indexer's GetFileLocations, then re-pays via storage
// nodes selected from the indexer. Returns the new submit tx hashes, or *ErrDataUnavailable.
func (c *Client) ExtendStorage(
    ctx context.Context, w3Client *web3go.Client,
    submitTxHashes []eth_common.Hash, opt transfer.ExtendOption,
) ([]eth_common.Hash, error)
```

### Typed errors — in `transfer/extend.go`

```go
type ErrDataUnavailable struct{ Missing []common.Hash } // data pruned/gone; re-upload required
func (e *ErrDataUnavailable) Error() string

type ErrSubmitEventNotFound struct{ TxHash common.Hash } // tx missing or no Submit log
func (e *ErrSubmitEventNotFound) Error() string
```

### CLI — new file `cmd/extend.go`

`extend` subcommand mirroring `cmd/upload.go`'s structure (`extendArgument` struct,
`bindExtendFlags`, `init()` → `rootCmd.AddCommand`, handler):

- `--tx` (repeatable / comma-separated) — original `Flow.submit` tx hashes. Required.
- `--indexer` **xor** `--node` (one required, like upload).
- `--key`, `--url` and the standard transaction flags (`--fee`, `--nonce`, `--max-gas-price`,
  `--n-retries`, `--step`), `--method`, `--expected-replica`, `--timeout`,
  `--flow-address` / `--market-address`.
- No `--file`, no `--tags` (tags come from chain).
- Output: the new submit tx hashes. On `ErrDataUnavailable`, print the missing roots and a
  clear "these fragments are no longer stored — upload them again" message; exit non-zero.

## Error handling

- Tx not found / no `Submit` log → `ErrSubmitEventNotFound`.
- Any fragment unavailable → `ErrDataUnavailable{Missing}`, **no payment**.
- Fee/gas handling and retries reuse the existing `TransactWithGasAdjustment` path, including
  the `--max-gas-price` mempool-bump behavior.
- Partial-progress on batched re-submit: like `SplitableUpload`, accumulate and return any
  tx hashes already sent before surfacing an error, so a retry does not double-pay batches
  that already succeeded.

## Testing

- **Unit** (`transfer/extend_test.go`): given a synthetic receipt containing one/more `Submit`
  logs, assert `recoverSubmissions` returns the right roots (== `Submission.Root()` ==
  `Identity`) and that the computed fee matches `Σ 2^height × pricePerSector`. Cover the
  no-`Submit`-log → `ErrSubmitEventNotFound` case.
- **Integration** (`tests/extend_storage_test.py`, mirroring `tests/cli_file_upload_download_test.py`
  and the `go_tests/` harness):
  1. upload a file (possibly large enough to fragment), capture the submit tx hash(es);
  2. call `extend` with those tx hashes; assert success and that a **new** `Submit` event with
     the **same identity** is emitted (this also locks the `identity == root` assumption);
  3. assert no segment re-upload occurs (e.g. node `uploadedSegNum` unchanged / fast completion);
  4. prune / stop a node holding a fragment so coverage is lost; assert `extend` returns
     `ErrDataUnavailable` and sends no transaction.

## Assumption to validate

Re-paying the fee for the same data root **extends its protocol-level lifetime**, rather than
creating an unrelated paid entry. This is the premise of the feature; it is the storage
protocol's behavior and is confirmed/locked by the integration test (a second `Submit` for the
same identity is accepted and the data remains finalized).

## Out of scope

- Reading/displaying remaining storage period or expiry (not exposed by the protocol).
- Reconstructing submissions from a root alone (rejected — full-chain scan).
- Persisting submission metadata at upload time.
- Automatic "extend near expiry" scheduling (caller's responsibility).
