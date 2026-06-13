package transfer

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The OnSubmitted broadcast callback (issue #159) rides on the embedded
// TransactionOption so it threads automatically from the public option
// structs (UploadOption / BatchUploadOption) down to the
// SubmitLogEntryOption that SubmitLogEntry actually passes to the
// contract layer. A refactor that reconstructs any of these structs
// field-by-field (or moves OnSubmitted off the embedded type) would
// silently drop the callback — and a dropped callback re-opens the
// landed-but-unrecorded window on cancel with NO behavioral test
// failure (the upload still succeeds; only crash-resume billing breaks).
// These tests pin the threading so that silent-failure mode can't ship.

// fires returns a callback plus a pointer to the hash it captures, so a
// test can prove the SAME callback survived a struct copy by invoking it
// (func values are not == comparable in Go beyond nil).
func fires() (func(common.Hash), *common.Hash) {
	var got common.Hash
	return func(h common.Hash) { got = h }, &got
}

func TestOnSubmitted_PreservedThroughNormalizeUpload(t *testing.T) {
	cb, got := fires()
	opt := UploadOption{TransactionOption: TransactionOption{OnSubmitted: cb}}

	normalizeUploadOption(&opt)

	require.NotNil(t, opt.OnSubmitted, "normalizeUploadOption dropped OnSubmitted")
	want := common.HexToHash("0xabc123")
	opt.OnSubmitted(want)
	assert.Equal(t, want, *got, "OnSubmitted after normalize is not the original callback")
}

// Mirrors the construction in submitLogEntryNoReceipt / submitLogEntryAndWait:
// SubmitLogEntryOption{TransactionOption: opt.TransactionOption, ...}.
func TestOnSubmitted_ThreadsToSubmitLogEntryOption(t *testing.T) {
	cb, got := fires()
	opt := UploadOption{TransactionOption: TransactionOption{OnSubmitted: cb}}

	submitOpts := SubmitLogEntryOption{TransactionOption: opt.TransactionOption}

	require.NotNil(t, submitOpts.OnSubmitted, "OnSubmitted did not thread into SubmitLogEntryOption")
	want := common.HexToHash("0xdeadbeef")
	submitOpts.OnSubmitted(want)
	assert.Equal(t, want, *got)
}

// Mirrors the batch path in SplitableUpload: txOpt := opt.TransactionOption;
// txOpt.Nonce = nil; batchOpt := BatchUploadOption{TransactionOption: txOpt}.
// Then BatchUpload builds its SubmitLogEntryOption from opts.TransactionOption.
func TestOnSubmitted_ThreadsThroughBatchToSubmitLogEntry(t *testing.T) {
	cb, got := fires()
	opt := UploadOption{TransactionOption: TransactionOption{OnSubmitted: cb}}

	txOpt := opt.TransactionOption
	txOpt.Nonce = nil // as SplitableUpload does per batch
	batchOpt := BatchUploadOption{TransactionOption: txOpt}

	// BatchUpload's inner construction.
	submitOpt := SubmitLogEntryOption{TransactionOption: batchOpt.TransactionOption}

	require.NotNil(t, submitOpt.OnSubmitted, "OnSubmitted did not survive UploadOption→batch→SubmitLogEntryOption")
	want := common.HexToHash("0xfeed")
	submitOpt.OnSubmitted(want)
	assert.Equal(t, want, *got)
}

func TestOnSubmitted_NilByDefault(t *testing.T) {
	// Existing callers that never set it must keep a nil callback — the
	// contract layer nil-guards before invoking, so this is the
	// no-behavior-change baseline.
	var opt UploadOption
	normalizeUploadOption(&opt)
	assert.Nil(t, opt.OnSubmitted)

	submitOpts := SubmitLogEntryOption{TransactionOption: opt.TransactionOption}
	assert.Nil(t, submitOpts.OnSubmitted)
}
