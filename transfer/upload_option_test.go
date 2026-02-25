package transfer

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

// TestNormalizeUploadOption_ZeroValue verifies that a completely zero-valued
// UploadOption (simulating an SDK caller that passes no flags) gets safe defaults.
func TestNormalizeUploadOption_ZeroValue(t *testing.T) {
	var opt UploadOption
	normalizeUploadOption(&opt)

	// Method must not be empty (empty breaks CheckReplica with Atoi(""))
	assert.Equal(t, "random", opt.Method)

	// Tags must be non-nil empty slice (nil has different ABI encoding than 0x)
	assert.NotNil(t, opt.Tags)
	assert.Empty(t, opt.Tags)

	// These zero values are all valid/safe defaults:
	assert.Equal(t, FileFinalized, opt.FinalityRequired, "zero value = FileFinalized (strictest)")
	assert.Equal(t, uint(0), opt.TaskSize, "0 is handled downstream by uploadFile (defaults to 10)")
	assert.Equal(t, uint(0), opt.ExpectedReplica, "0 short-circuits CheckReplica")
	assert.False(t, opt.SkipTx, "should not skip tx by default")
	assert.False(t, opt.FastMode, "should not be fast mode by default")
	assert.Nil(t, opt.Fee, "nil fee means auto-calculate")
	assert.Nil(t, opt.Nonce, "nil nonce means auto")
	assert.Nil(t, opt.MaxGasPrice, "nil max gas price means no limit")
	assert.Equal(t, 0, opt.NRetries)
	assert.Equal(t, int64(0), opt.Step)
	assert.False(t, opt.FullTrusted)
	assert.Nil(t, opt.EncryptionKey, "nil means no encryption")
	assert.Equal(t, common.Address{}, opt.Submitter, "zero address filled later from flow contract")
	assert.Equal(t, defaultFragmentSize, opt.FragmentSize, "fragment size defaults to 4GiB")
	assert.Equal(t, defaultBatchSize, opt.BatchSize, "batch size defaults to 10")
}

// TestNormalizeUploadOption_Preserves verifies that user-supplied values are not overwritten.
func TestNormalizeUploadOption_Preserves(t *testing.T) {
	key := make([]byte, 32)
	opt := UploadOption{
		TransactionOption: TransactionOption{
			Fee:         big.NewInt(100),
			Nonce:       big.NewInt(42),
			MaxGasPrice: big.NewInt(999),
			NRetries:    3,
			Step:        10,
		},
		Tags:             []byte{0x01, 0x02},
		EncryptionKey:    key,
		FinalityRequired: TransactionPacked,
		TaskSize:         5,
		ExpectedReplica:  3,
		SkipTx:           true,
		FastMode:         true,
		Method:           "max",
		FullTrusted:      true,
		FragmentSize:     1024 * 1024,
		BatchSize:        20,
	}
	normalizeUploadOption(&opt)

	assert.Equal(t, "max", opt.Method, "user-supplied method preserved")
	assert.Equal(t, []byte{0x01, 0x02}, opt.Tags, "user-supplied tags preserved")
	assert.Equal(t, TransactionPacked, opt.FinalityRequired)
	assert.Equal(t, uint(5), opt.TaskSize)
	assert.Equal(t, uint(3), opt.ExpectedReplica)
	assert.True(t, opt.SkipTx)
	assert.True(t, opt.FastMode)
	assert.Equal(t, big.NewInt(100), opt.Fee)
	assert.Equal(t, big.NewInt(42), opt.Nonce)
	assert.Equal(t, big.NewInt(999), opt.MaxGasPrice)
	assert.Equal(t, 3, opt.NRetries)
	assert.Equal(t, int64(10), opt.Step)
	assert.True(t, opt.FullTrusted)
	assert.Equal(t, key, opt.EncryptionKey)
	assert.Equal(t, int64(1024*1024), opt.FragmentSize, "user-supplied fragment size preserved")
	assert.Equal(t, uint(20), opt.BatchSize, "user-supplied batch size preserved")
}

// TestNormalizeBatchUploadOption_ZeroValue verifies batch defaults for SDK callers.
func TestNormalizeBatchUploadOption_ZeroValue(t *testing.T) {
	opts := BatchUploadOption{
		DataOptions: make([]UploadOption, 3),
	}
	normalizeBatchUploadOption(&opts, 3)

	assert.Equal(t, "random", opts.Method, "batch method defaults to random")
	assert.Equal(t, uint(1), opts.TaskSize, "batch task size defaults to 1")

	// Each DataOption should be normalized
	for i, dopt := range opts.DataOptions {
		assert.Equal(t, "random", dopt.Method, "DataOptions[%d].Method", i)
		assert.NotNil(t, dopt.Tags, "DataOptions[%d].Tags not nil", i)
		assert.Empty(t, dopt.Tags, "DataOptions[%d].Tags empty", i)
	}
}

// TestNormalizeBatchUploadOption_Preserves verifies user-supplied batch values are kept.
func TestNormalizeBatchUploadOption_Preserves(t *testing.T) {
	opts := BatchUploadOption{
		Method:   "3",
		TaskSize: 5,
		DataOptions: []UploadOption{
			{Method: "max", Tags: []byte{0xAA}},
			{Method: "2", Tags: []byte{0xBB}},
		},
	}
	normalizeBatchUploadOption(&opts, 2)

	assert.Equal(t, "3", opts.Method)
	assert.Equal(t, uint(5), opts.TaskSize)
	assert.Equal(t, "max", opts.DataOptions[0].Method)
	assert.Equal(t, []byte{0xAA}, opts.DataOptions[0].Tags)
	assert.Equal(t, "2", opts.DataOptions[1].Method)
	assert.Equal(t, []byte{0xBB}, opts.DataOptions[1].Tags)
}

// TestNormalizeBatchUploadOption_MixedDataOptions verifies that only zero-valued
// DataOptions get defaults while user-supplied ones are preserved.
func TestNormalizeBatchUploadOption_MixedDataOptions(t *testing.T) {
	opts := BatchUploadOption{
		DataOptions: []UploadOption{
			{Method: "max", Tags: []byte{0x01}}, // user-supplied
			{},                                  // zero-valued, needs defaults
			{Method: "", Tags: nil},             // explicitly zero, needs defaults
		},
	}
	normalizeBatchUploadOption(&opts, 3)

	// First: preserved
	assert.Equal(t, "max", opts.DataOptions[0].Method)
	assert.Equal(t, []byte{0x01}, opts.DataOptions[0].Tags)

	// Second: defaulted
	assert.Equal(t, "random", opts.DataOptions[1].Method)
	assert.NotNil(t, opts.DataOptions[1].Tags)
	assert.Empty(t, opts.DataOptions[1].Tags)

	// Third: defaulted
	assert.Equal(t, "random", opts.DataOptions[2].Method)
	assert.NotNil(t, opts.DataOptions[2].Tags)
	assert.Empty(t, opts.DataOptions[2].Tags)
}
