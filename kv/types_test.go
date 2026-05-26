package kv

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

// TestEncodedSizeForSingleWriteMatchesSize pins the closed-form helper
// against the authoritative Size() method across a range of key/data
// lengths. Both must agree, AND both must match the actual byte length
// of Encode() — otherwise a pricing pre-flight built on the helper
// would under-charge.
func TestEncodedSizeForSingleWriteMatchesSize(t *testing.T) {
	cases := []struct{ keyLen, dataLen int }{
		{1, 1},
		{1, 256},
		{8, 0},
		{16, 4096},
		{32, 65536},
		{64, 1 << 20},
		{0xFFFF, 0xFFFF},
	}
	for _, tc := range cases {
		sd := &StreamData{
			Version: 0,
			Writes: []streamWrite{{
				StreamId: common.Hash{},
				Key:      make([]byte, tc.keyLen),
				Data:     make([]byte, tc.dataLen),
			}},
		}

		want := sd.Size()
		got := EncodedSizeForSingleWrite(tc.keyLen, tc.dataLen)
		assert.Equal(t, want, got,
			"helper drifted from Size(): keyLen=%d dataLen=%d", tc.keyLen, tc.dataLen)

		// Belt-and-braces: actually encode and check the byte length.
		// Size() promises encoded size, so this catches any bug where
		// Size() itself drifts from Encode().
		encoded, err := sd.Encode()
		assert.NoError(t, err)
		assert.Equal(t, want, len(encoded),
			"Size() drifted from Encode(): keyLen=%d dataLen=%d", tc.keyLen, tc.dataLen)
	}
}
