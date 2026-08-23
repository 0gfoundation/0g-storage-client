package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SegmentRoot is reached with client-supplied bytes: indexer/gateway/upload.go passes
// the raw Data field of an upload request into PaddedSegmentRoot, which forwards it
// here, and nothing on that path validates the length. Slicing a fixed
// DefaultChunkSize per iteration therefore has to tolerate a trailing partial chunk,
// or a single malformed request takes the gateway process down.
func TestSegmentRoot_UnalignedInputDoesNotPanic(t *testing.T) {
	for _, size := range []int{1, 100, 255, 257, 300, 511, DefaultChunkSize + 1} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i%251 + 1)
		}

		require.NotPanics(t, func() { SegmentRoot(data) }, "size=%d", size)
	}
}

// A trailing partial chunk is treated as zero-padded to a full chunk, which is how the
// flow pads whole chunks too, so the root matches explicitly padded input.
func TestSegmentRoot_UnalignedInputIsZeroPadded(t *testing.T) {
	for _, size := range []int{1, 100, 255, 257, 300, 511} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i%251 + 1)
		}

		alignedLen := (size + DefaultChunkSize - 1) / DefaultChunkSize * DefaultChunkSize
		padded := make([]byte, alignedLen)
		copy(padded, data)

		assert.Equal(t, SegmentRoot(padded), SegmentRoot(data),
			"size=%d: partial chunk should hash as if zero-padded", size)
	}
}

// The exact gateway path: PaddedSegmentRoot on unvalidated client data.
func TestPaddedSegmentRoot_UnalignedClientDataDoesNotPanic(t *testing.T) {
	require.NotPanics(t, func() {
		PaddedSegmentRoot(0, make([]byte, 100), 100)
	})
}
