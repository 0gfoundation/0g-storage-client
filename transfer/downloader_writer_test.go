package transfer

import (
	"testing"

	"github.com/0gfoundation/0g-storage-client/core"
)

// These tests exercise the chunk + segment + slicing geometry that
// downloadRangeToWriter relies on. The real fetch path goes through
// storage-node RPCs (covered by integration tests against MinIO/0G
// testnet); here we verify the boundary math in isolation.

const (
	tChunk     = core.DefaultChunkSize        // 256
	tSegChunks = core.DefaultSegmentMaxChunks // 1024
	tSeg       = tChunk * tSegChunks          // 262144
)

// computeRangeBounds replicates the segment-range derivation in
// downloadRangeToWriter so the math can be tested in isolation. If the
// implementation drifts from this helper, one or both must be updated.
func computeRangeBounds(offset, length, fileSize int64) (startSeg, endSeg uint64, ok bool) {
	if length < 0 {
		length = fileSize - offset
	}
	if offset < 0 || offset > fileSize || offset+length > fileSize {
		return 0, 0, false
	}
	if length == 0 {
		return 0, 0, true
	}
	chunkSize := int64(core.DefaultChunkSize)
	segChunks := uint64(core.DefaultSegmentMaxChunks)
	fileNumChunks := core.NumSplits(fileSize, core.DefaultChunkSize)
	endByte := offset + length
	startChunk := uint64(offset / chunkSize)
	endChunkExcl := uint64((endByte + chunkSize - 1) / chunkSize)
	if endChunkExcl > fileNumChunks {
		endChunkExcl = fileNumChunks
	}
	startSeg = startChunk / segChunks
	endSeg = (endChunkExcl - 1) / segChunks
	return startSeg, endSeg, true
}

func TestComputeRangeBounds_FirstSegmentOnly(t *testing.T) {
	startSeg, endSeg, ok := computeRangeBounds(100, 50, int64(2*tSeg+1000))
	if !ok || startSeg != 0 || endSeg != 0 {
		t.Fatalf("got start=%d end=%d ok=%v", startSeg, endSeg, ok)
	}
}

func TestComputeRangeBounds_CrossingSegmentBoundary(t *testing.T) {
	off := int64(tSeg - 100)
	startSeg, endSeg, ok := computeRangeBounds(off, 200, int64(3*tSeg))
	if !ok || startSeg != 0 || endSeg != 1 {
		t.Fatalf("got start=%d end=%d ok=%v", startSeg, endSeg, ok)
	}
}

func TestComputeRangeBounds_LastSegmentRespectsFileSize(t *testing.T) {
	fileSize := int64(2*tSeg + 100)
	startSeg, endSeg, ok := computeRangeBounds(2*tSeg, 100, fileSize)
	if !ok || startSeg != 2 || endSeg != 2 {
		t.Fatalf("got start=%d end=%d ok=%v", startSeg, endSeg, ok)
	}
}

func TestComputeRangeBounds_FullFileSentinel(t *testing.T) {
	if _, _, ok := computeRangeBounds(0, -1, 1000); !ok {
		t.Error("length=-1 with offset=0 should be treated as full file")
	}
}

func TestComputeRangeBounds_RejectsOutOfBounds(t *testing.T) {
	if _, _, ok := computeRangeBounds(-1, 10, 1000); ok {
		t.Error("negative offset should reject")
	}
	if _, _, ok := computeRangeBounds(900, 200, 1000); ok {
		t.Error("offset+length past file end should reject")
	}
}
