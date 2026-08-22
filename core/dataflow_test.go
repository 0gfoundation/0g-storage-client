package core

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileAndInMemoryData(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	size := DefaultSegmentSize*10 + 10

	data := make([]byte, size)
	n, err := r.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, n, len(data))

	tmpFile, err := os.CreateTemp("", "0g-storage-client-*")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(data)
	assert.NoError(t, err)

	file, err := Open(tmpFile.Name())
	assert.NoError(t, err)

	fileTree, err := MerkleTree(file)
	assert.NoError(t, err)

	inMem, _ := NewDataInMemory(data)
	inMemTree, err := MerkleTree(inMem)
	assert.NoError(t, err)

	assert.Equal(t, fileTree.Root(), inMemTree.Root())
}

// A single-segment file yields a single-leaf segment proof, whose lemma holds one
// hash that serves as leaf, segment root and file root at once. Proof.ValidateHash
// compares the caller's contentHash and root against that same element, so segment
// proof validation in transfer/segment_fetch.go and indexer/gateway/upload.go is
// only correct while the file root and the padded segment root agree whenever
// PaddedSegmentRoot reports one flow-padded segment.
//
// This holds because a lone segment is padded to the file's full flow-padded chunk
// count, making the segment tree the file tree. If the padding rules ever diverge,
// single-segment downloads with --proof would start failing, so pin it here.
func TestPaddedSegmentRoot_SingleSegmentRootMatchesFileRoot(t *testing.T) {
	sizes := []int64{
		1, 100, 255, 256, 257, 1000, 4096, 25600, 245760,
		int64(DefaultSegmentSize) - 1,
		int64(DefaultSegmentSize),
		int64(DefaultSegmentSize) + 1, // first size needing two segments
		2 * int64(DefaultSegmentSize),
	}

	sawSingle, sawMulti := false, false

	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i%251 + 1)
		}

		mem, err := NewDataInMemory(data)
		require.NoError(t, err, "size=%d", size)
		tree, err := MerkleTree(mem)
		require.NoError(t, err, "size=%d", size)

		// Segment 0 as a storage node returns it: chunk-aligned bytes.
		segChunks := min(NumSplits(size, DefaultChunkSize), uint64(DefaultSegmentMaxChunks))
		aligned := make([]byte, segChunks*DefaultChunkSize)
		copy(aligned, data)

		segRoot, numSegPad := PaddedSegmentRoot(0, aligned, size)

		if numSegPad == 1 {
			sawSingle = true
			assert.Equal(t, tree.Root(), segRoot,
				"size=%d: one flow-padded segment, so the segment root must equal the file root "+
					"or single-leaf proof validation breaks", size)
		} else {
			sawMulti = true
		}
	}

	require.True(t, sawSingle, "no single-segment size exercised")
	require.True(t, sawMulti, "no multi-segment size exercised")
}
