package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fragmentSize is deliberately not a multiple of DefaultChunkSize (256), so each
// fragment's logical view ends mid-chunk and the padded read runs past it.
const testFragmentSize = 100

// distinctBytes fills each 100-byte region with a different value, so data belonging
// to a later fragment is immediately recognisable if it leaks into an earlier one.
func distinctBytes(regions int) []byte {
	data := make([]byte, 0, regions*testFragmentSize)
	for r := 0; r < regions; r++ {
		data = append(data, bytes.Repeat([]byte{byte('A' + r)}, testFragmentSize)...)
	}
	return data
}

// A fragment must never expose bytes past its logical size. core.ReadAt allocates a
// zero-filled buffer and relies on Read leaving the tail untouched to act as padding,
// so an unclamped Read silently replaces that padding with the next fragment's data.
// EncryptedDataFragment.Read already clamps this way.
func TestDataInMemory_FragmentReadStopsAtLogicalEnd(t *testing.T) {
	data, err := NewDataInMemory(distinctBytes(3))
	require.NoError(t, err)

	fragments := data.Split(testFragmentSize)
	require.Len(t, fragments, 3)

	for i, fragment := range fragments {
		require.Equal(t, int64(testFragmentSize), fragment.Size(), "fragment %d", i)

		buf := make([]byte, DefaultChunkSize) // 256 > 100, so the read spans the boundary
		n, err := fragment.Read(buf, 0)
		require.NoError(t, err)

		assert.Equal(t, testFragmentSize, n, "fragment %d should report only its own bytes", i)
		assert.Equal(t, bytes.Repeat([]byte{byte('A' + i)}, testFragmentSize), buf[:testFragmentSize],
			"fragment %d content", i)
		assert.Equal(t, make([]byte, DefaultChunkSize-testFragmentSize), buf[testFragmentSize:],
			"fragment %d must leave the padding region zeroed, not fill it with later data", i)
	}
}

// The consequence that matters: core.ReadAt feeds both merkle tree construction and
// segment upload, so a fragment's root must depend only on the fragment's own bytes.
func TestDataInMemory_FragmentMerkleRootIgnoresLaterFragments(t *testing.T) {
	first, err := NewDataInMemory(distinctBytes(3))
	require.NoError(t, err)

	// Same leading fragment, entirely different trailing fragments.
	tailChanged := append(distinctBytes(1), bytes.Repeat([]byte{'Z'}, 2*testFragmentSize)...)
	second, err := NewDataInMemory(tailChanged)
	require.NoError(t, err)

	rootOf := func(data *DataInMemory) string {
		fragment := data.Split(testFragmentSize)[0]
		tree, err := MerkleTree(fragment)
		require.NoError(t, err)
		return tree.Root().Hex()
	}

	assert.Equal(t, rootOf(first), rootOf(second),
		"fragment 0 has identical content in both, so its root must not depend on what follows it")
}

func TestFile_FragmentReadStopsAtLogicalEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.bin")
	require.NoError(t, os.WriteFile(path, distinctBytes(3), 0644))

	file, err := Open(path)
	require.NoError(t, err)
	defer file.Close()

	fragments := file.Split(testFragmentSize)
	require.Len(t, fragments, 3)

	for i, fragment := range fragments {
		buf := make([]byte, DefaultChunkSize)
		n, err := fragment.Read(buf, 0)
		require.NoError(t, err)

		assert.Equal(t, testFragmentSize, n, "fragment %d should report only its own bytes", i)
		assert.Equal(t, make([]byte, DefaultChunkSize-testFragmentSize), buf[testFragmentSize:],
			"fragment %d must leave the padding region zeroed, not fill it with later data", i)
	}
}

// Reading at or past the logical end yields nothing rather than the next fragment's
// bytes, and an out-of-range offset must not panic.
func TestDataInMemory_FragmentReadPastEnd(t *testing.T) {
	data, err := NewDataInMemory(distinctBytes(3))
	require.NoError(t, err)
	fragment := data.Split(testFragmentSize)[0]

	for _, offset := range []int64{testFragmentSize, testFragmentSize + 1, 1 << 20} {
		buf := make([]byte, DefaultChunkSize)
		n, err := fragment.Read(buf, offset)
		require.NoError(t, err, "offset %d", offset)
		assert.Zero(t, n, "offset %d", offset)
		assert.Equal(t, make([]byte, DefaultChunkSize), buf, "offset %d must not copy anything", offset)
	}
}

// Finding 12: a fragment's chunk/segment counts describe the fragment, not the buffer
// it was split from. File already derives these from Size().
func TestDataInMemory_FragmentChunkAndSegmentCounts(t *testing.T) {
	big := make([]byte, 3*DefaultSegmentSize)
	data, err := NewDataInMemory(big)
	require.NoError(t, err)

	fragments := data.Split(DefaultSegmentSize)
	require.Len(t, fragments, 3)

	for i, fragment := range fragments {
		assert.Equal(t, NumSplits(fragment.Size(), DefaultChunkSize), fragment.NumChunks(),
			"fragment %d NumChunks must describe the fragment", i)
		assert.Equal(t, NumSplits(fragment.Size(), DefaultSegmentSize), fragment.NumSegments(),
			"fragment %d NumSegments must describe the fragment", i)
	}
}
