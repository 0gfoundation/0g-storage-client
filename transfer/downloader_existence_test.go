package transfer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Both existence errors are reported for a fragment's temp file as well as for the
// caller's own destination. Without the path, someone hitting the fragment case reads
// "File already exists", inspects the output file they asked for, finds nothing wrong
// with it, and never learns the obstacle is a <root>.temp they never created.
func TestCheckFileExistence_NamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "0x1111.temp")
	require.NoError(t, os.WriteFile(path, []byte("a completed fragment"), 0644))

	root, err := core.MerkleRoot(path)
	require.NoError(t, err)

	matching := checkFileExistence(path, root)
	require.Error(t, matching)
	assert.ErrorIs(t, matching, ErrFileAlreadyExists,
		"download_dir matches on this sentinel, so it must stay wrapped rather than replaced")
	assert.Contains(t, matching.Error(), path, "the message must say which file")

	mismatched := checkFileExistence(path, common.HexToHash("0xdead"))
	require.Error(t, mismatched)
	assert.NotErrorIs(t, mismatched, ErrFileAlreadyExists, "a different hash is a distinct, fatal error")
	assert.Contains(t, mismatched.Error(), "different hash")
	assert.Contains(t, mismatched.Error(), path, "the message must say which file")
}

// A path that does not exist is not an error at all.
func TestCheckFileExistence_MissingFileIsNotAnError(t *testing.T) {
	assert.NoError(t, checkFileExistence(filepath.Join(t.TempDir(), "absent.dat"), common.HexToHash("0xdead")))
}
