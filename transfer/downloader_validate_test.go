package transfer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every step of the download normalises the caller's root through common.HexToHash,
// except the final validation, which compared it as text against Hash.Hex's canonical
// form. So a root spelled in any other accepted way - uppercase digits, no 0x prefix,
// fewer than 64 digits - completed its download and was then rejected for its spelling.
func TestValidateDownloadFile_AcceptsEquivalentRootForms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.dat")
	content := []byte("some downloaded content")
	require.NoError(t, os.WriteFile(path, content, 0644))

	root, err := core.MerkleRoot(path)
	require.NoError(t, err)
	canonical := root.Hex()

	downloader := &Downloader{logger: logrus.New()}

	for _, form := range []struct {
		name string
		root string
	}{
		{"canonical", canonical},
		{"uppercase digits", "0x" + strings.ToUpper(strings.TrimPrefix(canonical, "0x"))},
		{"no 0x prefix", strings.TrimPrefix(canonical, "0x")},
	} {
		t.Run(form.name, func(t *testing.T) {
			assert.NoError(t, downloader.validateDownloadFile(form.root, path, int64(len(content))),
				"%q denotes the same hash as %q", form.root, canonical)
		})
	}
}

// A genuinely different root must still be rejected, and the message should name both.
func TestValidateDownloadFile_RejectsDifferentRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.dat")
	content := []byte("some downloaded content")
	require.NoError(t, os.WriteFile(path, content, 0644))

	downloader := &Downloader{logger: logrus.New()}
	err := downloader.validateDownloadFile(
		"0xbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad0", path, int64(len(content)))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Merkle root mismatch")
	assert.Contains(t, err.Error(), "expected", "the message should name the root that was asked for")
}

func TestValidateDownloadFile_RejectsSizeMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.dat")
	require.NoError(t, os.WriteFile(path, []byte("short"), 0644))

	root, err := core.MerkleRoot(path)
	require.NoError(t, err)

	downloader := &Downloader{logger: logrus.New()}
	assert.ErrorContains(t, downloader.validateDownloadFile(root.Hex(), path, 9999), "File size mismatch")
}
