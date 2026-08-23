package download

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0gfoundation/0g-storage-client/transfer/dir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTouchFile_CreatesEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.dat")

	require.NoError(t, touchFile(path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())
}

// touchFile closes the descriptor before calling os.Chtimes, which works on the path
// rather than the descriptor. This pins that the timestamps are still applied.
func TestTouchFile_RefreshesModTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.dat")
	require.NoError(t, os.WriteFile(path, nil, 0644))

	stale := time.Now().Add(-72 * time.Hour)
	require.NoError(t, os.Chtimes(path, stale, stale))

	before := time.Now().Add(-time.Second)
	require.NoError(t, touchFile(path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, info.ModTime().After(before),
		"mod time %v was not refreshed (still near the stale %v)", info.ModTime(), stale)
}

// Characterizes today's behavior: touchFile opens without O_TRUNC, so an entry left
// over from an earlier run into the same .download directory keeps its content. If
// that is ever changed, it should be a deliberate decision rather than a surprise.
func TestTouchFile_LeavesExistingContentIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.dat")
	require.NoError(t, os.WriteFile(path, []byte("previously downloaded"), 0644))

	require.NoError(t, touchFile(path))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("previously downloaded"), data)
}

func TestTouchFile_ReturnsErrorWhenParentMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "file.dat")

	err := touchFile(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create or open file")
}

// Add must surface a touchFile failure rather than reporting the entry as materialized.
func TestDownloadingDir_Add_PropagatesTouchFileError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	directory, err := CreateDownloadingDir(root)
	require.NoError(t, err)

	// The parent directory of the entry is never created, so touchFile cannot succeed.
	err = directory.Add(&dir.FsNode{Name: "file.dat", Type: dir.FileTypeFile}, "missing/file.dat", nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create empty file")
}

func TestDownloadingDir_Add_CreatesEmptyFileEntry(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	directory, err := CreateDownloadingDir(root)
	require.NoError(t, err)

	require.NoError(t, directory.Add(&dir.FsNode{Name: "empty.dat", Type: dir.FileTypeFile}, "empty.dat", nil))

	info, err := os.Stat(filepath.Join(root+downloadingFileSuffix, "empty.dat"))
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())
}

// An existing directory is never touched, matching the single-file contract where
// checkFileExistence refuses rather than overwrites. Staging used to rename it aside,
// so a mid-download failure left it existing only under the staging name.
func TestCreateDownloadingDir_RefusesExistingDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	require.NoError(t, os.Mkdir(root, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "keep.dat"), []byte("pre-existing"), 0644))

	directory, err := CreateDownloadingDir(root)

	require.Error(t, err)
	assert.Nil(t, directory)
	assert.Contains(t, err.Error(), "already exists")

	// Untouched: still at its own path, contents intact, nothing staged.
	data, readErr := os.ReadFile(filepath.Join(root, "keep.dat"))
	require.NoError(t, readErr)
	assert.Equal(t, []byte("pre-existing"), data)
	assert.NoDirExists(t, root+downloadingFileSuffix)
}

func TestCreateDownloadingDir_CreatesStagingForFreshPath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")

	directory, err := CreateDownloadingDir(root)

	require.NoError(t, err)
	require.NotNil(t, directory)
	assert.DirExists(t, root+downloadingFileSuffix)
	assert.NoDirExists(t, root, "the destination appears only on Seal")
}

// A previous attempt's staging directory is reused so a retry resumes rather than
// re-fetching everything: Add skips entries whose content already matches.
func TestCreateDownloadingDir_ReusesStagingFromEarlierAttempt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")

	first, err := CreateDownloadingDir(root)
	require.NoError(t, err)
	require.NotNil(t, first)
	partial := filepath.Join(root+downloadingFileSuffix, "partial.dat")
	require.NoError(t, os.WriteFile(partial, []byte("already fetched"), 0644))

	// Retry: the destination still does not exist, so this must proceed and keep the work.
	second, err := CreateDownloadingDir(root)
	require.NoError(t, err)
	require.NotNil(t, second)

	data, err := os.ReadFile(partial)
	require.NoError(t, err)
	assert.Equal(t, []byte("already fetched"), data, "partial work must survive a retry")
}

func TestDownloadingDir_SealInstallsStaging(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")

	directory, err := CreateDownloadingDir(root)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root+downloadingFileSuffix, "new.dat"), []byte("new"), 0644))

	require.NoError(t, directory.Seal())

	assert.DirExists(t, root)
	assert.NoDirExists(t, root+downloadingFileSuffix)
	assert.FileExists(t, filepath.Join(root, "new.dat"))
}
