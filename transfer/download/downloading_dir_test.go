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

// touchFile is reached only for entries the manifest declares empty. An existing file
// with content used to be left exactly as it was, so the downloaded tree silently
// disagreed with the manifest that produced it — while a non-empty entry whose local
// copy differs has always failed the download outright with "File already exists with
// different hash". This makes the two consistent, without truncating data the caller
// may still want.
func TestTouchFile_RefusesExistingFileWithContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "was-not-empty.dat")
	content := []byte("content the manifest says should not be here")
	require.NoError(t, os.WriteFile(path, content, 0644))

	err := touchFile(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove it and retry", "the message must say what to do")
	assert.NotContains(t, err.Error(), path,
		"Add supplies the path, so touchFile must not repeat it")

	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, content, data, "the file must not be truncated — that would destroy data")
}

// An existing empty file is exactly what the entry asks for, so it is accepted.
func TestTouchFile_AcceptsExistingEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "already-empty.dat")
	require.NoError(t, os.WriteFile(path, nil, 0644))

	assert.NoError(t, touchFile(path))
}

// Add surfaces the refusal rather than reporting the entry as materialized.
func TestDownloadingDir_Add_RefusesNonEmptyFileForEmptyEntry(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	directory, err := CreateDownloadingDir(root)
	require.NoError(t, err)

	staged := filepath.Join(root+downloadingFileSuffix, "keep.dat")
	require.NoError(t, os.WriteFile(staged, []byte("pre-existing content"), 0644))

	err = directory.Add(&dir.FsNode{Name: "keep.dat", Type: dir.FileTypeFile}, "keep.dat", nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove it and retry")
}
