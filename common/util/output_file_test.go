package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSimulatedClose = errors.New("simulated close failure")

// failCloseFile writes through to a real file but reports an error from Close. It
// stands in for the delayed writeback failures that only surface when a descriptor
// is closed - ENOSPC, EIO, quota exhaustion, a network filesystem giving up - and
// that cannot be provoked on demand against a real local filesystem.
type failCloseFile struct {
	*os.File
}

func (f failCloseFile) Close() error {
	f.File.Close() // release the real descriptor; the caller still sees the failure

	return errSimulatedClose
}

// The download paths that use this helper reach a real storage node, so they are
// covered by the functional tests; these cases pin the helper's own contract.
func TestCloseOutputFile(t *testing.T) {
	newFile := func(t *testing.T) (string, *os.File) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "output.dat")
		file, err := os.Create(path)
		require.NoError(t, err)
		return path, file
	}

	t.Run("clean close passes the caller's error through", func(t *testing.T) {
		path, file := newFile(t)
		assert.NoError(t, CloseOutputFile(file, path, nil))
		assert.FileExists(t, path)
	})

	t.Run("close failure is reported and the file removed", func(t *testing.T) {
		path, file := newFile(t)
		err := CloseOutputFile(failCloseFile{file}, path, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, errSimulatedClose)
		assert.NoFileExists(t, path, "a file that failed to close must not be left behind")
	})

	t.Run("an earlier error wins and its partial output is kept", func(t *testing.T) {
		path, file := newFile(t)
		downloadErr := errors.New("failed to download fragment 2")
		err := CloseOutputFile(failCloseFile{file}, path, downloadErr)
		assert.Equal(t, downloadErr, err)
		assert.FileExists(t, path, "pre-existing error paths keep their partial output")
	})
}
