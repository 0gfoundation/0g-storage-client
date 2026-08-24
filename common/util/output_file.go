package util

import (
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// CloseOutputFile closes a finished output file and folds the result into the error
// the caller has already accumulated.
//
// The close result must not be discarded: it is the first point at which the OS can
// report a delayed writeback failure - ENOSPC, EIO, quota exhaustion, a network
// filesystem giving up - so a write sequence whose every call succeeded can still
// end up truncated on disk. Returning nil there hands the caller a silently
// incomplete file that looks complete.
//
// An error the caller already holds always wins, since a close failure is at most a
// secondary symptom of it. The file is only removed when close is the sole failure,
// which leaves the partial output of pre-existing error paths exactly where it was.
//
// Intended for a deferred call under a named error result:
//
//	defer func() { err = util.CloseOutputFile(outFile, filename, err) }()
func CloseOutputFile(file io.Closer, filename string, prevErr error) error {
	closeErr := file.Close()
	if closeErr == nil || prevErr != nil {
		return prevErr
	}

	os.Remove(filename)

	return errors.WithMessage(closeErr, "failed to close output file")
}

// TempDirBeside creates a temporary directory alongside filename, so intermediate work
// for that destination shares the destination's filesystem rather than landing wherever
// the process happens to be running or in a system temp directory that may be much
// smaller. The caller is responsible for removing it, normally with a deferred
// os.RemoveAll.
//
// pattern is interpreted as by os.MkdirTemp: a trailing "*" is replaced by a random
// string, otherwise one is appended.
func TempDirBeside(filename, pattern string) (string, error) {
	dir, err := os.MkdirTemp(filepath.Dir(filename), pattern)
	if err != nil {
		return "", errors.WithMessagef(err, "failed to create temp directory beside %v", filename)
	}

	return dir, nil
}
