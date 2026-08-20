package util

import (
	"io"
	"os"

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
