package download

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countOpenFDs returns the number of descriptors currently open in this process.
// Both /proc/self/fd (Linux) and /dev/fd (Darwin) enumerate them. Readdirnames is
// used rather than os.ReadDir because the latter lstats every entry, and on Darwin
// the directory's own transient descriptor is already gone by then. The count
// includes that transient descriptor, but it does so on every call, so successive
// counts remain comparable.
func countOpenFDs(t *testing.T) int {
	t.Helper()

	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		dirFile, err := os.Open(dir)
		if err != nil {
			continue
		}
		names, err := dirFile.Readdirnames(-1)
		dirFile.Close()
		if err == nil {
			return len(names)
		}
	}

	t.Skip("cannot enumerate open descriptors on this platform")
	return 0
}

// CreateDownloadingFile opens the .download file before validating it, so the
// descriptor is only handed to the returned DownloadingFile on success. Root and
// size mismatches are ordinary occurrences — they happen whenever a download is
// resumed against a stale .download file — so leaking on those paths accumulates
// descriptors in any process that retries downloads.
func TestCreateDownloadingFile_NoDescriptorLeakOnValidationFailure(t *testing.T) {
	dir := t.TempDir()

	rootA := common.HexToHash("0xaa")
	rootB := common.HexToHash("0xbb")
	const size int64 = 100

	// Seed a valid .download file for (rootA, size) and release it.
	seeded := filepath.Join(dir, "seeded.dat")
	file, err := CreateDownloadingFile(seeded, rootA, size)
	require.NoError(t, err)
	require.NoError(t, file.Close())

	// A .download file too short to hold metadata, so LoadMetadata fails.
	truncated := filepath.Join(dir, "truncated.dat")
	require.NoError(t, os.WriteFile(truncated+downloadingFileSuffix, []byte("short"), 0644))

	for _, tc := range []struct {
		name     string
		filename string
		root     common.Hash
		size     int64
	}{
		{"root mismatch", seeded, rootB, size},
		{"size mismatch", seeded, rootA, size * 2},
		{"unreadable metadata", truncated, rootA, size},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Prime once so lazily-initialized runtime state isn't counted as a leak.
			_, err := CreateDownloadingFile(tc.filename, tc.root, tc.size)
			require.Error(t, err)

			const iterations = 200
			before := countOpenFDs(t)
			for i := 0; i < iterations; i++ {
				downloading, err := CreateDownloadingFile(tc.filename, tc.root, tc.size)
				require.Error(t, err)
				require.Nil(t, downloading)
			}
			after := countOpenFDs(t)

			assert.LessOrEqual(t, after, before+2,
				"CreateDownloadingFile leaked descriptors: %d open before, %d after %d failed calls",
				before, after, iterations)
		})
	}
}
