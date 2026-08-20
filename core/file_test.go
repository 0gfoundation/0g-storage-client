package core

import (
	"os"
	"path/filepath"
	"testing"

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

// Open owns the descriptor it opened until it hands it to the returned *File, so
// every post-open failure has to close it first. Callers that validate many
// user-supplied paths without ever holding a *File — the local gateway opens one
// per HTTP request — would otherwise leak a descriptor per failure until the
// process hits its limit.
func TestOpen_NoDescriptorLeakOnValidationFailure(t *testing.T) {
	dir := t.TempDir()

	emptyFile := filepath.Join(dir, "empty.dat")
	require.NoError(t, os.WriteFile(emptyFile, nil, 0644))

	subDir := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0755))

	for _, tc := range []struct {
		name    string
		path    string
		wantErr error
	}{
		{"directory", subDir, ErrFileRequired},
		{"empty file", emptyFile, ErrFileEmpty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Prime once so lazily-initialized runtime state isn't counted as a leak.
			_, err := Open(tc.path)
			require.ErrorIs(t, err, tc.wantErr)

			const iterations = 200
			before := countOpenFDs(t)
			for i := 0; i < iterations; i++ {
				file, err := Open(tc.path)
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, file)
			}
			after := countOpenFDs(t)

			assert.LessOrEqual(t, after, before+2,
				"Open leaked descriptors: %d open before, %d after %d failed calls",
				before, after, iterations)
		})
	}
}

func TestOpen_SucceedsForRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.dat")
	require.NoError(t, os.WriteFile(path, []byte("0g storage"), 0644))

	before := countOpenFDs(t)

	file, err := Open(path)
	require.NoError(t, err)
	assert.Equal(t, int64(len("0g storage")), file.Size())
	require.NoError(t, file.Close())

	assert.LessOrEqual(t, countOpenFDs(t), before+1, "descriptor still open after Close")
}
