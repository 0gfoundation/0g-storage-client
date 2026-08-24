package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The direct /file route reached downloadAndServeFile without any size check, so the
// configured maximum applied only to in-folder downloads. These cases pin the boundary
// the shared check now enforces for both routes.
func TestCheckDownloadSize(t *testing.T) {
	const max uint64 = 100

	ctrl := NewRestController(nil, nil, max)
	require.NotNil(t, ctrl)

	for _, tc := range []struct {
		name     string
		size     uint64
		rejected bool
	}{
		{"empty file", 0, false},
		{"below the limit", max - 1, false},
		{"exactly at the limit", max, false},
		{"one byte over", max + 1, true},
		{"far over", max * 1000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ctrl.checkDownloadSize(tc.size)
			if tc.rejected {
				require.Error(t, err, "size %d must be rejected", tc.size)
			} else {
				assert.NoError(t, err, "size %d must be allowed", tc.size)
			}
		})
	}
}

// A maximum of 0 rejects every non-empty file rather than meaning "unlimited". That is
// the pre-existing behaviour of the in-folder check, documented here so a future change
// to it is deliberate.
func TestCheckDownloadSize_ZeroMaximumRejectsEverything(t *testing.T) {
	ctrl := NewRestController(nil, nil, 0)

	assert.NoError(t, ctrl.checkDownloadSize(0), "an empty file is not over the limit")
	assert.Error(t, ctrl.checkDownloadSize(1), "0 is a limit, not a sentinel for unlimited")
}
