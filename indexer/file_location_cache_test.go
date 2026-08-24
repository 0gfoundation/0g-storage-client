package indexer

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countOpenFDs returns the number of descriptors currently open in this process.
// Readdirnames is used rather than os.ReadDir because the latter lstats every entry, and
// on Darwin the directory's own transient descriptor is already gone by then.
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

func shardConfigServer(t *testing.T) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"shardId":0,"numShard":1}}`))
	}))
	t.Cleanup(server.Close)

	return server
}

// Discovery probes a client per candidate URL on every lookup that reaches it. Each
// client carries its own HTTP transport whose connections Close does not release, so
// constructing one per probe grew the descriptor count with traffic rather than with the
// number of distinct nodes.
func TestFileLocationCache_ReusesOneClientPerURL(t *testing.T) {
	server := shardConfigServer(t)

	var cache FileLocationCache
	defer cache.Close()

	first, err := cache.zgsClient(server.URL)
	require.NoError(t, err)
	require.NotNil(t, first)

	const iterations = 50
	before := countOpenFDs(t)
	for i := 0; i < iterations; i++ {
		again, err := cache.zgsClient(server.URL)
		require.NoError(t, err)
		require.Same(t, first, again, "the same URL must yield the same client")
	}
	after := countOpenFDs(t)

	assert.LessOrEqual(t, after, before+2,
		"repeated lookups leaked descriptors: %d open before, %d after %d lookups", before, after, iterations)
}

// Distinct URLs get distinct clients — the cost scales with nodes, not with traffic.
func TestFileLocationCache_DistinctURLsGetDistinctClients(t *testing.T) {
	one, two := shardConfigServer(t), shardConfigServer(t)

	var cache FileLocationCache
	defer cache.Close()

	a, err := cache.zgsClient(one.URL)
	require.NoError(t, err)
	b, err := cache.zgsClient(two.URL)
	require.NoError(t, err)

	assert.NotSame(t, a, b)
}

// A URL whose shard-config lookup fails is not cached, so a later attempt can retry it.
func TestFileLocationCache_FailedClientIsNotCached(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}))
	defer failing.Close()

	var cache FileLocationCache
	defer cache.Close()

	_, err := cache.zgsClient(failing.URL)
	require.Error(t, err)

	_, cached := cache.zgsClients.Load(failing.URL)
	assert.False(t, cached, "a client that could not be initialized must not be stored")
}
