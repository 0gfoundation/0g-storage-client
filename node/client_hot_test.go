package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHotCacheStatusConstants(t *testing.T) {
	assert.Equal(t, HotCacheStatus("FullyCached"), HotCacheStatusFullyCached)
	assert.Equal(t, HotCacheStatus("FetchInProgress"), HotCacheStatusFetchInProgress)
	assert.Equal(t, HotCacheStatus("NotCached"), HotCacheStatusNotCached)
}

func TestNewHotClient_InvalidURL(t *testing.T) {
	_, err := NewHotClient("://invalid-url")
	assert.Error(t, err)
}

func TestNewHotClient_ValidURL(t *testing.T) {
	client, err := NewHotClient("http://localhost:6789")
	assert.NoError(t, err)
	assert.NotNil(t, client)
	client.Close()
}

// newMockHotNode creates a test JSON-RPC server that handles hot storage methods.
func newMockHotNode(t *testing.T, handler func(method string, params json.RawMessage) (interface{}, *jsonRPCError)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			ID     interface{}     `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		w.Header().Set("Content-Type", "application/json")

		result, rpcErr := handler(req.Method, req.Params)
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req.ID,
		}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func TestCheckCached_FullyCached(t *testing.T) {
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		assert.Equal(t, "hot_checkCached", method)
		return HotCacheStatusFullyCached, nil
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	status, err := client.CheckCached(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, HotCacheStatusFullyCached, status)
}

func TestCheckCached_FetchInProgress(t *testing.T) {
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		return HotCacheStatusFetchInProgress, nil
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	status, err := client.CheckCached(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, HotCacheStatusFetchInProgress, status)
}

func TestCheckCached_NotCached(t *testing.T) {
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		return HotCacheStatusNotCached, nil
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	status, err := client.CheckCached(context.Background(), 99)
	require.NoError(t, err)
	assert.Equal(t, HotCacheStatusNotCached, status)
}

func TestCheckCached_RPCError(t *testing.T) {
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		return nil, &jsonRPCError{Code: -32000, Message: "internal error"}
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	_, err = client.CheckCached(context.Background(), 1)
	assert.Error(t, err)
}

func TestPrefetch_Success(t *testing.T) {
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		assert.Equal(t, "hot_prefetch", method)
		return &HotPrefetchResponse{
			Accepted:        true,
			AlreadyCached:   false,
			FetchInProgress: false,
		}, nil
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	resp, err := client.Prefetch(context.Background(), "0xabcd")
	require.NoError(t, err)
	assert.True(t, resp.Accepted)
	assert.False(t, resp.AlreadyCached)
	assert.False(t, resp.FetchInProgress)
}

func TestPrefetch_AlreadyCached(t *testing.T) {
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		return &HotPrefetchResponse{
			Accepted:        true,
			AlreadyCached:   true,
			FetchInProgress: false,
		}, nil
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	resp, err := client.Prefetch(context.Background(), "0xabcd")
	require.NoError(t, err)
	assert.True(t, resp.AlreadyCached)
}

func TestPrefetch_FetchInProgress(t *testing.T) {
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		return &HotPrefetchResponse{
			Accepted:        true,
			AlreadyCached:   false,
			FetchInProgress: true,
		}, nil
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	resp, err := client.Prefetch(context.Background(), "0xabcd")
	require.NoError(t, err)
	assert.True(t, resp.FetchInProgress)
}

func TestHotDownload_CacheHit(t *testing.T) {
	encoded := "aGVsbG8=" // base64("hello")
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		assert.Equal(t, "hot_download", method)
		return &HotDownloadResponse{
			Data:   &encoded,
			FeeWei: "500",
		}, nil
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	auth := &HotRouterDownloadResponse{
		NodeURL:   server.URL,
		Provider:  "0x1111",
		FileHash:  "0xabcd",
		MaxFee:    "1000",
		Nonce:     1,
		Signature: "0xdeadbeef",
	}
	resp, err := client.HotDownload(context.Background(), "0xuser", auth)
	require.NoError(t, err)
	require.NotNil(t, resp.Data)
	assert.Equal(t, encoded, *resp.Data)
	assert.Equal(t, "500", resp.FeeWei)
}

func TestHotDownload_CacheMiss(t *testing.T) {
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		return &HotDownloadResponse{
			Data:   nil,
			FeeWei: "0",
		}, nil
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	auth := &HotRouterDownloadResponse{
		NodeURL:   server.URL,
		FileHash:  "0xabcd",
		MaxFee:    "1000",
		Nonce:     1,
		Signature: "0xdeadbeef",
	}
	resp, err := client.HotDownload(context.Background(), "0xuser", auth)
	require.NoError(t, err)
	assert.Nil(t, resp.Data)
}

func TestCheckCached_ContextCanceled(t *testing.T) {
	server := newMockHotNode(t, func(method string, params json.RawMessage) (interface{}, *jsonRPCError) {
		return HotCacheStatusFullyCached, nil
	})
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.CheckCached(ctx, 1)
	assert.Error(t, err)
}
