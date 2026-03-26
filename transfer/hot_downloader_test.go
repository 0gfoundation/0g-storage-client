package transfer

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	return key
}

// mockFallbackDownloader is a test double implementing IDownloader.
type mockFallbackDownloader struct {
	downloadFunc          func(ctx context.Context, root, filename string, withProof bool) error
	downloadFragmentsFunc func(ctx context.Context, roots []string, filename string, withProof bool) error
}

func (m *mockFallbackDownloader) Download(ctx context.Context, root, filename string, withProof bool) error {
	if m.downloadFunc != nil {
		return m.downloadFunc(ctx, root, filename, withProof)
	}
	return nil
}

func (m *mockFallbackDownloader) DownloadFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	if m.downloadFragmentsFunc != nil {
		return m.downloadFragmentsFunc(ctx, roots, filename, withProof)
	}
	return nil
}

// newTestHotNode creates a mock hot storage node JSON-RPC server.
func newTestHotNode(t *testing.T, fileData []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rpcReq struct {
			Method string      `json:"method"`
			ID     interface{} `json:"id"`
		}
		json.NewDecoder(r.Body).Decode(&rpcReq)

		w.Header().Set("Content-Type", "application/json")

		if rpcReq.Method == "hot_download" {
			encoded := base64.StdEncoding.EncodeToString(fileData)
			result := node.HotDownloadResponse{
				Data:   encoded,
				FeeWei: "1000",
			}
			resp := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      rpcReq.ID,
				"result":  result,
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      rpcReq.ID,
			"error":   map[string]interface{}{"code": -32601, "message": "method not found"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

// newTestRouter creates a mock router. If hotNodeURL is non-empty, it returns that node (cache hit).
// If empty, it returns 404 (cache miss).
func newTestRouter(t *testing.T, hotNodeURL string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download" && r.Method == http.MethodPost {
			if hotNodeURL == "" {
				// Cache miss — router returns 404 and handles prefetch server-side.
				http.Error(w, "file not cached", http.StatusNotFound)
				return
			}

			var req node.HotRouterDownloadRequest
			json.NewDecoder(r.Body).Decode(&req)

			resp := node.HotRouterDownloadResponse{
				NodeURL:   hotNodeURL,
				Provider:  "0x1111111111111111111111111111111111111111",
				FileHash:  req.FileHash,
				MaxFee:    "1000000",
				Nonce:     99999,
				Signature: "0xdeadbeef",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
}

func TestHotDownloader_CacheHit(t *testing.T) {
	fileContent := []byte("hello hot storage world")
	hotNode := newTestHotNode(t, fileContent)
	defer hotNode.Close()
	router := newTestRouter(t, hotNode.URL)
	defer router.Close()

	key := testKey(t)
	routerClient := node.NewHotRouterClient(router.URL)

	fallbackCalled := false
	fallback := &mockFallbackDownloader{
		downloadFunc: func(ctx context.Context, root, filename string, withProof bool) error {
			fallbackCalled = true
			return nil
		},
	}

	downloader := NewHotDownloader(routerClient, key, fallback)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "output.dat")

	err := downloader.Download(context.Background(), "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", outFile, false)
	require.NoError(t, err)
	assert.False(t, fallbackCalled, "fallback should not be called on cache hit")

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, fileContent, data)
}

func TestHotDownloader_CacheMiss_FallbackCalled(t *testing.T) {
	router := newTestRouter(t, "") // empty = 404 cache miss
	defer router.Close()

	key := testKey(t)
	routerClient := node.NewHotRouterClient(router.URL)

	fallbackContent := []byte("fallback content")
	fallback := &mockFallbackDownloader{
		downloadFunc: func(ctx context.Context, root, filename string, withProof bool) error {
			return os.WriteFile(filename, fallbackContent, 0644)
		},
	}

	downloader := NewHotDownloader(routerClient, key, fallback)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "output.dat")

	err := downloader.Download(context.Background(), "0xaaaa", outFile, false)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, fallbackContent, data)
}

func TestHotDownloader_RouterDown_FallbackCalled(t *testing.T) {
	// Router that always returns error.
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer router.Close()

	key := testKey(t)
	routerClient := node.NewHotRouterClient(router.URL)

	fallbackContent := []byte("fallback on router error")
	fallback := &mockFallbackDownloader{
		downloadFunc: func(ctx context.Context, root, filename string, withProof bool) error {
			return os.WriteFile(filename, fallbackContent, 0644)
		},
	}

	downloader := NewHotDownloader(routerClient, key, fallback)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "output.dat")

	err := downloader.Download(context.Background(), "0xbbbb", outFile, false)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, fallbackContent, data)
}

func TestHotDownloader_DownloadFragments_AllCached(t *testing.T) {
	frag1 := []byte("fragment one data")

	hotNode := newTestHotNode(t, frag1)
	defer hotNode.Close()
	router := newTestRouter(t, hotNode.URL)
	defer router.Close()

	key := testKey(t)
	routerClient := node.NewHotRouterClient(router.URL)

	fallbackCalled := false
	fallback := &mockFallbackDownloader{
		downloadFunc: func(ctx context.Context, root, filename string, withProof bool) error {
			fallbackCalled = true
			return nil
		},
	}

	downloader := NewHotDownloader(routerClient, key, fallback)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "output.dat")

	roots := []string{
		"0x1111111111111111111111111111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222222222222222222222222222",
	}

	err := downloader.DownloadFragments(context.Background(), roots, outFile, false)
	require.NoError(t, err)
	assert.False(t, fallbackCalled)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	// Both fragments return frag1 (from the hot node mock).
	expected := append(frag1, frag1...)
	assert.Equal(t, expected, data)
}

func TestHotDownloader_DownloadFragments_AllCacheMiss(t *testing.T) {
	// Router returns 404 for all fragments.
	router := newTestRouter(t, "")
	defer router.Close()

	key := testKey(t)
	routerClient := node.NewHotRouterClient(router.URL)

	fallbackData := []byte("fallback fragment")
	fallback := &mockFallbackDownloader{
		downloadFunc: func(ctx context.Context, root, filename string, withProof bool) error {
			return os.WriteFile(filename, fallbackData, 0644)
		},
	}

	downloader := NewHotDownloader(routerClient, key, fallback)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "output.dat")

	roots := []string{"0xaaaa", "0xbbbb"}

	err := downloader.DownloadFragments(context.Background(), roots, outFile, false)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	expected := append(fallbackData, fallbackData...)
	assert.Equal(t, expected, data)
}

func TestHotDownloader_ImplementsIDownloader(t *testing.T) {
	var _ IDownloader = (*HotDownloader)(nil)
}

func TestHotDownloader_WithEncryptionKey(t *testing.T) {
	key := testKey(t)
	routerClient := node.NewHotRouterClient("http://unused")
	fallback := &mockFallbackDownloader{}

	downloader := NewHotDownloader(routerClient, key, fallback)
	encKey := make([]byte, 32)
	for i := range encKey {
		encKey[i] = byte(i)
	}
	result := downloader.WithEncryptionKey(encKey)
	assert.Equal(t, downloader, result)
	assert.Equal(t, encKey, downloader.encryptionKey)
}

func TestHotDownloader_CacheHit_LargeFile(t *testing.T) {
	// Test with a larger file (1MB).
	fileContent := make([]byte, 1024*1024)
	for i := range fileContent {
		fileContent[i] = byte(i % 256)
	}

	hotNode := newTestHotNode(t, fileContent)
	defer hotNode.Close()
	router := newTestRouter(t, hotNode.URL)
	defer router.Close()

	key := testKey(t)
	routerClient := node.NewHotRouterClient(router.URL)
	fallback := &mockFallbackDownloader{}

	downloader := NewHotDownloader(routerClient, key, fallback)

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "large_output.dat")

	err := downloader.Download(context.Background(), "0xcccc", outFile, false)
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, fileContent, data)
}

func TestHotDownloader_ContextCanceled(t *testing.T) {
	// Router that blocks until context canceled.
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer router.Close()

	key := testKey(t)
	routerClient := node.NewHotRouterClient(router.URL)

	fallback := &mockFallbackDownloader{
		downloadFunc: func(ctx context.Context, root, filename string, withProof bool) error {
			return ctx.Err()
		},
	}

	downloader := NewHotDownloader(routerClient, key, fallback)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "output.dat")

	err := downloader.Download(ctx, "0xdddd", outFile, false)
	// Should fail — either router request fails or fallback context is canceled.
	assert.Error(t, err)
}
