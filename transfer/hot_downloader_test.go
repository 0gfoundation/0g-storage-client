package transfer

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testChainID int64 = 16601 // 0G testnet — value doesn't matter here since the mock router doesn't verify, but avoids hard-coding magic numbers.

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

// newTestHotNode creates a mock hot storage node HTTP server.
func newTestHotNode(t *testing.T, fileData []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/download" {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(fileData)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
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
				NodeURL:    hotNodeURL,
				Provider:   "0x1111111111111111111111111111111111111111",
				FileHashes: req.FileHashes,
				MaxFee:     "1000000",
				Nonce:      99999,
				Signature:  "0xdeadbeef",
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
	routerClient := node.NewHotRouterClient(router.URL, testChainID)

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
	routerClient := node.NewHotRouterClient(router.URL, testChainID)

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
	routerClient := node.NewHotRouterClient(router.URL, testChainID)

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
	routerClient := node.NewHotRouterClient(router.URL, testChainID)

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
	routerClient := node.NewHotRouterClient(router.URL, testChainID)

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
	routerClient := node.NewHotRouterClient("http://unused", testChainID)
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
	routerClient := node.NewHotRouterClient(router.URL, testChainID)
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
	routerClient := node.NewHotRouterClient(router.URL, testChainID)

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

// failOutputCloseFor makes every download file whose name satisfies match report a
// Close failure for the duration of the test. Writes still land on disk, so the
// only thing under test is whether the close result is honoured.
func failOutputCloseFor(t *testing.T, match func(name string) bool) {
	t.Helper()

	original := createOutputFile
	createOutputFile = func(name string) (io.WriteCloser, error) {
		file, err := os.Create(name)
		if err != nil {
			return nil, err
		}
		if match(name) {
			return failCloseFile{file}, nil
		}

		return file, nil
	}
	t.Cleanup(func() { createOutputFile = original })
}

func isTempFragment(name string) bool { return strings.HasSuffix(name, ".temp") }
func isFinalOutput(name string) bool  { return !isTempFragment(name) }

// chdirTemp moves the test into a scratch directory, because the fragment paths
// write their per-root .temp files relative to the process working directory.
func chdirTemp(t *testing.T) {
	t.Helper()

	original, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(t.TempDir()))
	t.Cleanup(func() { require.NoError(t, os.Chdir(original)) })
}

// encryptedV1Fragment builds a v1 (symmetric) encrypted stream: header followed by
// AES-256-CTR ciphertext starting at plaintext offset 0.
func encryptedV1Fragment(t *testing.T, key [32]byte, plaintext []byte) []byte {
	t.Helper()

	header, err := core.NewEncryptionHeader()
	require.NoError(t, err)

	body := append([]byte(nil), plaintext...)
	core.CryptAt(&key, &header.Nonce, 0, body)

	return append(header.ToBytes(), body...)
}

func testEncryptionKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	return key
}

// A hot download whose output file fails to close may be truncated on disk, so it
// must not be reported as a completed download.
func TestHotDownloader_Download_CloseFailureIsReported(t *testing.T) {
	hotNode := newTestHotNode(t, []byte("hot storage payload"))
	defer hotNode.Close()
	router := newTestRouter(t, hotNode.URL)
	defer router.Close()

	failOutputCloseFor(t, isFinalOutput)

	fallbackCalled := false
	downloader := NewHotDownloader(
		node.NewHotRouterClient(router.URL, testChainID),
		testKey(t),
		&mockFallbackDownloader{downloadFunc: func(context.Context, string, string, bool) error {
			fallbackCalled = true
			return nil
		}},
	)

	output := filepath.Join(t.TempDir(), "output.dat")
	err := downloader.Download(context.Background(), "0xabcd", output, false)

	require.Error(t, err)
	assert.ErrorIs(t, err, errSimulatedClose)
	assert.False(t, fallbackCalled, "a close failure is not a cache miss")
	assert.NoFileExists(t, output, "a file that failed to close must not be left behind looking complete")
}

// The close result has to be inspected before the file is read back for decryption,
// otherwise a truncated download surfaces as a confusing decryption failure.
func TestHotDownloader_Download_CloseCheckedBeforeDecryption(t *testing.T) {
	hotNode := newTestHotNode(t, []byte("not a valid encryption header"))
	defer hotNode.Close()
	router := newTestRouter(t, hotNode.URL)
	defer router.Close()

	failOutputCloseFor(t, isFinalOutput)

	downloader := NewHotDownloader(
		node.NewHotRouterClient(router.URL, testChainID),
		testKey(t),
		&mockFallbackDownloader{},
	).WithEncryptionKey(testEncryptionKey())

	output := filepath.Join(t.TempDir(), "output.dat")
	err := downloader.Download(context.Background(), "0xabcd", output, false)

	require.Error(t, err)
	assert.ErrorIs(t, err, errSimulatedClose)
	assert.NotContains(t, err.Error(), "decrypt", "close failure must be reported ahead of decryption")
}

// Honouring the close result must not break the cache-miss path: the partial file is
// discarded there anyway, so the fallback download still has to run.
func TestHotDownloader_Download_CloseFailureOnCacheMissStillFallsBack(t *testing.T) {
	router := newTestRouter(t, "") // empty = 404 cache miss
	defer router.Close()

	failOutputCloseFor(t, isFinalOutput)

	fallbackContent := []byte("fallback content")
	downloader := NewHotDownloader(
		node.NewHotRouterClient(router.URL, testChainID),
		testKey(t),
		&mockFallbackDownloader{downloadFunc: func(_ context.Context, _, filename string, _ bool) error {
			return os.WriteFile(filename, fallbackContent, 0644)
		}},
	)

	output := filepath.Join(t.TempDir(), "output.dat")
	require.NoError(t, downloader.Download(context.Background(), "0xabcd", output, false))

	data, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, fallbackContent, data)
}

func TestHotDownloader_DownloadFragments_OutputCloseFailureIsReported(t *testing.T) {
	chdirTemp(t)

	hotNode := newTestHotNode(t, []byte("fragment payload"))
	defer hotNode.Close()
	router := newTestRouter(t, hotNode.URL)
	defer router.Close()

	failOutputCloseFor(t, isFinalOutput)

	downloader := NewHotDownloader(
		node.NewHotRouterClient(router.URL, testChainID),
		testKey(t),
		&mockFallbackDownloader{},
	)

	roots := []string{"0x1111", "0x2222"}
	err := downloader.DownloadFragments(context.Background(), roots, "output.dat", false)

	require.Error(t, err)
	assert.ErrorIs(t, err, errSimulatedClose)
}

// A temp fragment that failed to close may be short, and it is read straight back
// into the concatenated output, so it must not count as a successful hot fetch.
func TestHotDownloader_DownloadFragments_TempCloseFailureFallsBack(t *testing.T) {
	chdirTemp(t)

	hotNode := newTestHotNode(t, []byte("hot fragment"))
	defer hotNode.Close()
	router := newTestRouter(t, hotNode.URL)
	defer router.Close()

	failOutputCloseFor(t, isTempFragment)

	fallbackContent := []byte("fallback fragment")
	fallbackCalls := 0
	downloader := NewHotDownloader(
		node.NewHotRouterClient(router.URL, testChainID),
		testKey(t),
		&mockFallbackDownloader{downloadFunc: func(_ context.Context, _, filename string, _ bool) error {
			fallbackCalls++
			return os.WriteFile(filename, fallbackContent, 0644)
		}},
	)

	roots := []string{"0x1111", "0x2222"}
	require.NoError(t, downloader.DownloadFragments(context.Background(), roots, "output.dat", false))

	assert.Equal(t, len(roots), fallbackCalls, "each fragment whose temp file failed to close must be refetched")

	data, err := os.ReadFile("output.dat")
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte(nil), fallbackContent...), fallbackContent...), data)
}

func TestHotDownloader_DownloadFragments_EncryptedOutputCloseFailureIsReported(t *testing.T) {
	chdirTemp(t)

	encryptionKey := testEncryptionKey()
	var key [32]byte
	copy(key[:], encryptionKey)

	hotNode := newTestHotNode(t, encryptedV1Fragment(t, key, []byte("secret fragment payload")))
	defer hotNode.Close()
	router := newTestRouter(t, hotNode.URL)
	defer router.Close()

	failOutputCloseFor(t, isFinalOutput)

	downloader := NewHotDownloader(
		node.NewHotRouterClient(router.URL, testChainID),
		testKey(t),
		&mockFallbackDownloader{},
	).WithEncryptionKey(encryptionKey)

	err := downloader.DownloadFragments(context.Background(), []string{"0x1111"}, "output.dat", false)

	require.Error(t, err)
	assert.ErrorIs(t, err, errSimulatedClose)
}

// On a cache miss this layer still owns decryption: the CLI deliberately leaves the
// fallback downloader without keys when --hot-router is set (cmd/download.go guards
// every WithEncryptionKey/WithWalletPrivateKey call on hotRouter == ""), so if
// Download returns straight from the fallback the caller is handed ciphertext and
// told it succeeded.
func TestHotDownloader_Download_CacheMissDecryptsFallbackData(t *testing.T) {
	router := newTestRouter(t, "") // empty = 404 cache miss
	defer router.Close()

	encryptionKey := testEncryptionKey()
	var key [32]byte
	copy(key[:], encryptionKey)

	plaintext := []byte("secret payload served by the fallback")
	ciphertext := encryptedV1Fragment(t, key, plaintext)

	downloader := NewHotDownloader(
		node.NewHotRouterClient(router.URL, testChainID),
		testKey(t),
		&mockFallbackDownloader{downloadFunc: func(_ context.Context, _, filename string, _ bool) error {
			return os.WriteFile(filename, ciphertext, 0644)
		}},
	).WithEncryptionKey(encryptionKey)

	output := filepath.Join(t.TempDir(), "output.dat")
	require.NoError(t, downloader.Download(context.Background(), "0xabcd", output, false))

	data, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Equal(t, plaintext, data, "fallback data must be decrypted, not left as ciphertext")
}

// A fallback failure must still surface rather than being masked by the new
// decryption step that follows it.
func TestHotDownloader_Download_CacheMissFallbackErrorWins(t *testing.T) {
	router := newTestRouter(t, "")
	defer router.Close()

	downloader := NewHotDownloader(
		node.NewHotRouterClient(router.URL, testChainID),
		testKey(t),
		&mockFallbackDownloader{downloadFunc: func(context.Context, string, string, bool) error {
			return errors.New("fallback exploded")
		}},
	).WithEncryptionKey(testEncryptionKey())

	err := downloader.Download(context.Background(), "0xabcd", filepath.Join(t.TempDir(), "output.dat"), false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "fallback exploded")
}
