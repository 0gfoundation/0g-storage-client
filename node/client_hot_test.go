package node

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestHotDownload_Success(t *testing.T) {
	fileData := []byte("hello world")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/download", r.URL.Path)
		assert.Equal(t, "0xuser", r.URL.Query().Get("user"))
		assert.Equal(t, "0xabcd", r.URL.Query().Get("file_hash"))
		assert.Equal(t, "0xabcd", r.URL.Query().Get("file_hashes"))
		assert.Equal(t, "1000", r.URL.Query().Get("max_fee"))
		assert.Equal(t, "1", r.URL.Query().Get("nonce"))
		assert.Equal(t, "0xdeadbeef", r.URL.Query().Get("signature"))
		w.WriteHeader(http.StatusOK)
		w.Write(fileData)
	}))
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	auth := &HotRouterDownloadResponse{
		NodeURL:    server.URL,
		Provider:   "0x1111",
		FileHashes: []string{"0xabcd"},
		MaxFee:     "1000",
		Nonce:      1,
		Signature:  "0xdeadbeef",
	}
	var buf bytes.Buffer
	err = client.HotDownload(context.Background(), "0xuser", auth, "0xabcd", &buf)
	require.NoError(t, err)
	assert.Equal(t, fileData, buf.Bytes())
}

func TestHotDownload_NodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	auth := &HotRouterDownloadResponse{
		NodeURL:    server.URL,
		FileHashes: []string{"0xabcd"},
		MaxFee:     "1000",
		Nonce:      1,
		Signature:  "0xdeadbeef",
	}
	var buf bytes.Buffer
	err = client.HotDownload(context.Background(), "0xuser", auth, "0xabcd", &buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestHotDownload_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	auth := &HotRouterDownloadResponse{
		NodeURL:    server.URL,
		FileHashes: []string{"0xabcd"},
		MaxFee:     "1000",
		Nonce:      1,
		Signature:  "0xdeadbeef",
	}
	var buf bytes.Buffer
	err = client.HotDownload(ctx, "0xuser", auth, "0xabcd", &buf)
	assert.Error(t, err)
}

func TestHotDownload_MultipleFileHashes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "0xfrag1", r.URL.Query().Get("file_hash"))
		assert.Equal(t, "0xfrag1,0xfrag2,0xfrag3", r.URL.Query().Get("file_hashes"))
		w.Write([]byte("fragment data"))
	}))
	defer server.Close()

	client, err := NewHotClient(server.URL)
	require.NoError(t, err)

	auth := &HotRouterDownloadResponse{
		NodeURL:    server.URL,
		FileHashes: []string{"0xfrag1", "0xfrag2", "0xfrag3"},
		MaxFee:     "3000",
		Nonce:      2,
		Signature:  "0xsig",
	}
	var buf bytes.Buffer
	err = client.HotDownload(context.Background(), "0xuser", auth, "0xfrag1", &buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("fragment data"), buf.Bytes())
}
