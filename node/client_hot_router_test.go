package node

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	return key
}

func TestSignDownloadRequest(t *testing.T) {
	key := generateTestKey(t)
	user := crypto.PubkeyToAddress(key.PublicKey)
	fileHash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	nonce := uint64(1709913600001)

	sig, err := signDownloadRequest(key, user, []common.Hash{fileHash}, nonce)
	require.NoError(t, err)
	assert.Len(t, sig, 65)

	// Verify the signature recovers to the correct address.
	data := make([]byte, 0, 20+32+32)
	data = append(data, user.Bytes()...)
	data = append(data, fileHash.Bytes()...)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(nonce).Bytes(), 32)...)
	hash := accounts.TextHash(data)

	pubKey, err := crypto.Ecrecover(hash, sig)
	require.NoError(t, err)
	recoveredAddr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])
	assert.Equal(t, user, recoveredAddr)
}

func TestSignDownloadRequest_MultipleHashes(t *testing.T) {
	key := generateTestKey(t)
	user := crypto.PubkeyToAddress(key.PublicKey)
	hash1 := common.HexToHash("0x1111")
	hash2 := common.HexToHash("0x2222")
	nonce := uint64(42)

	sig, err := signDownloadRequest(key, user, []common.Hash{hash1, hash2}, nonce)
	require.NoError(t, err)
	assert.Len(t, sig, 65)

	// Verify.
	data := make([]byte, 0, 20+32*2+32)
	data = append(data, user.Bytes()...)
	data = append(data, hash1.Bytes()...)
	data = append(data, hash2.Bytes()...)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(nonce).Bytes(), 32)...)
	msgHash := accounts.TextHash(data)

	pubKey, err := crypto.Ecrecover(msgHash, sig)
	require.NoError(t, err)
	recoveredAddr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])
	assert.Equal(t, user, recoveredAddr)
}

func TestSignDownloadRequest_DifferentNonces(t *testing.T) {
	key := generateTestKey(t)
	user := crypto.PubkeyToAddress(key.PublicKey)
	fileHash := common.HexToHash("0xaaaa")

	sig1, err := signDownloadRequest(key, user, []common.Hash{fileHash}, 1)
	require.NoError(t, err)

	sig2, err := signDownloadRequest(key, user, []common.Hash{fileHash}, 2)
	require.NoError(t, err)

	assert.NotEqual(t, sig1, sig2)
}

func TestSignDownloadRequest_DifferentKeys(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)
	fileHash := common.HexToHash("0xbbbb")
	nonce := uint64(100)

	sig1, err := signDownloadRequest(key1, crypto.PubkeyToAddress(key1.PublicKey), []common.Hash{fileHash}, nonce)
	require.NoError(t, err)

	sig2, err := signDownloadRequest(key2, crypto.PubkeyToAddress(key2.PublicKey), []common.Hash{fileHash}, nonce)
	require.NoError(t, err)

	assert.NotEqual(t, sig1, sig2)
}

func TestGetDownloadAuth_Success(t *testing.T) {
	key := generateTestKey(t)
	user := crypto.PubkeyToAddress(key.PublicKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/download", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req HotRouterDownloadRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.Equal(t, user.Hex(), req.User)
		assert.Len(t, req.FileHashes, 1)
		assert.NotEmpty(t, req.Signature)
		assert.NotZero(t, req.Nonce)

		// Verify the user's signature.
		sigBytes, err := hex.DecodeString(req.Signature[2:]) // strip 0x
		require.NoError(t, err)
		assert.Len(t, sigBytes, 65)

		fileHash := common.HexToHash(req.FileHashes[0])
		data := make([]byte, 0, 20+32+32)
		data = append(data, user.Bytes()...)
		data = append(data, fileHash.Bytes()...)
		data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(req.Nonce).Bytes(), 32)...)
		hash := accounts.TextHash(data)

		pubKey, err := crypto.Ecrecover(hash, sigBytes)
		require.NoError(t, err)
		recoveredAddr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])
		assert.Equal(t, user, recoveredAddr)

		resp := HotRouterDownloadResponse{
			NodeURL:    "http://hot-node:6789",
			Provider:   "0x1111111111111111111111111111111111111111",
			FileHashes: req.FileHashes,
			MaxFee:     "1000000",
			Nonce:      12345,
			Signature:  "0xabcdef",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHotRouterClient(server.URL)
	root := "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	resp, err := client.GetDownloadAuth(context.Background(), key, []string{root})
	require.NoError(t, err)
	assert.Equal(t, "http://hot-node:6789", resp.NodeURL)
	assert.Equal(t, "0x1111111111111111111111111111111111111111", resp.Provider)
	assert.Equal(t, "1000000", resp.MaxFee)
	assert.Equal(t, uint64(12345), resp.Nonce)
	assert.Equal(t, "0xabcdef", resp.Signature)
	assert.Equal(t, []string{common.HexToHash(root).Hex()}, resp.FileHashes)
}

func TestGetDownloadAuth_MultipleRoots(t *testing.T) {
	key := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req HotRouterDownloadRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Len(t, req.FileHashes, 3)

		resp := HotRouterDownloadResponse{
			NodeURL:    "http://hot-node:6789",
			Provider:   "0x1111",
			FileHashes: req.FileHashes,
			MaxFee:     "3000000",
			Nonce:      1,
			Signature:  "0xsig",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHotRouterClient(server.URL)
	roots := []string{"0xaaaa", "0xbbbb", "0xcccc"}

	resp, err := client.GetDownloadAuth(context.Background(), key, roots)
	require.NoError(t, err)
	assert.Len(t, resp.FileHashes, 3)
}

func TestGetDownloadAuth_CacheMiss_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "file not cached", http.StatusNotFound)
	}))
	defer server.Close()

	key := generateTestKey(t)
	client := NewHotRouterClient(server.URL)
	resp, err := client.GetDownloadAuth(context.Background(), key, []string{"0xaaaa"})
	require.NoError(t, err)
	assert.Nil(t, resp)
}

func TestGetDownloadAuth_RouterError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{"insufficient balance", http.StatusPaymentRequired, "insufficient balance"},
		{"unauthorized", http.StatusUnauthorized, "signature does not match user"},
		{"server error", http.StatusInternalServerError, "internal error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, tt.body, tt.statusCode)
			}))
			defer server.Close()

			key := generateTestKey(t)
			client := NewHotRouterClient(server.URL)
			_, err := client.GetDownloadAuth(context.Background(), key, []string{"0xaaaa"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.body)
		})
	}
}

func TestGetBalance_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/balance", r.URL.Path)
		assert.NotEmpty(t, r.URL.Query().Get("user"))

		resp := HotRouterBalanceResponse{
			Balance:       "1000000000000000000",
			LocalReserved: "50000",
			Available:     "999999999999950000",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHotRouterClient(server.URL)
	user := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	resp, err := client.GetBalance(context.Background(), user)
	require.NoError(t, err)
	assert.Equal(t, "1000000000000000000", resp.Balance)
	assert.Equal(t, "50000", resp.LocalReserved)
	assert.Equal(t, "999999999999950000", resp.Available)
}

func TestGetBalance_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "account not found", http.StatusNotFound)
	}))
	defer server.Close()

	client := NewHotRouterClient(server.URL)
	_, err := client.GetBalance(context.Background(), common.HexToAddress("0x1234"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "account not found")
}

func TestGetService_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/service", r.URL.Path)
		assert.NotEmpty(t, r.URL.Query().Get("provider"))

		resp := HotRouterServiceResponse{
			PricePerByte: "1000",
			URL:          "http://node:6789",
			Active:       true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHotRouterClient(server.URL)
	provider := common.HexToAddress("0x1111111111111111111111111111111111111111")

	resp, err := client.GetService(context.Background(), provider)
	require.NoError(t, err)
	assert.Equal(t, "1000", resp.PricePerByte)
	assert.Equal(t, "http://node:6789", resp.URL)
	assert.True(t, resp.Active)
}

func TestGetService_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service not found", http.StatusNotFound)
	}))
	defer server.Close()

	client := NewHotRouterClient(server.URL)
	_, err := client.GetService(context.Background(), common.HexToAddress("0x1234"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service not found")
}

func TestGetDownloadAuth_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	key := generateTestKey(t)
	client := NewHotRouterClient(server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetDownloadAuth(ctx, key, []string{"0xaaaa"})
	require.Error(t, err)
}

func TestGetDownloadAuth_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	key := generateTestKey(t)
	client := NewHotRouterClient(server.URL)

	_, err := client.GetDownloadAuth(context.Background(), key, []string{"0xaaaa"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode router response")
}
