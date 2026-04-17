package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// HotRouterClient is an HTTP client for the hot storage router.
type HotRouterClient struct {
	url        string
	httpClient *http.Client
}

// NewHotRouterClient creates a new hot storage router client.
func NewHotRouterClient(url string) *HotRouterClient {
	return &HotRouterClient{
		url: url,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// signDownloadRequest signs the download request using EIP-191 personal_sign.
// Message: keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg)
// where msg = user || fileHash1 || ... || fileHashN || nonce (32-byte big-endian).
func signDownloadRequest(privateKey *ecdsa.PrivateKey, user common.Address, fileHashes []common.Hash, nonce uint64) ([]byte, error) {
	data := make([]byte, 0, 20+32*len(fileHashes)+32)
	data = append(data, user.Bytes()...)
	for _, h := range fileHashes {
		data = append(data, h.Bytes()...)
	}
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(nonce).Bytes(), 32)...)

	hash := accounts.TextHash(data)
	sig, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign download request: %w", err)
	}
	return sig, nil
}

// GetDownloadAuth requests download authorization from the hot storage router.
// roots is the list of file root hashes to download (one or more fragments).
// Returns nil, nil on 404 (no hot node has the file cached).
func (c *HotRouterClient) GetDownloadAuth(ctx context.Context, privateKey *ecdsa.PrivateKey, roots []string) (*HotRouterDownloadResponse, error) {
	user := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce := uint64(time.Now().UnixMilli())

	fileHashes := make([]common.Hash, len(roots))
	fileHashHexes := make([]string, len(roots))
	for i, root := range roots {
		fileHashes[i] = common.HexToHash(root)
		fileHashHexes[i] = fileHashes[i].Hex()
	}

	sig, err := signDownloadRequest(privateKey, user, fileHashes, nonce)
	if err != nil {
		return nil, err
	}

	req := HotRouterDownloadRequest{
		User:       user.Hex(),
		FileHashes: fileHashHexes,
		Nonce:      nonce,
		Signature:  fmt.Sprintf("0x%x", sig),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/download", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to router: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		// 404 means no hot node has the file cached; router triggers prefetch server-side.
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("router returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var downloadResp HotRouterDownloadResponse
	if err := json.Unmarshal(respBody, &downloadResp); err != nil {
		return nil, fmt.Errorf("failed to decode router response: %w", err)
	}

	return &downloadResp, nil
}

// GetBalance queries the user's balance from the hot storage router.
func (c *HotRouterClient) GetBalance(ctx context.Context, user common.Address) (*HotRouterBalanceResponse, error) {
	url := fmt.Sprintf("%s/balance?user=%s", c.url, user.Hex())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to router: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("router returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var balanceResp HotRouterBalanceResponse
	if err := json.Unmarshal(respBody, &balanceResp); err != nil {
		return nil, fmt.Errorf("failed to decode balance response: %w", err)
	}

	return &balanceResp, nil
}

// GetService queries a provider's service info from the hot storage router.
func (c *HotRouterClient) GetService(ctx context.Context, provider common.Address) (*HotRouterServiceResponse, error) {
	url := fmt.Sprintf("%s/service?provider=%s", c.url, provider.Hex())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to router: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("router returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var serviceResp HotRouterServiceResponse
	if err := json.Unmarshal(respBody, &serviceResp); err != nil {
		return nil, fmt.Errorf("failed to decode service response: %w", err)
	}

	return &serviceResp, nil
}
