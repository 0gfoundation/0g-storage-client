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

// signDownloadRequest computes keccak256(user || fileHash || nonce) and signs it with the private key.
func signDownloadRequest(privateKey *ecdsa.PrivateKey, user common.Address, fileHash common.Hash, nonce uint64) ([]byte, error) {
	data := make([]byte, 0, 20+32+32)
	data = append(data, user.Bytes()...)
	data = append(data, fileHash.Bytes()...)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(nonce).Bytes(), 32)...)

	hash := crypto.Keccak256Hash(data)
	sig, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign download request: %w", err)
	}
	return sig, nil
}

// GetDownloadAuth requests download authorization from the hot storage router.
// It signs the request with the user's private key using a timestamp-based nonce.
func (c *HotRouterClient) GetDownloadAuth(ctx context.Context, privateKey *ecdsa.PrivateKey, root string) (*HotRouterDownloadResponse, error) {
	user := crypto.PubkeyToAddress(privateKey.PublicKey)
	fileHash := common.HexToHash(root)
	nonce := uint64(time.Now().UnixMilli())

	sig, err := signDownloadRequest(privateKey, user, fileHash, nonce)
	if err != nil {
		return nil, err
	}

	req := HotRouterDownloadRequest{
		User:      user.Hex(),
		FileHash:  fileHash.Hex(),
		Nonce:     nonce,
		Signature: fmt.Sprintf("0x%x", sig),
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
