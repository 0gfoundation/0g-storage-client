package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// EIP-712 domain parameters. These MUST match the router/frontend byte-for-byte
// — any drift breaks signature recovery silently. The router has its own copy
// in 0g-hot-storage-router/internal/router/eip712.go and a cross-language
// canary in test/eip712_vector.py; keep all three in sync.
const (
	hotDownloadDomainName    = "0G Storage Scan"
	hotDownloadDomainVersion = "1"
)

// hotDownloadAuthTypes is the EIP-712 type set the router accepts for download
// authorization. Wallets render these as labeled fields rather than an opaque
// hex blob.
var hotDownloadAuthTypes = apitypes.Types{
	"EIP712Domain": []apitypes.Type{
		{Name: "name", Type: "string"},
		{Name: "version", Type: "string"},
		{Name: "chainId", Type: "uint256"},
	},
	"HotDownloadAuth": []apitypes.Type{
		{Name: "user", Type: "address"},
		{Name: "fileHashes", Type: "bytes32[]"},
		{Name: "nonce", Type: "uint256"},
	},
}

// HotRouterClient is an HTTP client for the hot storage router.
type HotRouterClient struct {
	url        string
	chainID    int64
	httpClient *http.Client
}

// NewHotRouterClient creates a new hot storage router client. chainID is used
// for the EIP-712 domain separator on download auth signatures and must match
// the router's configured chain ID.
func NewHotRouterClient(url string, chainID int64) *HotRouterClient {
	return &HotRouterClient{
		url:     url,
		chainID: chainID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// hashHotDownloadAuth computes the EIP-712 digest a user signs over for a
// /download request. Result is keccak256(0x1901 || domainSeparator || hashStruct(message)).
func hashHotDownloadAuth(user common.Address, fileHashes []common.Hash, nonce uint64, chainID int64) (common.Hash, error) {
	hashes := make([]interface{}, len(fileHashes))
	for i, h := range fileHashes {
		hashes[i] = hexutil.Bytes(h.Bytes())
	}
	td := apitypes.TypedData{
		Types:       hotDownloadAuthTypes,
		PrimaryType: "HotDownloadAuth",
		Domain: apitypes.TypedDataDomain{
			Name:    hotDownloadDomainName,
			Version: hotDownloadDomainVersion,
			ChainId: math.NewHexOrDecimal256(chainID),
		},
		Message: apitypes.TypedDataMessage{
			"user":       user.Hex(),
			"fileHashes": hashes,
			"nonce":      math.NewHexOrDecimal256(int64(nonce)),
		},
	}

	domainSep, err := td.HashStruct("EIP712Domain", td.Domain.Map())
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash domain: %w", err)
	}
	msgHash, err := td.HashStruct(td.PrimaryType, td.Message)
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash message: %w", err)
	}

	preimage := make([]byte, 0, 2+32+32)
	preimage = append(preimage, 0x19, 0x01)
	preimage = append(preimage, domainSep...)
	preimage = append(preimage, msgHash...)
	return crypto.Keccak256Hash(preimage), nil
}

// signDownloadRequest signs the download request as EIP-712 typed data over
// the HotDownloadAuth message.
func signDownloadRequest(privateKey *ecdsa.PrivateKey, user common.Address, fileHashes []common.Hash, nonce uint64, chainID int64) ([]byte, error) {
	hash, err := hashHotDownloadAuth(user, fileHashes, nonce, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to hash download auth: %w", err)
	}
	sig, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign download request: %w", err)
	}
	// Convert recovery byte from 0/1 (go-ethereum) to 27/28 (EIP-155 / EIP-712
	// canonical), so the router's recoverSigner — which subtracts 27 — agrees.
	if sig[64] < 27 {
		sig[64] += 27
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

	sig, err := signDownloadRequest(privateKey, user, fileHashes, nonce, c.chainID)
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
