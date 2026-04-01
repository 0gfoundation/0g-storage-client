package node

import (
	"context"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
)

// HotClient is an HTTP client connected to a hot storage node.
type HotClient struct {
	url        string
	httpClient *http.Client
}

// NewHotClient initializes a hot storage client.
func NewHotClient(url string, option ...providers.Option) (*HotClient, error) {
	if _, err := neturl.ParseRequestURI(url); err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	return &HotClient{
		url: url,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}, nil
}

// Close is a no-op for compatibility.
func (c *HotClient) Close() {}

// HotDownload sends a GET /download request to the hot storage node and streams the response to w.
// auth contains the routing authorization from the hot storage router.
// fileHash is the specific file to download (must be one of auth.FileHashes).
func (c *HotClient) HotDownload(ctx context.Context, userAddress string, auth *HotRouterDownloadResponse, fileHash string, w io.Writer) error {
	params := neturl.Values{}
	params.Set("user", userAddress)
	params.Set("file_hash", fileHash)
	if len(auth.FileHashes) > 0 {
		params.Set("file_hashes", strings.Join(auth.FileHashes, ","))
	}
	params.Set("node_url", auth.NodeURL)
	params.Set("max_fee", auth.MaxFee)
	params.Set("nonce", strconv.FormatUint(auth.Nonce, 10))
	params.Set("signature", auth.Signature)

	reqURL := c.url + "/download?" + params.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hot node returned status %d: %s", resp.StatusCode, string(body))
	}

	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("failed to stream response: %w", err)
	}

	return nil
}
