package node

import (
	"context"

	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
)

// HotClient is a JSON-RPC client connected to a hot storage node.
type HotClient struct {
	*rpcClient
}

// NewHotClient initializes a hot storage client.
func NewHotClient(url string, option ...providers.Option) (*HotClient, error) {
	client, err := newRpcClient(url, option...)
	if err != nil {
		return nil, err
	}
	return &HotClient{client}, nil
}

// HotDownload calls hot_download RPC to download a file from the hot storage node.
// The auth parameter contains the routing authorization from the hot storage router.
// userAddress is the hex-encoded address of the user requesting the download.
func (c *HotClient) HotDownload(ctx context.Context, userAddress string, auth *HotRouterDownloadResponse) (*HotDownloadResponse, error) {
	return providers.CallContext[*HotDownloadResponse](c, ctx, "hot_download",
		map[string]interface{}{
			"user_address": userAddress,
			"node_url":     auth.NodeURL,
			"file_hash":    auth.FileHash,
			"max_fee":      auth.MaxFee,
			"nonce":        auth.Nonce,
			"signature":    auth.Signature,
		},
	)
}
