package node

import (
	"context"

	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/sirupsen/logrus"
)

// HotClient is a JSON-RPC client connected to a hot storage node.
type HotClient struct {
	*rpcClient
}

// MustNewHotClient initializes a hot storage client and panics on failure.
func MustNewHotClient(url string, option ...providers.Option) *HotClient {
	client, err := NewHotClient(url, option...)
	if err != nil {
		logrus.WithError(err).WithField("url", url).Fatal("Failed to create hot storage client")
	}
	return client
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

// Prefetch calls hot_prefetch RPC to request the hot storage node to cache a file.
func (c *HotClient) Prefetch(ctx context.Context, fileHash string) (*HotPrefetchResponse, error) {
	return providers.CallContext[*HotPrefetchResponse](c, ctx, "hot_prefetch", fileHash)
}

// CheckCached calls hot_checkCached RPC to check if a file is cached on the hot storage node.
func (c *HotClient) CheckCached(ctx context.Context, txSeq uint64) (HotCacheStatus, error) {
	return providers.CallContext[HotCacheStatus](c, ctx, "hot_checkCached", txSeq)
}
