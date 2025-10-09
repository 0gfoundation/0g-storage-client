package indexer

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/0glabs/0g-storage-client/common"
	"github.com/0glabs/0g-storage-client/common/rpc"
	"github.com/0glabs/0g-storage-client/common/shard"
	"github.com/0glabs/0g-storage-client/core"
	"github.com/0glabs/0g-storage-client/node"
	"github.com/0glabs/0g-storage-client/transfer"
	eth_common "github.com/ethereum/go-ethereum/common"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/openweb3/web3go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	// Requires `Client` implements the `Interface` interface.
	_ Interface = (*Client)(nil)
	// Requires `Client` implements the `IDownloader` interface.
	_ transfer.IDownloader = (*Client)(nil)
)

// Client indexer client
type Client struct {
	*rpc.Client
	option IndexerClientOption
	logger *logrus.Logger
}

// IndexerClientOption indexer client option
type IndexerClientOption struct {
	ProviderOption providers.Option
	LogOption      common.LogOption // log option when uploading data
	FullTrusted    bool             // whether to use full trusted nodes
}

// NewClient create new indexer client, url is indexer service url
func NewClient(url string, option ...IndexerClientOption) (*Client, error) {
	var opt IndexerClientOption
	if len(option) > 0 {
		opt = option[0]
	}

	client, err := rpc.NewClient(url, opt.ProviderOption)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: client,
		option: opt,
		logger: common.NewLogger(opt.LogOption),
	}, nil
}

// GetShardedNodes get node list from indexer service
func (c *Client) GetShardedNodes(ctx context.Context) (ShardedNodes, error) {
	return providers.CallContext[ShardedNodes](c, ctx, "indexer_getShardedNodes")
}

// GetNodeLocations return storage nodes with IP location information.
func (c *Client) GetNodeLocations(ctx context.Context) (map[string]*IPLocation, error) {
	return providers.CallContext[map[string]*IPLocation](c, ctx, "indexer_getNodeLocations")
}

// GetFileLocations return locations info of given file.
func (c *Client) GetFileLocations(ctx context.Context, root string) ([]*shard.ShardedNode, error) {
	return providers.CallContext[[]*shard.ShardedNode](c, ctx, "indexer_getFileLocations", root)
}

// SelectNodes selects nodes from both trusted and discovered, with discovered max 3/5 of expectedReplica. If discovered cannot meet, all from trusted.
func (c *Client) SelectNodes(ctx context.Context, expectedReplica uint, dropped []string, method string, fullTrusted bool) (*transfer.SelectedNodes, error) {
	allNodes, err := c.GetShardedNodes(ctx)
	if err != nil {
		return nil, err
	}

	fetchNodes := func(shardedNodes []*shard.ShardedNode) []*shard.ShardedNode {
		nodes := make([]*shard.ShardedNode, 0)
		for _, shardedNode := range shardedNodes {
			if slices.Contains(dropped, shardedNode.URL) {
				continue
			}
			client, err := node.NewZgsClient(shardedNode.URL, c.option.ProviderOption)
			if err != nil {
				c.logger.Debugf("failed to initialize client of node %v, dropped.", shardedNode.URL)
				continue
			}
			defer client.Close()
			start := time.Now()
			config, err := client.GetShardConfig(ctx)
			if err != nil || !config.IsValid() {
				c.logger.Debugf("failed to get shard config of node %v, dropped.", shardedNode.URL)
				continue
			}
			nodes = append(nodes, &shard.ShardedNode{
				URL:     shardedNode.URL,
				Config:  config,
				Latency: time.Since(start).Milliseconds(),
			})
		}
		return nodes
	}

	trustedNodes := fetchNodes(allNodes.Trusted)
	discoveredNodes := fetchNodes(allNodes.Discovered)

	discoveredReplica := uint(0)
	if !fullTrusted {
		discoveredReplica = uint(expectedReplica) * 3 / 5
	}

	discoveredSelected, _ := shard.Select(discoveredNodes, discoveredReplica, method)
	if len(discoveredSelected) == 0 {
		discoveredReplica = 0
	}

	trustedSelected, ok := shard.Select(trustedNodes, expectedReplica-discoveredReplica, method)
	if !ok {
		return nil, fmt.Errorf("cannot select a subset from the returned nodes that meets the replication requirement")
	}

	trustedClients := make([]*node.ZgsClient, 0, len(trustedSelected))
	for _, shardedNode := range trustedSelected {
		client, err := node.NewZgsClient(shardedNode.URL, c.option.ProviderOption)
		if err == nil {
			trustedClients = append(trustedClients, client)
		}
	}

	discoveredClients := make([]*node.ZgsClient, 0, len(discoveredSelected))
	for _, shardedNode := range discoveredSelected {
		client, err := node.NewZgsClient(shardedNode.URL, c.option.ProviderOption)
		if err == nil {
			discoveredClients = append(discoveredClients, client)
		}
	}

	return &transfer.SelectedNodes{
		Trusted:    trustedClients,
		Discovered: discoveredClients,
	}, nil
}

// NewUploaderFromIndexerNodes return an uploader with selected storage nodes from indexer service.
func (c *Client) NewUploaderFromIndexerNodes(ctx context.Context, segNum uint64, w3Client *web3go.Client, expectedReplica uint, dropped []string, method string, fullTrusted bool) (*transfer.Uploader, error) {
	selected, err := c.SelectNodes(ctx, expectedReplica, dropped, method, fullTrusted)
	if err != nil {
		return nil, err
	}

	c.logger.Infof("get storage nodes from indexer (trusted: %v, discovered: %v)", len(selected.Trusted), len(selected.Discovered))
	return transfer.NewUploader(ctx, w3Client, selected, c.option.LogOption)
}

// Upload submit data to 0g storage contract, then transfer the data to the storage nodes selected from indexer service.
func (c *Client) Upload(ctx context.Context, w3Client *web3go.Client, data core.IterableData, option ...transfer.UploadOption) (eth_common.Hash, error) {
	expectedReplica := uint(1)
	if len(option) > 0 {
		expectedReplica = max(expectedReplica, option[0].ExpectedReplica)
	}
	dropped := make([]string, 0)
	for {
		uploader, err := c.NewUploaderFromIndexerNodes(ctx, data.NumSegments(), w3Client, expectedReplica, dropped, option[0].Method, option[0].FullTrusted)
		if err != nil {
			return eth_common.Hash{}, err
		}
		txHash, _, err := uploader.Upload(ctx, data, option...)
		var rpcError *node.RPCError
		if errors.As(err, &rpcError) {
			dropped = append(dropped, rpcError.URL)
			c.logger.Infof("dropped problematic node and retry: %v", rpcError.Error())
		} else {
			return txHash, err
		}
	}
}

// BatchUpload submit multiple data to 0g storage contract batchly in single on-chain transaction, then transfer the data to the storage nodes selected from indexer service.
func (c *Client) BatchUpload(ctx context.Context, w3Client *web3go.Client, datas []core.IterableData, option ...transfer.BatchUploadOption) (eth_common.Hash, []eth_common.Hash, error) {
	expectedReplica := uint(1)
	if len(option) > 0 {
		for _, opt := range option[0].DataOptions {
			expectedReplica = max(expectedReplica, opt.ExpectedReplica)
		}
	}
	var maxSegNum uint64
	for _, data := range datas {
		maxSegNum = max(maxSegNum, data.NumSegments())
	}
	dropped := make([]string, 0)
	for {
		uploader, err := c.NewUploaderFromIndexerNodes(ctx, maxSegNum, w3Client, expectedReplica, dropped, option[0].Method, option[0].FullTrusted)
		if err != nil {
			return eth_common.Hash{}, nil, err
		}
		hash, roots, err := uploader.BatchUpload(ctx, datas, option...)
		var rpcError *node.RPCError
		if errors.As(err, &rpcError) {
			dropped = append(dropped, rpcError.URL)
			c.logger.Infof("dropped problematic node and retry: %v", rpcError.Error())
		} else {
			return hash, roots, err
		}
	}
}

// NewUploaderFromIndexerNodes return a file segment uploader with selected storage nodes from indexer service.
func (c *Client) NewFileSegmentUploaderFromIndexerNodes(
	ctx context.Context, segNum uint64, expectedReplica uint, dropped []string, method string, fullTrusted bool) ([]*transfer.FileSegmentUploader, error) {
	selected, err := c.SelectNodes(ctx, expectedReplica, dropped, method, fullTrusted)
	if err != nil {
		return nil, err
	}

	uploaders := make([]*transfer.FileSegmentUploader, 0, 2)
	if len(selected.Trusted) > 0 {
		uploader := transfer.NewFileSegmentUploader(selected.Trusted, c.option.LogOption)
		uploaders = append(uploaders, uploader)
	}
	if len(selected.Discovered) > 0 {
		uploader := transfer.NewFileSegmentUploader(selected.Discovered, c.option.LogOption)
		uploaders = append(uploaders, uploader)
	}
	c.logger.Infof("get storage nodes from indexer (trusted: %v, discovered: %v)", len(selected.Trusted), len(selected.Discovered))
	return uploaders, nil
}

// UploadFileSegments transfer segment data of a file, which should has already been submitted to the 0g storage contract,
// to the storage nodes selected from indexer service.
func (c *Client) UploadFileSegments(
	ctx context.Context, fileSeg transfer.FileSegmentsWithProof, option ...transfer.UploadOption) error {

	if fileSeg.FileInfo == nil {
		return errors.New("file not found")
	}

	if len(fileSeg.Segments) == 0 {
		return errors.New("segment data is empty")
	}

	expectedReplica := uint(1)
	if len(option) > 0 {
		expectedReplica = max(expectedReplica, option[0].ExpectedReplica)
	}

	numSeg := core.NumSplits(int64(fileSeg.FileInfo.Tx.Size), core.DefaultSegmentSize)
	dropped := make([]string, 0)
	for {
		uploaders, err := c.NewFileSegmentUploaderFromIndexerNodes(ctx, numSeg, expectedReplica, dropped, option[0].Method, true)
		if err != nil {
			return err
		}

		var rpcError *node.RPCError
		for _, uploader := range uploaders {
			if err := uploader.Upload(ctx, fileSeg, option...); errors.As(err, &rpcError) {
				dropped = append(dropped, rpcError.URL)
				c.logger.Infof("dropped problematic node and retry: %v", rpcError.Error())
			} else {
				return err
			}
		}
	}
}

func (c *Client) NewDownloaderFromIndexerNodes(ctx context.Context, root string) (*transfer.Downloader, error) {
	locations, err := c.GetFileLocations(ctx, root)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get file locations")
	}
	clients := make([]*node.ZgsClient, 0)
	for _, location := range locations {
		client, err := node.NewZgsClient(location.URL, c.option.ProviderOption)
		if err != nil {
			c.logger.Debugf("failed to initialize client of node %v, dropped.", location.URL)
			continue
		}
		config, err := client.GetShardConfig(ctx)
		if err != nil || !config.IsValid() {
			c.logger.Debugf("failed to get shard config of node %v, dropped.", client.URL())
			continue
		}
		clients = append(clients, client)
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("no node holding the file found, FindFile triggered, try again later")
	}
	downloader, err := transfer.NewDownloader(clients, c.option.LogOption)
	if err != nil {
		return nil, err
	}

	return downloader, nil
}

func (c *Client) DownloadFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}
	defer outFile.Close()

	for _, root := range roots {
		tempFile := fmt.Sprintf("%v.temp", root)
		downloader, err := c.NewDownloaderFromIndexerNodes(ctx, root)
		if err != nil {
			return err
		}
		err = downloader.Download(ctx, root, tempFile, withProof)
		if err != nil {
			return errors.WithMessage(err, "Failed to download file")
		}
		inFile, err := os.Open(tempFile)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to open file %s", tempFile))
		}
		_, err = io.Copy(outFile, inFile)
		inFile.Close()
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to copy content from temp file %s", tempFile))
		}

		err = os.Remove(tempFile)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to delete temp file %s:", tempFile))
		}
	}

	return nil
}

// Download download file by given data root
func (c *Client) Download(ctx context.Context, root, filename string, withProof bool) error {
	downloader, err := c.NewDownloaderFromIndexerNodes(ctx, root)
	if err != nil {
		return err
	}
	return downloader.Download(ctx, root, filename, withProof)
}
