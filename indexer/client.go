package indexer

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/rpc"
	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
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
	option        IndexerClientOption
	logger        *logrus.Logger
	encryptionKey []byte // optional 32-byte AES-256 decryption key
}

// IndexerClientOption indexer client option
type IndexerClientOption struct {
	ProviderOption providers.Option
	LogOption      common.LogOption // log option when uploading data
	FullTrusted    bool             // whether to use full trusted nodes
	Routines       int              // number of routines for uploader
	Contract       *transfer.ContractAddress
}

// NewClient create new indexer client, url is indexer service url
func NewClient(url string, option IndexerClientOption) (*Client, error) {

	client, err := rpc.NewClient(url, option.ProviderOption)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: client,
		option: option,
		logger: common.NewLogger(option.LogOption),
	}, nil
}

// GetShardedNodes get node list from indexer service
func (c *Client) GetShardedNodes(ctx context.Context) (ShardedNodes, error) {
	return providers.CallContext[ShardedNodes](c, ctx, "indexer_getShardedNodes")
}

// GetSelectedNodes get selected nodes from indexer service
func (c *Client) GetSelectedNodes(ctx context.Context, expectedReplica uint, method string, fullTrusted bool, dropped []string) (ShardedNodes, error) {
	return providers.CallContext[ShardedNodes](c, ctx, "indexer_getSelectedNodes", expectedReplica, method, fullTrusted, dropped)
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
	logrus.Info("Selecting nodes ...")
	allNodes, err := c.GetSelectedNodes(ctx, expectedReplica, method, fullTrusted, dropped)
	if err != nil {
		return nil, err
	}

	trustedIps := make([]string, 0, len(allNodes.Trusted))
	trustedClients := make([]*node.ZgsClient, 0, len(allNodes.Trusted))
	for _, shardedNode := range allNodes.Trusted {
		client, err := node.NewZgsClient(shardedNode.URL, &shardedNode.Config, c.option.ProviderOption)
		if err == nil {
			trustedClients = append(trustedClients, client)
			trustedIps = append(trustedIps, shardedNode.URL)
		}
	}

	var discoveredClients []*node.ZgsClient
	if len(allNodes.Discovered) > 0 {
		discoveredClients = make([]*node.ZgsClient, 0, len(allNodes.Discovered))
		for _, shardedNode := range allNodes.Discovered {
			client, err := node.NewZgsClient(shardedNode.URL, &shardedNode.Config, c.option.ProviderOption)
			if err == nil {
				discoveredClients = append(discoveredClients, client)
			}
		}
	}

	logrus.WithField("ips", trustedIps).Info("Selected Nodes...")

	return &transfer.SelectedNodes{
		Trusted:    trustedClients,
		Discovered: discoveredClients,
	}, nil
}

// NewUploaderFromIndexerNodesWithContractConfig returns an uploader with selected storage nodes and optional contract config.
func (c *Client) NewUploaderFromIndexerNodes(ctx context.Context, segNum uint64, w3Client *web3go.Client, expectedReplica uint, dropped []string, method string, fullTrusted bool) (*transfer.Uploader, error) {
	selected, err := c.SelectNodes(ctx, expectedReplica, dropped, method, fullTrusted)
	if err != nil {
		return nil, err
	}

	c.logger.Infof("get storage nodes from indexer (trusted: %v, discovered: %v)", len(selected.Trusted), len(selected.Discovered))
	uploader, err := transfer.NewUploaderWithContractConfig(ctx, w3Client, selected, transfer.UploaderConfig{
		Routines:  c.option.Routines,
		LogOption: c.option.LogOption,
		Contact:   c.option.Contract,
	})
	if err != nil {
		return nil, err
	}
	return uploader, nil
}

// SplitableUpload submits data and retries on node errors. If FullTrusted is false,
// it tries once and falls back to full trusted nodes.
func (c *Client) SplitableUpload(ctx context.Context, w3Client *web3go.Client, data core.IterableData, fragmentSize int64, option ...transfer.UploadOption) ([]eth_common.Hash, []eth_common.Hash, error) {
	var opt transfer.UploadOption
	if len(option) > 0 {
		opt = option[0]
	}
	expectedReplica := max(uint(1), opt.ExpectedReplica)
	maxRetry := opt.NRetries
	if maxRetry <= 0 {
		maxRetry = 3
	}

	dropped := make([]string, 0)
	attempts := 0

	for {
		uploader, err := c.NewUploaderFromIndexerNodes(ctx, data.NumSegments(), w3Client, expectedReplica, dropped, opt.Method, opt.FullTrusted)
		if err != nil {
			return nil, nil, err
		}

		txHashes, roots, err := uploader.SplitableUpload(ctx, data, fragmentSize, opt)
		if err == nil {
			return txHashes, roots, nil
		}

		if !opt.FullTrusted {
			opt.FullTrusted = true
			c.logger.WithError(err).Warn("Upload failed, retrying with full trusted nodes")
		} else {
			attempts += 1
		}

		var rpcError *node.RPCError
		if errors.As(err, &rpcError) {
			dropped = append(dropped, rpcError.URL)
			c.logger.Infof("dropped problematic node and retry: %v", rpcError.Error())
		} else {
			c.logger.WithError(err).Warn("Upload failed, retrying")
		}

		if attempts >= maxRetry {
			return txHashes, roots, err
		}
	}
}

// BatchUpload submit multiple data to 0g storage contract batchly in single on-chain transaction, then transfer the data to the storage nodes selected from indexer service.
func (c *Client) BatchUpload(ctx context.Context, w3Client *web3go.Client, datas []core.IterableData, option ...transfer.BatchUploadOption) (eth_common.Hash, []eth_common.Hash, error) {
	var opts transfer.BatchUploadOption
	if len(option) > 0 {
		opts = option[0]
	}

	expectedReplica := uint(1)
	for _, opt := range opts.DataOptions {
		expectedReplica = max(expectedReplica, opt.ExpectedReplica)
	}
	var maxSegNum uint64
	for _, data := range datas {
		maxSegNum = max(maxSegNum, data.NumSegments())
	}
	dropped := make([]string, 0)
	maxRetry := 3
	attempts := 0
	for {
		uploader, err := c.NewUploaderFromIndexerNodes(ctx, maxSegNum, w3Client, expectedReplica, dropped, opts.Method, opts.FullTrusted)
		if err != nil {
			return eth_common.Hash{}, nil, err
		}
		hash, roots, err := uploader.BatchUpload(ctx, datas, opts)
		var rpcError *node.RPCError
		if errors.As(err, &rpcError) {
			dropped = append(dropped, rpcError.URL)
			c.logger.Infof("dropped problematic node and retry: %v", rpcError.Error())
		} else {
			return hash, roots, err
		}
		attempts++
		if attempts >= maxRetry {
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

	var opt transfer.UploadOption
	if len(option) > 0 {
		opt = option[0]
	}

	expectedReplica := max(uint(1), opt.ExpectedReplica)

	numSeg := core.NumSplits(int64(fileSeg.FileInfo.Tx.Size), core.DefaultSegmentSize)
	dropped := make([]string, 0)
	maxRetry := 3
	attempts := 0
	for {
		uploaders, err := c.NewFileSegmentUploaderFromIndexerNodes(ctx, numSeg, expectedReplica, dropped, opt.Method, true)
		if err != nil {
			return err
		}

		var rpcError *node.RPCError
		for _, uploader := range uploaders {
			if err := uploader.Upload(ctx, fileSeg, opt); errors.As(err, &rpcError) {
				dropped = append(dropped, rpcError.URL)
				c.logger.Infof("dropped problematic node and retry: %v", rpcError.Error())
			} else {
				return err
			}
		}
		attempts++
		if attempts >= maxRetry {
			return rpcError
		}
	}
}

func (c *Client) NewDownloaderFromIndexerNodes(ctx context.Context, root string) (*transfer.Downloader, error) {
	locations, err := c.GetFileLocations(ctx, root)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get file locations")
	}
	selected, covered := shard.Select(locations, 1, "random")
	if !covered {
		return nil, fmt.Errorf("file not found or shards incomplete, FindFile triggered, try again later")
	}

	clientUrls := make([]string, 0, len(selected))
	clients := make([]*node.ZgsClient, 0, len(selected))
	for _, location := range selected {
		client, err := node.NewZgsClient(location.URL, &location.Config, c.option.ProviderOption)
		if err != nil {
			c.logger.Debugf("failed to initialize client of node %v, dropped.", location.URL)
			continue
		}

		clients = append(clients, client)
		clientUrls = append(clientUrls, location.URL)
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("no node holding the file found, FindFile triggered, try again later")
	}

	c.logger.Infof("get storage nodes from indexer: %v", clientUrls)
	downloader, err := transfer.NewDownloader(clients, c.option.LogOption)
	if err != nil {
		return nil, err
	}

	return downloader, nil
}

// WithEncryptionKey sets the encryption key for post-download decryption.
// The key must be exactly 32 bytes (AES-256).
func (c *Client) WithEncryptionKey(key []byte) *Client {
	c.encryptionKey = key
	return c
}

func (c *Client) DownloadFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	if len(c.encryptionKey) > 0 {
		return c.downloadEncryptedFragments(ctx, roots, filename, withProof)
	}
	return c.downloadPlainFragments(ctx, roots, filename, withProof)
}

func (c *Client) downloadPlainFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
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

// downloadEncryptedFragments downloads fragments raw (without decryption),
// extracts the encryption header from fragment 0, then decrypts each fragment
// with proper CTR offset tracking and writes decrypted data to the output file.
func (c *Client) downloadEncryptedFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	if len(c.encryptionKey) != 32 {
		return errors.New("encryption key must be 32 bytes")
	}
	var key [32]byte
	copy(key[:], c.encryptionKey)

	outFile, err := os.Create(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}
	defer outFile.Close()

	var header *core.EncryptionHeader
	var cumulativeDataOffset uint64

	for i, root := range roots {
		tempFile := fmt.Sprintf("%v.temp", root)

		// Download raw (no encryption key on the per-root downloader)
		downloader, err := c.NewDownloaderFromIndexerNodes(ctx, root)
		if err != nil {
			return err
		}
		err = downloader.Download(ctx, root, tempFile, withProof)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("Failed to download fragment %d", i))
		}

		fragmentData, err := os.ReadFile(tempFile)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to read fragment %d", i))
		}
		os.Remove(tempFile)

		if i == 0 {
			// First fragment: extract header
			header, err = core.ParseEncryptionHeader(fragmentData)
			if err != nil {
				return errors.WithMessage(err, "Failed to parse encryption header from fragment 0")
			}
		}

		plaintext, newOffset, err := core.DecryptFragmentData(&key, header, fragmentData, i == 0, cumulativeDataOffset)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("Failed to decrypt fragment %d", i))
		}
		cumulativeDataOffset = newOffset

		if _, err := outFile.Write(plaintext); err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to write decrypted fragment %d", i))
		}
	}

	c.logger.Info("Succeeded to decrypt and concatenate encrypted fragments")
	return nil
}

// Download download file by given data root
func (c *Client) Download(ctx context.Context, root, filename string, withProof bool) error {
	downloader, err := c.NewDownloaderFromIndexerNodes(ctx, root)
	if err != nil {
		return err
	}
	if len(c.encryptionKey) > 0 {
		downloader.WithEncryptionKey(c.encryptionKey)
	}
	return downloader.Download(ctx, root, filename, withProof)
}
