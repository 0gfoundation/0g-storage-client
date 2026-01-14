package node

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/ethereum/go-ethereum/common"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/sirupsen/logrus"
)

// ZgsClient RPC Client connected to a 0g storage node's zgs RPC endpoint.
type ZgsClient struct {
	*rpcClient
	shardConfig *shard.ShardConfig
}

// MustNewZgsClient Initalize a zgs client and panic on failure.
func MustNewZgsClient(url string, shardConfig *shard.ShardConfig, option ...providers.Option) *ZgsClient {
	client, err := NewZgsClient(url, shardConfig, option...)
	if err != nil {
		logrus.WithError(err).WithField("url", url).Fatal("Failed to create zgs client")
	}

	return client
}

// NewZgsClient Initalize a zgs client.
func NewZgsClient(url string, shardConfig *shard.ShardConfig, option ...providers.Option) (*ZgsClient, error) {
	client, err := newRpcClient(url, option...)
	if err != nil {
		return nil, err
	}

	zgsClient := &ZgsClient{client, shardConfig}
	if zgsClient.shardConfig == nil {
		config, err := zgsClient.GetShardConfig(context.Background())
		if err != nil {
			return nil, err
		}
		zgsClient.shardConfig = &config
	}

	return zgsClient, nil
}

// MustNewZgsClients Initialize a list of zgs clients and panic on failure.
func MustNewZgsClients(urls []string, shardConfigs []*shard.ShardConfig, option ...providers.Option) []*ZgsClient {
	var clients []*ZgsClient

	for i, url := range urls {
		var shardConfig *shard.ShardConfig
		if i < len(shardConfigs) {
			shardConfig = shardConfigs[i]
		}
		client := MustNewZgsClient(url, shardConfig, option...)
		clients = append(clients, client)
	}

	return clients
}

// GetStatus Call zgs_getStatus RPC to get sync status of the node.
func (c *ZgsClient) GetStatus(ctx context.Context) (Status, error) {
	return providers.CallContext[Status](c, ctx, "zgs_getStatus")
}

func (c *ZgsClient) ShardConfig() *shard.ShardConfig {
	return c.shardConfig
}

// CheckFileFinalized Call zgs_checkFileFinalized to check if specified file is finalized.
// Returns nil if file not available on storage node.
func (c *ZgsClient) CheckFileFinalized(ctx context.Context, txSeqOrRoot TxSeqOrRoot) (*bool, error) {
	return providers.CallContext[*bool](c, ctx, "zgs_checkFileFinalized", txSeqOrRoot)
}

// GetFileInfo Call zgs_getFileInfo RPC to get the information of a file by file data root from the node.
func (c *ZgsClient) GetFileInfo(ctx context.Context, root common.Hash, needAvailable bool) (*FileInfo, error) {
	return providers.CallContext[*FileInfo](c, ctx, "zgs_getFileInfo", root, needAvailable)
}

// GetFileInfoByTxSeq Call zgs_getFileInfoByTxSeq RPC to get the information of a file by file sequence id from the node.
func (c *ZgsClient) GetFileInfoByTxSeq(ctx context.Context, txSeq uint64) (*FileInfo, error) {
	return providers.CallContext[*FileInfo](c, ctx, "zgs_getFileInfoByTxSeq", txSeq)
}

// UploadSegment Call zgs_uploadSegment RPC to upload a segment to the node.
func (c *ZgsClient) UploadSegment(ctx context.Context, segment SegmentWithProof) (int, error) {
	return providers.CallContext[int](c, ctx, "zgs_uploadSegment", segment)
}

// UploadSegmentByTxSeq Call zgs_uploadSegmentByTxSeq RPC to upload a segment to the node.
func (c *ZgsClient) UploadSegmentByTxSeq(ctx context.Context, segment SegmentWithProof, txSeq uint64) (int, error) {
	return providers.CallContext[int](c, ctx, "zgs_uploadSegmentByTxSeq", segment, txSeq)
}

// UploadSegments Call zgs_uploadSegments RPC to upload a slice of segments to the node.
func (c *ZgsClient) UploadSegments(ctx context.Context, segments []SegmentWithProof) (int, error) {
	return providers.CallContext[int](c, ctx, "zgs_uploadSegments", segments)
}

// UploadSegmentsByTxSeq Call zgs_uploadSegmentsByTxSeq RPC to upload a slice of segments to the node.
func (c *ZgsClient) UploadSegmentsByTxSeq(ctx context.Context, segments []SegmentWithProof, txSeq uint64) (int, error) {
	return providers.CallContext[int](c, ctx, "zgs_uploadSegmentsByTxSeq", segments, txSeq)
}

// DownloadSegment Call zgs_downloadSegment RPC to download a segment from the node.
func (c *ZgsClient) DownloadSegment(ctx context.Context, root common.Hash, startIndex, endIndex uint64) ([]byte, error) {
	data, err := providers.CallContext[[]byte](c, ctx, "zgs_downloadSegment", root, startIndex, endIndex)
	if len(data) == 0 {
		return nil, err
	}

	return data, err
}

// DownloadSegmentByTxSeq Call zgs_downloadSegmentByTxSeq RPC to download a segment from the node.
func (c *ZgsClient) DownloadSegmentByTxSeq(ctx context.Context, txSeq uint64, startIndex, endIndex uint64) ([]byte, error) {
	data, err := providers.CallContext[[]byte](c, ctx, "zgs_downloadSegmentByTxSeq", txSeq, startIndex, endIndex)
	if len(data) == 0 {
		return nil, err
	}

	return data, err
}

// DownloadSegmentWithProof Call zgs_downloadSegmentWithProof RPC to download a segment along with its merkle proof from the node.
func (c *ZgsClient) DownloadSegmentWithProof(ctx context.Context, root common.Hash, index uint64) (*SegmentWithProof, error) {
	return providers.CallContext[*SegmentWithProof](c, ctx, "zgs_downloadSegmentWithProof", root, index)
}

// DownloadSegmentWithProofByTxSeq Call zgs_downloadSegmentWithProofByTxSeq RPC to download a segment along with its merkle proof from the node.
func (c *ZgsClient) DownloadSegmentWithProofByTxSeq(ctx context.Context, txSeq uint64, index uint64) (*SegmentWithProof, error) {
	return providers.CallContext[*SegmentWithProof](c, ctx, "zgs_downloadSegmentWithProofByTxSeq", txSeq, index)
}

// GetShardConfig Call zgs_getShardConfig RPC to get the current shard configuration of the node.
func (c *ZgsClient) GetShardConfig(ctx context.Context) (shard.ShardConfig, error) {
	return providers.CallContext[shard.ShardConfig](c, ctx, "zgs_getShardConfig")
}

// GetSectorProof Call zgs_getSectorProof RPC to get the proof of a sector.
func (c *ZgsClient) GetSectorProof(ctx context.Context, sectorIndex uint64, root *common.Hash) (FlowProof, error) {
	return providers.CallContext[FlowProof](c, ctx, "zgs_getSectorProof", sectorIndex, root)
}
