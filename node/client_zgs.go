package node

import (
	"context"
	"net"
	"net/url"

	"github.com/0glabs/0g-storage-client/common/shard"
	zgs_grpc "github.com/0glabs/0g-storage-client/node/proto"
	"github.com/ethereum/go-ethereum/common"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/sirupsen/logrus"
)

// ZgsClient RPC Client connected to a 0g storage node's zgs RPC endpoint.
type ZgsClient struct {
	*rpcClient
	*grpcClient
}

type NodeIpPair struct {
	RPC  string // e.g. "http://1.2.3.4:5678" or "http://1.2.3.4"
	GRPC string // e.g. "1.2.3.4:50051"
}

func PairTrustedHTTP(rpcs, grpcs []string) []NodeIpPair {
	grpcByHost := make(map[string]string, len(grpcs))
	for _, grpcAddr := range grpcs {
		host, _, err := net.SplitHostPort(grpcAddr)
		if err != nil {
			continue
		}
		grpcByHost[host] = grpcAddr
	}

	var out []NodeIpPair
	for _, rpcURL := range rpcs {
		u, err := url.Parse(rpcURL)
		if err != nil {
			continue
		}
		host := u.Hostname()

		out = append(out, NodeIpPair{
			RPC:  rpcURL,
			GRPC: grpcByHost[host],
		})
	}

	return out
}

// MustNewZgsClient Initalize a zgs client and panic on failure.
func MustNewZgsClient(u NodeIpPair, option ...providers.Option) *ZgsClient {
	client, err := NewZgsClient(u, option...)
	if err != nil {
		logrus.WithError(err).WithField("url", u.RPC).Fatal("Failed to create zgs client")
	}

	return client
}

// NewZgsClient Initalize a zgs client.
func NewZgsClient(u NodeIpPair, option ...providers.Option) (*ZgsClient, error) {
	client, err := newRpcClient(u.RPC, option...)
	if err != nil {
		return nil, err
	}

	res := &ZgsClient{
		client,
		nil,
	}

	if u.GRPC != "" {
		grpcClient, err := newGrpcClient(u.GRPC)
		if err != nil {
			return nil, err
		}
		res.grpcClient = grpcClient
	}
	// TODO: Can add rpc on node to return grpc information to make the discovered nodes serve grpc requests.

	return res, nil
}

// MustNewZgsClients Initialize a list of zgs clients and panic on failure.
func MustNewZgsClients(rpcs, grpcs []string, option ...providers.Option) []*ZgsClient {
	var clients []*ZgsClient

	nodes := PairTrustedHTTP(rpcs, grpcs)

	for _, n := range nodes {
		client := MustNewZgsClient(n, option...)
		clients = append(clients, client)
	}

	return clients
}

// GetStatus Call zgs_getStatus RPC to get sync status of the node.
func (c *ZgsClient) GetStatus(ctx context.Context) (Status, error) {
	return providers.CallContext[Status](c, ctx, "zgs_getStatus")
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

func (c *ZgsClient) UploadSegmentsByTxSeqChoice(ctx context.Context, segments []SegmentWithProof, txSeq uint64, useGrpc bool) (int, error) {
	if useGrpc && c.grpcClient != nil {
		return c.UploadSegmentsByTxSeqGrpc(ctx, segments, txSeq)
	}
	return c.UploadSegmentsByTxSeq(ctx, segments, txSeq)
}

func (c *ZgsClient) UploadSegmentsByTxSeqGrpc(ctx context.Context, segments []SegmentWithProof, txSeq uint64) (int, error) {
	grpcSegs, err := ConvertToGrpcSegments(segments)
	if err != nil {
		return 0, err
	}

	_, err = c.grpcClient.client.UploadSegmentsByTxSeq(ctx, &zgs_grpc.UploadSegmentsByTxSeqRequest{
		Segments: grpcSegs,
		TxSeq:    txSeq,
	})
	if err != nil {
		return 0, err
	}

	return 0, nil
}

func (c *ZgsClient) CloseGrpc() {
	if c.grpcClient != nil {
		c.grpcClient.close()
	}
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
