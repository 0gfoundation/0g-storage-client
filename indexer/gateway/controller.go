package gateway

import (
	"context"
	"strconv"

	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/node"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

type Cid struct {
	Root  string  `form:"root" json:"root"`
	TxSeq *uint64 `form:"txSeq" json:"txSeq"`
}

// NewCid parsing the CID from the input string.
func NewCid(cidStr string) Cid {
	var cid Cid
	if v, err := strconv.ParseUint(cidStr, 10, 64); err == nil { // TxnSeq is used as CID
		cid.TxSeq = &v
	} else {
		cid.Root = cidStr
	}
	return cid
}

type RestController struct {
	nodeManager       *indexer.NodeManager
	fileLocationCache *indexer.FileLocationCache

	maxDownloadFileSize uint64 // max download file size
}

func NewRestController(nodeManager *indexer.NodeManager, locationCache *indexer.FileLocationCache, maxDownloadFileSize uint64) *RestController {
	return &RestController{
		nodeManager:         nodeManager,
		fileLocationCache:   locationCache,
		maxDownloadFileSize: maxDownloadFileSize,
	}
}

// getAvailableFileLocations returns a list of available file locations for a file with the given CID.
func (ctrl *RestController) getAvailableFileLocations(ctx context.Context, cid Cid) ([]*shard.ShardedNode, error) {
	if cid.TxSeq != nil {
		return ctrl.fileLocationCache.GetFileLocations(ctx, *cid.TxSeq)
	}

	// find corresponding tx sequence
	hash := eth_common.HexToHash(cid.Root)
	for _, client := range ctrl.nodeManager.TrustedClients() {
		info, err := client.GetFileInfo(ctx, hash, true)
		if err == nil && info != nil {
			return ctrl.fileLocationCache.GetFileLocations(ctx, info.Tx.Seq)
		}
	}

	return nil, nil
}

// getAvailableStorageNodes returns a list of available storage nodes for a file with the given CID.
func (ctrl *RestController) getAvailableStorageNodes(ctx context.Context, cid Cid) (clients []*node.ZgsClient, err error) {
	nodes, err := ctrl.getAvailableFileLocations(ctx, cid)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get file locations")
	}

	defer func() {
		if err != nil { // close clients that were already built if any error occurs
			for _, client := range clients {
				client.Close()
			}
		}
	}()

	for i := range nodes {
		var client *node.ZgsClient
		client, err = node.NewZgsClient(nodes[i].URL, nil)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to create zgs client")
		}

		clients = append(clients, client)
	}

	return clients, nil
}

// fetchFileInfo encapsulates the logic for attempting to retrieve file info from storage nodes.
func (ctrl *RestController) fetchFileInfo(ctx context.Context, cid Cid) (*node.FileInfo, error) {
	clients, err := ctrl.getAvailableStorageNodes(ctx, cid)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to get available storage nodes")
	}

	defer func() {
		for _, client := range clients {
			client.Close()
		}
	}()

	fileInfo, err := getOverallFileInfo(ctx, clients, cid)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to retrieve file info from storage nodes")
	}

	if fileInfo != nil {
		return fileInfo, nil
	}

	// Attempt retrieval from trusted clients as a fallback
	fileInfo, err = getOverallFileInfo(ctx, ctrl.nodeManager.TrustedClients(), cid)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to retrieve file info from trusted clients")
	}

	return fileInfo, nil
}

func getOverallFileInfo(ctx context.Context, clients []*node.ZgsClient, cid Cid) (info *node.FileInfo, err error) {
	var rootHash eth_common.Hash
	if cid.TxSeq == nil {
		rootHash = eth_common.HexToHash(cid.Root)
	}

	var finalInfo *node.FileInfo
	for _, client := range clients {
		if cid.TxSeq != nil {
			info, err = client.GetFileInfoByTxSeq(ctx, *cid.TxSeq)
		} else {
			info, err = client.GetFileInfo(ctx, rootHash, true)
		}

		if err != nil {
			return nil, err
		}

		if info == nil {
			return nil, nil
		}

		if finalInfo == nil {
			finalInfo = info
			continue
		}
		finalInfo.Finalized = finalInfo.Finalized && info.Finalized
		finalInfo.IsCached = finalInfo.IsCached && info.IsCached
		finalInfo.Pruned = finalInfo.Pruned || info.Pruned
		finalInfo.UploadedSegNum = min(finalInfo.UploadedSegNum, info.UploadedSegNum)
	}

	return finalInfo, nil
}
