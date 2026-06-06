package indexer

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/transfer"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/openweb3/web3go"
)

// ExtendStorage re-pays the storage fee for data already stored on the network, identified
// by the original Flow.submit tx hashes, without re-uploading bytes. Each recovered fragment
// root is checked for availability via the indexer's GetFileLocations (requiring full shard
// coverage). Returns the new submit tx hashes, or *transfer.ErrDataUnavailable if any fragment
// is no longer stored (in which case no transaction is sent).
func (c *Client) ExtendStorage(
	ctx context.Context, w3Client *web3go.Client,
	submitTxHashes []eth_common.Hash, opt transfer.ExtendOption,
) ([]eth_common.Hash, error) {
	expectedReplica := max(uint(1), opt.ExpectedReplica)

	uploader, err := c.NewUploaderFromIndexerNodes(ctx, 0, w3Client, expectedReplica, nil, opt.Method, opt.FullTrusted)
	if err != nil {
		return nil, err
	}

	items, err := uploader.RecoverSubmissions(ctx, submitTxHashes)
	if err != nil {
		return nil, err
	}

	var missing []eth_common.Hash
	for _, it := range items {
		locations, err := c.GetFileLocations(ctx, it.Root.Hex())
		if err != nil {
			c.logger.WithError(err).Debugf("fragment %v not located", it.Root.Hex())
			missing = append(missing, it.Root)
			continue
		}
		if _, covered := shard.Select(locations, 1, "random"); !covered {
			missing = append(missing, it.Root)
		}
	}
	if len(missing) > 0 {
		return nil, &transfer.ErrDataUnavailable{Missing: missing}
	}

	return uploader.Resubmit(ctx, items, opt)
}
