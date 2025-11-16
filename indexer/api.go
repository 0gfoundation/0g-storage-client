package indexer

import (
	"context"
	"fmt"

	"github.com/0gfoundation/0g-storage-client/common/shard"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

// Requires `indexerApi` implements the `Interface` interface.
var _ Interface = (*IndexerApi)(nil)

// IndexerApi indexer service configuration
type IndexerApi struct {
	Namespace string
}

// NewIndexerApi creates indexer service configuration
func NewIndexerApi() *IndexerApi {
	return &IndexerApi{"indexer"}
}

// GetShardedNodes return storage node list
func (api *IndexerApi) GetShardedNodes(ctx context.Context) (ShardedNodes, error) {
	trusted, err := defaultNodeManager.Trusted()
	if err != nil {
		return ShardedNodes{}, errors.WithMessage(err, "Failed to retrieve trusted nodes")
	}

	return ShardedNodes{
		Trusted:    trusted,
		Discovered: defaultNodeManager.Discovered(),
	}, nil
}

// GetNodeLocations return IP locations of all nodes.
func (api *IndexerApi) GetNodeLocations(ctx context.Context) (map[string]*IPLocation, error) {
	result := make(map[string]*IPLocation)

	// trusted nodes
	for _, v := range defaultNodeManager.TrustedClients() {
		ip := parseIP(v.URL())
		if loc, ok := defaultIPLocationManager.Get(ip); ok {
			result[ip] = loc
		}
	}

	// discovered nodes
	for _, v := range defaultNodeManager.Discovered() {
		ip := parseIP(v.URL)
		if loc, ok := defaultIPLocationManager.Get(ip); ok {
			result[ip] = loc
		}
	}

	return result, nil
}

// GetFileLocations return locations info of given file.
func (api *IndexerApi) GetFileLocations(ctx context.Context, root string) (locations []*shard.ShardedNode, err error) {
	// find corresponding tx sequence
	hash := eth_common.HexToHash(root)
	trustedClients := defaultNodeManager.TrustedClients()
	var txSeq uint64
	found := false
	for _, client := range trustedClients {
		info, err := client.GetFileInfo(ctx, hash, true)
		if err != nil || info == nil {
			continue
		}
		txSeq = info.Tx.Seq
		found = true
		break
	}
	if !found {
		return nil, fmt.Errorf("file not found")
	}
	return defaultFileLocationCache.GetFileLocations(ctx, txSeq)
}
