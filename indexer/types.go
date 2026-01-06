package indexer

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/common/shard"
)

type ShardedNodes struct {
	Trusted    []*shard.ShardedNode `json:"trusted"`
	Discovered []*shard.ShardedNode `json:"discovered"`
}

type FileLocation struct {
	Url         string            `json:"url"`
	ShardConfig shard.ShardConfig `json:"shardConfig"`
}

type Interface interface {
	GetShardedNodes(ctx context.Context) (ShardedNodes, error)

	GetSelectedNodes(ctx context.Context, expectedReplica uint, method string, fullTrusted bool, dropped []string) (ShardedNodes, error)

	GetNodeLocations(ctx context.Context) (map[string]*IPLocation, error)

	GetFileLocations(ctx context.Context, root string) ([]*shard.ShardedNode, error)
}
