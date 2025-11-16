package shard

import (
	"sort"
	"strconv"

	"github.com/0gfoundation/0g-storage-client/common/util"
)

type ShardConfig struct {
	ShardId  uint64 `json:"shardId"`
	NumShard uint64 `json:"numShard"`
}

func (config *ShardConfig) HasSegment(segmentIndex uint64) bool {
	return config.NumShard < 2 || segmentIndex%config.NumShard == config.ShardId
}

func (config *ShardConfig) IsValid() bool {
	// NumShard should be larger than zero and be power of 2
	return config.NumShard > 0 && (config.NumShard&(config.NumShard-1) == 0) && config.ShardId < config.NumShard
}

// NextSegmentIndex calculates the next segment index for the shard, starting from the given startSegmentIndex.
// If the startSegmentIndex is already covered by the shard (i.e., the shard is responsible for this segment),
// it will be included in the result and returned directly. Otherwise, the function will calculate and return
// the next segment index that this shard is responsible for.
func (config *ShardConfig) NextSegmentIndex(startSegmentIndex uint64) uint64 {
	if config.NumShard < 2 {
		return startSegmentIndex
	}
	return (startSegmentIndex+config.NumShard-1-config.ShardId)/config.NumShard*config.NumShard + config.ShardId
}

type ShardedNode struct {
	URL    string      `json:"url"`
	Config ShardConfig `json:"config"`
	// Latency RPC latency in milli seconds.
	Latency int64 `json:"latency"`
	// Since last updated timestamp.
	Since int64 `json:"since"`
}

func NewShardNodesFromConfig(configs []*ShardConfig) []*ShardedNode {
	nodes := make([]*ShardedNode, len(configs))
	for i, config := range configs {
		nodes[i] = &ShardedNode{
			Config: *config,
		}
	}
	return nodes
}

type shardSegmentTreeNode struct {
	childs   []*shardSegmentTreeNode
	numShard uint
	lazyTags uint
	replica  uint
}

func (node *shardSegmentTreeNode) pushdown() {
	if node.childs == nil {
		node.childs = make([]*shardSegmentTreeNode, 2)
		for i := 0; i < 2; i += 1 {
			node.childs[i] = &shardSegmentTreeNode{
				numShard: node.numShard << 1,
				replica:  0,
				lazyTags: 0,
			}
		}
	}
	for i := 0; i < 2; i += 1 {
		node.childs[i].replica += node.lazyTags
		node.childs[i].lazyTags += node.lazyTags
	}
	node.lazyTags = 0
}

// insert a shard if it contributes to the replica
func (node *shardSegmentTreeNode) insert(numShard uint, shardId uint, expectedReplica uint) bool {
	if node.replica >= expectedReplica {
		return false
	}
	if node.numShard == numShard {
		node.replica += 1
		node.lazyTags += 1
		return true
	}
	node.pushdown()
	inserted := node.childs[shardId%2].insert(numShard, shardId>>1, expectedReplica)
	node.replica = min(node.childs[0].replica, node.childs[1].replica)
	return inserted
}

// select a set of given sharded node and make the data is replicated at least expctedReplica times
// return the selected nodes and if selection is successful
func Select(nodes []*ShardedNode, expectedReplica uint, method string) ([]*ShardedNode, bool) {
	selected := make([]*ShardedNode, 0)
	if expectedReplica == 0 {
		return selected, true
	}

	// shuffle or sort nodes before selection
	nodes = prepareSelectionNodes(nodes, method)

	// build segment tree to select proper nodes by shard configs
	root := shardSegmentTreeNode{
		numShard: 1,
		replica:  0,
		lazyTags: 0,
	}

	for _, node := range nodes {
		if root.insert(uint(node.Config.NumShard), uint(node.Config.ShardId), expectedReplica) {
			selected = append(selected, node)
		}
		if root.replica >= expectedReplica {
			return selected, true
		}
	}
	return make([]*ShardedNode, 0), false
}

func CheckReplica(shardConfigs []*ShardConfig, expectedReplica uint, method string) bool {
	shardedNodes := NewShardNodesFromConfig(shardConfigs)
	_, ok := Select(shardedNodes, expectedReplica, method)
	return ok
}

// Helper function to pre-process (sort or shuffle) the nodes before selection
func prepareSelectionNodes(nodes []*ShardedNode, method string) []*ShardedNode {
	switch method {
	case "random":
		util.Shuffle(nodes)
	case "max":
		// Sort nodes based on NumShard and ShardId
		sort.Slice(nodes, func(i, j int) bool {
			if nodes[i].Config.NumShard == nodes[j].Config.NumShard {
				return nodes[i].Config.ShardId < nodes[j].Config.ShardId
			}
			return nodes[i].Config.NumShard > nodes[j].Config.NumShard
		})
	case "min":
		// Sort nodes based on NumShard and ShardId
		sort.Slice(nodes, func(i, j int) bool {
			if nodes[i].Config.NumShard == nodes[j].Config.NumShard {
				return nodes[i].Config.ShardId < nodes[j].Config.ShardId
			}
			return nodes[i].Config.NumShard < nodes[j].Config.NumShard
		})
	default:
		// Attempt to parse `method` as a positive integer
		size, err := strconv.Atoi(method)
		if err != nil || size <= 0 {
			// If parsing fails or size <= 0, return an empty slice
			return []*ShardedNode{}
		}

		// Filter nodes whose NumShard == size
		var filtered []*ShardedNode
		for _, n := range nodes {
			if n.Config.NumShard == uint64(size) {
				filtered = append(filtered, n)
			}
		}
		return filtered
	}

	return nodes
}
