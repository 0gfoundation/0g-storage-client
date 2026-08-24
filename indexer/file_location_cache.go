package indexer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const defaultFindFileCooldown = time.Minute * 60
const defaultDiscoveredURLRetryInterval = time.Minute * 10
const defaultSuccessCallLifetime = time.Minute * 10

type FileLocationCacheConfig struct {
	CacheSize      int
	Expiry         time.Duration
	DiscoveryNode  string
	DiscoveryPorts []int
}

type successCall struct {
	node *shard.ShardedNode
	ts   time.Time
}

type FileLocationCache struct {
	cache             *expirable.LRU[uint64, []*shard.ShardedNode]
	latestFindFile    sync.Map // tx seq -> time.Time
	latestFailedCall  sync.Map // url -> time.Time
	latestSuccessCall sync.Map // url -> successCall
	zgsClients        sync.Map // url -> *node.ZgsClient, kept for the process lifetime
	discoverNode      *node.AdminClient
	discoveryPorts    []int
}

var defaultFileLocationCache FileLocationCache

func InitFileLocationCache(config FileLocationCacheConfig) (cache *FileLocationCache, err error) {
	if len(config.DiscoveryNode) > 0 {
		if defaultFileLocationCache.discoverNode, err = node.NewAdminClient(config.DiscoveryNode, defaultZgsClientOpt); err != nil {
			return nil, errors.WithMessage(err, "Failed to create admin client to discover peers")
		}
	}
	defaultFileLocationCache.cache = expirable.NewLRU[uint64, []*shard.ShardedNode](config.CacheSize, nil, config.Expiry)
	defaultFileLocationCache.discoveryPorts = config.DiscoveryPorts
	return &defaultFileLocationCache, nil
}

func (c *FileLocationCache) Close() {
	if c.discoverNode != nil {
		c.discoverNode.Close()
	}

	c.zgsClients.Range(func(_, value any) bool {
		value.(*node.ZgsClient).Close()
		return true
	})
}

// zgsClient returns a client for url, creating it once and reusing it thereafter.
//
// Discovery probes a client per candidate URL on every lookup that reaches it, and each
// client carries its own HTTP transport whose connections its Close does not release -
// so constructing one per probe grew the process's descriptor count with traffic. Keying
// them by URL makes that cost proportional to the number of distinct nodes seen instead,
// which the network bounds.
//
// They are deliberately not evicted: an evicted client's connections would not be
// reclaimed either, so eviction would restore the unbounded growth rather than cap it.
func (c *FileLocationCache) zgsClient(url string) (*node.ZgsClient, error) {
	if cached, ok := c.zgsClients.Load(url); ok {
		return cached.(*node.ZgsClient), nil
	}

	client, err := node.NewZgsClient(url, nil, defaultZgsClientOpt)
	if err != nil {
		return nil, err
	}

	// Another goroutine may have won the race; keep whichever is stored and discard ours.
	if actual, loaded := c.zgsClients.LoadOrStore(url, client); loaded {
		client.Close()
		return actual.(*node.ZgsClient), nil
	}

	return client, nil
}

func (c *FileLocationCache) GetFileLocations(ctx context.Context, txSeq uint64) ([]*shard.ShardedNode, error) {
	var nodes []*shard.ShardedNode
	nodes, ok := c.cache.Get(txSeq)
	if !ok {
		nodes = make([]*shard.ShardedNode, 0)
	}

	newNodes, err := c.getFileLocation(ctx, txSeq, nodes)
	if err != nil {
		return nil, err
	}

	return newNodes, nil
}

func (c *FileLocationCache) getFileLocation(ctx context.Context, txSeq uint64, cachedNodes []*shard.ShardedNode) ([]*shard.ShardedNode, error) {
	nodes := cachedNodes
	cachedUrl := make(map[string]bool)
	for _, v := range cachedNodes {
		cachedUrl[v.URL] = true
	}

	// fetch from trusted
	selected := make(map[string]struct{})
	trusted := defaultNodeManager.TrustedClients()
	var segNum uint64
	for _, v := range trusted {
		if _, ok := cachedUrl[v.URL()]; ok {
			continue
		}
		start := time.Now()
		fileInfo, err := v.GetFileInfoByTxSeq(ctx, txSeq)
		if fileInfo != nil {
			segNum = core.NumSplits(int64(fileInfo.Tx.Size), core.DefaultSegmentSize)
		}
		if err != nil || fileInfo == nil || !fileInfo.Finalized {
			continue
		}
		config, err := v.GetShardConfig(context.Background())
		if err != nil || !config.IsValid() {
			continue
		}
		nodes = append(nodes, &shard.ShardedNode{
			URL:     v.URL(),
			Config:  config,
			Latency: time.Since(start).Milliseconds(),
		})
		selected[v.URL()] = struct{}{}
	}
	// Only give up here when there is nothing else to ask. Trusted nodes not knowing the
	// transaction yet is exactly the case the discovery node is configured for, and
	// returning early skipped it entirely.
	if len(nodes) == 0 && segNum == 0 && c.discoverNode == nil {
		return nil, fmt.Errorf("file info not found")
	}
	logrus.Debugf("find file #%v from trusted nodes, got %v nodes holding the file", txSeq, len(nodes))
	if _, covered := shard.Select(nodes, 1, "random"); covered {
		c.cache.Add(txSeq, nodes)
		return nodes, nil
	}
	// trusted nodes do not hold all shards of the file, try to find file
	if c.discoverNode != nil {
		locations, err := c.discoverNode.GetFileLocation(ctx, txSeq, false)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("find file #%v from location cache, got %v nodes holding the file", txSeq, len(locations))
		for _, location := range locations {
			for _, port := range c.discoveryPorts {
				url := fmt.Sprintf("http://%v:%v", location.Ip, port)
				if _, ok := selected[url]; ok {
					break
				}
				if val, ok := c.latestSuccessCall.Load(url); ok {
					call := val.(successCall)
					if time.Since(call.ts) < defaultSuccessCallLifetime {
						nodes = append(nodes, call.node)
						break
					}
				}
				if val, ok := c.latestFailedCall.Load(url); ok {
					if time.Since(val.(time.Time)) < defaultDiscoveredURLRetryInterval {
						continue
					}
				}
				zgsClient, err := c.zgsClient(url)
				if err != nil {
					continue
				}
				fileInfo, err := zgsClient.GetFileInfoByTxSeq(ctx, txSeq)
				if err != nil {
					c.latestFailedCall.Store(url, time.Now())
					continue
				}
				if fileInfo == nil || !fileInfo.Finalized {
					continue
				}
				start := time.Now()
				config, err := zgsClient.GetShardConfig(context.Background())
				if err != nil {
					c.latestFailedCall.Store(url, time.Now())
					continue
				}
				if !config.IsValid() {
					continue
				}
				call := successCall{
					node: &shard.ShardedNode{
						URL:     url,
						Config:  config,
						Latency: time.Since(start).Milliseconds(),
					},
					ts: time.Now(),
				}
				nodes = append(nodes, call.node)
				c.latestSuccessCall.Store(url, call)
				selected[url] = struct{}{}
				break
			}
		}
		if _, covered := shard.Select(nodes, 1, "random"); covered {
			c.cache.Add(txSeq, nodes)
			return nodes, nil
		}
		if val, ok := c.latestFindFile.Load(txSeq); ok {
			if time.Since(val.(time.Time)) < defaultFindFileCooldown {
				return nil, nil
			}
		}
		logrus.Debugf("triggering FindFile for tx seq %v", txSeq)
		if _, err := c.discoverNode.FindFile(ctx, txSeq); err != nil {
			// Record the cooldown only for a request that was actually accepted. Storing it
			// regardless meant one transient RPC failure suppressed every further attempt
			// for defaultFindFileCooldown, so a momentary blip stopped discovery for an hour.
			logrus.WithError(err).Warnf("failed to trigger FindFile for tx seq %v", txSeq)
			return nil, nil
		}
		c.latestFindFile.Store(txSeq, time.Now())
	}
	return nil, nil

}
