package indexer

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/0gfoundation/0g-storage-client/common/parallel"
	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/0gfoundation/0g-storage-client/node"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	defaultZgsClientOpt = providers.Option{
		RequestTimeout: 3 * time.Second,
	}

	defaultRpcOpt = parallel.RpcOption{
		Parallel: parallel.SerialOption{
			Routines: 500,
		},
		Provider: defaultZgsClientOpt,
	}

	defaultNodeManager = NodeManager{}
)

type NodeManagerConfig struct {
	TrustedNodes []string

	DiscoveryNode     string
	DiscoveryInterval time.Duration
	DiscoveryPorts    []int

	UpdateInterval time.Duration
}

// NodeManager manages trusted storage nodes and auto discover peers from network.
type NodeManager struct {
	trusted sync.Map // url -> *node.ZgsClient

	discoverNode   *node.AdminClient
	discoveryPorts []int
	discovered     sync.Map // url -> *shard.ShardedNode
}

// InitDefaultNodeManager initializes the default `NodeManager`.
func InitDefaultNodeManager(config NodeManagerConfig) (mgr *NodeManager, err error) {
	if len(config.DiscoveryNode) > 0 {
		if defaultNodeManager.discoverNode, err = node.NewAdminClient(config.DiscoveryNode, defaultZgsClientOpt); err != nil {
			return nil, errors.WithMessage(err, "Failed to create admin client to discover peers")
		}
	}
	defaultNodeManager.discoveryPorts = config.DiscoveryPorts

	if err = defaultNodeManager.AddTrustedNodes(config.TrustedNodes...); err != nil {
		return nil, errors.WithMessage(err, "Failed to add trusted nodes")
	}

	if len(config.DiscoveryNode) > 0 {
		go util.ScheduleNow(defaultNodeManager.discover, config.DiscoveryInterval, "Failed to discover storage nodes once")
		go util.Schedule(defaultNodeManager.update, config.UpdateInterval, "Failed to update shard configs once")
	}

	return &defaultNodeManager, nil
}

// TrustedClients returns trusted clients.
func (nm *NodeManager) TrustedClients() []*node.ZgsClient {
	var clients []*node.ZgsClient
	nm.trusted.Range(func(key, value any) bool {
		clients = append(clients, value.(*node.ZgsClient))
		return true
	})
	return clients
}

// Trusted returns trusted sharded nodes.
func (nm *NodeManager) Trusted() ([]*shard.ShardedNode, error) {
	clients := nm.TrustedClients()

	var nodes []*shard.ShardedNode
	results := make(chan *shard.ShardedNode, len(clients))

	for _, v := range clients {
		client := v
		go func() {
			start := time.Now()
			config, err := client.GetShardConfig(context.Background())
			if err != nil {
				logrus.Debugf("Failed to retrieve shard config from trusted storage node %v, error: %v", client.URL(), err)
				results <- nil
				return
			}

			if !config.IsValid() {
				logrus.Debugf("Invalid shard config retrieved from trusted storage node %v: %v", client.URL(), config)
				results <- nil
				return
			}

			results <- &shard.ShardedNode{
				URL:     client.URL(),
				Config:  config,
				Latency: time.Since(start).Milliseconds(),
			}
		}()
	}

	for range clients {
		if node := <-results; node != nil {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

// Discovered returns discovered sharded nodes.
func (nm *NodeManager) Discovered() []*shard.ShardedNode {
	var nodes []*shard.ShardedNode

	nm.discovered.Range(func(key, value any) bool {
		nodes = append(nodes, value.(*shard.ShardedNode))
		return true
	})

	return nodes
}

func parseIP(url string) string {
	url = strings.ToLower(url)

	index := strings.Index(url, ":")
	if index == -1 {
		return url
	}

	url = url[index+3:]

	index = strings.Index(url, ":")
	if index == -1 {
		return url
	}

	return url[:index]
}

// AddTrustedNodes add trusted storage nodes.
func (nm *NodeManager) AddTrustedNodes(nodes ...string) error {
	for _, v := range nodes {
		ip := parseIP(v)
		if _, err := defaultIPLocationManager.Query(ip); err != nil {
			logrus.WithError(err).WithField("ip", ip).Warn("Failed to query IP location")
		}

		client, err := node.NewZgsClient(v, nil)
		if err != nil {
			return errors.WithMessagef(err, "Failed to create zgs client, url = %v", v)
		}

		nm.trusted.LoadOrStore(v, client)
	}

	return nil
}

func (nm *NodeManager) Close() {
	nm.trusted.Range(func(key, value any) bool {
		value.(*node.ZgsClient).Close()
		return true
	})

	if nm.discoverNode != nil {
		nm.discoverNode.Close()
	}
}

// discover discovers peers from storage node.
func (nm *NodeManager) discover() error {
	start := time.Now()
	peers, err := nm.discoverNode.GetPeers(context.Background())
	if err != nil {
		return errors.WithMessage(err, "Failed to retrieve peers from storage node")
	}

	logrus.WithFields(logrus.Fields{
		"peers":   len(peers),
		"elapsed": time.Since(start),
	}).Debug("Succeeded to retrieve peers from storage node")

	var numNew int
	var newPeers []string

	for _, v := range peers {
		// public ip address required
		if len(v.SeenIps) == 0 {
			continue
		}

		if len(v.SeenIps) > 1 {
			logrus.WithField("seenIPs", v.SeenIps).Warn("More than one seen IPs")
		}

		for _, port := range nm.discoveryPorts {
			url := fmt.Sprintf("http://%v:%v", v.SeenIps[0], port)

			// ignore trusted node
			if _, ok := nm.trusted.Load(url); ok {
				continue
			}

			// discovered already
			if _, ok := nm.discovered.Load(url); ok {
				continue
			}

			newPeers = append(newPeers, url)
			break
		}
	}

	result := queryShardConfigs(newPeers)
	for url, rpcResult := range result {
		if rpcResult.Err != nil {
			logrus.WithError(rpcResult.Err).WithField("url", url).Debug("Failed to add new peer")
			continue
		}

		nm.discovered.Store(url, &shard.ShardedNode{
			URL:     url,
			Config:  rpcResult.Data,
			Latency: rpcResult.Latency.Milliseconds(),
			Since:   time.Now().Unix(),
		})

		numNew++

		logrus.WithFields(logrus.Fields{
			"url":     url,
			"shard":   rpcResult.Data,
			"latency": rpcResult.Latency.Milliseconds(),
		}).Debug("New peer discovered")
	}

	if numNew > 0 {
		logrus.WithField("count", numNew).Info("New peers discovered")
	}

	return nil
}

// update updates shard configs of all storage nodes.
func (nm *NodeManager) update() error {
	var urls []string
	nm.discovered.Range(func(key, value any) bool {
		urls = append(urls, key.(string))
		return true
	})

	if len(urls) == 0 {
		return nil
	}

	logrus.WithField("nodes", len(urls)).Info("Begin to update shard config")

	start := time.Now()

	result := queryShardConfigs(urls)
	for url, rpcResult := range result {
		if rpcResult.Err == nil {
			nm.discovered.Store(url, &shard.ShardedNode{
				URL:     url,
				Config:  rpcResult.Data,
				Latency: rpcResult.Latency.Milliseconds(),
				Since:   time.Now().Unix(),
			})
		} else {
			logrus.WithError(rpcResult.Err).WithField("url", url).Debug("Failed to update shard config, remove from cache")
			nm.discovered.Delete(url)
		}
	}

	logrus.WithFields(logrus.Fields{
		"nodes":   len(urls),
		"elapsed": time.Since(start),
	}).Info("Completed to update shard config")

	return nil
}

func queryShardConfigs(nodes []string) map[string]*parallel.RpcResult[shard.ShardConfig] {
	// update IP if absent
	for _, v := range nodes {
		ip := parseIP(v)
		if _, err := defaultIPLocationManager.Query(ip); err != nil {
			logrus.WithError(err).WithField("ip", ip).Warn("Failed to query IP location")
		}
	}

	rpcFunc := func(client *node.ZgsClient, ctx context.Context) (shard.ShardConfig, error) {
		config, err := client.GetShardConfig(ctx)
		if err != nil {
			return shard.ShardConfig{}, err
		}

		if !config.IsValid() {
			return shard.ShardConfig{}, errors.Errorf("Invalid shard config retrieved %v", config)
		}

		return config, nil
	}

	return parallel.QueryZgsRpc(context.Background(), nodes, rpcFunc, defaultRpcOpt)
}
