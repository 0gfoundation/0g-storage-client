package cmd

import (
	"time"

	"github.com/0gfoundation/0g-storage-client/common/rpc"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/indexer/gateway"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	indexerArgs struct {
		endpoint            string
		nodes               indexer.NodeManagerConfig
		locations           indexer.IPLocationConfig
		locationCache       indexer.FileLocationCacheConfig
		maxDownloadFileSize uint64
	}

	indexerCmd = &cobra.Command{
		Use:   "indexer",
		Short: "Start indexer service",
		Run:   startIndexer,
	}
)

func init() {
	indexerCmd.Flags().StringVar(&indexerArgs.endpoint, "endpoint", ":12345", "Indexer service endpoint")

	indexerCmd.Flags().StringSliceVar(&indexerArgs.nodes.TrustedNodes, "trusted", nil, "Trusted storage node URLs that separated by comma")
	indexerCmd.Flags().StringVar(&indexerArgs.nodes.DiscoveryNode, "node", "", "Storage node to discover peers in P2P network")
	indexerCmd.Flags().DurationVar(&indexerArgs.nodes.DiscoveryInterval, "discover-interval", 10*time.Minute, "Interval to discover peers in network")
	indexerCmd.Flags().DurationVar(&indexerArgs.nodes.UpdateInterval, "update-interval", 10*time.Minute, "Interval to update shard config of discovered peers")

	indexerCmd.Flags().IntSliceVar(&indexerArgs.nodes.DiscoveryPorts, "discover-ports", []int{5678}, "Ports to try for discovered nodes")

	indexerCmd.Flags().StringVar(&indexerArgs.locations.CacheFile, "ip-location-cache-file", ".ip-location-cache.json", "File name to cache IP locations")
	indexerCmd.Flags().DurationVar(&indexerArgs.locations.CacheWriteInterval, "ip-location-cache-interval", 10*time.Minute, "Interval to write ip locations to cache file")
	indexerCmd.Flags().StringVar(&indexerArgs.locations.AccessToken, "ip-location-token", "", "Access token to retrieve IP location from ipinfo.io")

	indexerCmd.Flags().DurationVar(&indexerArgs.locationCache.Expiry, "file-location-cache-expiry", 24*time.Hour, "Validity period of location information")
	indexerCmd.Flags().IntVar(&indexerArgs.locationCache.CacheSize, "file-location-cache-size", 100000, "size of file location cache")

	indexerCmd.Flags().Uint64Var(&indexerArgs.maxDownloadFileSize, "max-download-file-size", 100*1024*1024, "Maximum file size in bytes to download")

	indexerCmd.MarkFlagsOneRequired("trusted", "node")

	rootCmd.AddCommand(indexerCmd)
}

func startIndexer(*cobra.Command, []string) {
	indexerArgs.locationCache.DiscoveryNode = indexerArgs.nodes.DiscoveryNode
	indexerArgs.locationCache.DiscoveryPorts = indexerArgs.nodes.DiscoveryPorts

	indexer.InitDefaultIPLocationManager(indexerArgs.locations)

	nodeManager, err := indexer.InitDefaultNodeManager(indexerArgs.nodes)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize the default node manager")
	}
	defer nodeManager.Close()

	fileLocationCache, err := indexer.InitFileLocationCache(indexerArgs.locationCache)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize the default file location cache")
	}
	defer fileLocationCache.Close()

	api := indexer.NewIndexerApi()

	logrus.WithFields(logrus.Fields{
		"trusted":  len(indexerArgs.nodes.TrustedNodes),
		"discover": len(indexerArgs.nodes.DiscoveryNode) > 0,
	}).Info("Starting indexer service ...")

	gateway.MustServeWithRPC(nodeManager, fileLocationCache, gateway.Config{
		Endpoint:            indexerArgs.endpoint,
		MaxDownloadFileSize: indexerArgs.maxDownloadFileSize,
		RPCHandler: rpc.MustNewHandler(map[string]interface{}{
			api.Namespace: api,
		}),
	})
}
