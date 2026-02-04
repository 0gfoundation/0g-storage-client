package cmd

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/0gfoundation/0g-storage-client/transfer/dir"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	diffDirArgs downloadArgument

	diffDirCmd = &cobra.Command{
		Use:   "diff-dir",
		Short: "Diff directory from ZeroGStorage network",
		Run:   diffDir,
	}
)

func init() {
	bindDownloadFlags(diffDirCmd, &diffDirArgs)

	rootCmd.AddCommand(diffDirCmd)
}

func diffDir(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if diffDirArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, diffDirArgs.timeout)
		defer cancel()
	}

	localRoot, err := dir.BuildFileTree(diffDirArgs.file)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to build local file tree")
	}

	var downloader transfer.IDownloader
	if diffDirArgs.indexer != "" {
		indexerClient, err := indexer.NewClient(diffDirArgs.indexer, indexer.IndexerClientOption{
			FullTrusted:    false,
			ProviderOption: providerOption,
			LogOption:      common.LogOption{Logger: logrus.StandardLogger()},
		})
		if err != nil {
			logrus.WithError(err).Fatal("Failed to initialize indexer client")
		}
		defer indexerClient.Close()
		downloader = indexerClient
	} else {
		clients := node.MustNewZgsClients(diffDirArgs.nodes, nil, providerOption)
		closer := func() {
			for _, client := range clients {
				client.Close()
			}
		}
		downloaderImpl, err := transfer.NewDownloader(clients, common.LogOption{Logger: logrus.StandardLogger()})
		if err != nil {
			closer()
			logrus.WithError(err).Fatal("Failed to initialize downloader")
		}
		downloaderImpl.WithRoutines(diffDirArgs.routines)
		downloader = downloaderImpl
		defer closer()
	}

	zgRoot, err := transfer.BuildFileTree(ctx, downloader, diffDirArgs.root, diffDirArgs.proof)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to build file tree from ZeroGStorage network")
	}

	diffRoot, err := dir.Diff(zgRoot, localRoot)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to diff directory")
	}

	// Print the diff result
	dir.PrettyPrint(diffRoot)
}
