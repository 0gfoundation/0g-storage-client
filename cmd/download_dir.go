package cmd

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	downloadDirArgs downloadArgument

	downloadDirCmd = &cobra.Command{
		Use:   "download-dir",
		Short: "Download directory from ZeroGStorage network",
		Run:   downloadDir,
	}
)

func init() {
	bindDownloadFlags(downloadDirCmd, &downloadDirArgs)

	rootCmd.AddCommand(downloadDirCmd)
}

func downloadDir(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if downloadDirArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, downloadDirArgs.timeout)
		defer cancel()
	}

	var downloader transfer.IDownloader
	if downloadDirArgs.indexer != "" {
		indexerClient, err := indexer.NewClient(downloadDirArgs.indexer, indexer.IndexerClientOption{
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
		clients := node.MustNewZgsClients(downloadDirArgs.nodes, nil, providerOption)
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
		downloaderImpl.WithRoutines(downloadDirArgs.routines)
		downloader = downloaderImpl
		defer closer()
	}

	// Download the entire directory structure.
	err := transfer.DownloadDir(ctx, downloader, downloadDirArgs.root, downloadDirArgs.file, downloadDirArgs.proof)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to download folder")
	}
}
