package cmd

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
		if downloadDirArgs.encryptionKey != "" {
			keyBytes, err := hexutil.Decode(downloadDirArgs.encryptionKey)
			if err != nil {
				logrus.WithError(err).Fatal("Failed to decode encryption key")
			}
			if len(keyBytes) != 32 {
				logrus.Fatal("Encryption key must be exactly 32 bytes (64 hex characters)")
			}
			indexerClient.WithEncryptionKey(keyBytes)
		}
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
		if downloadDirArgs.encryptionKey != "" {
			keyBytes, err := hexutil.Decode(downloadDirArgs.encryptionKey)
			if err != nil {
				closer()
				logrus.WithError(err).Fatal("Failed to decode encryption key")
			}
			if len(keyBytes) != 32 {
				closer()
				logrus.Fatal("Encryption key must be exactly 32 bytes (64 hex characters)")
			}
			downloaderImpl.WithEncryptionKey(keyBytes)
		}
		downloader = downloaderImpl
		defer closer()
	}

	// Download the entire directory structure.
	err := transfer.DownloadDir(ctx, downloader, downloadDirArgs.root, downloadDirArgs.file, downloadDirArgs.proof)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to download folder")
	}
}
