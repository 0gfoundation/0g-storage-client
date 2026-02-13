package cmd

import (
	"context"
	"runtime"
	"time"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type downloadArgument struct {
	file string

	indexer string
	nodes   []string

	root  string
	roots []string
	proof bool

	encryptionKey string

	routines int

	timeout time.Duration
}

func bindDownloadFlags(cmd *cobra.Command, args *downloadArgument) {
	cmd.Flags().StringVar(&args.file, "file", "", "File name to download")
	cmd.MarkFlagRequired("file")

	cmd.Flags().StringSliceVar(&args.nodes, "node", []string{}, "ZeroGStorage storage node URL. Multiple nodes could be specified and separated by comma, e.g. url1,url2,url3")
	cmd.Flags().StringVar(&args.indexer, "indexer", "", "ZeroGStorage indexer URL")
	cmd.MarkFlagsOneRequired("indexer", "node")

	cmd.Flags().StringVar(&args.root, "root", "", "Merkle root to download file")
	cmd.Flags().StringSliceVar(&args.roots, "roots", []string{}, "Merkle roots to download fragments")
	cmd.MarkFlagsOneRequired("root", "roots")
	cmd.MarkFlagsMutuallyExclusive("root", "roots")

	cmd.Flags().BoolVar(&args.proof, "proof", false, "Whether to download with merkle proof for validation")

	cmd.Flags().StringVar(&args.encryptionKey, "encryption-key", "", "Hex-encoded 32-byte AES-256 encryption key for file decryption")

	cmd.Flags().IntVar(&args.routines, "routines", runtime.GOMAXPROCS(0), "number of go routines for downloading simultaneously")

	cmd.Flags().DurationVar(&args.timeout, "timeout", 0, "cli task timeout, 0 for no timeout")
}

var (
	downloadArgs downloadArgument

	downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "Download file from ZeroGStorage network",
		Run:   download,
	}
)

func init() {
	bindDownloadFlags(downloadCmd, &downloadArgs)

	rootCmd.AddCommand(downloadCmd)
}

func download(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if downloadArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, downloadArgs.timeout)
		defer cancel()
	}

	var (
		downloader transfer.IDownloader
		closer     func()
	)
	if downloadArgs.indexer != "" {
		indexerClient, err := indexer.NewClient(downloadArgs.indexer, indexer.IndexerClientOption{
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
		clients := node.MustNewZgsClients(downloadArgs.nodes, nil, providerOption)
		closer = func() {
			for _, client := range clients {
				client.Close()
			}
		}
		downloaderImpl, err := transfer.NewDownloader(clients, common.LogOption{Logger: logrus.StandardLogger()})
		if err != nil {
			closer()
			logrus.WithError(err).Fatal("Failed to initialize downloader")
		}
		downloaderImpl.WithRoutines(downloadArgs.routines)
		if downloadArgs.encryptionKey != "" {
			keyBytes, err := hexutil.Decode(downloadArgs.encryptionKey)
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

	if downloadArgs.root != "" {
		if err := downloader.Download(ctx, downloadArgs.root, downloadArgs.file, downloadArgs.proof); err != nil {
			logrus.WithError(err).Fatal("Failed to download file")
		}
	} else {
		if err := downloader.DownloadFragments(ctx, downloadArgs.roots, downloadArgs.file, downloadArgs.proof); err != nil {
			logrus.WithError(err).Fatal("Failed to download file")
		}
	}
}
