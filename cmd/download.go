package cmd

import (
	"context"
	"crypto/ecdsa"
	"runtime"
	"strings"
	"time"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type downloadArgument struct {
	file string

	indexer string
	nodes   []string

	hotRouter  string
	chainID    int64
	privateKey string

	root  string
	roots []string
	proof bool

	encryptionKey string
	decrypt       bool

	routines int

	timeout time.Duration
}

func bindDownloadFlags(cmd *cobra.Command, args *downloadArgument) {
	cmd.Flags().StringVar(&args.file, "file", "", "File name to download")
	cmd.MarkFlagRequired("file")

	cmd.Flags().StringSliceVar(&args.nodes, "node", []string{}, "ZeroGStorage storage node URL. Multiple nodes could be specified and separated by comma, e.g. url1,url2,url3")
	cmd.Flags().StringVar(&args.indexer, "indexer", "", "ZeroGStorage indexer URL")

	cmd.Flags().StringVar(&args.hotRouter, "hot-router", "", "Hot storage router URL for fast download")
	cmd.Flags().Int64Var(&args.chainID, "chain-id", 16601, "Chain ID for EIP-712 domain separator on hot storage download auth (must match the router's configured chain)")
	cmd.Flags().StringVar(&args.privateKey, "private-key", "", "User's private key for signing hot storage download requests")

	cmd.Flags().StringVar(&args.root, "root", "", "Merkle root to download file")
	cmd.Flags().StringSliceVar(&args.roots, "roots", []string{}, "Merkle roots to download fragments")
	cmd.MarkFlagsOneRequired("root", "roots")
	cmd.MarkFlagsMutuallyExclusive("root", "roots")

	cmd.Flags().BoolVar(&args.proof, "proof", false, "Whether to download with merkle proof for validation")

	cmd.Flags().StringVar(&args.encryptionKey, "encryption-key", "", "Hex-encoded 32-byte AES-256 symmetric key for v1 decryption (mutually exclusive with --decrypt)")
	cmd.Flags().BoolVar(&args.decrypt, "decrypt", false, "Decrypt v2 (ECIES) files using --private-key as the wallet private key (mutually exclusive with --encryption-key)")

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

	// Validate flag combinations.
	if downloadArgs.hotRouter != "" {
		if downloadArgs.privateKey == "" {
			logrus.Fatal("--private-key is required when using --hot-router")
		}
		if downloadArgs.indexer == "" && len(downloadArgs.nodes) == 0 {
			logrus.Fatal("--indexer or --node is required as fallback when using --hot-router")
		}
	} else if downloadArgs.indexer == "" && len(downloadArgs.nodes) == 0 {
		logrus.Fatal("one of --indexer, --node, or --hot-router is required")
	}
	if downloadArgs.decrypt && downloadArgs.encryptionKey != "" {
		logrus.Fatal("--decrypt and --encryption-key are mutually exclusive")
	}
	if downloadArgs.decrypt && downloadArgs.privateKey == "" {
		logrus.Fatal("--decrypt requires --private-key")
	}

	var (
		downloader transfer.IDownloader
		closer     func()
	)

	// Build the base downloader (used directly or as fallback for hot storage).
	var baseDownloader transfer.IDownloader
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
		if downloadArgs.encryptionKey != "" && downloadArgs.hotRouter == "" {
			keyBytes := mustDecodeEncryptionKey(downloadArgs.encryptionKey)
			indexerClient.WithEncryptionKey(keyBytes)
		}
		if downloadArgs.decrypt && downloadArgs.hotRouter == "" {
			indexerClient.WithWalletPrivateKey(mustParsePrivateKey(downloadArgs.privateKey))
		}
		baseDownloader = indexerClient
	} else if len(downloadArgs.nodes) > 0 {
		clients := node.MustNewZgsClients(downloadArgs.nodes, nil, providerOption)
		closer = func() {
			for _, client := range clients {
				client.Close()
			}
		}
		downloaderImpl, err := transfer.NewDownloader(clients, common.LogOption{Logger: logrus.StandardLogger()})
		if err != nil {
			if closer != nil {
				closer()
			}
			logrus.WithError(err).Fatal("Failed to initialize downloader")
		}
		downloaderImpl.WithRoutines(downloadArgs.routines)
		if downloadArgs.encryptionKey != "" && downloadArgs.hotRouter == "" {
			keyBytes := mustDecodeEncryptionKey(downloadArgs.encryptionKey)
			downloaderImpl.WithEncryptionKey(keyBytes)
		}
		if downloadArgs.decrypt && downloadArgs.hotRouter == "" {
			downloaderImpl.WithWalletPrivateKey(mustParsePrivateKey(downloadArgs.privateKey))
		}
		baseDownloader = downloaderImpl
		defer closer()
	}

	// Build the hot downloader if hot-router is specified.
	if downloadArgs.hotRouter != "" {
		privateKey := mustParsePrivateKey(downloadArgs.privateKey)
		routerClient := node.NewHotRouterClient(downloadArgs.hotRouter, downloadArgs.chainID)
		hotDownloader := transfer.NewHotDownloader(routerClient, privateKey, baseDownloader, common.LogOption{Logger: logrus.StandardLogger()})
		if downloadArgs.encryptionKey != "" {
			keyBytes := mustDecodeEncryptionKey(downloadArgs.encryptionKey)
			hotDownloader.WithEncryptionKey(keyBytes)
		}
		if downloadArgs.decrypt {
			hotDownloader.WithWalletPrivateKey(privateKey)
		}
		downloader = hotDownloader
	} else {
		downloader = baseDownloader
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

func mustDecodeEncryptionKey(hexKey string) []byte {
	keyBytes, err := hexutil.Decode(hexKey)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to decode encryption key")
	}
	if len(keyBytes) != 32 {
		logrus.Fatal("Encryption key must be exactly 32 bytes (64 hex characters)")
	}
	return keyBytes
}

func mustParsePrivateKey(hexKey string) *ecdsa.PrivateKey {
	hexKey = strings.TrimPrefix(hexKey, "0x")
	hexKey = strings.TrimPrefix(hexKey, "0X")
	key, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to parse private key")
	}
	return key
}
