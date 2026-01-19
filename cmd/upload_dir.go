package cmd

import (
	"context"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	uploadDirArgs uploadArgument

	uploadDirCmd = &cobra.Command{
		Use:   "upload-dir",
		Short: "Upload directory to ZeroGStorage network",
		Run:   uploadDir,
	}
)

func init() {
	bindUploadFlags(uploadDirCmd, &uploadDirArgs)
	uploadDirCmd.Flags().StringVar(&uploadDirArgs.url, "url", "", "Fullnode URL to interact with ZeroGStorage smart contract")
	uploadDirCmd.MarkFlagRequired("url")
	uploadDirCmd.Flags().StringVar(&uploadDirArgs.key, "key", "", "Private key to interact with smart contract")
	uploadDirCmd.MarkFlagRequired("key")

	rootCmd.AddCommand(uploadDirCmd)
}

func uploadDir(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if uploadDirArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, uploadDirArgs.timeout)
		defer cancel()
	}

	w3client := blockchain.MustNewWeb3(uploadDirArgs.url, uploadDirArgs.key, providerOption)
	defer w3client.Close()

	finalityRequired := transfer.TransactionPacked
	if uploadDirArgs.finalityRequired {
		finalityRequired = transfer.FileFinalized
	}
	opt := transfer.UploadOption{
		Tags:             hexutil.MustDecode(uploadDirArgs.tags),
		FinalityRequired: finalityRequired,
		TaskSize:         uploadDirArgs.taskSize,
		ExpectedReplica:  uploadDirArgs.expectedReplica,
		SkipTx:           uploadDirArgs.skipTx,
		Method:           uploadDirArgs.method,
		FullTrusted:      uploadDirArgs.fullTrusted,
	}

	uploader, closer, err := transfer.NewUploaderFromConfig(ctx, w3client, transfer.UploaderConfig{
		Nodes:          uploadDirArgs.node,
		ProviderOption: providerOption,
		LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
		Contact: &transfer.ContractAddress{
			FlowAddress:   uploadDirArgs.flowAddress,
			MarketAddress: uploadDirArgs.marketAddress,
		},
		Routines: uploadDirArgs.routines,
	})
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize uploader")
	}
	defer closer()

	txnHash, rootHash, err := uploader.UploadDir(ctx, uploadDirArgs.file, opt)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to upload directory")
	}

	logrus.WithFields(logrus.Fields{
		"txnHash":  txnHash,
		"rootHash": rootHash,
	}).Info("Directory uploaded done")
}
