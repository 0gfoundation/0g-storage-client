package cmd

import (
	"context"
	"math/big"
	"runtime"
	"strings"
	"time"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// L1 transaction relevant operations, including nonce, fee, and so on.
type transactionArgument struct {
	url string
	key string

	fee   float64
	nonce uint
}

func bindTransactionFlags(cmd *cobra.Command, args *transactionArgument) {
	cmd.Flags().StringVar(&args.url, "url", "", "Fullnode URL to interact with ZeroGStorage smart contract")
	cmd.MarkFlagRequired("url")
	cmd.Flags().StringVar(&args.key, "key", "", "Private key to interact with smart contract")
	cmd.MarkFlagRequired("key")

	cmd.Flags().Float64Var(&args.fee, "fee", 0, "fee paid in a0gi")
	cmd.Flags().UintVar(&args.nonce, "nonce", 0, "nonce of upload transaction")
}

type uploadArgument struct {
	transactionArgument

	file      string
	tags      string
	submitter string

	node    []string
	indexer string

	expectedReplica uint

	skipTx           bool
	finalityRequired bool
	taskSize         uint
	routines         int
	fastMode         bool

	fragmentSize int64
	maxGasPrice  uint
	nRetries     int
	step         int64
	method       string
	fullTrusted  bool

	timeout time.Duration

	flowAddress   string
	marketAddress string
}

func bindUploadFlags(cmd *cobra.Command, args *uploadArgument) {
	cmd.Flags().StringVar(&args.file, "file", "", "File name to upload")
	cmd.MarkFlagRequired("file")
	cmd.Flags().StringVar(&args.tags, "tags", "0x", "Tags of the file")
	cmd.Flags().StringVar(&args.submitter, "submitter", "", "Address to submit transaction from (optional, defaults to key owner)")

	cmd.Flags().StringSliceVar(&args.node, "node", []string{}, "ZeroGStorage storage node URL")
	cmd.Flags().StringVar(&args.indexer, "indexer", "", "ZeroGStorage indexer URL")
	cmd.MarkFlagsOneRequired("indexer", "node")
	cmd.MarkFlagsMutuallyExclusive("indexer", "node")

	cmd.Flags().UintVar(&args.expectedReplica, "expected-replica", 1, "expected number of replications to upload")

	cmd.Flags().BoolVar(&args.skipTx, "skip-tx", true, "Skip sending the transaction on chain if already exists")
	cmd.Flags().BoolVar(&args.finalityRequired, "finality-required", false, "Wait for file finality on nodes to upload")
	cmd.Flags().UintVar(&args.taskSize, "task-size", 10, "Number of segments to upload in single rpc request")
	cmd.Flags().BoolVar(&args.fastMode, "fast-mode", true, "Enable fast mode (no receipt wait, root-based upload for small files)")

	cmd.Flags().Int64Var(&args.fragmentSize, "fragment-size", 1024*1024*1024*4, "the size of fragment to split into when file is too large")

	cmd.Flags().IntVar(&args.routines, "routines", runtime.GOMAXPROCS(0), "number of go routines for uploading simutanously")
	cmd.Flags().UintVar(&args.maxGasPrice, "max-gas-price", 0, "max gas price to send transaction")
	cmd.Flags().IntVar(&args.nRetries, "n-retries", 0, "number of retries for uploading when it's not gas price issue")
	cmd.Flags().Int64Var(&args.step, "step", 15, "step of gas price increasing, step / 10 (for 15, the new gas price is 1.5 * last gas price)")
	cmd.Flags().StringVar(&args.method, "method", "min", "method for selecting nodes, can be max, min, random, or positive number, if provided a number, will fail if the requirement cannot be met")
	cmd.Flags().BoolVar(&args.fullTrusted, "full-trusted", true, "whether to use full trusted nodes")

	cmd.Flags().DurationVar(&args.timeout, "timeout", 0, "cli task timeout, 0 for no timeout")

	cmd.Flags().StringVar(&args.flowAddress, "flow-address", "", "Flow contract address (skip storage node status call when set)")
	cmd.Flags().StringVar(&args.marketAddress, "market-address", "", "Market contract address (optional, skip flow lookup when set)")
}

var (
	uploadArgs uploadArgument

	uploadCmd = &cobra.Command{
		Use:   "upload",
		Short: "Upload file to ZeroGStorage network",
		Run:   upload,
	}
)

func init() {
	bindUploadFlags(uploadCmd, &uploadArgs)
	bindTransactionFlags(uploadCmd, &uploadArgs.transactionArgument)

	rootCmd.AddCommand(uploadCmd)
}

func upload(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if uploadArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, uploadArgs.timeout)
		defer cancel()
	}

	w3client := blockchain.MustNewWeb3(uploadArgs.url, uploadArgs.key, providerOption)
	defer w3client.Close()

	// Extract submitter address once from w3client, or use provided submitter if specified
	var submitter common.Address
	if uploadArgs.submitter != "" {
		submitter = common.HexToAddress(uploadArgs.submitter)
		if submitter == (common.Address{}) {
			logrus.Fatal("Invalid submitter address provided")
		}
	} else {
		sm, err := w3client.GetSignerManager()
		if err != nil {
			logrus.WithError(err).Fatal("Failed to get signer manager")
		}
		submitter = sm.List()[0].Address()
	}

	var fee *big.Int
	if uploadArgs.fee > 0 {
		feeInA0GI := big.NewFloat(uploadArgs.fee)
		fee, _ = feeInA0GI.Mul(feeInA0GI, big.NewFloat(1e18)).Int(nil)
	}
	var nonce *big.Int
	if uploadArgs.nonce > 0 {
		nonce = big.NewInt(int64(uploadArgs.nonce))
	}
	finalityRequired := transfer.TransactionPacked
	if uploadArgs.finalityRequired {
		finalityRequired = transfer.FileFinalized
	}

	var maxGasPrice *big.Int
	if uploadArgs.maxGasPrice > 0 {
		maxGasPrice = big.NewInt(int64(uploadArgs.maxGasPrice))
	}
	opt := transfer.UploadOption{
		Submitter:        submitter,
		Tags:             hexutil.MustDecode(uploadArgs.tags),
		FinalityRequired: finalityRequired,
		TaskSize:         uploadArgs.taskSize,
		ExpectedReplica:  uploadArgs.expectedReplica,
		SkipTx:           uploadArgs.skipTx,
		Fee:              fee,
		Nonce:            nonce,
		MaxGasPrice:      maxGasPrice,
		NRetries:         uploadArgs.nRetries,
		Step:             uploadArgs.step,
		Method:           uploadArgs.method,
		FullTrusted:      uploadArgs.fullTrusted,
		FastMode:         uploadArgs.fastMode,
	}

	file, err := core.Open(uploadArgs.file)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to open file")
	}
	defer file.Close()

	var roots []common.Hash
	if uploadArgs.indexer != "" {
		indexerClient, err := indexer.NewClient(uploadArgs.indexer, indexer.IndexerClientOption{
			ProviderOption: providerOption,
			LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
			Routines:       uploadArgs.routines,
			Contract: &transfer.ContractAddress{
				FlowAddress:   uploadArgs.flowAddress,
				MarketAddress: uploadArgs.marketAddress,
			},
		})
		if err != nil {
			logrus.WithError(err).Fatal("Failed to initialize indexer client")
		}
		defer indexerClient.Close()

		_, roots, err = indexerClient.SplitableUpload(ctx, w3client, file, uploadArgs.fragmentSize, opt)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to upload file")
		}
	} else {
		uploader, closer, err := transfer.NewUploaderFromConfig(ctx, w3client, transfer.UploaderConfig{
			Nodes:          uploadArgs.node,
			ProviderOption: providerOption,
			LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
			Contact: &transfer.ContractAddress{
				FlowAddress:   uploadArgs.flowAddress,
				MarketAddress: uploadArgs.marketAddress,
			},
			Routines: uploadArgs.routines,
		})
		if err != nil {
			logrus.WithError(err).Fatal("Failed to initialize uploader")
		}
		defer closer()

		_, roots, err = uploader.SplitableUpload(ctx, file, uploadArgs.fragmentSize, opt)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to upload file")
		}
	}

	if len(roots) == 1 {
		logrus.Infof("file uploaded, root = %v", roots[0])
	} else {
		s := make([]string, len(roots))
		for i, root := range roots {
			s[i] = root.String()
		}
		logrus.Infof("file uploaded in %v fragments, roots = %v", len(roots), strings.Join(s, ","))
	}
}
