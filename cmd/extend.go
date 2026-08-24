package cmd

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type extendArgument struct {
	transactionArgument

	txs []string // original Flow.submit tx hashes

	node    []string
	indexer string

	submitter       string
	expectedReplica uint
	method          string
	fullTrusted     bool
	batchSize       uint
	maxGasPrice     uint
	nRetries        int
	step            int64
	routines        int
	timeout         time.Duration

	flowAddress   string
	marketAddress string
}

func bindExtendFlags(cmd *cobra.Command, args *extendArgument) {
	cmd.Flags().StringSliceVar(&args.txs, "tx", []string{}, "Original Flow.submit tx hash(es) returned by upload (repeatable or comma-separated)")
	mustMarkFlagRequired(cmd, "tx")

	cmd.Flags().StringSliceVar(&args.node, "node", []string{}, "ZeroGStorage storage node URL")
	cmd.Flags().StringVar(&args.indexer, "indexer", "", "ZeroGStorage indexer URL")
	cmd.MarkFlagsOneRequired("indexer", "node")
	cmd.MarkFlagsMutuallyExclusive("indexer", "node")

	cmd.Flags().StringVar(&args.submitter, "submitter", "", "Address to submit transaction from (optional, defaults to key owner)")
	cmd.Flags().UintVar(&args.expectedReplica, "expected-replica", 1, "expected number of replications to check/select")
	cmd.Flags().StringVar(&args.method, "method", "min", "method for selecting nodes: max, min, random, or positive number")
	cmd.Flags().BoolVar(&args.fullTrusted, "full-trusted", true, "whether to use full trusted nodes")
	cmd.Flags().UintVar(&args.batchSize, "batch-size", 10, "number of submissions to re-submit in a single on-chain transaction")
	cmd.Flags().UintVar(&args.maxGasPrice, "max-gas-price", 0, "max gas price to send transaction")
	cmd.Flags().IntVar(&args.nRetries, "n-retries", 0, "number of retries when it's not a gas price issue")
	cmd.Flags().Int64Var(&args.step, "step", 15, "step of gas price increasing, step / 10")
	cmd.Flags().DurationVar(&args.timeout, "timeout", 0, "cli task timeout, 0 for no timeout")
	cmd.Flags().StringVar(&args.flowAddress, "flow-address", "", "Flow contract address (skip storage node status call when set)")
	cmd.Flags().StringVar(&args.marketAddress, "market-address", "", "Market contract address (optional)")
}

var (
	extendArgs extendArgument

	extendCmd = &cobra.Command{
		Use:   "extend",
		Short: "Extend the storage period of already-stored data by re-paying, without re-uploading",
		Run:   extend,
	}
)

func init() {
	bindExtendFlags(extendCmd, &extendArgs)
	bindTransactionFlags(extendCmd, &extendArgs.transactionArgument)
	rootCmd.AddCommand(extendCmd)
}

func extend(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if extendArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, extendArgs.timeout)
		defer cancel()
	}

	if len(extendArgs.txs) == 0 {
		logrus.Fatal("at least one --tx is required")
	}
	txHashes := make([]common.Hash, 0, len(extendArgs.txs))
	for _, s := range extendArgs.txs {
		h := common.HexToHash(strings.TrimSpace(s))
		if h == (common.Hash{}) {
			logrus.Fatalf("invalid tx hash: %q", s)
		}
		txHashes = append(txHashes, h)
	}

	w3client := blockchain.MustNewWeb3(extendArgs.url, extendArgs.key, providerOption)
	defer w3client.Close()

	var submitter common.Address
	if extendArgs.submitter != "" {
		submitter = common.HexToAddress(extendArgs.submitter)
	}
	var nonce *big.Int
	if extendArgs.nonce > 0 {
		nonce = big.NewInt(int64(extendArgs.nonce))
	}
	var fee *big.Int
	if extendArgs.fee > 0 {
		feeInA0GI := big.NewFloat(extendArgs.fee)
		fee, _ = feeInA0GI.Mul(feeInA0GI, big.NewFloat(1e18)).Int(nil)
	}
	var maxGasPrice *big.Int
	if extendArgs.maxGasPrice > 0 {
		maxGasPrice = big.NewInt(int64(extendArgs.maxGasPrice))
	}

	opt := transfer.ExtendOption{
		TransactionOption: transfer.TransactionOption{
			Submitter:   submitter,
			Fee:         fee,
			Nonce:       nonce,
			MaxGasPrice: maxGasPrice,
			NRetries:    extendArgs.nRetries,
			Step:        extendArgs.step,
		},
		Method:          extendArgs.method,
		ExpectedReplica: extendArgs.expectedReplica,
		FullTrusted:     extendArgs.fullTrusted,
		BatchSize:       extendArgs.batchSize,
	}

	var txHashesOut []common.Hash
	var err error
	if extendArgs.indexer != "" {
		indexerClient, ierr := indexer.NewClient(extendArgs.indexer, indexer.IndexerClientOption{
			ProviderOption: providerOption,
			LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
			Routines:       extendArgs.routines,
			Contract: &transfer.ContractAddress{
				FlowAddress:   extendArgs.flowAddress,
				MarketAddress: extendArgs.marketAddress,
			},
		})
		if ierr != nil {
			logrus.WithError(ierr).Fatal("Failed to initialize indexer client")
		}
		defer indexerClient.Close()
		txHashesOut, err = indexerClient.ExtendStorage(ctx, w3client, txHashes, opt)
	} else {
		uploader, closer, uerr := transfer.NewUploaderFromConfig(ctx, w3client, transfer.UploaderConfig{
			Nodes:          extendArgs.node,
			ProviderOption: providerOption,
			LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
			Contact: &transfer.ContractAddress{
				FlowAddress:   extendArgs.flowAddress,
				MarketAddress: extendArgs.marketAddress,
			},
			Routines: extendArgs.routines,
		})
		if uerr != nil {
			logrus.WithError(uerr).Fatal("Failed to initialize uploader")
		}
		defer closer()
		txHashesOut, err = uploader.ExtendStorage(ctx, txHashes, opt)
	}

	var unavailable *transfer.ErrDataUnavailable
	if errors.As(err, &unavailable) {
		logrus.Errorf("storage period NOT extended: %v", unavailable.Error())
		logrus.Fatal("re-run `upload` for the missing data")
	}
	if err != nil {
		logrus.WithError(err).Fatal("Failed to extend storage period")
	}

	s := make([]string, len(txHashesOut))
	for i, h := range txHashesOut {
		s[i] = h.Hex()
	}
	logrus.Infof("storage period extended, submit tx = %v", strings.Join(s, ","))
}
