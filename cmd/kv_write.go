package cmd

import (
	"context"
	"math"
	"math/big"
	"time"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/kv"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	kvWriteArgs struct {
		streamId string
		keys     []string
		values   []string
		version  uint64

		url string
		key string

		node    []string
		indexer string

		expectedReplica uint

		skipTx           bool
		finalityRequired bool
		taskSize         uint

		fee   float64
		nonce uint

		method      string
		fullTrusted bool
		timeout     time.Duration
	}

	kvWriteCmd = &cobra.Command{
		Use:   "kv-write",
		Short: "write to kv streams",
		Run:   kvWrite,
	}
)

func init() {
	kvWriteCmd.Flags().StringVar(&kvWriteArgs.streamId, "stream-id", "0x", "stream to read/write")
	kvWriteCmd.MarkFlagRequired("stream-id")

	kvWriteCmd.Flags().StringSliceVar(&kvWriteArgs.keys, "stream-keys", []string{}, "kv keys")
	kvWriteCmd.MarkFlagRequired("stream-keys")
	kvWriteCmd.Flags().StringSliceVar(&kvWriteArgs.values, "stream-values", []string{}, "kv values")
	kvWriteCmd.MarkFlagRequired("stream-values")

	kvWriteCmd.Flags().Uint64Var(&kvWriteArgs.version, "version", math.MaxUint64, "key version")

	kvWriteCmd.Flags().StringVar(&kvWriteArgs.url, "url", "", "Fullnode URL to interact with ZeroGStorage smart contract")
	kvWriteCmd.MarkFlagRequired("url")
	kvWriteCmd.Flags().StringVar(&kvWriteArgs.key, "key", "", "Private key to interact with smart contract")
	kvWriteCmd.MarkFlagRequired("key")

	kvWriteCmd.Flags().StringSliceVar(&kvWriteArgs.node, "node", []string{}, "ZeroGStorage storage node URL")
	kvWriteCmd.Flags().StringVar(&kvWriteArgs.indexer, "indexer", "", "ZeroGStorage indexer URL")

	kvWriteCmd.Flags().UintVar(&kvWriteArgs.expectedReplica, "expected-replica", 1, "expected number of replications to kvWrite")

	// note: for KV operations, skip-tx should by default to be false
	kvWriteCmd.Flags().BoolVar(&kvWriteArgs.skipTx, "skip-tx", false, "Skip sending the transaction on chain if already exists")
	kvWriteCmd.Flags().BoolVar(&kvWriteArgs.finalityRequired, "finality-required", false, "Wait for file finality on nodes to kvWrite")
	kvWriteCmd.Flags().UintVar(&kvWriteArgs.taskSize, "task-size", 10, "Number of segments to kvWrite in single rpc request")

	kvWriteCmd.Flags().DurationVar(&kvWriteArgs.timeout, "timeout", 0, "cli task timeout, 0 for no timeout")

	kvWriteCmd.Flags().Float64Var(&kvWriteArgs.fee, "fee", 0, "fee paid in a0gi")
	kvWriteCmd.Flags().UintVar(&kvWriteArgs.nonce, "nonce", 0, "nonce of upload transaction")
	kvWriteCmd.Flags().StringVar(&kvWriteArgs.method, "method", "random", "method for selecting nodes, can be max, min, random, or positive number, if provided a number, will fail if the requirement cannot be met")
	kvWriteCmd.Flags().BoolVar(&kvWriteArgs.fullTrusted, "full-trusted", false, "whether all selected nodes should be from trusted nodes")

	rootCmd.AddCommand(kvWriteCmd)
}

func kvWrite(*cobra.Command, []string) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if kvWriteArgs.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, kvWriteArgs.timeout)
		defer cancel()
	}

	w3client := blockchain.MustNewWeb3(kvWriteArgs.url, kvWriteArgs.key, providerOption)
	defer w3client.Close()

	var fee *big.Int
	if kvWriteArgs.fee > 0 {
		feeInA0GI := big.NewFloat(kvWriteArgs.fee)
		fee, _ = feeInA0GI.Mul(feeInA0GI, big.NewFloat(1e18)).Int(nil)
	}
	var nonce *big.Int
	if kvWriteArgs.nonce > 0 {
		nonce = big.NewInt(int64(kvWriteArgs.nonce))
	}
	finalityRequired := transfer.TransactionPacked
	if kvWriteArgs.finalityRequired {
		finalityRequired = transfer.FileFinalized
	}
	opt := transfer.UploadOption{
		FinalityRequired: finalityRequired,
		TaskSize:         kvWriteArgs.taskSize,
		ExpectedReplica:  kvWriteArgs.expectedReplica,
		SkipTx:           kvWriteArgs.skipTx,
		Fee:              fee,
		Nonce:            nonce,
		Method:           kvWriteArgs.method,
		FullTrusted:      kvWriteArgs.fullTrusted,
	}

	var clients *transfer.SelectedNodes
	if kvWriteArgs.indexer != "" {
		indexerClient, err := indexer.NewClient(kvWriteArgs.indexer, indexer.IndexerClientOption{
			ProviderOption: providerOption,
			LogOption:      zg_common.LogOption{Logger: logrus.StandardLogger()},
		})
		if err != nil {
			logrus.WithError(err).Fatal("Failed to initialize indexer client")
		}
		if clients, err = indexerClient.SelectNodes(ctx, max(1, opt.ExpectedReplica), []string{}, opt.Method, opt.FullTrusted); err != nil {
			logrus.WithError(err).Fatal("failed to select nodes from indexer")
		}
	}
	if len(clients.Trusted) == 0 && len(clients.Discovered) == 0 {
		if len(kvWriteArgs.node) == 0 {
			logrus.Fatal("At least one of --node and --indexer should not be empty")
		}
		trusted := node.MustNewZgsClients(kvWriteArgs.node, nil, providerOption)
		clients = &transfer.SelectedNodes{Trusted: trusted}
		for _, client := range trusted {
			defer client.Close()
		}
	}

	batcher := kv.NewBatcher(kvWriteArgs.version, clients, w3client, zg_common.LogOption{Logger: logrus.StandardLogger()})
	if len(kvWriteArgs.keys) != len(kvWriteArgs.values) {
		logrus.Fatal("keys and values length mismatch")
	}
	if len(kvWriteArgs.keys) == 0 {
		logrus.Fatal("no keys to write")
	}
	streamId := common.HexToHash(kvWriteArgs.streamId)

	for i := range kvWriteArgs.keys {
		batcher.Set(streamId,
			[]byte(kvWriteArgs.keys[i]),
			[]byte(kvWriteArgs.values[i]),
		)
	}

	_, err := batcher.Exec(ctx, opt)
	if err != nil {
		logrus.WithError(err).Fatal("fail to execute kv batch")
	}
}
