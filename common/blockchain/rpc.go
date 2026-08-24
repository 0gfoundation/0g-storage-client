package blockchain

import (
	"context"
	"time"

	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/mcuadros/go-defaults"
	rpcprovider "github.com/openweb3/go-rpc-provider"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/openweb3/web3go"
	"github.com/openweb3/web3go/interfaces"
	"github.com/openweb3/web3go/signers"
	"github.com/openweb3/web3go/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var Web3LogEnabled bool

type RetryOption struct {
	NRetries int
	Interval time.Duration
	logger   *logrus.Logger
}

func MustNewWeb3(url, key string, opt ...providers.Option) *web3go.Client {
	client, err := NewWeb3(url, key, opt...)
	if err != nil {
		logrus.WithError(err).WithField("url", url).Fatal("Failed to connect to fullnode")
	}

	return client
}

func NewWeb3(url, key string, opt ...providers.Option) (*web3go.Client, error) {
	sm := signers.MustNewSignerManagerByPrivateKeyStrings([]string{key})

	option := new(web3go.ClientOption)
	if len(opt) > 0 {
		option.Option = opt[0]
	}
	defaults.SetDefaults(&option.Option)
	option.WithSignerManager(sm)

	if Web3LogEnabled {
		option = option.WithLooger(logrus.StandardLogger().Out)
	}

	return web3go.NewClientWithOption(url, *option)
}

func NewWeb3WithOption(url, key string, option ...providers.Option) (*web3go.Client, error) {
	var opt web3go.ClientOption

	if len(option) > 0 {
		opt.Option = option[0]
	}

	sm := signers.MustNewSignerManagerByPrivateKeyStrings([]string{key})

	return web3go.NewClientWithOption(url, *opt.WithSignerManager(sm))
}

func WaitForReceipt(ctx context.Context, client *web3go.Client, txHash common.Hash, successRequired bool, opts ...RetryOption) (receipt *types.Receipt, err error) {
	var opt RetryOption
	if len(opts) > 0 {
		opt = opts[0]
	} else {
		opt.Interval = time.Second * 1
	}

	if opt.Interval == 0 {
		opt.Interval = time.Second * 1
	}

	reminder := util.NewReminder(opt.logger, time.Minute)
	for receipt == nil {
		if receipt, err = client.WithContext(ctx).Eth.TransactionReceipt(txHash); err != nil {
			return nil, err
		}

		logrus.WithField("txHash", txHash).WithField("receipt", receipt).Info("Transaction receipt")

		// remind
		if receipt == nil {
			reminder.RemindWith("Transaction not executed yet", "hash", txHash)
		}

		time.Sleep(opt.Interval)
	}

	if receipt.Status == nil {
		return nil, errors.New("Status not found in receipt")
	}

	switch *receipt.Status {
	case gethTypes.ReceiptStatusSuccessful:
		return receipt, nil
	case gethTypes.ReceiptStatusFailed:
		if !successRequired {
			return receipt, nil
		}

		if receipt.TxExecErrorMsg != nil {
			return nil, errors.Errorf("Transaction execution failed, %v", *receipt.TxExecErrorMsg)
		}

		if reason := revertReason(ctx, client, txHash, receipt.BlockNumber); reason != "" {
			return nil, errors.Errorf("Transaction execution failed, %v", reason)
		}

		return nil, errors.New("Transaction execution failed")
	default:
		return nil, errors.Errorf("Unknown receipt status %v", *receipt.Status)
	}
}

// revertReason recovers why the EVM rejected a transaction by replaying it with
// eth_call. A geth-compatible receipt carries no such field - web3go populates
// TxExecErrorMsg only for Conflux - so without the replay a failed transaction
// reports nothing beyond the fact that it failed.
//
// Diagnosis only, and best-effort: a node that has pruned the block's state
// recovers nothing, and a revert that depends on the position of the
// transaction within its block will not reproduce. An empty string means the
// caller should report the bare failure rather than a guess.
func revertReason(ctx context.Context, client *web3go.Client, txHash common.Hash, blockNumber uint64) string {
	eth := client.WithContext(ctx).Eth

	tx, err := eth.TransactionByHash(txHash)
	if err != nil || tx == nil {
		logrus.WithError(err).WithField("txHash", txHash).
			Debug("Cannot diagnose the revert: transaction not retrievable")
		return ""
	}

	// Replay in the block that contains the transaction, not in its parent. A
	// revert is atomic, so the block's state holds none of this transaction's
	// effects and is what it actually ran against - while the block context,
	// number and timestamp included, matches only here. Replaying in the parent
	// would silently answer a different question, which is what a condition
	// tied to block height would turn into a false negative.
	block := types.BlockNumberOrHashWithNumber(types.NewBlockNumber(int64(blockNumber)))

	// Gas price is deliberately omitted: a call needs none, and forwarding both
	// the legacy and the dynamic-fee fields is rejected outright by geth, which
	// would mask the revert we came here to read.
	if _, err := eth.Call(types.CallRequest{
		From:  &tx.From,
		To:    tx.To,
		Gas:   &tx.Gas,
		Value: tx.Value,
		Data:  tx.Input,
	}, &block); err != nil {
		return revertReasonFromError(err)
	}

	// Reporting nothing is the honest outcome, but it is also the one that
	// leaves no trace, so say why the caller is about to see a bare failure.
	logrus.WithFields(logrus.Fields{"txHash": txHash, "blockNumber": blockNumber}).
		Debug("Cannot diagnose the revert: the replay succeeded where the transaction failed")

	return ""
}

// revertReasonFromError extracts the reason a node returned alongside a failed
// eth_call. Nodes report it as ABI-encoded revert data on the JSON-RPC error;
// whatever cannot be decoded falls back to the node's own message, which is
// still more than the caller had.
func revertReasonFromError(err error) string {
	var jsonErr *rpcprovider.JsonError
	if !errors.As(err, &jsonErr) {
		return err.Error()
	}

	data, ok := jsonErr.Data.(string)
	if !ok {
		return jsonErr.Error()
	}

	revertData, decodeErr := hexutil.Decode(data)
	if decodeErr != nil {
		return jsonErr.Error()
	}

	// UnpackRevert covers both Error(string) and Panic(uint256).
	reason, unpackErr := abi.UnpackRevert(revertData)
	if unpackErr != nil {
		return jsonErr.Error()
	}

	return reason
}

func defaultSigner(clientWithSigner *web3go.Client) (interfaces.Signer, error) {
	sm, err := clientWithSigner.GetSignerManager()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to get signer manager from client")
	}

	if sm == nil {
		return nil, errors.New("Signer not specified")
	}

	signers := sm.List()
	if len(signers) == 0 {
		return nil, errors.WithMessage(err, "Account not configured in signer manager")
	}

	return signers[0], nil
}

func ConvertToGethLog(log *types.Log) *gethTypes.Log {
	if log == nil {
		return nil
	}

	return &gethTypes.Log{
		Address:     log.Address,
		Topics:      log.Topics,
		Data:        log.Data,
		BlockNumber: log.BlockNumber,
		TxHash:      log.TxHash,
		TxIndex:     log.TxIndex,
		BlockHash:   log.BlockHash,
		Index:       log.Index,
		Removed:     log.Removed,
	}
}
