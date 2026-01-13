package blockchain

import (
	"context"
	"time"

	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/ethereum/go-ethereum/common"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/mcuadros/go-defaults"
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

		if receipt.TxExecErrorMsg == nil {
			return nil, errors.New("Transaction execution failed")
		}

		return nil, errors.Errorf("Transaction execution failed, %v", *receipt.TxExecErrorMsg)
	default:
		return nil, errors.Errorf("Unknown receipt status %v", *receipt.Status)
	}
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
