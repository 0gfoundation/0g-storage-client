package contract

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/openweb3/web3go"
	"github.com/openweb3/web3go/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type FlowContract struct {
	*blockchain.Contract
	*Flow
	clientWithSigner *web3go.Client
}

type TxRetryOption struct {
	Timeout          time.Duration
	MaxNonGasRetries int
	MaxGasPrice      *big.Int
	Step             int64
}

var SpecifiedBlockError = "Specified block header does not exist"
var DefaultTimeout = 15 * time.Minute
var DefaultMaxNonGasRetries = 20
var DefaultStep = int64(15)

func IsRetriableSubmitLogEntryError(msg string) bool {
	return strings.Contains(msg, SpecifiedBlockError) || strings.Contains(msg, "mempool") || strings.Contains(msg, "timeout")
}

func NewFlowContract(flowAddress common.Address, clientWithSigner *web3go.Client) (*FlowContract, error) {
	backend, signer := clientWithSigner.ToClientForContract()

	contract, err := blockchain.NewContract(clientWithSigner, signer)
	if err != nil {
		return nil, err
	}

	flow, err := NewFlow(flowAddress, backend)
	if err != nil {
		return nil, err
	}

	return &FlowContract{contract, flow, clientWithSigner}, nil
}

func (f *FlowContract) GetSubmitterAddress() (common.Address, error) {
	sm, err := f.clientWithSigner.GetSignerManager()
	if err != nil {
		return common.Address{}, err
	}
	return sm.List()[0].Address(), nil
}

func (f *FlowContract) GetNonce(ctx context.Context) (*big.Int, error) {
	sm, err := f.clientWithSigner.GetSignerManager()
	if err != nil {
		return nil, err
	}

	addr := sm.List()[0].Address()

	pending := types.BlockNumberOrHashWithNumber(types.PendingBlockNumber)
	nonce, err := f.clientWithSigner.Eth.TransactionCount(addr, &pending)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func (f *FlowContract) GetGasPrice() (*big.Int, error) {
	gasPrice, err := f.clientWithSigner.Eth.GasPrice()
	if err != nil {
		return nil, err
	}

	return gasPrice, nil
}

func (f *FlowContract) GetMarketContract(ctx context.Context) (*Market, error) {
	marketAddr, err := f.Market(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, err
	}

	backend, _ := f.clientWithSigner.ToClientForContract()

	market, err := NewMarket(marketAddr, backend)
	if err != nil {
		return nil, err
	}

	return market, nil
}

func (submission Submission) String() string {
	var heights []uint64
	for _, v := range submission.Data.Nodes {
		heights = append(heights, v.Height.Uint64())
	}

	return fmt.Sprintf("{ Size: %v, Heights: %v }", submission.Data.Length, heights)
}

func (submission Submission) Root() common.Hash {
	numNodes := len(submission.Data.Nodes)

	// should be never occur
	if numNodes == 0 {
		return common.Hash{}
	}

	// calculate root in reverse order
	root := submission.Data.Nodes[numNodes-1].Root
	for i := 1; i < numNodes; i++ {
		left := submission.Data.Nodes[numNodes-1-i]
		root = crypto.Keccak256Hash(left.Root[:], root[:])
	}

	return root
}

func TransactWithGasAdjustment(
	contract *FlowContract,
	method string,
	opts *bind.TransactOpts,
	retryOpts *TxRetryOption,
	params ...any,
) (*types.Receipt, error) {
	// Set timeout and max non-gas retries from retryOpts if provided.
	if retryOpts == nil {
		retryOpts = &TxRetryOption{
			MaxNonGasRetries: DefaultMaxNonGasRetries,
		}
	}

	if retryOpts.MaxNonGasRetries == 0 {
		retryOpts.MaxNonGasRetries = DefaultMaxNonGasRetries
	}

	if retryOpts.Step == 0 {
		retryOpts.Step = DefaultStep
	}

	if t, ok := opts.Context.Deadline(); ok {
		retryOpts.Timeout = time.Until(t)
	}

	if opts.Nonce == nil {
		// Get the current nonce if not set.
		nonce, err := contract.GetNonce(opts.Context)
		if err != nil {
			return nil, err
		}
		// add one to the nonce
		opts.Nonce = nonce
	}

	if opts.GasPrice == nil {
		// Get the current gas price if not set.
		gasPrice, err := contract.GetGasPrice()
		if err != nil {
			return nil, errors.WithMessage(err, "failed to get gas price")
		}
		opts.GasPrice = gasPrice
		logrus.WithField("gasPrice", opts.GasPrice).Debug("Receive current gas price from chain node")
	}

	logrus.WithFields(logrus.Fields{
		"timeout":          retryOpts.Timeout,
		"maxNonGasRetries": retryOpts.MaxNonGasRetries,
		"nonce":            opts.Nonce,
		"gasPrice":         opts.GasPrice,
	}).Info("Set tx params")

	receiptCh := make(chan *types.Receipt, 1)
	errCh := make(chan error, 1)
	failCh := make(chan error, 1)

	var ctx context.Context
	var cancel context.CancelFunc
	if retryOpts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), retryOpts.Timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}

	// calculate number of gas retry by dividing max gas price by current gas price and the ration
	nGasRetry := 0
	if retryOpts.MaxGasPrice != nil {
		gasPrice := opts.GasPrice
		for gasPrice.Cmp(retryOpts.MaxGasPrice) <= 0 {
			gasPrice = new(big.Int).Mul(gasPrice, big.NewInt(retryOpts.Step))
			gasPrice.Div(gasPrice, big.NewInt(10))
			nGasRetry++
		}
	}

	go func() {
		nRetries := 0
		for {
			select {
			case <-ctx.Done():
				// main or another goroutine canceled the context
				logrus.Info("Context canceled; stopping outer loop")
				return
			default:
			}
			tx, err := contract.FlowTransactor.contract.Transact(opts, method, params...)

			var receipt *types.Receipt
			if err == nil {
				// Wait for successful execution
				go func() {
					receipt, err = contract.WaitForReceipt(ctx, tx.Hash(), true, blockchain.RetryOption{NRetries: retryOpts.MaxNonGasRetries})
					if err == nil {
						receiptCh <- receipt
						return
					}
					errCh <- err
				}()
				// even if the receipt is received, this loop will continue until the context is canceled
				time.Sleep(30 * time.Second)
				err = fmt.Errorf("timeout")
			}

			errStr := strings.ToLower(err.Error())

			if !IsRetriableSubmitLogEntryError(errStr) {
				if strings.Contains(errStr, "invalid nonce") {
					return
				}
				failCh <- errors.WithMessage(err, "failed to send transaction")
				return
			}

			// If the error is due to mempool full or timeout, retry with a higher gas price
			if strings.Contains(errStr, "mempool") || strings.Contains(errStr, "timeout") {
				if retryOpts.MaxGasPrice == nil {
					failCh <- errors.WithMessage(err, "mempool full and no max gas price is set, failed to send transaction")
					return
				} else if opts.GasPrice.Cmp(retryOpts.MaxGasPrice) >= 0 {
					return
				} else {
					newGasPrice := new(big.Int).Mul(opts.GasPrice, big.NewInt(retryOpts.Step))
					newGasPrice.Div(newGasPrice, big.NewInt(10))
					if newGasPrice.Cmp(retryOpts.MaxGasPrice) > 0 {
						opts.GasPrice = new(big.Int).Set(retryOpts.MaxGasPrice)
					} else {
						opts.GasPrice = newGasPrice
					}
					logrus.WithError(err).Infof("Increasing gas price to %v due to mempool/timeout error", opts.GasPrice)
				}
			} else {
				nRetries++
				if nRetries >= retryOpts.MaxNonGasRetries {
					failCh <- errors.WithMessage(err, "failed to send transaction")
					return
				}
				logrus.WithError(err).Infof("Retrying with same gas price %v, attempt %d", opts.GasPrice, nRetries)
			}
		}
	}()

	nErr := 0
	for {
		select {
		case receipt := <-receiptCh:
			cancel()

			return receipt, nil
		case err := <-errCh:
			nErr++
			if nErr >= nGasRetry {
				failCh <- errors.WithMessage(err, "All gas price retries failed")
				cancel()
				return nil, err
			}
		case err := <-failCh:
			cancel()
			return nil, err
		}
	}
}

func TransactWithGasAdjustmentNoReceipt(
	contract *FlowContract,
	method string,
	opts *bind.TransactOpts,
	retryOpts *TxRetryOption,
	params ...any,
) (*types.Transaction, error) {
	// Set timeout and max non-gas retries from retryOpts if provided.
	if retryOpts == nil {
		retryOpts = &TxRetryOption{
			MaxNonGasRetries: DefaultMaxNonGasRetries,
		}
	}

	if retryOpts.MaxNonGasRetries == 0 {
		retryOpts.MaxNonGasRetries = DefaultMaxNonGasRetries
	}

	if retryOpts.Step == 0 {
		retryOpts.Step = DefaultStep
	}

	if t, ok := opts.Context.Deadline(); ok {
		retryOpts.Timeout = time.Until(t)
	}

	logrus.WithFields(logrus.Fields{
		"timeout":          retryOpts.Timeout,
		"maxNonGasRetries": retryOpts.MaxNonGasRetries,
		"nonce":            opts.Nonce,
		"gasPrice":         opts.GasPrice,
	}).Info("Set tx params")

	nRetries := 0
	for {
		if retryOpts.Timeout > 0 && opts.Context != nil && opts.Context.Err() != nil {
			return nil, errors.WithMessage(opts.Context.Err(), "transaction submission canceled")
		}

		tx, err := contract.FlowTransactor.contract.Transact(opts, method, params...)
		if err == nil {
			return tx, nil
		}

		errStr := strings.ToLower(err.Error())

		if !IsRetriableSubmitLogEntryError(errStr) {
			if strings.Contains(errStr, "invalid nonce") {
				return nil, err
			}
			return nil, errors.WithMessage(err, "failed to send transaction")
		}

		// If the error is due to mempool full or timeout, retry with a higher gas price
		if strings.Contains(errStr, "mempool") || strings.Contains(errStr, "timeout") {
			if retryOpts.MaxGasPrice == nil {
				return nil, errors.WithMessage(err, "mempool full and no max gas price is set, failed to send transaction")
			} else if opts.GasPrice.Cmp(retryOpts.MaxGasPrice) >= 0 {
				return nil, errors.WithMessage(err, "reached max gas price, failed to send transaction")
			} else {
				newGasPrice := new(big.Int).Mul(opts.GasPrice, big.NewInt(retryOpts.Step))
				newGasPrice.Div(newGasPrice, big.NewInt(10))
				if newGasPrice.Cmp(retryOpts.MaxGasPrice) > 0 {
					opts.GasPrice = new(big.Int).Set(retryOpts.MaxGasPrice)
				} else {
					opts.GasPrice = newGasPrice
				}
				logrus.WithError(err).Infof("Increasing gas price to %v due to mempool/timeout error", opts.GasPrice)
			}
		} else {
			nRetries++
			if nRetries >= retryOpts.MaxNonGasRetries {
				return nil, errors.WithMessage(err, "failed to send transaction")
			}
			logrus.WithError(err).Infof("Retrying with same gas price %v, attempt %d", opts.GasPrice, nRetries)
		}
	}
}

func (submission Submission) Fee(pricePerSector *big.Int) *big.Int {
	var sectors int64
	for _, node := range submission.Data.Nodes {
		sectors += 1 << node.Height.Int64()
	}

	return big.NewInt(0).Mul(big.NewInt(sectors), pricePerSector)
}
