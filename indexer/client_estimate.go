package indexer

import (
	"context"
	"math/big"

	"github.com/0gfoundation/0g-storage-client/contract"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/openweb3/web3go"
	"github.com/pkg/errors"
)

// EstimateFee computes the on-chain protocol fee (in wei) that an upload
// of `data` with `tags` would charge.
//
// Cheaper than going through Uploader.EstimateFee: the latter requires
// NewUploaderFromIndexerNodes (an indexer RPC + storage-node selection)
// even though node selection has nothing to do with the fee. This path
// only needs the market contract's pricePerSector.
//
//	fee = pricePerSector * numSectors(data, tags)
//
// numSectors is a pure off-chain computation derived from data size and
// tags length. pricePerSector is one eth_call per invocation — cheap and
// in practice never changes (governance-gated FixedPrice.setPricePerSector
// in 0g-storage-contracts). Callers that estimate fees on a hot path
// should layer their own cache.
func (c *Client) EstimateFee(ctx context.Context, w3Client *web3go.Client, marketAddr eth_common.Address, data core.IterableData, tags []byte) (*big.Int, error) {
	flow := core.NewFlow(data, tags)
	submission, err := flow.CreateSubmission(eth_common.Address{})
	if err != nil {
		return nil, errors.WithMessage(err, "create flow submission")
	}

	backend, _ := w3Client.ToClientForContract()
	market, err := contract.NewMarket(marketAddr, backend)
	if err != nil {
		return nil, errors.WithMessage(err, "NewMarket")
	}
	pricePerSector, err := market.PricePerSector(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, errors.WithMessage(err, "PricePerSector")
	}

	return submission.Fee(pricePerSector), nil
}

// EstimateFeeFromUploader is provided as a fallback for callers that
// already have an Uploader instance (e.g. they're about to upload and
// want a final pre-flight check). Equivalent to Uploader.EstimateFee.
func EstimateFeeFromUploader(ctx context.Context, uploader *transfer.Uploader, data core.IterableData, tags []byte) (*big.Int, error) {
	return uploader.EstimateFee(ctx, data, tags)
}
