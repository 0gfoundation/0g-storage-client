package indexer

import (
	"context"
	"math/big"
	"time"

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
// only needs the market contract's pricePerSector, which we cache.
//
// fee = pricePerSector * numSectors(data, tags)
//
// numSectors is a pure off-chain computation derived from data size and
// tags length. pricePerSector is read from the market contract at most
// once per cacheTTL — by default 30s, configurable via
// (*Client).SetEstimateCacheTTL.
func (c *Client) EstimateFee(ctx context.Context, w3Client *web3go.Client, marketAddr eth_common.Address, data core.IterableData, tags []byte) (*big.Int, error) {
	flow := core.NewFlow(data, tags)
	submission, err := flow.CreateSubmission(eth_common.Address{})
	if err != nil {
		return nil, errors.WithMessage(err, "create flow submission")
	}

	pricePerSector, err := c.cachedPricePerSector(ctx, w3Client, marketAddr)
	if err != nil {
		return nil, err
	}

	return submission.Fee(pricePerSector), nil
}

// SetEstimateCacheTTL configures how long EstimateFee caches the
// market-contract pricePerSector read. Default 30s. Pass 0 to disable
// caching (re-read on every call).
func (c *Client) SetEstimateCacheTTL(d time.Duration) {
	c.estimateMu.Lock()
	defer c.estimateMu.Unlock()
	c.estimateTTL = d
}

func (c *Client) cachedPricePerSector(ctx context.Context, w3Client *web3go.Client, marketAddr eth_common.Address) (*big.Int, error) {
	c.estimateMu.Lock()
	ttl := c.estimateTTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	if c.estimatePrice != nil && time.Since(c.estimateLoaded) < ttl {
		price := new(big.Int).Set(c.estimatePrice)
		c.estimateMu.Unlock()
		return price, nil
	}
	c.estimateMu.Unlock()

	// Cache miss / expired — read from chain. Done outside the lock so
	// concurrent callers don't serialize on the RPC.
	backend, _ := w3Client.ToClientForContract()
	market, err := contract.NewMarket(marketAddr, backend)
	if err != nil {
		return nil, errors.WithMessage(err, "NewMarket")
	}
	price, err := market.PricePerSector(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, errors.WithMessage(err, "PricePerSector")
	}

	c.estimateMu.Lock()
	c.estimatePrice = new(big.Int).Set(price)
	c.estimateLoaded = time.Now()
	c.estimateMu.Unlock()

	return price, nil
}

// EstimateFeeFromUploader is provided as a fallback for callers that
// already have an Uploader instance (e.g. they're about to upload and
// want a final pre-flight check). Equivalent to Uploader.EstimateFee.
func EstimateFeeFromUploader(ctx context.Context, uploader *transfer.Uploader, data core.IterableData, tags []byte) (*big.Int, error) {
	return uploader.EstimateFee(ctx, data, tags)
}
