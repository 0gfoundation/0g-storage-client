package kv

import (
	"context"
	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/openweb3/web3go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Batcher struct to cache and execute KV write and access control operations.
type Batcher struct {
	*streamDataBuilder
	kvClient *Client
	clients  *transfer.SelectedNodes
	w3Client *web3go.Client
	logger   *logrus.Logger
}

// NewBatcher Initialize a new batcher. Version denotes the expected version of keys to read or write when the cached KV operations is settled on chain.
func NewBatcher(version uint64, clients *transfer.SelectedNodes, w3Client *web3go.Client, opts ...zg_common.LogOption) *Batcher {
	return &Batcher{
		streamDataBuilder: newStreamDataBuilder(version),
		clients:           clients,
		w3Client:          w3Client,
		logger:            zg_common.NewLogger(opts...),
	}
}

// WithKVClient sets a KV client on the batcher to enable Get (read-your-own-writes with remote fallback).
func (b *Batcher) WithKVClient(kvClient *Client) *Batcher {
	b.kvClient = kvClient
	return b
}

// Get returns the value for a key. It first checks the local write cache (uncommitted Set calls),
// and falls back to querying the KV node using the batcher's version.
func (b *Batcher) Get(ctx context.Context, streamId common.Hash, key []byte) (*node.Value, error) {
	// Check local writes first
	if keys, ok := b.writes[streamId]; ok {
		if data, ok := keys[hexutil.Encode(key)]; ok {
			return &node.Value{
				Version: b.version,
				Data:    data,
				Size:    uint64(len(data)),
			}, nil
		}
	}

	// Fall back to KV node
	if b.kvClient == nil {
		return nil, errors.New("key not found locally and no KV client configured")
	}
	return b.kvClient.GetValue(ctx, streamId, key, b.version)
}

// Exec Serialize the cached KV operations in Batcher, then submit the serialized data to 0g storage network.
// The submission process is the same as uploading a normal file. The batcher should be dropped after execution.
// Note, this may be time consuming operation, e.g. several seconds or even longer.
// When it comes to a time sentitive context, it should be executed in a separate go-routine.
func (b *Batcher) Exec(ctx context.Context, option ...transfer.UploadOption) (common.Hash, error) {
	// build stream data
	streamData, err := b.Build()
	if err != nil {
		return common.Hash{}, errors.WithMessage(err, "Failed to build stream data")
	}

	encoded, err := streamData.Encode()
	logrus.WithFields(logrus.Fields{
		"version": streamData.Version,
		"data":    encoded,
	}).Debug("Built stream data")

	if err != nil {
		return common.Hash{}, errors.WithMessage(err, "Failed to encode data")
	}
	data, err := core.NewDataInMemory(encoded)
	if err != nil {
		return common.Hash{}, err
	}

	// upload file
	uploader, err := transfer.NewUploaderWithContractConfig(ctx, b.w3Client, b.clients, transfer.UploaderConfig{
		LogOption: zg_common.LogOption{Logger: b.logger},
	})
	if err != nil {
		return common.Hash{}, err
	}
	var opt transfer.UploadOption
	if len(option) > 0 {
		opt = option[0]
	}
	opt.Tags = b.buildTags()
	txHashes, _, err := uploader.SplitableUpload(ctx, data, 4*1024*1024*1024, opt)
	if err != nil {
		return common.Hash{}, errors.WithMessagef(err, "Failed to upload data")
	}
	var txHash common.Hash
	if len(txHashes) > 0 {
		txHash = txHashes[0]
	}
	return txHash, nil
}
