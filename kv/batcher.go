package kv

import (
	"context"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/openweb3/web3go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Batcher struct to cache and execute KV write and access control operations.
type Batcher struct {
	*streamDataBuilder
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
	txHash, _, err := uploader.Upload(ctx, data, opt)
	if err != nil {
		return txHash, errors.WithMessagef(err, "Failed to upload data")
	}
	return txHash, nil
}
