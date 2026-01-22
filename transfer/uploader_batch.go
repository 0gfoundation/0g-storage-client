package transfer

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/core/merkle"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/common"
	"github.com/openweb3/web3go/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// BatchUploadOption upload option for a batching
type BatchUploadOption struct {
	Submitter   common.Address // address of the transaction sender
	Fee         *big.Int       // fee in neuron
	Nonce       *big.Int       // nonce for transaction
	MaxGasPrice *big.Int       // max gas price for transaction
	NRetries    int            // number of retries for uploading
	Step        int64          // step for uploading
	TaskSize    uint           // number of files to upload simutanously
	Method      string         // method for selecting nodes, can be "max", "random" or certain positive number in string
	FullTrusted bool           // whether to use full trusted nodes
	DataOptions []UploadOption // upload option for single file, nonce and fee are ignored
	FastMode    bool           // skip waiting for receipt and upload segments by root (recommended for small files)
}

// BatchUpload submit multiple data to 0g storage contract batchly in single on-chain transaction, then transfer the data to the storage nodes.
// The nonce for upload transaction will be the first non-nil nonce in given upload options, the protocol fee is the sum of fees in upload options.
func (uploader *Uploader) BatchUpload(ctx context.Context, datas []core.IterableData, option ...BatchUploadOption) (common.Hash, []common.Hash, error) {
	stageTimer := time.Now()

	n := len(datas)
	if n == 0 {
		return common.Hash{}, nil, errors.New("empty datas")
	}
	var opts BatchUploadOption
	if len(option) > 0 {
		opts = option[0]
	} else {
		opts = BatchUploadOption{
			Fee:         nil,
			Nonce:       nil,
			DataOptions: make([]UploadOption, n),
			Method:      "min",
			FullTrusted: true,
		}
	}
	if opts.Submitter == (common.Address{}) {
		submitter, err := uploader.flow.GetSubmitterAddress()
		if err != nil {
			return common.Hash{}, nil, errors.WithMessage(err, "Failed to get submitter address from flow contract")
		}
		opts.Submitter = submitter
	}
	opts.TaskSize = max(opts.TaskSize, 1)
	if len(opts.DataOptions) != n {
		return common.Hash{}, nil, errors.New("datas and tags length mismatch")
	}

	uploader.logger.WithFields(logrus.Fields{
		"dataNum": n,
	}).Info("Prepare to upload batchly")

	trees := make([]*merkle.Tree, n)
	toSubmitDatas := make([]core.IterableData, 0)
	toSubmitTags := make([][]byte, 0)
	dataRoots := make([]common.Hash, n)
	var lastTreeToSubmit *merkle.Tree

	var wg sync.WaitGroup
	errs := make(chan error, opts.TaskSize)
	fileInfos := make([]*node.FileInfo, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			data := datas[i]
			uploader.logger.WithFields(logrus.Fields{
				"size":     data.Size(),
				"chunks":   data.NumChunks(),
				"segments": data.NumSegments(),
			}).Info("Data prepared to upload")

			// Calculate file merkle root.
			tree, err := core.MerkleTree(data)
			if err != nil {
				errs <- errors.WithMessage(err, "Failed to create data merkle tree")
				return
			}
			uploader.logger.WithField("root", tree.Root()).Info("Data merkle root calculated")
			trees[i] = tree
			dataRoots[i] = trees[i].Root()

			// Check existence
			info, err := checkLogExistence(ctx, uploader.clients, trees[i].Root())
			if err != nil {
				errs <- errors.WithMessage(err, "Failed to check if skipped log entry available on storage node")
				return
			}
			fileInfos[i] = info
		}(i)
		if (i+1)%int(opts.TaskSize) == 0 || i == n-1 {
			wg.Wait()
			close(errs)
			for e := range errs {
				if e != nil {
					return common.Hash{}, nil, e
				}
			}
			errs = make(chan error, opts.TaskSize)
		}
	}
	for i := 0; i < n; i += 1 {
		opt := opts.DataOptions[i]
		if !opt.SkipTx || fileInfos[i] == nil {
			toSubmitDatas = append(toSubmitDatas, datas[i])
			toSubmitTags = append(toSubmitTags, opt.Tags)
			lastTreeToSubmit = trees[i]
		}
	}

	// Append log on blockchain
	var txHash common.Hash
	var receipt *types.Receipt
	rootSeqMap := make(map[common.Hash]uint64)

	if len(toSubmitDatas) > 0 {
		waitReceipt := !opts.FastMode
		receiptFlag := waitReceipt
		submitOpt := SubmitLogEntryOption{
			Submitter:   opts.Submitter,
			Fee:         opts.Fee,
			Nonce:       opts.Nonce,
			MaxGasPrice: opts.MaxGasPrice,
			NRetries:    opts.NRetries,
			Step:        opts.Step,
			WaitReceipt: &receiptFlag,
		}
		var err error
		if txHash, receipt, err = uploader.SubmitLogEntry(ctx, toSubmitDatas, toSubmitTags, submitOpt); err != nil {
			return txHash, nil, errors.WithMessage(err, "Failed to submit log entry")
		}
		if waitReceipt {
			seqNums, err := uploader.ParseLogs(ctx, receipt.Logs)
			if err != nil {
				return txHash, nil, errors.WithMessage(err, "Failed to parse logs")
			}
			// Wait for storage node to retrieve log entry from blockchain
			if len(seqNums) != len(toSubmitDatas) {
				return txHash, nil, errors.New("log entry event count mismatch")
			}

			logIndex := 0
			for i := 0; i < n; i += 1 {
				opt := opts.DataOptions[i]
				if !opt.SkipTx || fileInfos[i] == nil {
					rootSeqMap[trees[i].Root()] = seqNums[logIndex]
					logIndex += 1
				}
			}

			if logIndex != len(seqNums) {
				return txHash, nil, errors.New("log entry event count mismatch after mapping to data")
			}

			if _, err := uploader.waitForLogEntry(ctx, lastTreeToSubmit.Root(), TransactionPacked, rootSeqMap[lastTreeToSubmit.Root()], true); err != nil {
				return txHash, nil, errors.WithMessage(err, "Failed to check if log entry available on storage node")
			}
		}
	}

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			info := fileInfos[i]
			fastMode := opts.FastMode && datas[i].Size() <= fastUploadMaxSize
			if opts.FastMode && !fastMode {
				uploader.logger.WithField("size", datas[i].Size()).Info("Fast mode disabled for data size over limit")
			}

			if fastMode && info == nil {
				if err := uploader.uploadFileByRoot(ctx, datas[i], trees[i], opts.DataOptions[i].ExpectedReplica, opts.DataOptions[i].TaskSize, opts.DataOptions[i].Method); err != nil {
					errs <- errors.WithMessage(err, "Failed to upload file")
					return
				}
				errs <- nil
				return
			}

			if info == nil {
				var err error
				info, err = uploader.waitForLogEntry(ctx, trees[i].Root(), TransactionPacked, rootSeqMap[trees[i].Root()], true)
				if err != nil {
					errs <- errors.WithMessage(err, "Failed to get file info from storage node")
					return
				}
			}

			// Upload file to storage node
			if err := uploader.uploadFile(ctx, info, datas[i], trees[i], opts.DataOptions[i].ExpectedReplica, opts.DataOptions[i].TaskSize, opts.DataOptions[i].Method); err != nil {
				errs <- errors.WithMessage(err, "Failed to upload file")
				return
			}

			if !fastMode {
				// Wait for transaction finality
				if _, err := uploader.waitForLogEntry(ctx, trees[i].Root(), opts.DataOptions[i].FinalityRequired, info.Tx.Seq, true); err != nil {
					errs <- errors.WithMessage(err, "Failed to wait for transaction finality on storage node")
					return
				}
			}
			errs <- nil
		}(i)
		if (i+1)%int(opts.TaskSize) == 0 || i == n-1 {
			wg.Wait()
			close(errs)
			for e := range errs {
				if e != nil {
					return txHash, nil, e
				}
			}
			errs = make(chan error, opts.TaskSize)
		}
	}

	uploader.logger.WithField("duration", time.Since(stageTimer)).Info("batch upload took")

	return txHash, dataRoots, nil
}
