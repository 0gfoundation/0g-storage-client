package transfer

import (
	"context"
	"math"
	"math/big"
	"path/filepath"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/transfer/dir"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (uploader *Uploader) UploadDir(ctx context.Context, folder string, option ...UploadOption) (txnHash, rootHash common.Hash, _ error) {
	var opt UploadOption
	if len(option) > 0 {
		opt = option[0]
	}
	normalizeUploadOption(&opt)

	// Align fragment size to power of 2, same as SplitableUpload.
	fragmentSize := opt.FragmentSize
	if fragmentSize < core.DefaultChunkSize {
		fragmentSize = core.DefaultChunkSize
	}
	aligned := core.NextPow2(uint64(fragmentSize))
	if aligned > uint64(math.MaxInt64) {
		fragmentSize = math.MaxInt64
	} else {
		fragmentSize = int64(aligned)
	}

	// Build the file tree representation of the directory (roots are empty at this point).
	root, err := dir.BuildFileTree(folder)
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to build file tree")
	}

	// Flatten to get file nodes and their relative paths.
	nodes, relPaths := root.Flatten(func(n *dir.FsNode) bool {
		return n.Type == dir.FileTypeFile && n.Size > 0
	})

	uploader.logger.Infof("Total %d files to be uploaded", len(nodes))

	// pendingDatas/Nodes/Closers accumulate small files for a single BatchUpload call.
	pendingDatas := make([]core.IterableData, 0, opt.BatchSize)
	pendingNodes := make([]*dir.FsNode, 0, opt.BatchSize)
	pendingClosers := make([]func() error, 0, opt.BatchSize)

	closeAll := func() {
		for _, close := range pendingClosers {
			close() //nolint:errcheck
		}
		pendingDatas = pendingDatas[:0]
		pendingNodes = pendingNodes[:0]
		pendingClosers = pendingClosers[:0]
	}

	// flushBatch submits all accumulated small files in a single on-chain transaction.
	flushBatch := func() error {
		if len(pendingDatas) == 0 {
			return nil
		}
		defer closeAll()

		dataOptions := make([]UploadOption, len(pendingDatas))
		for i := range dataOptions {
			dataOptions[i] = opt
		}
		batchOpt := BatchUploadOption{
			TransactionOption: opt.TransactionOption,
			DataOptions:       dataOptions,
			Method:            opt.Method,
			FullTrusted:       opt.FullTrusted,
			TaskSize:          opt.TaskSize,
		}

		_, roots, err := uploader.BatchUpload(ctx, pendingDatas, batchOpt)
		if err != nil {
			return err
		}

		for i, node := range pendingNodes {
			node.Roots = []string{roots[i].Hex()}
			uploader.logger.WithFields(logrus.Fields{
				"root": roots[i].Hex(),
			}).Info("File uploaded successfully")
		}
		return nil
	}

	for i := range nodes {
		path := filepath.Join(folder, relPaths[i])

		file, err := core.Open(path)
		if err != nil {
			closeAll()
			return txnHash, rootHash, errors.WithMessagef(err, "failed to open file %s", path)
		}

		// Wrap encryption upfront for all files uniformly, before any split decision.
		// wrapEncryption is a no-op when no key is set, and lazy (no data read) when it is.
		encData, err := uploader.wrapEncryption(file, opt)
		if err != nil {
			file.Close()
			closeAll()
			return txnHash, rootHash, errors.WithMessagef(err, "failed to wrap encryption for %s", path)
		}

		if encData.Size() <= fragmentSize {
			// Small file: accumulate for batch upload.
			// File handle stays open until flushBatch completes since reads are lazy.
			pendingDatas = append(pendingDatas, encData)
			pendingNodes = append(pendingNodes, nodes[i])
			pendingClosers = append(pendingClosers, file.Close)

			if uint(len(pendingDatas)) >= opt.BatchSize {
				if err := flushBatch(); err != nil {
					return txnHash, rootHash, errors.WithMessage(err, "failed to batch upload")
				}
			}
		} else {
			// Large file: flush pending small-file batch first, then split and upload.
			if err := flushBatch(); err != nil {
				file.Close()
				return txnHash, rootHash, errors.WithMessage(err, "failed to batch upload")
			}

			rootStrs, err := uploader.uploadFragments(ctx, encData, fragmentSize, opt)
			file.Close()
			if err != nil {
				return txnHash, rootHash, errors.WithMessagef(err, "failed to upload file %s", path)
			}

			nodes[i].Roots = rootStrs
			uploader.logger.WithFields(logrus.Fields{
				"roots": rootStrs,
				"path":  path,
			}).Info("File uploaded successfully")
		}
	}

	// Flush any remaining small files that didn't fill a complete batch.
	if err := flushBatch(); err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to batch upload remaining files")
	}

	// Serialize the updated file tree (now with all roots populated).
	tdata, err := root.MarshalBinary()
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to encode file tree")
	}

	iterdata, err := core.NewDataInMemory(tdata)
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to create `IterableData` in memory")
	}

	// Upload the directory metadata blob.
	txHashes, metaRoots, err := uploader.SplitableUpload(ctx, iterdata, opt)
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to upload directory metadata")
	}

	if len(txHashes) > 0 {
		txnHash = txHashes[0]
	}
	if len(metaRoots) > 0 {
		rootHash = metaRoots[0]
	}

	return txnHash, rootHash, nil
}

// uploadFragments splits an already-encrypted large file into fragments and submits them
// in windows of BatchSize fragments per transaction, mirroring SplitableUpload's fragment path.
func (uploader *Uploader) uploadFragments(ctx context.Context, data core.IterableData, fragmentSize int64, opt UploadOption) ([]string, error) {
	fragments := data.Split(fragmentSize)
	uploader.logger.Infof("Split large file into %d fragments", len(fragments))

	totalSize := data.Size()
	rootStrs := make([]string, 0, len(fragments))

	for l := 0; l < len(fragments); l += int(opt.BatchSize) {
		r := min(l+int(opt.BatchSize), len(fragments))

		txOpt := opt.TransactionOption
		txOpt.Nonce = nil // let each batch auto-assign nonce
		if txOpt.Fee != nil {
			// Apportion fee proportionally to this batch's share of total data.
			var batchSize int64
			for j := l; j < r; j++ {
				batchSize += fragments[j].Size()
			}
			txOpt.Fee = new(big.Int).Div(
				new(big.Int).Mul(opt.Fee, big.NewInt(batchSize)),
				big.NewInt(totalSize),
			)
		}

		dataOptions := make([]UploadOption, r-l)
		for j := range dataOptions {
			dataOptions[j] = opt
		}
		batchOpt := BatchUploadOption{
			TransactionOption: txOpt,
			DataOptions:       dataOptions,
			Method:            opt.Method,
			FullTrusted:       opt.FullTrusted,
			TaskSize:          opt.TaskSize,
		}

		_, roots, err := uploader.BatchUpload(ctx, fragments[l:r], batchOpt)
		if err != nil {
			return nil, err
		}
		for _, root := range roots {
			rootStrs = append(rootStrs, root.Hex())
		}
	}

	return rootStrs, nil
}
