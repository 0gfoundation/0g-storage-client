package transfer

import (
	"context"
	"path/filepath"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/transfer/dir"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (uploader *Uploader) UploadDir(ctx context.Context, folder string, fragmentSize int64, option ...UploadOption) (txnHash, rootHash common.Hash, _ error) {
	var opt UploadOption
	if len(option) > 0 {
		opt = option[0]
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

	// Upload each file via SplitableUpload (handles encryption + splitting).
	for i := range nodes {
		path := filepath.Join(folder, relPaths[i])
		file, err := core.Open(path)
		if err != nil {
			return txnHash, rootHash, errors.WithMessagef(err, "failed to open file %s", path)
		}

		_, roots, err := uploader.SplitableUpload(ctx, file, fragmentSize, opt)
		file.Close()
		if err != nil {
			return txnHash, rootHash, errors.WithMessagef(err, "failed to upload file %s", path)
		}

		// Populate the file node with actual root hashes from the upload.
		rootStrs := make([]string, len(roots))
		for j, r := range roots {
			rootStrs[j] = r.Hex()
		}
		nodes[i].Roots = rootStrs

		uploader.logger.WithFields(logrus.Fields{
			"roots": rootStrs,
			"path":  path,
		}).Info("File uploaded successfully")
	}

	// Serialize the updated file tree (now with roots populated).
	tdata, err := root.MarshalBinary()
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to encode file tree")
	}

	iterdata, err := core.NewDataInMemory(tdata)
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to create `IterableData` in memory")
	}

	// Upload the directory metadata via SplitableUpload.
	txHashes, metaRoots, err := uploader.SplitableUpload(ctx, iterdata, fragmentSize, opt)
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
