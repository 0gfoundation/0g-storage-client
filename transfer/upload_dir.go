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

func (uploader *Uploader) UploadDir(ctx context.Context, folder string, option ...UploadOption) (txnHash, rootHash common.Hash, _ error) {
	// Build the file tree representation of the directory.
	root, err := dir.BuildFileTree(folder)
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to build file tree")
	}

	tdata, err := root.MarshalBinary()
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to encode file tree")
	}

	// Create an in-memory data object from the encoded file tree.
	iterdata, err := core.NewDataInMemory(tdata)
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to create `IterableData` in memory")
	}

	// Generate the Merkle tree from the in-memory data.
	mtree, err := core.MerkleTree(iterdata)
	if err != nil {
		return txnHash, rootHash, errors.WithMessage(err, "failed to create merkle tree")
	}
	rootHash = mtree.Root()

	// Flattening the file tree to get the list of files and their relative paths.
	_, relPaths := root.Flatten(func(n *dir.FsNode) bool {
		return n.Type == dir.FileTypeFile && n.Size > 0
	})

	logrus.Infof("Total %d files to be uploaded", len(relPaths))

	// Upload each file to the storage network.
	for i := range relPaths {
		path := filepath.Join(folder, relPaths[i])
		txhash, _, err := uploader.UploadFile(ctx, path, option...)
		if err != nil {
			return txnHash, rootHash, errors.WithMessagef(err, "failed to upload file %s", path)
		}

		logrus.WithFields(logrus.Fields{
			"txnHash": txhash,
			"path":    path,
		}).Info("File uploaded successfully")
	}

	// Finally, upload the directory metadata
	txnHash, _, err = uploader.Upload(ctx, iterdata, option...)
	if err != nil {
		err = errors.WithMessage(err, "failed to upload directory metadata")
	}

	return txnHash, rootHash, err
}
