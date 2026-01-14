package transfer

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer/download"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	_ IDownloader = (*Downloader)(nil)

	ErrFileAlreadyExists = errors.New("File already exists")
)

type IDownloader interface {
	Download(ctx context.Context, root, filename string, withProof bool) error
	DownloadFragments(ctx context.Context, roots []string, filename string, withProof bool) error
}

// Downloader downloader to download file to storage nodes
type Downloader struct {
	clients []*node.ZgsClient

	routines int

	logger *logrus.Logger
}

// NewDownloader Initialize a new downloader.
func NewDownloader(clients []*node.ZgsClient, opts ...zg_common.LogOption) (*Downloader, error) {
	if len(clients) == 0 {
		return nil, errors.New("storage node not specified")
	}
	downloader := &Downloader{
		clients: clients,
		logger:  zg_common.NewLogger(opts...),
	}
	downloader.routines = runtime.GOMAXPROCS(0)
	return downloader, nil
}

func (downloader *Downloader) WithRoutines(routines int) *Downloader {
	downloader.routines = routines
	return downloader
}

func (downloader *Downloader) DownloadFragments(ctx context.Context, roots []string, filename string, withProof bool) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to create output file")
	}
	defer outFile.Close()

	for _, root := range roots {
		tempFile := fmt.Sprintf("%v.temp", root)
		err := downloader.Download(ctx, root, tempFile, withProof)
		if err != nil {
			return errors.WithMessage(err, "Failed to download file")
		}
		inFile, err := os.Open(tempFile)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to open file %s", tempFile))
		}
		_, err = io.Copy(outFile, inFile)
		inFile.Close()
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to copy content from temp file %s", tempFile))
		}

		err = os.Remove(tempFile)
		if err != nil {
			return errors.WithMessage(err, fmt.Sprintf("failed to delete temp file %s:", tempFile))
		}
	}

	return nil
}

// Download download data from storage nodes.
func (downloader *Downloader) Download(ctx context.Context, root, filename string, withProof bool) error {
	hash := common.HexToHash(root)

	// Query file info from storage node
	info, err := downloader.queryFile(ctx, hash)
	if err != nil {
		return errors.WithMessage(err, "Failed to query file info")
	}

	// Check file existence before downloading
	if err = downloader.checkExistence(filename, hash); err != nil {
		return errors.WithMessage(err, "Failed to check file existence")
	}

	// Download segments
	if err = downloader.downloadFile(ctx, filename, hash, info, withProof); err != nil {
		return errors.WithMessage(err, "Failed to download file")
	}

	// Validate the downloaded file
	if err = downloader.validateDownloadFile(root, filename, int64(info.Tx.Size)); err != nil {
		return errors.WithMessage(err, "Failed to validate downloaded file")
	}

	return nil
}

func (downloader *Downloader) queryFile(ctx context.Context, root common.Hash) (info *node.FileInfo, err error) {
	// do not require file finalized
	for _, v := range downloader.clients {
		info, err = v.GetFileInfo(ctx, root, true)
		if err != nil {
			return nil, err
		}

		if info == nil {
			return nil, fmt.Errorf("file not found on node %v", v.URL())
		}
	}

	downloader.logger.WithField("file", info).Debug("File found by root hash")

	return
}

func (downloader *Downloader) checkExistence(filename string, hash common.Hash) error {
	file, err := core.Open(filename)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return errors.WithMessage(err, "Failed to open file")
	}

	defer file.Close()

	tree, err := core.MerkleTree(file)
	if err != nil {
		return errors.WithMessage(err, "Failed to create file merkle tree")
	}

	if tree.Root().Hex() == hash.Hex() {
		return ErrFileAlreadyExists
	}

	return errors.New("File already exists with different hash")
}

func (downloader *Downloader) downloadFile(ctx context.Context, filename string, root common.Hash, info *node.FileInfo, withProof bool) error {
	file, err := download.CreateDownloadingFile(filename, root, int64(info.Tx.Size))
	if err != nil {
		return errors.WithMessage(err, "Failed to create downloading file")
	}
	defer file.Close()

	downloader.logger.WithField("num nodes", len(downloader.clients)).Info("Begin to download file from storage nodes")

	sd, err := newSegmentDownloader(downloader, info, file, withProof)
	if err != nil {
		return errors.WithMessage(err, "Failed to create segment downloader")
	}

	if err = sd.Download(ctx); err != nil {
		return errors.WithMessage(err, "Failed to download file")
	}

	if err := file.Seal(); err != nil {
		return errors.WithMessage(err, "Failed to seal downloading file")
	}

	downloader.logger.Info("Completed to download file")

	return nil
}

func (downloader *Downloader) validateDownloadFile(root, filename string, fileSize int64) error {
	file, err := core.Open(filename)
	if err != nil {
		return errors.WithMessage(err, "Failed to open file")
	}
	defer file.Close()

	if file.Size() != fileSize {
		return errors.Errorf("File size mismatch: expected = %v, downloaded = %v", fileSize, file.Size())
	}

	tree, err := core.MerkleTree(file)
	if err != nil {
		return errors.WithMessage(err, "Failed to create merkle tree")
	}

	if rootHex := tree.Root().Hex(); rootHex != root {
		return errors.Errorf("Merkle root mismatch, downloaded = %v", rootHex)
	}

	downloader.logger.Info("Succeeded to validate the downloaded file")

	return nil
}
