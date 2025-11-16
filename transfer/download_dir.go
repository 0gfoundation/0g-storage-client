package transfer

import (
	"context"
	"os"
	"path/filepath"

	"github.com/0gfoundation/0g-storage-client/transfer/dir"
	"github.com/0gfoundation/0g-storage-client/transfer/download"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// DownloadDir downloads files within a directory recursively from the ZeroGStorage network.
// It first builds a file tree from the directory metadata, then downloads each file in the directory,
// and finally seals the directory when the download is complete.
//
// Parameters:
//   - ctx:        Context for managing request timeouts and cancellations.
//   - downloader: The interface responsible for downloading files from the ZeroGStorage network.
//   - root:       The root hash of the directory to be downloaded.
//   - filename:   The name of the local directory to store the downloaded files.
//   - withProof:  Whether to download the files with a Merkle proof for validation.
//
// Returns:
//   - error: An error if any part of the download or file creation process fails.
func DownloadDir(ctx context.Context, downloader IDownloader, root, filename string, withProof bool) error {
	// Build a file tree from the directory metadata stored on the network.
	tree, err := BuildFileTree(ctx, downloader, root, withProof)
	if err != nil {
		return errors.WithMessage(err, "failed to build file tree")
	}

	// Create or prepare the local directory where files will be downloaded.
	folder, err := download.CreateDownloadingDir(filename)
	if err != nil {
		return errors.WithMessage(err, "failed to prepare downloading directory")
	}

	// Flatten the file tree to get a list of nodes (files and directories) and their relative paths.
	nodes, relpaths := tree.Flatten()
	for i := range nodes {
		// Only download if it's a file and has content
		var persist func(string) error
		if nodes[i].Type == dir.FileTypeFile && nodes[i].Size > 0 {
			// Generate a function to persist the file by downloading it.
			persist = downloadPersistFunc(downloader, ctx, nodes[i].Root, withProof)
		}

		logrus.WithFields(logrus.Fields{
			"node":     nodes[i],
			"filename": relpaths[i],
		}).Debug("Adding file to downloading folder")

		// Add the node (file or directory) to the local folder.
		if err := folder.Add(nodes[i], relpaths[i], persist); err != nil {
			return errors.WithMessagef(err, "failed to add `%s` to folder", relpaths[i])
		}
	}

	// Seal the folder by renaming the temporary downloading folder to its final name.
	if err := folder.Seal(); err != nil {
		return errors.WithMessage(err, "failed to seal folder")
	}

	return nil
}

// BuildFileTree downloads directory metadata from the ZeroGStorage network and decodes it into an FsNode structure.
// This function retrieves the metadata of a directory, which is stored in the ZeroGStorage network,
// and then decodes the metadata to construct a file tree representation of the directory.
//
// Parameters:
//   - ctx:        Context to manage request deadlines, cancellation, and timeout.
//   - downloader: The interface responsible for downloading files from the ZeroGStorage network.
//   - root:       The root hash of the directory's metadata.
//   - proof:      Whether to download with Merkle proof validation.
//
// Returns:
//   - *dir.FsNode: A pointer to the decoded file tree structure representing the directory.
//   - error: An error if downloading or decoding the directory metadata fails.
func BuildFileTree(ctx context.Context, downloader IDownloader, root string, proof bool) (*dir.FsNode, error) {
	// Create a temporary path to store the downloaded metadata file.
	metapath := filepath.Join(os.TempDir(), root+".zgdm")

	logrus.WithFields(logrus.Fields{
		"root":     root,
		"filename": metapath,
	}).Debug("Downloading directory metadata to build file tree")

	// Download the directory metadata from the ZeroGStorage network.
	// If the file already exists, skip re-downloading it.
	err := downloader.Download(ctx, root, metapath, proof)
	if err != nil && !errors.Is(err, ErrFileAlreadyExists) {
		return nil, errors.WithMessage(err, "failed to download directory metadata")
	}
	defer os.Remove(metapath) // Ensure that the temporary file is deleted after usage.

	// Read the downloaded metadata file from the temporary path.
	metaData, err := os.ReadFile(metapath)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to read directory metadata")
	}

	// Decode the metadata from binary format into an FsNode structure.
	var tree dir.FsNode
	if err := tree.UnmarshalBinary(metaData); err != nil {
		return nil, errors.WithMessage(err, "failed to decode directory metadata")
	}

	// Return the decoded file tree representing the directory.
	return &tree, nil
}

// downloadPersistFunc is a helper function that returns a function that downloads a file from ZeroGStorage network.
func downloadPersistFunc(downloader IDownloader, ctx context.Context, root string, withProof bool) func(string) error {
	return func(path string) error {
		err := downloader.Download(ctx, root, path, withProof)
		if err != nil && !errors.Is(err, ErrFileAlreadyExists) {
			return errors.WithMessagef(err, "failed to download file with root %s", root)
		}
		return nil
	}
}
