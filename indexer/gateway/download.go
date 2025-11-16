package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0gfoundation/0g-storage-client/common/api"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/0gfoundation/0g-storage-client/transfer/dir"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

// downloadFile handles file downloads by root hash or transaction sequence.
func (ctrl *RestController) downloadFile(c *gin.Context) (interface{}, error) {
	var input struct {
		Cid
		Name string `form:"name" json:"name"`
	}

	if err := c.ShouldBind(&input); err != nil {
		return nil, api.ErrValidation.WithData(err.Error())
	}

	if input.TxSeq == nil && len(input.Root) == 0 {
		return nil, api.ErrValidation.WithData("Either 'root' or 'txSeq' must be provided")
	}

	return nil, ctrl.downloadAndServeFile(c, input.Cid, input.Name)
}

// downloadFileInFolder handles file downloads from a directory structure.
func (ctrl *RestController) downloadFileInFolder(c *gin.Context) (interface{}, error) {
	cidStr := strings.TrimSpace(c.Param("cid"))
	filePath := filepath.Clean(c.Param("filePath"))
	cid := NewCid(cidStr)

	clients, err := ctrl.getAvailableStorageNodes(c, cid)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to get available storage nodes")
	}

	defer func() {
		for _, client := range clients {
			client.Close()
		}
	}()

	fileInfo, err := getOverallFileInfo(c, clients, cid)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to retrieve file info")
	}

	if fileInfo == nil {
		return nil, ErrFileNotFound
	}

	if fileInfo.Pruned {
		return nil, ErrFilePruned
	}

	if !fileInfo.Finalized {
		return nil, ErrFileNotFinalized
	}

	downloader, err := transfer.NewDownloader(clients)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to create downloader")
	}

	root := fileInfo.Tx.DataMerkleRoot

	ftree, err := transfer.BuildFileTree(c, downloader, root.Hex(), true)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to build file tree")
	}

	fnode, err := ftree.Locate(filePath)
	if err != nil {
		return nil, ErrFilePathNotFound.WithData(err.Error())
	}

	switch fnode.Type {
	case dir.FileTypeDirectory:
		// Show the list of files in the directory.
		return serveDirectoryListing(fnode), nil
	case dir.FileTypeSymbolic:
		// If the file type is symbolic (a symlink), return the metadata of the symbolic link itself
		// (i.e., information about the symlink, not the target it points to).
		// This prevents the server from following the symbolic link and returning the target file's content.
		return fnode, nil
	case dir.FileTypeFile:
		if fnode.Size > int64(ctrl.maxDownloadFileSize) {
			return nil, ErrFileSizeTooLarge.WithData(map[string]uint64{
				"actual": uint64(fnode.Size),
				"max":    ctrl.maxDownloadFileSize,
			})
		}

		return nil, ctrl.downloadAndServeFile(c, Cid{Root: fnode.Root}, fnode.Name)
	default:
		return nil, ErrFileTypeUnsupported.WithData(fnode.Type)
	}
}

// downloadAndServeFile downloads the file and serves it as an attachment.
func (ctrl *RestController) downloadAndServeFile(c *gin.Context, cid Cid, filename string) error {
	clients, err := ctrl.getAvailableStorageNodes(c, cid)
	if err != nil {
		return errors.WithMessage(err, "Failed to get available storage nodes")
	}

	defer func() {
		for _, client := range clients {
			client.Close()
		}
	}()

	fileInfo, err := getOverallFileInfo(c, clients, cid)
	if err != nil {
		return errors.WithMessage(err, "Failed to retrieve file info")
	}

	if fileInfo == nil {
		return ErrFileNotFound
	}

	if fileInfo.Pruned {
		return ErrFilePruned
	}

	if !fileInfo.Finalized {
		return ErrFileNotFinalized
	}

	downloader, err := transfer.NewDownloader(clients)
	if err != nil {
		return errors.WithMessage(err, "Failed to create downloader")
	}

	root := fileInfo.Tx.DataMerkleRoot.Hex()
	tmpfile := filepath.Join(os.TempDir(), fmt.Sprintf("zgs_indexer_download_%v", root))
	defer os.Remove(tmpfile)

	if err := downloader.Download(c, root, tmpfile, true); err != nil {
		return errors.WithMessage(err, "Failed to download file")
	}

	if len(filename) == 0 {
		filename = root
	}

	c.FileAttachment(tmpfile, filename)

	return api.ErrHandled
}

// serveDirectoryListing serves the list of files in a directory.
func serveDirectoryListing(dirNode *dir.FsNode) interface{} {
	type DirListing struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Size uint64 `json:"size,omitempty"`
	}

	var dirListing []DirListing
	for _, entry := range dirNode.Entries {
		dirListing = append(dirListing, DirListing{
			Name: entry.Name,
			Type: string(entry.Type),
			Size: uint64(entry.Size),
		})
	}
	return dirListing
}
