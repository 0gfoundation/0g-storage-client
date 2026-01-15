package gateway

import (
	"context"
	"path/filepath"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/api"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var LocalFileRepo string = "."

func listNodes(c *gin.Context) (interface{}, error) {
	var nodes []string

	for _, c := range allClients {
		nodes = append(nodes, c.URL())
	}

	return nodes, nil
}

func getFilePath(path string, download bool) string {
	if filepath.IsAbs(path) {
		return path
	}

	if !download {
		return filepath.Join(LocalFileRepo, path)
	}

	return filepath.Join(LocalFileRepo, "download", path)
}

func getLocalFileInfo(c *gin.Context) (interface{}, error) {
	var input struct {
		Path string `form:"path" json:"path" binding:"required"`
	}

	if err := c.ShouldBind(&input); err != nil {
		return nil, err
	}

	filename := getFilePath(input.Path, false)

	file, err := core.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	tree, err := core.MerkleTree(file)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"name":     file.Name(),
		"root":     tree.Root(),
		"size":     file.Size(),
		"segments": file.NumSegments(),
	}, nil
}

func getFileStatus(c *gin.Context) (interface{}, error) {
	var input struct {
		Root string `form:"root" json:"root" binding:"required"`
	}

	if err := c.ShouldBind(&input); err != nil {
		return nil, err
	}

	root := common.HexToHash(input.Root)

	var notFinalized bool

	for _, client := range allClients {
		info, err := client.GetFileInfo(context.Background(), root, false)
		if err != nil {
			return nil, err
		}

		if info == nil {
			return "unavailable", nil
		}

		if info.Pruned {
			return "pruned", nil
		}

		if !info.Finalized {
			notFinalized = true
		}
	}

	if notFinalized {
		return "available", nil
	}

	return "finalized", nil
}

// Assume that file status is `available` and not `finalized` yet.
func uploadLocalFile(c *gin.Context) (interface{}, error) {
	var input struct {
		Path string `form:"path" json:"path" binding:"required"`
		Node int    `form:"node" json:"node"`
	}

	if err := c.ShouldBind(&input); err != nil {
		return nil, err
	}

	if input.Node < 0 || input.Node >= len(allClients) {
		return nil, api.ErrValidation.WithData("node index out of bound")
	}

	uploader, err := transfer.NewUploaderWithContractConfig(context.Background(), nil, &transfer.SelectedNodes{
		Trusted: []*node.ZgsClient{allClients[input.Node]},
	}, transfer.UploaderConfig{
		LogOption: zg_common.LogOption{Logger: logrus.StandardLogger()},
	})
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to create uploader")
	}

	filename := getFilePath(input.Path, false)

	// Open file to upload
	file, err := core.Open(filename)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to open file")
	}
	defer file.Close()

	if _, _, err := uploader.Upload(context.Background(), file); err != nil {
		return nil, err
	}

	return nil, nil
}

func downloadFileLocal(c *gin.Context) (interface{}, error) {
	var input struct {
		Node int    `form:"node" json:"node"`
		Root string `form:"root" json:"root" binding:"required"`
		Path string `form:"path" json:"path" binding:"required"`
	}

	if err := c.ShouldBind(&input); err != nil {
		return nil, err
	}

	if input.Node < 0 || input.Node >= len(allClients) {
		return nil, api.ErrValidation.WithData("node index out of bound")
	}

	downloader, err := transfer.NewDownloader([]*node.ZgsClient{allClients[input.Node]}, zg_common.LogOption{Logger: logrus.StandardLogger()})
	if err != nil {
		return nil, err
	}

	filename := getFilePath(input.Path, true)

	if err := downloader.Download(context.Background(), input.Root, filename, false); err != nil {
		return nil, err
	}

	return nil, nil
}
