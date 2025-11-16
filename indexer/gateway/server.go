package gateway

import (
	"net/http"

	"github.com/0gfoundation/0g-storage-client/common/api"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/gin-gonic/gin"
)

type Config struct {
	Endpoint            string       // http endpoint
	RPCHandler          http.Handler // enable to provide both RPC and REST API service
	MaxDownloadFileSize uint64       // max download file size
}

func MustServeWithRPC(nodeManager *indexer.NodeManager, locationCache *indexer.FileLocationCache, config Config) {
	controller := NewRestController(nodeManager, locationCache, config.MaxDownloadFileSize)

	api.Serve(config.Endpoint, func(router *gin.Engine) {
		router.GET("/file", api.Wrap(controller.downloadFile))
		router.GET("/file/:cid/*filePath", api.Wrap(controller.downloadFileInFolder))
		router.GET("/file/info/:cid", api.Wrap(controller.getFileStatus))
		router.GET("/files/info", api.Wrap(controller.batchGetFileStatus))
		router.GET("/node/status", api.Wrap(controller.getNodeStatus))
		router.POST("/file/segment", api.Wrap(controller.uploadSegment))

		if config.RPCHandler != nil {
			router.POST("/", gin.WrapH(config.RPCHandler))
		}
	})
}
