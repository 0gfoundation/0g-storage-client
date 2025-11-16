package gateway

import (
	"fmt"
	"strings"

	"github.com/0gfoundation/0g-storage-client/common/api"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

const maxBatchSize = 100

func (ctrl *RestController) getFileStatus(c *gin.Context) (interface{}, error) {
	cidStr := strings.TrimSpace(c.Param("cid"))
	cid := NewCid(cidStr)

	fileInfo, err := ctrl.fetchFileInfo(c, cid)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to retrieve file info")
	}

	if fileInfo == nil {
		return nil, ErrFileNotFound
	}

	return fileInfo, nil
}

func (ctrl *RestController) batchGetFileStatus(c *gin.Context) (interface{}, error) {
	var params struct {
		Cids []string `form:"cid" json:"cid"`
	}

	if err := c.ShouldBind(&params); err != nil {
		return nil, api.ErrValidation.WithData(err.Error())
	}

	if len(params.Cids) == 0 {
		return nil, api.ErrValidation.WithData("No cid specified")
	}

	if len(params.Cids) > maxBatchSize {
		return nil, api.ErrValidation.WithData(fmt.Sprintf("Too many cid specified, exceeded %v", maxBatchSize))
	}

	var result []interface{}

	for _, v := range params.Cids {
		cid := NewCid(strings.TrimSpace(v))

		fileInfo, err := ctrl.fetchFileInfo(c, cid)
		if err != nil {
			result = append(result, errors.WithMessage(err, "Failed to retrieve file info").Error())
		} else {
			result = append(result, fileInfo)
		}
	}

	return result, nil
}

func (ctrl *RestController) getNodeStatus(c *gin.Context) (interface{}, error) {
	var finalStatus *node.Status
	for _, client := range ctrl.nodeManager.TrustedClients() {
		status, err := client.GetStatus(c)
		if err != nil {
			return nil, errors.WithMessagef(err, "Failed to retrieve node status")
		}

		if finalStatus == nil {
			finalStatus = &status
			continue
		}

		if finalStatus.LogSyncHeight > status.LogSyncHeight {
			finalStatus.LogSyncHeight = status.LogSyncHeight
			finalStatus.LogSyncBlock = status.LogSyncBlock
		}

		finalStatus.ConnectedPeers = max(finalStatus.ConnectedPeers, status.ConnectedPeers)
		finalStatus.NextTxSeq = min(finalStatus.NextTxSeq, status.NextTxSeq)
	}

	return finalStatus, nil
}
