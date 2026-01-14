package transfer

import (
	"context"
	"strings"

	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

var dataAlreadyExistsError = "Invalid params: root; data: already uploaded and finalized"
var segmentAlreadyExistsError = "segment has already been uploaded or is being uploaded"
var tooManyDataError = "too many data writing"
var tooManyDataRetries = 12

func isDuplicateError(msg string) bool {
	return strings.Contains(msg, dataAlreadyExistsError) || strings.Contains(msg, segmentAlreadyExistsError)
}

func isTooManyDataError(msg string) bool {
	return strings.Contains(msg, tooManyDataError)
}

func getShardConfigs(clients []*node.ZgsClient) ([]*shard.ShardConfig, error) {
	shardConfigs := make([]*shard.ShardConfig, 0)
	for _, client := range clients {
		shardConfig := client.ShardConfig()
		if shardConfig == nil {
			return nil, errors.New("ShardConfig is required on ZgsClient")
		}
		if !shardConfig.IsValid() {
			return nil, errors.New("NumShard is zero")
		}
		shardConfigs = append(shardConfigs, shardConfig)
	}
	return shardConfigs, nil
}

func checkLogExistence(ctx context.Context, clients *SelectedNodes, root common.Hash) (*node.FileInfo, error) {
	var info *node.FileInfo
	var err error

	for _, client := range clients.Trusted {
		info, err = client.GetFileInfo(ctx, root, true)
		if err != nil {
			return nil, err
		}
		// log entry available
		if info != nil {
			return info, nil
		}
	}
	return info, nil
}
