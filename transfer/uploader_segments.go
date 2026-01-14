package transfer

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"time"

	zg_common "github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/parallel"
	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// FileSegmentsWithProof wraps segments with proof and file info
type FileSegmentsWithProof struct {
	*node.FileInfo
	Segments []node.SegmentWithProof
}

type FileSegmentUploader struct {
	clients []*node.ZgsClient // 0g storage clients
	logger  *logrus.Logger    // logger
}

func NewFileSegmentUploader(clients []*node.ZgsClient, opts ...zg_common.LogOption) *FileSegmentUploader {
	return &FileSegmentUploader{
		clients: clients,
		logger:  zg_common.NewLogger(opts...),
	}
}

// Upload uploads file segments with proof to the storage nodes parallelly.
// Note: only `ExpectedReplica` and `TaskSize` are used from UploadOption.
func (uploader *FileSegmentUploader) Upload(ctx context.Context, fileSeg FileSegmentsWithProof, option ...UploadOption) error {
	var opt UploadOption
	if len(option) > 0 {
		opt = option[0]
	}

	if opt.TaskSize == 0 {
		opt.TaskSize = defaultTaskSize
	}

	stageTimer := time.Now()
	if uploader.logger.IsLevelEnabled(logrus.DebugLevel) {
		uploader.logger.WithFields(logrus.Fields{
			"uploadOption": opt,
			"fileSegments": fileSeg,
		}).Debug("Begin to upload file segments with proof")
	}

	fsUploader, err := uploader.newFileSegmentUploader(ctx, fileSeg, opt.ExpectedReplica, opt.TaskSize, opt.Method)
	if err != nil {
		return err
	}

	sopt := parallel.SerialOption{
		Routines: min(runtime.GOMAXPROCS(0), len(uploader.clients)*5),
	}
	err = parallel.Serial(ctx, fsUploader, len(fsUploader.tasks), sopt)
	if err != nil {
		return err
	}

	if uploader.logger.IsLevelEnabled(logrus.DebugLevel) {
		uploader.logger.WithFields(logrus.Fields{
			"total":    len(fileSeg.Segments),
			"duration": time.Since(stageTimer),
		}).Debug("Completed to upload file segments with proof")
	}

	return nil
}

func (uploader *FileSegmentUploader) newFileSegmentUploader(
	ctx context.Context, fileSeg FileSegmentsWithProof, expectedReplica, taskSize uint, method string) (*fileSegmentUploader, error) {

	shardConfigs := make([]*shard.ShardConfig, 0, len(uploader.clients))
	for _, client := range uploader.clients {
		shardConfig := client.ShardConfig()
		if shardConfig == nil {
			return nil, errors.New("ShardConfig is required on ZgsClient")
		}
		if !shardConfig.IsValid() {
			return nil, errors.New("NumShard is zero")
		}
		shardConfigs = append(shardConfigs, shardConfig)
	}

	// validate replica requirements
	if !shard.CheckReplica(shardConfigs, expectedReplica, method) {
		return nil, fmt.Errorf("selected nodes cannot cover all shards")
	}

	// create upload tasks for each segment
	clientTasks := make([][]*uploadTask, len(uploader.clients))
	for i, segment := range fileSeg.Segments {
		startSegmentIndex, endSegmentIndex := core.SegmentRange(fileSeg.Tx.StartEntryIndex, fileSeg.Tx.Size)
		segmentIndex := startSegmentIndex + segment.Index

		if segmentIndex > endSegmentIndex {
			return nil, errors.New("segment index out of range")
		}

		// assign segment to shard configurations
		for clientIndex, shardConfig := range shardConfigs {
			// skip nodes that do not cover the segment
			if !shardConfig.HasSegment(segmentIndex) {
				continue
			}

			// skip finalized nodes
			nodeInfo, _ := uploader.clients[clientIndex].GetFileInfo(ctx, segment.Root, true)
			if nodeInfo != nil && nodeInfo.Finalized {
				continue
			}

			// add task for the client to upload the segment
			clientTasks[clientIndex] = append(clientTasks[clientIndex], &uploadTask{
				clientIndex: clientIndex,
				segIndex:    uint64(i),
			})
		}
	}
	sort.SliceStable(clientTasks, func(i, j int) bool {
		return len(clientTasks[i]) > len(clientTasks[j])
	})

	// group tasks by task size
	uploadTasks := make([][]*uploadTask, 0, len(clientTasks))
	for _, tasks := range clientTasks {
		// split tasks into batches of taskSize
		for len(tasks) > int(taskSize) {
			uploadTasks = append(uploadTasks, tasks[:taskSize])
			tasks = tasks[taskSize:]
		}

		if len(tasks) > 0 {
			uploadTasks = append(uploadTasks, tasks)
		}
	}
	util.Shuffle(uploadTasks)

	return &fileSegmentUploader{
		FileSegmentsWithProof: fileSeg,
		clients:               uploader.clients,
		tasks:                 uploadTasks,
		logger:                uploader.logger,
	}, nil
}
