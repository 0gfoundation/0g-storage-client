package transfer

import (
	"context"
	"encoding/json"
	"time"

	"github.com/0glabs/0g-storage-client/common/parallel"
	"github.com/0glabs/0g-storage-client/core"
	"github.com/0glabs/0g-storage-client/core/merkle"
	"github.com/0glabs/0g-storage-client/node"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type uploadTask struct {
	clientIndex int
	segIndex    uint64
	numShard    uint64
}

type segmentUploader struct {
	data     core.IterableData
	tree     *merkle.Tree
	txSeq    uint64
	clients  []*node.ZgsClient
	tasks    []*uploadTask
	taskSize uint
	logger   *logrus.Logger
}

var _ parallel.Interface = (*segmentUploader)(nil)

// ParallelCollect implements parallel.Interface.
func (uploader *segmentUploader) ParallelCollect(result *parallel.Result) error {
	return nil
}

func (uploader *segmentUploader) getSegment(segIndex uint64) (bool, *node.SegmentWithProof, error) {
	numChunks := uploader.data.NumChunks()
	// check segment index
	startIndex := segIndex * core.DefaultSegmentMaxChunks
	allDataUploaded := false
	if startIndex >= numChunks {
		// file real data already uploaded
		return true, nil, nil
	}
	// get segment
	segment, err := core.ReadAt(uploader.data, core.DefaultSegmentSize, int64(segIndex*core.DefaultSegmentSize), uploader.data.PaddedSize())
	if err != nil {
		return false, nil, err
	}
	if startIndex+uint64(len(segment))/core.DefaultChunkSize >= numChunks {
		// last segment has real data
		expectedLen := core.DefaultChunkSize * int(numChunks-startIndex)
		segment = segment[:expectedLen]
		allDataUploaded = true
	}
	// fill proof
	proof := uploader.tree.ProofAt(int(segIndex))

	segWithProof := node.SegmentWithProof{
		Root:     uploader.tree.Root(),
		Data:     segment,
		Index:    segIndex,
		Proof:    proof,
		FileSize: uint64(uploader.data.Size()),
	}

	m, err := json.Marshal(segWithProof)
	if err != nil {
		return false, nil, errors.WithMessage(err, "Failed to marshal segment with proof")
	}

	logrus.WithFields(logrus.Fields{
		"segment size":        len(segWithProof.Data),
		"total size in bytes": len(m),
	}).Debug("Segment with proof prepared for upload")
	return allDataUploaded, &segWithProof, nil
}

// ParallelDo implements parallel.Interface.
func (uploader *segmentUploader) ParallelDo(ctx context.Context, routine int, task int) (interface{}, error) {
	numSegments := uploader.data.NumSegments()
	uploadTask := uploader.tasks[task]
	segIndex := uploadTask.segIndex
	startSegIndex := segIndex
	segments := make([]node.SegmentWithProof, 0)
	for i := 0; i < int(uploader.taskSize); i++ {
		allDataUploaded, segWithProof, err := uploader.getSegment(segIndex)
		if err != nil {
			return nil, err
		}
		if segWithProof != nil {
			segments = append(segments, *segWithProof)
		}
		if allDataUploaded {
			break
		}
		segIndex += uploadTask.numShard
	}

	uploader.logger.WithFields(logrus.Fields{
		"total":          numSegments,
		"from_seg_index": startSegIndex,
		"to_seg_index":   segIndex,
		"step":           uploadTask.numShard,
		"root":           core.SegmentRoot(segments[0].Data),
		"to_node":        uploader.clients[uploadTask.clientIndex].URL(),
	}).Debug("Segments uploading")

	m, err := json.Marshal(segments)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to marshal segments")
	}

	logrus.WithField("size of entire segments in bytes", len(m)).Debug("Total size of segments being uploaded")

	for i := 0; i < tooManyDataRetries; i++ {
		_, err := uploader.clients[uploadTask.clientIndex].UploadSegmentsByTxSeqGrpc(ctx, segments, uploader.txSeq)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"taskId":      task,
				"segIndex":    segIndex,
				"startSegIdx": startSegIndex,
				"numSegments": numSegments,
			}).Error("Failed to upload segments", err)

		}
		if err == nil || isDuplicateError(err.Error()) {
			break
		}

		if isTooManyDataError(err.Error()) && i < tooManyDataRetries-1 {
			time.Sleep(10 * time.Second)
			continue
		}

		return nil, errors.WithMessage(err, "Failed to upload segment")
	}

	uploader.logger.WithFields(logrus.Fields{
		"total":          numSegments,
		"from_seg_index": startSegIndex,
		"to_seg_index":   segIndex,
		"step":           uploadTask.numShard,
		"root":           core.SegmentRoot(segments[0].Data),
		"to_node":        uploader.clients[uploadTask.clientIndex].URL(),
	}).Debug("Segments uploaded")

	return nil, nil
}

type fileSegmentUploader struct {
	FileSegmentsWithProof
	clients []*node.ZgsClient
	tasks   [][]*uploadTask
	logger  *logrus.Logger
}

var _ parallel.Interface = (*fileSegmentUploader)(nil)

// ParallelCollect implements parallel.Interface.
func (uploader *fileSegmentUploader) ParallelCollect(result *parallel.Result) error {
	return nil
}

// ParallelDo implements parallel.Interface.
func (uploader *fileSegmentUploader) ParallelDo(ctx context.Context, routine int, task int) (interface{}, error) {
	clientTasks := uploader.tasks[task]
	if len(clientTasks) == 0 {
		return nil, nil
	}

	stageTimer := time.Now()
	if uploader.logger.IsLevelEnabled(logrus.DebugLevel) {
		uploader.logger.WithFields(logrus.Fields{
			"taskId":      task,
			"uploadTasks": clientTasks,
		}).Debug("Begin task to upload file segments with proof")
	}

	clientIdx := clientTasks[0].clientIndex
	if clientIdx >= len(uploader.clients) {
		return nil, errors.Errorf("client index out of range: %d", clientIdx)
	}

	// collect the segments to be uploaded based on the upload tasks
	segments := make([]node.SegmentWithProof, 0, len(clientTasks))
	for _, task := range clientTasks {
		if int(task.segIndex) >= len(uploader.Segments) {
			return nil, errors.Errorf("segment index out of range: %d", task.segIndex)
		}
		segments = append(segments, uploader.Segments[task.segIndex])
	}

	// retry logic for segment uploads
	for i := 0; i < tooManyDataRetries; i++ {
		_, err := uploader.clients[clientIdx].UploadSegmentsByTxSeqGrpc(ctx, segments, uploader.Tx.Seq)
		if err == nil || isDuplicateError(err.Error()) {
			break
		}

		if isTooManyDataError(err.Error()) && i < tooManyDataRetries-1 {
			time.Sleep(10 * time.Second)
			continue
		}

		return nil, errors.WithMessage(err, "Failed to upload segment")
	}

	if uploader.logger.IsLevelEnabled(logrus.DebugLevel) {
		segs := make([]node.SegmentWithProof, 0, len(segments))
		for i := range segments {
			segs = append(segs, node.SegmentWithProof{
				Root:  segments[i].Root,
				Index: segments[i].Index,
			})
		}
		uploader.logger.WithFields(logrus.Fields{
			"clientIndex": clientIdx,
			"taskId":      task,
			"totalSegs":   len(segments),
			"segments":    segs,
			"duration":    time.Since(stageTimer),
		}).Debug("Completed task to upload file segments with proof")
	}

	return nil, nil
}
