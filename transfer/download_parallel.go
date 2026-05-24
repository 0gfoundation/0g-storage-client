package transfer

import (
	"context"
	"fmt"

	"github.com/0gfoundation/0g-storage-client/common/parallel"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer/download"
	"github.com/sirupsen/logrus"
)

type segmentDownloader struct {
	clients []*node.ZgsClient
	file    *download.DownloadingFile
	txSeq   uint64

	startSegmentIndex uint64
	endSegmentIndex   uint64

	offset uint64

	withProof bool

	numChunks uint64

	routines int

	logger *logrus.Logger
}

var _ parallel.Interface = (*segmentDownloader)(nil)

func newSegmentDownloader(downloader *Downloader, info *node.FileInfo, file *download.DownloadingFile, withProof bool) (*segmentDownloader, error) {
	startSegmentIndex := info.Tx.StartEntryIndex / core.DefaultSegmentMaxChunks
	endSegmentIndex := (info.Tx.StartEntryIndex + core.NumSplits(int64(info.Tx.Size), core.DefaultChunkSize) - 1) / core.DefaultSegmentMaxChunks

	logrus.WithFields(logrus.Fields{
		"size":              info.Tx.Size,
		"startEntryIndex":   info.Tx.StartEntryIndex,
		"numChunks":         core.NumSplits(int64(info.Tx.Size), core.DefaultChunkSize),
		"startSegmentIndex": startSegmentIndex,
		"endSegmentIndex":   endSegmentIndex,
	}).Info("Start downloading file")

	offset := file.Metadata().Offset / core.DefaultSegmentSize

	return &segmentDownloader{
		clients: downloader.clients,
		file:    file,
		txSeq:   info.Tx.Seq,

		startSegmentIndex: startSegmentIndex,
		endSegmentIndex:   endSegmentIndex,

		offset: uint64(offset),

		withProof: withProof,

		numChunks: core.NumSplits(int64(info.Tx.Size), core.DefaultChunkSize),

		routines: downloader.routines,

		logger: downloader.logger,
	}, nil
}

// Download downloads segments in parallel.
func (downloader *segmentDownloader) Download(ctx context.Context) error {
	numTasks := downloader.endSegmentIndex - downloader.startSegmentIndex + 1 - downloader.offset
	option := parallel.SerialOption{
		Routines: downloader.routines,
	}
	return parallel.Serial(ctx, downloader, int(numTasks), option)
}

// ParallelDo implements the parallel.Interface interface.
func (downloader *segmentDownloader) ParallelDo(ctx context.Context, routine, task int) (interface{}, error) {
	segmentIndex := downloader.offset + uint64(task)
	// there is no not-aligned & segment-crossed file
	startIndex := segmentIndex * core.DefaultSegmentMaxChunks
	endIndex := startIndex + core.DefaultSegmentMaxChunks

	if endIndex > downloader.numChunks {
		endIndex = downloader.numChunks
	}

	root := downloader.file.Metadata().Root
	fileSize := downloader.file.Metadata().Size
	globalSegIdx := downloader.startSegmentIndex + segmentIndex

	logCtx := func(nodeIndex int) logrus.Fields {
		return logrus.Fields{
			"node index": nodeIndex,
			"segment":    fmt.Sprintf("%v/(%v-%v)", globalSegIdx, downloader.startSegmentIndex, downloader.endSegmentIndex),
			"chunks":     fmt.Sprintf("[%v, %v)", startIndex, endIndex),
		}
	}

	for i := 0; i < len(downloader.clients); i += 1 {
		nodeIndex := (routine + i) % len(downloader.clients)
		client := downloader.clients[nodeIndex]

		// Shard-skip + RPC + (optional) proof-validation all happen
		// inside fetchSegmentFromNode (segment_fetch.go). This is the
		// single source of truth shared with downloader_writer.go.
		segment, err := fetchSegmentFromNode(ctx, client, segmentFetchRequest{
			TxSeq:        downloader.txSeq,
			Root:         root,
			FileSize:     fileSize,
			SegIdx:       segmentIndex,
			GlobalSegIdx: globalSegIdx,
			StartChunk:   startIndex,
			EndChunk:     endIndex,
			WithProof:    downloader.withProof,
		})
		if err != nil {
			downloader.logger.WithError(err).WithFields(logCtx(nodeIndex)).Error("Failed to download segment")
			continue
		}
		if segment == nil {
			// Either this node doesn't shard the segment (silent skip)
			// or the RPC returned an empty segment. Try the next node.
			downloader.logger.WithFields(logCtx(nodeIndex)).Debug("segment not available from this node")
			continue
		}
		if len(segment)%core.DefaultChunkSize != 0 {
			downloader.logger.WithFields(logCtx(nodeIndex)).Warn("invalid segment length")
			continue
		}
		if downloader.logger.IsLevelEnabled(logrus.DebugLevel) {
			downloader.logger.WithFields(logCtx(nodeIndex)).Debug("Succeeded to download segment")
		}

		// remove paddings for the last chunk
		if globalSegIdx == downloader.endSegmentIndex {
			if lastChunkSize := fileSize % core.DefaultChunkSize; lastChunkSize > 0 {
				paddings := core.DefaultChunkSize - lastChunkSize
				segment = segment[0 : len(segment)-int(paddings)]
			}
		}
		return segment, nil
	}
	return nil, fmt.Errorf("failed to download segment %v", segmentIndex)
}

// ParallelCollect implements the parallel.Interface interface.
func (downloader *segmentDownloader) ParallelCollect(result *parallel.Result) error {
	return downloader.file.Write(result.Value.([]byte))
}
