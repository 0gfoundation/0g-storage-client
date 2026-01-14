package transfer

import (
	"context"
	"fmt"

	"github.com/0gfoundation/0g-storage-client/common/parallel"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer/download"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
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

	var (
		segment []byte
		err     error
	)

	for i := 0; i < len(downloader.clients); i += 1 {
		nodeIndex := (routine + i) % len(downloader.clients)
		shardConfig := downloader.clients[nodeIndex].ShardConfig()
		if shardConfig == nil {
			return nil, errors.New("ShardConfig is required on ZgsClient")
		}
		if (downloader.startSegmentIndex+segmentIndex)%shardConfig.NumShard != shardConfig.ShardId {
			continue
		}
		// try download from current node
		if downloader.withProof {
			segment, err = downloader.downloadWithProof(ctx, downloader.clients[nodeIndex], downloader.txSeq, root, startIndex, endIndex)
		} else {
			segment, err = downloader.clients[nodeIndex].DownloadSegmentByTxSeq(ctx, downloader.txSeq, startIndex, endIndex)
		}

		if err != nil {
			downloader.logger.WithError(err).WithFields(logrus.Fields{
				"node index": nodeIndex,
				"segment":    fmt.Sprintf("%v/(%v-%v)", downloader.startSegmentIndex+segmentIndex, downloader.startSegmentIndex, downloader.endSegmentIndex),
				"chunks":     fmt.Sprintf("[%v, %v)", startIndex, endIndex),
			}).Error("Failed to download segment")
			continue
		}
		if segment == nil {
			downloader.logger.WithFields(logrus.Fields{
				"node index": nodeIndex,
				"segment":    fmt.Sprintf("%v/(%v-%v)", downloader.startSegmentIndex+segmentIndex, downloader.startSegmentIndex, downloader.endSegmentIndex),
				"chunks":     fmt.Sprintf("[%v, %v)", startIndex, endIndex),
			}).Warn("segment not found")
			continue
		}
		if len(segment)%core.DefaultChunkSize != 0 {
			downloader.logger.WithFields(logrus.Fields{
				"node index": nodeIndex,
				"segment":    fmt.Sprintf("%v/(%v-%v)", downloader.startSegmentIndex+segmentIndex, downloader.startSegmentIndex, downloader.endSegmentIndex),
				"chunks":     fmt.Sprintf("[%v, %v)", startIndex, endIndex),
			}).Warn("invalid segment length")
			continue
		}
		if downloader.logger.IsLevelEnabled(logrus.DebugLevel) {
			downloader.logger.WithFields(logrus.Fields{
				"node index": nodeIndex,
				"segment":    fmt.Sprintf("%v/(%v-%v)", downloader.startSegmentIndex+segmentIndex, downloader.startSegmentIndex, downloader.endSegmentIndex),
				"chunks":     fmt.Sprintf("[%v, %v)", startIndex, endIndex),
			}).Debug("Succeeded to download segment")
		}

		// remove paddings for the last chunk
		if downloader.startSegmentIndex+segmentIndex == downloader.endSegmentIndex {
			fileSize := downloader.file.Metadata().Size
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

func (downloader *segmentDownloader) downloadWithProof(ctx context.Context, client *node.ZgsClient, txSeq uint64, root common.Hash, startIndex, endIndex uint64) ([]byte, error) {
	segmentIndex := startIndex / core.DefaultSegmentMaxChunks

	segment, err := client.DownloadSegmentWithProofByTxSeq(ctx, txSeq, segmentIndex)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to download segment with proof from storage node")
	}
	if segment == nil {
		return nil, nil
	}

	if expectedDataLen := (endIndex - startIndex) * core.DefaultChunkSize; int(expectedDataLen) != len(segment.Data) {
		return nil, errors.Errorf("Downloaded data length mismatch, expected = %v, actual = %v", expectedDataLen, len(segment.Data))
	}

	segmentRootHash, numSegmentsFlowPadded := core.PaddedSegmentRoot(segmentIndex, segment.Data, downloader.file.Metadata().Size)
	if err := segment.Proof.ValidateHash(root, segmentRootHash, segmentIndex, numSegmentsFlowPadded); err != nil {
		return nil, errors.WithMessage(err, "Failed to validate proof")
	}

	return segment.Data, nil
}
