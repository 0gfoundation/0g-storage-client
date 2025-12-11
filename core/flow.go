package core

import (
	"context"
	"math"
	"math/big"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/parallel"
	"github.com/0gfoundation/0g-storage-client/contract"
	"github.com/0gfoundation/0g-storage-client/core/merkle"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

type Flow struct {
	data IterableData
	tags []byte

	logger *logrus.Logger
}

func NewFlow(data IterableData, tags []byte, opts ...common.LogOption) *Flow {
	return &Flow{data: data, tags: tags, logger: common.NewLogger(opts...)}
}

func (flow *Flow) CreateSubmission(submitter ethcommon.Address) (*contract.Submission, error) {
	// TODO(kevin): limit file size, e.g., 2^31
	submission := contract.Submission{
		Data: contract.SubmissionData{
			Length: big.NewInt(flow.data.Size()),
			Tags:   flow.tags,
			Nodes:  make([]contract.SubmissionNode, 0),
		},
		Submitter: submitter,
	}

	var offset int64
	for _, chunks := range flow.splitNodes() {
		node, err := flow.createNode(offset, chunks)
		if err != nil {
			return nil, err
		}
		submission.Data.Nodes = append(submission.Data.Nodes, *node)
		offset += chunks * DefaultChunkSize
	}

	return &submission, nil
}

func NextPow2(input uint64) uint64 {
	x := input
	x -= 1
	x |= x >> 32
	x |= x >> 16
	x |= x >> 8
	x |= x >> 4
	x |= x >> 2
	x |= x >> 1
	x += 1
	return x
}

func ComputePaddedSize(chunks uint64) (uint64, uint64) {
	chunksNextPow2 := NextPow2(chunks)
	if chunksNextPow2 == chunks {
		return chunksNextPow2, chunksNextPow2
	}

	var minChunk uint64
	if chunksNextPow2 >= 16 {
		minChunk = chunksNextPow2 / 16
	} else {
		minChunk = 1
	}

	paddedChunks := ((chunks-1)/minChunk + 1) * minChunk
	return paddedChunks, chunksNextPow2
}

// e.g. 64, 32, 1 in chunks
func (flow *Flow) splitNodes() []int64 {
	var nodes []int64

	chunks := flow.data.NumChunks()
	paddedChunks, chunksNextPow2 := ComputePaddedSize(chunks)
	nextChunkSize := chunksNextPow2

	for paddedChunks > 0 {
		if paddedChunks >= nextChunkSize {
			paddedChunks -= nextChunkSize
			nodes = append(nodes, int64(nextChunkSize))
		}
		nextChunkSize /= 2
	}
	flow.logger.WithFields(logrus.Fields{
		"chunks":   chunks,
		"nodeSize": nodes,
	}).Debug("SplitNodes")

	return nodes
}

func (flow *Flow) createNode(offset, chunks int64) (*contract.SubmissionNode, error) {
	batch := chunks
	if chunks > DefaultSegmentMaxChunks {
		batch = DefaultSegmentMaxChunks
	}

	return flow.createSegmentNode(offset, DefaultChunkSize*batch, DefaultChunkSize*chunks)
}

func (flow *Flow) createSegmentNode(offset, batch, size int64) (*contract.SubmissionNode, error) {
	var builder merkle.TreeBuilder
	initializer := &TreeBuilderInitializer{
		data:    flow.data,
		offset:  offset,
		batch:   batch,
		builder: &builder,
	}

	err := parallel.Serial(context.Background(), initializer, int((size-1)/batch+1))
	if err != nil {
		return nil, err
	}

	numChunks := size / DefaultChunkSize
	height := int64(math.Log2(float64(numChunks)))

	return &contract.SubmissionNode{
		Root:   builder.Build().Root(),
		Height: big.NewInt(height),
	}, nil
}
