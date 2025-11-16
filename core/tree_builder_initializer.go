package core

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/common/parallel"
	"github.com/0gfoundation/0g-storage-client/core/merkle"
	"github.com/ethereum/go-ethereum/common"
)

type TreeBuilderInitializer struct {
	data    IterableData
	offset  int64
	batch   int64
	builder *merkle.TreeBuilder
}

var _ parallel.Interface = (*TreeBuilderInitializer)(nil)

// ParallelCollect implements parallel.Interface.
func (t *TreeBuilderInitializer) ParallelCollect(result *parallel.Result) error {
	t.builder.AppendHash(result.Value.(common.Hash))
	return nil
}

// ParallelDo implements parallel.Interface.
func (t *TreeBuilderInitializer) ParallelDo(ctx context.Context, routine int, task int) (interface{}, error) {
	offset := t.offset + int64(task)*t.batch
	buf, err := ReadAt(t.data, int(t.batch), offset, t.data.PaddedSize())
	if err != nil {
		return nil, err
	}

	hash := SegmentRoot(buf)
	return hash, nil
}
