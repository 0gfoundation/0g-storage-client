package core

import "errors"

// DataInMemory implement of IterableData, the underlying is memory data
type DataInMemory struct {
	underlying []byte
	offset     int64
	size       int64
	paddedSize uint64
}

var _ IterableData = (*DataInMemory)(nil)

// NewDataInMemory creates DataInMemory from given data
func NewDataInMemory(data []byte) (*DataInMemory, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	return &DataInMemory{
		underlying: data,
		offset:     0,
		size:       int64(len(data)),
		paddedSize: IteratorPaddedSize(int64(len(data)), true),
	}, nil
}

func (data *DataInMemory) Read(buf []byte, offset int64) (int, error) {
	// Reads must not cross the logical view: a fragment from Split shares the
	// underlying buffer with its siblings, so reading past its size would return the
	// next fragment's bytes. core.ReadAt hands us a zero-filled buffer and treats
	// whatever we leave untouched as padding, so overrunning here silently replaces
	// that padding with real data - changing both the merkle root and the uploaded
	// bytes. The offset guard also keeps an out-of-range offset from panicking.
	if offset < 0 || offset >= data.size {
		return 0, nil
	}
	if remaining := data.size - offset; int64(len(buf)) > remaining {
		buf = buf[:remaining]
	}

	return copy(buf, data.underlying[data.offset+offset:]), nil
}

// NumChunks and NumSegments describe this view, not the buffer it was split from,
// matching File. Upload planning derives segment work from them, so a fragment
// reporting its parent's counts would request offsets beyond its own padded size.
func (data *DataInMemory) NumChunks() uint64 {
	return NumSplits(data.size, DefaultChunkSize)
}

func (data *DataInMemory) NumSegments() uint64 {
	return NumSplits(data.size, DefaultSegmentSize)
}

func (data *DataInMemory) Size() int64 {
	return data.size
}

func (data *DataInMemory) Offset() int64 {
	return data.offset
}

func (data *DataInMemory) PaddedSize() uint64 {
	return data.paddedSize
}

func (data *DataInMemory) Split(fragmentSize int64) []IterableData {
	fragments := make([]IterableData, 0)
	for offset := data.offset; offset < data.offset+data.size; offset += fragmentSize {
		size := min(data.size-offset, fragmentSize)
		fragment := &DataInMemory{
			underlying: data.underlying,
			offset:     offset,
			size:       size,
			paddedSize: IteratorPaddedSize(size, true),
		}
		fragments = append(fragments, fragment)
	}
	return fragments
}
