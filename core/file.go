package core

import (
	"io"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

var (
	// ErrFileRequired is returned when manipulate on a folder.
	ErrFileRequired = errors.New("file required")

	// ErrFileEmpty is returned when empty file opened.
	ErrFileEmpty = errors.New("file is empty")
)

// File implement of IterableData, the underlying is a file on disk
type File struct {
	os.FileInfo
	underlying *os.File
	paddedSize uint64
	offset     int64
	size       int64
}

var _ IterableData = (*File)(nil)

func (file *File) Read(buf []byte, offset int64) (int, error) {
	n, err := file.underlying.ReadAt(buf, file.offset+offset)
	// unexpected IO error
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	return n, nil
}

func Exists(name string) (bool, error) {
	file, err := os.Open(name)
	if os.IsNotExist(err) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	defer file.Close()

	return true, nil
}

// Open create a File from a file on disk
func Open(name string) (*File, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return nil, ErrFileRequired
	}

	if info.Size() == 0 {
		return nil, ErrFileEmpty
	}

	return &File{
		FileInfo:   info,
		underlying: file,
		offset:     0,
		size:       info.Size(),
		paddedSize: IteratorPaddedSize(info.Size(), true),
	}, nil
}

// MerkleRoot returns the merkle root hash of a file on disk
func MerkleRoot(filename string) (common.Hash, error) {
	file, err := Open(filename)
	if err != nil {
		return common.Hash{}, errors.WithMessage(err, "failed to open file")
	}
	defer file.Close()

	// Generate the Merkle tree from the file content
	tree, err := MerkleTree(file)
	if err != nil {
		return common.Hash{}, errors.WithMessage(err, "failed to create merkle tree")
	}

	// Return the root hash of the Merkle tree
	return tree.Root(), nil
}

func (file *File) Close() error {
	return file.underlying.Close()
}

func (file *File) NumChunks() uint64 {
	return NumSplits(file.Size(), DefaultChunkSize)
}

func (file *File) NumSegments() uint64 {
	return NumSplits(file.Size(), DefaultSegmentSize)
}

func (file *File) PaddedSize() uint64 {
	return file.paddedSize
}

func (file *File) Size() int64 {
	return file.size
}

func (file *File) Offset() int64 {
	return file.offset
}

func (file *File) Split(fragmentSize int64) []IterableData {
	fragments := make([]IterableData, 0)
	for offset := file.offset; offset < file.offset+file.size; offset += fragmentSize {
		size := min(file.size-offset, fragmentSize)
		fragment := &File{
			FileInfo:   file.FileInfo,
			underlying: file.underlying,
			offset:     offset,
			size:       size,
			paddedSize: IteratorPaddedSize(size, true),
		}
		fragments = append(fragments, fragment)
	}
	return fragments
}
