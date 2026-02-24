package download

import (
	"encoding/binary"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

const MetadataSize = common.HashLength + 8 + 8

type Metadata struct {
	Root   common.Hash // file merkle root
	Size   int64       // file size to download
	Offset int64       // offset to write for the next time
}

func NewMetadata(root common.Hash, size int64) *Metadata {
	return &Metadata{root, size, 0}
}

func LoadMetadata(file *os.File) (*Metadata, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to stat file")
	}

	size := info.Size()
	if size < MetadataSize {
		return nil, errors.Errorf("File size too small %v", size)
	}

	// read metadata at the end of file
	buf := make([]byte, MetadataSize)
	n, err := file.ReadAt(buf, size-MetadataSize)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to read metadata from file")
	}

	if n != MetadataSize {
		return nil, errors.Errorf("Read metadata length mismatch, expected = %v, actual = %v", MetadataSize, n)
	}

	metadata, err := DeserializeMetadata(buf)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to deserialize metadata")
	}

	return metadata, nil
}

func (md *Metadata) Serialize() []byte {
	encoded := make([]byte, MetadataSize)

	copy(encoded[:common.HashLength], md.Root.Bytes())
	binary.BigEndian.PutUint64(encoded[common.HashLength:common.HashLength+8], uint64(md.Size))
	binary.BigEndian.PutUint64(encoded[common.HashLength+8:], uint64(md.Offset))

	return encoded
}

func DeserializeMetadata(encoded []byte) (*Metadata, error) {
	if len(encoded) != MetadataSize {
		return nil, errors.Errorf("Invalid data length, expected = %v, actual = %v", MetadataSize, len(encoded))
	}

	return &Metadata{
		Root:   common.BytesToHash(encoded[:common.HashLength]),
		Size:   int64(binary.BigEndian.Uint64(encoded[common.HashLength : common.HashLength+8])),
		Offset: int64(binary.BigEndian.Uint64(encoded[common.HashLength+8:])),
	}, nil
}

func (md *Metadata) Extend(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return errors.WithMessage(err, "Failed to stat file")
	}

	// file already truncated and length mismatch with metadata
	if size := info.Size(); size > 0 && size != md.Size {
		return errors.Errorf("Invalid file size, expected = %v, actual = %v", md.Size, size)
	}

	// extend file with metadata
	if err = file.Truncate(md.Size + MetadataSize); err != nil {
		return errors.WithMessage(err, "Failed to truncate file to extend metadata")
	}

	// write metadata at the end of file
	n, err := file.WriteAt(md.Serialize(), md.Size)
	if err != nil {
		return errors.WithMessage(err, "Failed to write metadata")
	}

	if n != MetadataSize {
		return errors.Errorf("Written metadata length mismatch, expected = %v, actual = %v", MetadataSize, n)
	}

	return nil
}

func (md *Metadata) Write(file *os.File, data []byte) error {
	// check boundary
	if md.Offset+int64(len(data)) > md.Size {
		return errors.Errorf("Written data out of bound, offset = %v, dataLen = %v, fileSize = %v", md.Offset, len(data), md.Size)
	}

	// write data
	n, err := file.WriteAt(data, md.Offset)
	if err != nil {
		return errors.WithMessage(err, "Failed to write data")
	}

	if n != len(data) {
		return errors.Errorf("Written data length mismatch, expected = %v, actual = %v", len(data), n)
	}

	// update offset of metadata
	offset := md.Offset + int64(len(data))
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(offset))

	n, err = file.WriteAt(buf, md.Size+int64(MetadataSize-len(buf)))
	if err != nil {
		return errors.WithMessage(err, "Failed to update offset of metadata")
	}

	if n != len(buf) {
		return errors.Errorf("Written offset length mismatch, expected = %v, actual = %v", len(buf), n)
	}

	md.Offset = offset

	return nil
}
