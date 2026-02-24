package core

// EncryptedData wraps an IterableData with AES-256-CTR encryption.
// It prepends a 17-byte encryption header (version + nonce) to the data stream
// and encrypts the inner data on-the-fly during reads.
type EncryptedData struct {
	inner         IterableData
	key           [32]byte
	header        *EncryptionHeader
	encryptedSize int64
	paddedSize    uint64
}

var _ IterableData = (*EncryptedData)(nil)

// NewEncryptedData creates an EncryptedData wrapper around the given data source.
// A random nonce is generated for the encryption header.
func NewEncryptedData(inner IterableData, key [32]byte) (*EncryptedData, error) {
	header, err := NewEncryptionHeader()
	if err != nil {
		return nil, err
	}
	encryptedSize := inner.Size() + int64(EncryptionHeaderSize)
	paddedSize := IteratorPaddedSize(encryptedSize, true)

	return &EncryptedData{
		inner:         inner,
		key:           key,
		header:        header,
		encryptedSize: encryptedSize,
		paddedSize:    paddedSize,
	}, nil
}

// Header returns the encryption header containing the version and nonce.
func (ed *EncryptedData) Header() *EncryptionHeader {
	return ed.header
}

func (ed *EncryptedData) NumChunks() uint64 {
	return NumSplits(ed.encryptedSize, DefaultChunkSize)
}

func (ed *EncryptedData) NumSegments() uint64 {
	return NumSplits(ed.encryptedSize, DefaultSegmentSize)
}

func (ed *EncryptedData) Size() int64 {
	return ed.encryptedSize
}

func (ed *EncryptedData) PaddedSize() uint64 {
	return ed.paddedSize
}

func (ed *EncryptedData) Offset() int64 {
	return 0
}

// Read reads encrypted data at the given offset.
// For offsets within the header region (0..16), header bytes are returned.
// For offsets beyond the header, data is read from the inner source and encrypted.
func (ed *EncryptedData) Read(buf []byte, offset int64) (int, error) {
	if offset < 0 || offset >= ed.encryptedSize {
		return 0, nil
	}

	headerSize := int64(EncryptionHeaderSize)
	written := 0

	// If offset falls within the header region
	if offset < headerSize {
		headerBytes := ed.header.ToBytes()
		headerStart := int(offset)
		headerEnd := int(headerSize)
		if headerEnd > headerStart+len(buf) {
			headerEnd = headerStart + len(buf)
		}
		n := headerEnd - headerStart
		copy(buf[:n], headerBytes[headerStart:headerEnd])
		written += n
	}

	// If we still have room in buf and there's data beyond the header
	if written < len(buf) {
		var dataOffset int64
		if offset < headerSize {
			dataOffset = 0
		} else {
			dataOffset = offset - headerSize
		}

		remainingBuf := buf[written:]
		innerRead, err := ed.inner.Read(remainingBuf, dataOffset)
		if err != nil {
			return written, err
		}

		// Encrypt the data we just read
		if innerRead > 0 {
			CryptAt(&ed.key, &ed.header.Nonce, uint64(dataOffset), buf[written:written+innerRead])
		}

		written += innerRead
	}

	return written, nil
}

// Split splits the encrypted data stream into fragments of the given size.
// Each fragment is an EncryptedDataFragment providing a view into this encrypted stream.
// If the encrypted data fits within fragmentSize, returns the EncryptedData itself.
func (ed *EncryptedData) Split(fragmentSize int64) []IterableData {
	if ed.encryptedSize <= fragmentSize {
		return []IterableData{ed}
	}

	fragments := make([]IterableData, 0)
	for offset := int64(0); offset < ed.encryptedSize; offset += fragmentSize {
		size := min(ed.encryptedSize-offset, fragmentSize)
		fragment := &EncryptedDataFragment{
			parent:     ed,
			offset:     offset,
			size:       size,
			paddedSize: IteratorPaddedSize(size, true),
		}
		fragments = append(fragments, fragment)
	}
	return fragments
}

// EncryptedDataFragment represents a contiguous view (fragment) of an EncryptedData stream.
// It delegates Read calls to the parent EncryptedData with an appropriate offset adjustment.
// This follows the same offset/size view pattern as File.Split() and DataInMemory.Split().
type EncryptedDataFragment struct {
	parent     *EncryptedData
	offset     int64  // byte offset within the parent's encrypted stream
	size       int64  // logical size of this fragment
	paddedSize uint64 // padded size for flow submission
}

var _ IterableData = (*EncryptedDataFragment)(nil)

func (f *EncryptedDataFragment) NumChunks() uint64 {
	return NumSplits(f.size, DefaultChunkSize)
}

func (f *EncryptedDataFragment) NumSegments() uint64 {
	return NumSplits(f.size, DefaultSegmentSize)
}

func (f *EncryptedDataFragment) Size() int64 {
	return f.size
}

func (f *EncryptedDataFragment) PaddedSize() uint64 {
	return f.paddedSize
}

func (f *EncryptedDataFragment) Offset() int64 {
	return f.offset
}

// Read reads from this fragment at the given offset.
// Delegates to the parent EncryptedData with the fragment's base offset added.
func (f *EncryptedDataFragment) Read(buf []byte, offset int64) (int, error) {
	remaining := f.size - offset
	if remaining <= 0 {
		return 0, nil
	}
	if int64(len(buf)) > remaining {
		buf = buf[:remaining]
	}
	return f.parent.Read(buf, f.offset+offset)
}

// Split returns the fragment itself (fragments are not further splittable).
func (f *EncryptedDataFragment) Split(fragmentSize int64) []IterableData {
	return []IterableData{f}
}
