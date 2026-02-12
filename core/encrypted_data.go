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

// Split returns the encrypted data as a single fragment (splitting is not supported for encrypted data).
func (ed *EncryptedData) Split(fragmentSize int64) []IterableData {
	return []IterableData{ed}
}
