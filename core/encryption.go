package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const (
	// EncryptionHeaderSize is the size of the encryption header in bytes (1 byte version + 16 bytes nonce).
	EncryptionHeaderSize = 17

	// EncryptionVersion is the current encryption format version.
	EncryptionVersion = 1
)

// EncryptionHeader stores the version and nonce for AES-256-CTR encryption.
type EncryptionHeader struct {
	Version uint8
	Nonce   [16]byte
}

// NewEncryptionHeader creates a new encryption header with a random nonce.
func NewEncryptionHeader() (*EncryptionHeader, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	return &EncryptionHeader{
		Version: EncryptionVersion,
		Nonce:   nonce,
	}, nil
}

// ParseEncryptionHeader extracts an encryption header from the given data.
func ParseEncryptionHeader(data []byte) (*EncryptionHeader, error) {
	if len(data) < EncryptionHeaderSize {
		return nil, fmt.Errorf("data too short for encryption header: %d < %d", len(data), EncryptionHeaderSize)
	}
	version := data[0]
	if version != EncryptionVersion {
		return nil, fmt.Errorf("unsupported encryption version: %d", version)
	}
	var nonce [16]byte
	copy(nonce[:], data[1:17])
	return &EncryptionHeader{
		Version: version,
		Nonce:   nonce,
	}, nil
}

// ToBytes serializes the header to a fixed-size byte array.
func (h *EncryptionHeader) ToBytes() [EncryptionHeaderSize]byte {
	var buf [EncryptionHeaderSize]byte
	buf[0] = h.Version
	copy(buf[1:17], h.Nonce[:])
	return buf
}

// CryptAt encrypts or decrypts data in-place at a given byte offset within the plaintext stream.
// AES-256-CTR is symmetric: encrypt and decrypt are the same operation.
// The offset is the byte offset within the data stream (not counting the header).
func CryptAt(key *[32]byte, nonce *[16]byte, offset uint64, data []byte) {
	if len(data) == 0 {
		return
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(fmt.Sprintf("aes.NewCipher: %v", err)) // key is always 32 bytes
	}

	blockSize := uint64(aes.BlockSize)
	blockOffset := offset / blockSize
	byteOffset := offset % blockSize

	// Compute the adjusted counter: nonce + blockOffset (big-endian 128-bit addition)
	counter := make([]byte, 16)
	copy(counter, nonce[:])
	addToCounter(counter, blockOffset)

	stream := cipher.NewCTR(block, counter)

	// Skip byteOffset bytes of keystream for sub-block alignment
	if byteOffset > 0 {
		skip := make([]byte, byteOffset)
		stream.XORKeyStream(skip, skip)
	}

	stream.XORKeyStream(data, data)
}

// addToCounter adds a uint64 value to a big-endian 128-bit counter.
func addToCounter(counter []byte, val uint64) {
	lo := binary.BigEndian.Uint64(counter[8:16])
	hi := binary.BigEndian.Uint64(counter[0:8])

	newLo := lo + val
	if newLo < lo {
		hi++ // carry
	}

	binary.BigEndian.PutUint64(counter[8:16], newLo)
	binary.BigEndian.PutUint64(counter[0:8], hi)
}

// DecryptFile decrypts a full downloaded file: strips the header and decrypts the remaining bytes.
// Returns the decrypted data without the header.
func DecryptFile(key *[32]byte, encrypted []byte) ([]byte, error) {
	if len(encrypted) < EncryptionHeaderSize {
		return nil, fmt.Errorf("encrypted data too short")
	}
	header, err := ParseEncryptionHeader(encrypted)
	if err != nil {
		return nil, err
	}
	data := make([]byte, len(encrypted)-EncryptionHeaderSize)
	copy(data, encrypted[EncryptionHeaderSize:])
	CryptAt(key, &header.Nonce, 0, data)
	return data, nil
}

// DecryptFragmentData decrypts a single fragment from a multi-fragment encrypted file.
// For the first fragment (isFirstFragment=true): strips the encryption header and decrypts
// the remaining data starting at CTR offset 0.
// For subsequent fragments: decrypts all bytes using the given dataOffset into the plaintext stream.
// Returns the decrypted plaintext and the updated cumulative data offset.
func DecryptFragmentData(key *[32]byte, header *EncryptionHeader, fragmentData []byte, isFirstFragment bool, dataOffset uint64) ([]byte, uint64, error) {
	if isFirstFragment {
		if len(fragmentData) < EncryptionHeaderSize {
			return nil, 0, fmt.Errorf("first fragment too short for encryption header: %d bytes", len(fragmentData))
		}
		dataBytes := make([]byte, len(fragmentData)-EncryptionHeaderSize)
		copy(dataBytes, fragmentData[EncryptionHeaderSize:])
		CryptAt(key, &header.Nonce, 0, dataBytes)
		return dataBytes, uint64(len(dataBytes)), nil
	}

	dataCopy := make([]byte, len(fragmentData))
	copy(dataCopy, fragmentData)
	CryptAt(key, &header.Nonce, dataOffset, dataCopy)
	return dataCopy, dataOffset + uint64(len(dataCopy)), nil
}
