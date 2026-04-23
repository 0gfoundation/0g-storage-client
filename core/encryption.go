package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const (
	// SymmetricVersion identifies v1 headers: user-supplied 32-byte AES-256-CTR key.
	SymmetricVersion = 1
	// SymmetricHeaderSize is the v1 header size: 1 byte version + 16 bytes nonce.
	SymmetricHeaderSize = 17

	// ECIESVersion identifies v2 headers: ECIES over secp256k1 with AES-256-CTR bulk cipher.
	ECIESVersion = 2
	// ECIESHeaderSize is the v2 header size: 1 byte version + 33 bytes compressed ephemeral pubkey + 16 bytes nonce.
	ECIESHeaderSize = 1 + EphemeralPubKeySize + 16
)

// EncryptionHeader stores the metadata needed to decrypt a file.
//
//	v1 (SymmetricVersion): Version + Nonce only. Caller supplies the AES-256 key out-of-band.
//	v2 (ECIESVersion):     Version + EphemeralPub + Nonce. Caller derives the AES-256 key
//	                       from a recipient private key via DeriveECIESDecryptKey.
type EncryptionHeader struct {
	Version      uint8
	Nonce        [16]byte
	EphemeralPub [EphemeralPubKeySize]byte // zero for v1
}

// NewEncryptionHeader creates a v1 header with a random nonce.
func NewEncryptionHeader() (*EncryptionHeader, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	return &EncryptionHeader{
		Version: SymmetricVersion,
		Nonce:   nonce,
	}, nil
}

// NewECIESEncryptionHeader creates a v2 header for the given recipient public key and
// returns both the header (to be serialized into the encrypted stream) and the 32-byte
// AES key the caller must use with CryptAt.
func NewECIESEncryptionHeader(recipientPub *ecdsa.PublicKey) (*EncryptionHeader, [32]byte, error) {
	var emptyKey [32]byte
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, emptyKey, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	aesKey, ephemeralPub, err := DeriveECIESEncryptKey(recipientPub)
	if err != nil {
		return nil, emptyKey, err
	}
	return &EncryptionHeader{
		Version:      ECIESVersion,
		Nonce:        nonce,
		EphemeralPub: ephemeralPub,
	}, aesKey, nil
}

// ParseEncryptionHeader extracts an encryption header from the given data. The caller
// may then call Size() to learn how many header bytes to skip before the ciphertext.
func ParseEncryptionHeader(data []byte) (*EncryptionHeader, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("data too short for encryption header: %d", len(data))
	}
	version := data[0]
	switch version {
	case SymmetricVersion:
		if len(data) < SymmetricHeaderSize {
			return nil, fmt.Errorf("data too short for v1 encryption header: %d < %d", len(data), SymmetricHeaderSize)
		}
		h := &EncryptionHeader{Version: version}
		copy(h.Nonce[:], data[1:17])
		return h, nil
	case ECIESVersion:
		if len(data) < ECIESHeaderSize {
			return nil, fmt.Errorf("data too short for v2 encryption header: %d < %d", len(data), ECIESHeaderSize)
		}
		h := &EncryptionHeader{Version: version}
		copy(h.EphemeralPub[:], data[1:1+EphemeralPubKeySize])
		copy(h.Nonce[:], data[1+EphemeralPubKeySize:1+EphemeralPubKeySize+16])
		return h, nil
	default:
		return nil, fmt.Errorf("unsupported encryption version: %d", version)
	}
}

// Size returns the on-wire size of this header (17 for v1, 50 for v2).
func (h *EncryptionHeader) Size() int {
	switch h.Version {
	case ECIESVersion:
		return ECIESHeaderSize
	default:
		return SymmetricHeaderSize
	}
}

// ToBytes serializes the header. Length depends on Version (see Size).
func (h *EncryptionHeader) ToBytes() []byte {
	switch h.Version {
	case ECIESVersion:
		buf := make([]byte, ECIESHeaderSize)
		buf[0] = h.Version
		copy(buf[1:1+EphemeralPubKeySize], h.EphemeralPub[:])
		copy(buf[1+EphemeralPubKeySize:], h.Nonce[:])
		return buf
	default:
		buf := make([]byte, SymmetricHeaderSize)
		buf[0] = h.Version
		copy(buf[1:17], h.Nonce[:])
		return buf
	}
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
	header, err := ParseEncryptionHeader(encrypted)
	if err != nil {
		return nil, err
	}
	headerSize := header.Size()
	data := make([]byte, len(encrypted)-headerSize)
	copy(data, encrypted[headerSize:])
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
		headerSize := header.Size()
		if len(fragmentData) < headerSize {
			return nil, 0, fmt.Errorf("first fragment too short for encryption header: %d bytes", len(fragmentData))
		}
		dataBytes := make([]byte, len(fragmentData)-headerSize)
		copy(dataBytes, fragmentData[headerSize:])
		CryptAt(key, &header.Nonce, 0, dataBytes)
		return dataBytes, uint64(len(dataBytes)), nil
	}

	dataCopy := make([]byte, len(fragmentData))
	copy(dataCopy, fragmentData)
	CryptAt(key, &header.Nonce, dataOffset, dataCopy)
	return dataCopy, dataOffset + uint64(len(dataCopy)), nil
}
