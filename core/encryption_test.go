package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderRoundtrip(t *testing.T) {
	header, err := NewEncryptionHeader()
	require.NoError(t, err)

	bytes := header.ToBytes()
	parsed, err := ParseEncryptionHeader(bytes[:])
	require.NoError(t, err)

	assert.Equal(t, uint8(EncryptionVersion), parsed.Version)
	assert.Equal(t, header.Nonce, parsed.Nonce)
}

func TestCryptRoundtrip(t *testing.T) {
	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	nonce := [16]byte{}
	for i := range nonce {
		nonce[i] = 0x13
	}
	original := []byte("hello world encryption test data")
	buf := make([]byte, len(original))
	copy(buf, original)

	// Encrypt
	CryptAt(&key, &nonce, 0, buf)
	assert.NotEqual(t, original, buf)

	// Decrypt (same operation for CTR)
	CryptAt(&key, &nonce, 0, buf)
	assert.Equal(t, original, buf)
}

func TestCryptAtOffset(t *testing.T) {
	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	nonce := [16]byte{}
	for i := range nonce {
		nonce[i] = 0x13
	}
	original := make([]byte, 100)

	// Encrypt full
	full := make([]byte, 100)
	copy(full, original)
	CryptAt(&key, &nonce, 0, full)

	// Encrypt in two parts at different offsets
	part1 := make([]byte, 50)
	part2 := make([]byte, 50)
	copy(part1, original[:50])
	copy(part2, original[50:])
	CryptAt(&key, &nonce, 0, part1)
	CryptAt(&key, &nonce, 50, part2)

	assert.Equal(t, full[:50], part1)
	assert.Equal(t, full[50:], part2)
}

func TestDecryptFileTooShort(t *testing.T) {
	key := [32]byte{}
	// Data shorter than header
	_, err := DecryptFile(&key, []byte{0x01, 0x02})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDecryptFileWrongVersion(t *testing.T) {
	key := [32]byte{}
	// Header with wrong version byte (0xFF), followed by 16 nonce bytes + 1 data byte
	data := make([]byte, EncryptionHeaderSize+1)
	data[0] = 0xFF // wrong version
	_, err := DecryptFile(&key, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported encryption version")
}

func TestDecryptFragmentDataFirstFragmentTooShort(t *testing.T) {
	key := [32]byte{}
	header := &EncryptionHeader{Version: EncryptionVersion}
	// First fragment shorter than header size
	_, _, err := DecryptFragmentData(&key, header, []byte{0x01}, true, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "first fragment too short")
}

func TestDecryptFile(t *testing.T) {
	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	original := []byte("test data for encryption")

	// Build encrypted file: header + encrypted data
	header, err := NewEncryptionHeader()
	require.NoError(t, err)

	encryptedData := make([]byte, len(original))
	copy(encryptedData, original)
	CryptAt(&key, &header.Nonce, 0, encryptedData)

	headerBytes := header.ToBytes()
	encryptedFile := make([]byte, 0, EncryptionHeaderSize+len(encryptedData))
	encryptedFile = append(encryptedFile, headerBytes[:]...)
	encryptedFile = append(encryptedFile, encryptedData...)

	// Decrypt
	decrypted, err := DecryptFile(&key, encryptedFile)
	require.NoError(t, err)
	assert.Equal(t, original, decrypted)
}
