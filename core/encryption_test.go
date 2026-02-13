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

func TestDecryptSegmentZero(t *testing.T) {
	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	header, err := NewEncryptionHeader()
	require.NoError(t, err)
	segmentSize := uint64(256 * 1024) // 256KB

	// Build segment 0: header + encrypted plaintext
	plaintext := make([]byte, int(segmentSize)-EncryptionHeaderSize)
	for i := range plaintext {
		plaintext[i] = 0xAB
	}
	encrypted := make([]byte, len(plaintext))
	copy(encrypted, plaintext)
	CryptAt(&key, &header.Nonce, 0, encrypted)

	headerBytes := header.ToBytes()
	segmentData := make([]byte, 0, segmentSize)
	segmentData = append(segmentData, headerBytes[:]...)
	segmentData = append(segmentData, encrypted...)
	assert.Equal(t, int(segmentSize), len(segmentData))

	// decrypt_segment for segment 0 returns plaintext without header
	decrypted := DecryptSegment(&key, 0, segmentSize, segmentData, header)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptSegmentNonzero(t *testing.T) {
	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	header, err := NewEncryptionHeader()
	require.NoError(t, err)
	segmentSize := uint64(256 * 1024)

	// Segment 1's data offset is segmentSize - HeaderSize
	dataOffset := segmentSize - uint64(EncryptionHeaderSize)
	plaintext := make([]byte, segmentSize)
	for i := range plaintext {
		plaintext[i] = 0xCD
	}
	encrypted := make([]byte, len(plaintext))
	copy(encrypted, plaintext)
	CryptAt(&key, &header.Nonce, dataOffset, encrypted)

	decrypted := DecryptSegment(&key, 1, segmentSize, encrypted, header)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptSegmentPaddedPreservesHeader(t *testing.T) {
	// Simulates what download_segment_padded does for segment 0
	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	header, err := NewEncryptionHeader()
	require.NoError(t, err)
	segmentSize := uint64(256 * 1024)

	plaintext := make([]byte, int(segmentSize)-EncryptionHeaderSize)
	for i := range plaintext {
		plaintext[i] = 0xEF
	}
	encrypted := make([]byte, len(plaintext))
	copy(encrypted, plaintext)
	CryptAt(&key, &header.Nonce, 0, encrypted)

	headerBytes := header.ToBytes()
	rawSegment := make([]byte, 0, segmentSize)
	rawSegment = append(rawSegment, headerBytes[:]...)
	rawSegment = append(rawSegment, encrypted...)

	// Decrypt in-place after header (what download_segment_padded does)
	result := make([]byte, len(rawSegment))
	copy(result, rawSegment)
	CryptAt(&key, &header.Nonce, 0, result[EncryptionHeaderSize:])

	// Header preserved, data decrypted
	assert.Equal(t, headerBytes[:], result[:EncryptionHeaderSize])
	assert.Equal(t, plaintext, result[EncryptionHeaderSize:])
	assert.Equal(t, int(segmentSize), len(result))
}

func TestEncryptDecryptBytes(t *testing.T) {
	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"binary", []byte{0x00, 0xff, 0x42, 0x13}},
		{"long", make([]byte, 10000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptBytes(&key, tt.data)
			require.NoError(t, err)
			assert.Equal(t, EncryptionHeaderSize+len(tt.data), len(encrypted))

			decrypted, err := DecryptBytes(&key, encrypted)
			require.NoError(t, err)
			assert.Equal(t, tt.data, decrypted)
		})
	}
}

func TestMultiSegmentDecryptMatchesFullFile(t *testing.T) {
	// Encrypt a file spanning 2 segments, decrypt per-segment, verify matches full decrypt
	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	header, err := NewEncryptionHeader()
	require.NoError(t, err)
	segmentSize := uint64(256) // Small for testing

	plaintext := make([]byte, int(segmentSize)*2-EncryptionHeaderSize)
	for i := range plaintext {
		plaintext[i] = 0x77
	}
	fullEncrypted := make([]byte, len(plaintext))
	copy(fullEncrypted, plaintext)
	CryptAt(&key, &header.Nonce, 0, fullEncrypted)

	// Build encrypted file
	headerBytes := header.ToBytes()
	fileData := make([]byte, 0, EncryptionHeaderSize+len(fullEncrypted))
	fileData = append(fileData, headerBytes[:]...)
	fileData = append(fileData, fullEncrypted...)

	// Segment 0: first segmentSize bytes of the file
	seg0Data := fileData[:segmentSize]
	seg0Decrypted := DecryptSegment(&key, 0, segmentSize, seg0Data, header)

	// Segment 1: remaining bytes
	seg1Data := fileData[segmentSize:]
	seg1Decrypted := DecryptSegment(&key, 1, segmentSize, seg1Data, header)

	// Concatenated decrypted segments should equal original plaintext
	combined := make([]byte, 0, len(plaintext))
	combined = append(combined, seg0Decrypted...)
	combined = append(combined, seg1Decrypted...)
	assert.Equal(t, plaintext, combined)
}
