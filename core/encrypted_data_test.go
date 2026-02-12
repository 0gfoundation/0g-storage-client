package core

import (
	"fmt"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptedDataSize(t *testing.T) {
	original := make([]byte, 1000)
	for i := range original {
		original[i] = 1
	}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	assert.Equal(t, inner.Size()+int64(EncryptionHeaderSize), encrypted.Size())
}

func TestEncryptedDataReadHeader(t *testing.T) {
	original := make([]byte, 100)
	for i := range original {
		original[i] = 1
	}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	// Read just the header
	buf := make([]byte, EncryptionHeaderSize)
	n, err := encrypted.Read(buf, 0)
	require.NoError(t, err)
	assert.Equal(t, EncryptionHeaderSize, n)
	assert.Equal(t, byte(EncryptionVersion), buf[0])
	assert.Equal(t, encrypted.Header().Nonce[:], buf[1:17])
}

func TestEncryptedDataRoundtrip(t *testing.T) {
	original := []byte("hello world encryption test with EncryptedData wrapper")
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	// Read full encrypted stream
	encryptedSize := int(encrypted.Size())
	encryptedBuf := make([]byte, encryptedSize)
	n, err := encrypted.Read(encryptedBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, encryptedSize, n)

	// Decrypt and verify
	decrypted, err := DecryptFile(&key, encryptedBuf)
	require.NoError(t, err)
	assert.Equal(t, original, decrypted)
}

func TestEncryptedDataReadAtOffset(t *testing.T) {
	original := make([]byte, 500)
	for i := range original {
		original[i] = 0xAB
	}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	// Read full encrypted data
	encryptedSize := int(encrypted.Size())
	fullBuf := make([]byte, encryptedSize)
	encrypted.Read(fullBuf, 0)

	// Read in two parts and verify they match
	split := 100
	part1 := make([]byte, split)
	part2 := make([]byte, encryptedSize-split)
	encrypted.Read(part1, 0)
	encrypted.Read(part2, int64(split))

	assert.Equal(t, fullBuf[:split], part1)
	assert.Equal(t, fullBuf[split:], part2)
}

func TestEncryptedDataMerkleTreeConsistency(t *testing.T) {
	// Verify that building a merkle tree on encrypted data works correctly
	// and that the same encrypted data produces the same merkle root
	original := make([]byte, 300)
	for i := range original {
		original[i] = 0x55
	}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	// Build merkle tree on encrypted data
	tree, err := MerkleTree(encrypted)
	require.NoError(t, err)
	assert.NotEmpty(t, tree.Root())

	// Read the full encrypted stream and build merkle tree on it as in-memory data
	encryptedSize := int(encrypted.Size())
	encryptedBuf := make([]byte, encryptedSize)
	n, err := encrypted.Read(encryptedBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, encryptedSize, n)

	inMem, err := NewDataInMemory(encryptedBuf)
	require.NoError(t, err)
	inMemTree, err := MerkleTree(inMem)
	require.NoError(t, err)

	// Both merkle trees should produce the same root
	assert.Equal(t, tree.Root(), inMemTree.Root())
}

// TestEncryptedFileSubmissionRootConsistency verifies that MerkleTree root and
// CreateSubmission root match when EncryptedData wraps a File (not DataInMemory).
// This catches the bug where File.Read returned 0 on non-EOF reads, causing
// EncryptedData to skip encryption for partial reads (e.g., 1023-byte files).
func TestEncryptedFileSubmissionRootConsistency(t *testing.T) {
	sizes := []int{1023, 1024, 1025, 256*4 - 17, 256*4 - 16, 256 * 5}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			// Write data to a temp file
			original := make([]byte, size)
			for i := range original {
				original[i] = byte(i % 251)
			}
			tmpFile, err := os.CreateTemp("", "encrypted_test_*")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())
			_, err = tmpFile.Write(original)
			require.NoError(t, err)
			tmpFile.Close()

			// Open as File (IterableData)
			file, err := Open(tmpFile.Name())
			require.NoError(t, err)
			defer file.Close()

			key := [32]byte{}
			for i := range key {
				key[i] = 0x42
			}
			encrypted, err := NewEncryptedData(file, key)
			require.NoError(t, err)

			// Build MerkleTree root (reads full segments, hits EOF)
			tree, err := MerkleTree(encrypted)
			require.NoError(t, err)

			// Build submission root (reads in smaller chunks per node)
			flow := NewFlow(encrypted, nil)
			submission, err := flow.CreateSubmission(common.Address{})
			require.NoError(t, err)

			// These must match; if File.Read returns wrong count,
			// encryption is skipped in CreateSubmission reads and roots diverge
			assert.Equal(t, tree.Root(), submission.Root(),
				"MerkleTree root and Submission root must match for file size %d", size)
		})
	}
}
