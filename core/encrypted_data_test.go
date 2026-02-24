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

func TestEncryptedDataSplitFragmentCount(t *testing.T) {
	original := make([]byte, 1000)
	for i := range original {
		original[i] = byte(i % 256)
	}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	// encrypted size = 1000 + 17 = 1017 bytes
	// fragment size = 512 → ceil(1017/512) = 2 fragments
	fragments := encrypted.Split(512)
	assert.Equal(t, 2, len(fragments))
	assert.Equal(t, int64(512), fragments[0].Size())
	assert.Equal(t, int64(505), fragments[1].Size())
}

func TestEncryptedDataSplitSingleFragment(t *testing.T) {
	original := make([]byte, 100)
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	// Fragment size larger than encrypted data → no split
	fragments := encrypted.Split(1024)
	assert.Equal(t, 1, len(fragments))
	assert.Equal(t, encrypted, fragments[0])
}

func TestEncryptedDataSplitReadConsistency(t *testing.T) {
	original := make([]byte, 2000)
	for i := range original {
		original[i] = byte(i % 251)
	}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	// Read full encrypted stream
	fullBuf := make([]byte, int(encrypted.Size()))
	n, err := encrypted.Read(fullBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, int(encrypted.Size()), n)

	// Split and read fragments, then concatenate
	fragmentSize := int64(512)
	fragments := encrypted.Split(fragmentSize)
	require.True(t, len(fragments) > 1)

	reconstructed := make([]byte, 0, int(encrypted.Size()))
	for _, frag := range fragments {
		buf := make([]byte, int(frag.Size()))
		n, err := frag.Read(buf, 0)
		require.NoError(t, err)
		assert.Equal(t, int(frag.Size()), n)
		reconstructed = append(reconstructed, buf[:n]...)
	}

	assert.Equal(t, fullBuf, reconstructed)
}

func TestEncryptedDataSplitDecryptRoundtrip(t *testing.T) {
	original := make([]byte, 3000)
	for i := range original {
		original[i] = byte(i % 251)
	}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	fragmentSize := int64(1024)
	fragments := encrypted.Split(fragmentSize)
	require.True(t, len(fragments) > 1)

	// Read each fragment as raw encrypted bytes (simulates upload/download)
	fragmentDatas := make([][]byte, len(fragments))
	for i, frag := range fragments {
		buf := make([]byte, int(frag.Size()))
		n, err := frag.Read(buf, 0)
		require.NoError(t, err)
		fragmentDatas[i] = buf[:n]
	}

	// Decrypt fragments using DecryptFragmentData (simulates download decryption)
	header, err := ParseEncryptionHeader(fragmentDatas[0][:EncryptionHeaderSize])
	require.NoError(t, err)

	decrypted := make([]byte, 0)
	var cumulativeOffset uint64
	for i, fragData := range fragmentDatas {
		plaintext, newOffset, err := DecryptFragmentData(&key, header, fragData, i == 0, cumulativeOffset)
		require.NoError(t, err)
		decrypted = append(decrypted, plaintext...)
		cumulativeOffset = newOffset
	}

	assert.Equal(t, original, decrypted)
}

func TestEncryptedDataFragmentMerkleTree(t *testing.T) {
	original := make([]byte, 2000)
	for i := range original {
		original[i] = byte(i % 251)
	}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	fragments := encrypted.Split(1024)
	require.True(t, len(fragments) > 1)

	// Each fragment should produce a valid independent merkle tree
	for i, frag := range fragments {
		tree, err := MerkleTree(frag)
		require.NoError(t, err, "fragment %d merkle tree failed", i)
		assert.NotEqual(t, [32]byte{}, tree.Root(), "fragment %d has zero root", i)
	}
}

func TestEncryptedDataSplitMultipleSizes(t *testing.T) {
	sizes := []int{256, 512, 1023, 1024, 1025, 2000, 5000}
	fragmentSizes := []int64{256, 512, 1024}

	for _, size := range sizes {
		for _, fragSize := range fragmentSizes {
			t.Run(fmt.Sprintf("size_%d_frag_%d", size, fragSize), func(t *testing.T) {
				original := make([]byte, size)
				for i := range original {
					original[i] = byte(i % 251)
				}
				inner, err := NewDataInMemory(original)
				require.NoError(t, err)

				key := [32]byte{}
				for i := range key {
					key[i] = 0x42
				}
				encrypted, err := NewEncryptedData(inner, key)
				require.NoError(t, err)

				fragments := encrypted.Split(fragSize)

				// Verify total size
				totalSize := int64(0)
				for _, f := range fragments {
					totalSize += f.Size()
				}
				assert.Equal(t, encrypted.Size(), totalSize)

				// Verify read consistency and decrypt roundtrip
				fragmentDatas := make([][]byte, len(fragments))
				for i, frag := range fragments {
					buf := make([]byte, int(frag.Size()))
					n, err := frag.Read(buf, 0)
					require.NoError(t, err)
					fragmentDatas[i] = buf[:n]
				}

				header, err := ParseEncryptionHeader(fragmentDatas[0][:EncryptionHeaderSize])
				require.NoError(t, err)

				decrypted := make([]byte, 0)
				var offset uint64
				for i, fragData := range fragmentDatas {
					plaintext, newOffset, err := DecryptFragmentData(&key, header, fragData, i == 0, offset)
					require.NoError(t, err)
					decrypted = append(decrypted, plaintext...)
					offset = newOffset
				}

				assert.Equal(t, original, decrypted, "decrypt roundtrip failed for size %d frag %d", size, fragSize)
			})
		}
	}
}

func TestEncryptedDataOneByteRoundtrip(t *testing.T) {
	original := []byte{0x42}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	assert.Equal(t, int64(1+EncryptionHeaderSize), encrypted.Size())

	// Read full encrypted stream
	buf := make([]byte, int(encrypted.Size()))
	n, err := encrypted.Read(buf, 0)
	require.NoError(t, err)
	assert.Equal(t, int(encrypted.Size()), n)

	// Decrypt and verify
	decrypted, err := DecryptFile(&key, buf)
	require.NoError(t, err)
	assert.Equal(t, original, decrypted)
}

func TestEncryptedDataReadPastEnd(t *testing.T) {
	original := make([]byte, 100)
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	// Read at exact end → should return 0 bytes
	buf := make([]byte, 10)
	n, err := encrypted.Read(buf, encrypted.Size())
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	// Read past end → should return 0 bytes
	n, err = encrypted.Read(buf, encrypted.Size()+100)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	// Read at negative offset → should return 0 bytes
	n, err = encrypted.Read(buf, -1)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestEncryptedDataExactFragmentBoundary(t *testing.T) {
	// Choose data size so encrypted size (data + 17) exactly equals fragment size
	fragSize := int64(256)
	dataSize := int(fragSize - int64(EncryptionHeaderSize)) // 239 bytes

	original := make([]byte, dataSize)
	for i := range original {
		original[i] = byte(i % 251)
	}
	inner, err := NewDataInMemory(original)
	require.NoError(t, err)

	key := [32]byte{}
	for i := range key {
		key[i] = 0x42
	}
	encrypted, err := NewEncryptedData(inner, key)
	require.NoError(t, err)

	assert.Equal(t, fragSize, encrypted.Size())

	// Split should return single fragment (encrypted data fits exactly)
	fragments := encrypted.Split(fragSize)
	assert.Equal(t, 1, len(fragments))

	// Full roundtrip
	buf := make([]byte, int(encrypted.Size()))
	n, err := encrypted.Read(buf, 0)
	require.NoError(t, err)
	assert.Equal(t, int(encrypted.Size()), n)

	decrypted, err := DecryptFile(&key, buf)
	require.NoError(t, err)
	assert.Equal(t, original, decrypted)
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
