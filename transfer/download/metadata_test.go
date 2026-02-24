package download

import (
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

var testHash = common.HexToHash("0xc8ad6d515dddd96e2e3cf28735944d631621d89f78f3379ffcd0262a6d1f7092")

func TestMetadataSerde(t *testing.T) {
	md := Metadata{
		Root:   testHash,
		Size:   1234567,
		Offset: 456,
	}

	encoded := md.Serialize()

	md2, err := DeserializeMetadata(encoded)
	assert.NoError(t, err)
	assert.Equal(t, md, *md2)
}

func TestMetadata(t *testing.T) {
	// create tmp file to test
	tmpFile, err := os.CreateTemp(os.TempDir(), "0g-storage-client-test-*")
	assert.NoError(t, err)
	tmpFilename := tmpFile.Name()

	// remove tmp file after test
	defer func() {
		assert.NoError(t, os.Remove(tmpFilename))
	}()

	// extend file with metadata
	md := NewMetadata(testHash, 12345)
	assert.NoError(t, md.Extend(tmpFile))

	// check file size after metadata extended
	info, err := tmpFile.Stat()
	assert.NoError(t, err)
	assert.Equal(t, md.Size+MetadataSize, info.Size())

	// write some data and metadata updated
	data := []byte("hello, world")
	assert.NoError(t, md.Write(tmpFile, data))
	assert.Equal(t, int64(len(data)), md.Offset)

	// close and reopen file
	assert.NoError(t, tmpFile.Close())
	file2, err := os.Open(tmpFilename)
	assert.NoError(t, err)
	defer file2.Close()

	// load metadata from file
	md2, err := LoadMetadata(file2)
	assert.NoError(t, err)
	assert.Equal(t, *md, *md2)
}
