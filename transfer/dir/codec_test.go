package dir_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/0gfoundation/0g-storage-client/transfer/dir"
)

func TestEncodeDecodeFsNode(t *testing.T) {
	// Create a sample FsNode structure
	rootNode := dir.FsNode{
		Name: "root",
		Type: dir.FileTypeDirectory,
		Entries: []*dir.FsNode{
			{
				Name: "file1.txt",
				Type: dir.FileTypeFile,
				Root: "0xabc123",
				Size: 1024,
			},
			{
				Name: "symlink",
				Type: dir.FileTypeSymbolic,
				Link: "/path/to/target",
			},
			{
				Name: "subdir",
				Type: dir.FileTypeDirectory,
				Entries: []*dir.FsNode{
					{
						Name: "file2.txt",
						Type: dir.FileTypeFile,
						Root: "0xdef456",
						Size: 2048,
					},
				},
			},
		},
	}

	// Encode the FsNode to bytes
	encodedData, err := rootNode.MarshalBinary()
	if err != nil {
		t.Fatalf("Binary marshal failed: %v", err)
	}

	// Decode the bytes back into an FsNode
	var decodedNode dir.FsNode
	err = decodedNode.UnmarshalBinary(encodedData)
	if err != nil {
		t.Fatalf("Binary unmarshal failed: %v", err)
	}

	// Compare the original and decoded FsNode to ensure they are the same
	if !reflect.DeepEqual(rootNode, decodedNode) {
		t.Errorf("Expected `FsNode` to be equal, but got %v and %v", rootNode, decodedNode)
	}
}

func TestInvalidMagicBytes(t *testing.T) {
	// Create a sample FsNode structure and encode it
	originalNode := dir.FsNode{
		Name: "testfile.txt",
		Type: dir.FileTypeFile,
		Root: "0x1234",
		Size: 1024,
	}
	encodedData, err := originalNode.MarshalBinary()
	if err != nil {
		t.Fatalf("EncodeFsNode failed: %v", err)
	}

	// Modify the magic bytes to simulate corruption
	encodedData[0] ^= 0xFF

	// Attempt to decode the corrupted data
	var decodedNode dir.FsNode
	err = decodedNode.UnmarshalBinary(encodedData)
	if err == nil || err.Error() != "invalid magic bytes" {
		t.Fatalf("expected error 'invalid magic bytes', got %v", err)
	}
}

func TestInvalidVersion(t *testing.T) {
	// Create a sample FsNode structure and encode it
	originalNode := dir.FsNode{
		Name: "testfile.txt",
		Type: dir.FileTypeFile,
		Root: "0x1234",
		Size: 1024,
	}
	encodedData, err := originalNode.MarshalBinary()
	if err != nil {
		t.Fatalf("EncodeFsNode failed: %v", err)
	}

	// Modify the version bytes to simulate an unsupported version
	encodedData[len(dir.CodecMagicBytes)] ^= 0xFF

	// Attempt to decode the data with the modified version
	var decodedNode dir.FsNode
	err = decodedNode.UnmarshalBinary(encodedData)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("unsupported codec version")) {
		t.Fatalf("expected version error, got %v", err)
	}
}
