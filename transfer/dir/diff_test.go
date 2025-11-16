package dir_test

import (
	"testing"

	"github.com/0gfoundation/0g-storage-client/transfer/dir"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestDiffIdenticalDirectories(t *testing.T) {
	dir1 := dir.NewDirFsNode("root", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x1"), 100),
		dir.NewFileFsNode("file2.txt", common.HexToHash("0x2"), 200),
	})

	dir2 := dir.NewDirFsNode("root", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x1"), 100),
		dir.NewFileFsNode("file2.txt", common.HexToHash("0x2"), 200),
	})

	diffNode, err := dir.Diff(dir1, dir2)
	assert.NoError(t, err)
	assert.Equal(t, dir.DiffStatusUnchanged, diffNode.Status)
	assert.Equal(t, 2, diffNode.Entries.Len())
}

func TestDiffFileAdded(t *testing.T) {
	dir1 := dir.NewDirFsNode("root", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x1"), 100),
	})

	dir2 := dir.NewDirFsNode("root", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x1"), 100),
		dir.NewFileFsNode("file2.txt", common.HexToHash("0x2"), 200),
	})

	diffNode, err := dir.Diff(dir1, dir2)
	assert.NoError(t, err)
	assert.Equal(t, dir.DiffStatusModified, diffNode.Status)
	assert.Equal(t, 2, diffNode.Entries.Len())

	// Check that the added file is correctly identified
	addedNode := findDiffNodeByName(diffNode, "file2.txt")
	assert.NotNil(t, addedNode)
	assert.Equal(t, dir.DiffStatusAdded, addedNode.Status)
}

func TestDiffFileRemoved(t *testing.T) {
	dir1 := dir.NewDirFsNode("root", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x1"), 100),
		dir.NewFileFsNode("file2.txt", common.HexToHash("0x2"), 200),
	})

	dir2 := dir.NewDirFsNode("root", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x1"), 100),
	})

	diffNode, err := dir.Diff(dir1, dir2)
	assert.NoError(t, err)
	assert.Equal(t, dir.DiffStatusModified, diffNode.Status)
	assert.Equal(t, 2, diffNode.Entries.Len())

	// Check that the removed file is correctly identified
	removedNode := findDiffNodeByName(diffNode, "file2.txt")
	assert.NotNil(t, removedNode)
	assert.Equal(t, dir.DiffStatusRemoved, removedNode.Status)
}

func TestDiffFileModified(t *testing.T) {
	dir1 := dir.NewDirFsNode("root", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x1"), 100),
	})

	dir2 := dir.NewDirFsNode("root", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x2"), 150),
	})

	diffNode, err := dir.Diff(dir1, dir2)
	assert.NoError(t, err)
	assert.Equal(t, dir.DiffStatusModified, diffNode.Status)
	assert.Equal(t, 1, diffNode.Entries.Len())

	// Check that the modified file is correctly identified
	modifiedNode := findDiffNodeByName(diffNode, "file1.txt")
	assert.NotNil(t, modifiedNode)
	assert.Equal(t, dir.DiffStatusModified, modifiedNode.Status)
}

func TestDiffSubdirectoryChanges(t *testing.T) {
	subDir1 := dir.NewDirFsNode("subdir", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x1"), 100),
	})

	subDir2 := dir.NewDirFsNode("subdir", []*dir.FsNode{
		dir.NewFileFsNode("file1.txt", common.HexToHash("0x2"), 150),
	})

	dir1 := dir.NewDirFsNode("root", []*dir.FsNode{subDir1})
	dir2 := dir.NewDirFsNode("root", []*dir.FsNode{subDir2})

	diffNode, err := dir.Diff(dir1, dir2)
	assert.NoError(t, err)
	assert.Equal(t, dir.DiffStatusModified, diffNode.Status)
	assert.Equal(t, 1, diffNode.Entries.Len())

	// Check the subdirectory for changes
	subDirDiffNode := findDiffNodeByName(diffNode, "subdir")
	assert.NotNil(t, subDirDiffNode)
	assert.Equal(t, dir.DiffStatusModified, subDirDiffNode.Status)

	// Check that the modified file is correctly identified
	modifiedNode := findDiffNodeByName(subDirDiffNode, "file1.txt")
	assert.NotNil(t, modifiedNode)
	assert.Equal(t, dir.DiffStatusModified, modifiedNode.Status)
}

// Utility function to find a DiffNode by name
func findDiffNodeByName(root *dir.DiffNode, name string) *dir.DiffNode {
	var result *dir.DiffNode
	root.Entries.Ascend(func(n *dir.DiffNode) bool {
		if n.Node.Name == name {
			result = n
			return false
		}
		return true
	})
	return result
}
