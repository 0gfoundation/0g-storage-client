package dir_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/transfer/dir"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestNewDirFsNode(t *testing.T) {
	child1 := &dir.FsNode{Name: "child1", Root: "0x01"}
	child2 := &dir.FsNode{Name: "child2", Root: "0x02"}
	children := []*dir.FsNode{child1, child2}

	node := dir.NewDirFsNode("root", children)

	assert.Equal(t, "root", node.Name)
	assert.Equal(t, dir.FileTypeDirectory, node.Type)
	assert.Len(t, node.Entries, 2)
	assert.Equal(t, "child1", node.Entries[0].Name)
	assert.Equal(t, "child2", node.Entries[1].Name)
}

func TestNewFileFsNode(t *testing.T) {
	hash := common.HexToHash("0x12345")
	node := dir.NewFileFsNode("file.txt", hash, 1024)

	assert.Equal(t, "file.txt", node.Name)
	assert.Equal(t, dir.FileTypeFile, node.Type)
	assert.Equal(t, hash.Hex(), node.Root)
	assert.Equal(t, int64(1024), node.Size)
}

func TestNewSymbolicFsNode(t *testing.T) {
	link := "/some/path"
	node := dir.NewSymbolicFsNode("symlink", link)

	assert.Equal(t, "symlink", node.Name)
	assert.Equal(t, dir.FileTypeSymbolic, node.Type)
	assert.Equal(t, link, node.Link)
}

func TestSearch(t *testing.T) {
	child1 := &dir.FsNode{Name: "child1"}
	child2 := &dir.FsNode{Name: "child2"}
	children := []*dir.FsNode{child1, child2}

	node := dir.NewDirFsNode("root", children)

	result, found := node.Search("child1")
	assert.True(t, found)
	assert.Equal(t, child1, result)

	result, found = node.Search("nonexistent")
	assert.False(t, found)
	assert.Nil(t, result)
}

func TestFsNodeEqual(t *testing.T) {
	tests := []struct {
		name     string
		node1    *dir.FsNode
		node2    *dir.FsNode
		expected bool
	}{
		{
			name:     "Equal Files",
			node1:    &dir.FsNode{Type: dir.FileTypeFile, Name: "file1", Root: "0xabc123", Size: 100},
			node2:    &dir.FsNode{Type: dir.FileTypeFile, Name: "file1", Root: "0xabc123", Size: 100},
			expected: true,
		},
		{
			name:     "Different File Hash",
			node1:    &dir.FsNode{Type: dir.FileTypeFile, Name: "file1", Root: "0xabc123", Size: 100},
			node2:    &dir.FsNode{Type: dir.FileTypeFile, Name: "file1", Root: "0xdef456", Size: 100},
			expected: false,
		},
		{
			name:     "Equal Symbolic Links",
			node1:    &dir.FsNode{Type: dir.FileTypeSymbolic, Name: "link1", Link: "/path/to/target"},
			node2:    &dir.FsNode{Type: dir.FileTypeSymbolic, Name: "link1", Link: "/path/to/target"},
			expected: true,
		},
		{
			name:     "Different Symbolic Link Target",
			node1:    &dir.FsNode{Type: dir.FileTypeSymbolic, Name: "link1", Link: "/path/to/target1"},
			node2:    &dir.FsNode{Type: dir.FileTypeSymbolic, Name: "link1", Link: "/path/to/target2"},
			expected: false,
		},
		{
			name:     "Equal Empty Directories",
			node1:    &dir.FsNode{Type: dir.FileTypeDirectory, Name: "dir1", Entries: []*dir.FsNode{}},
			node2:    &dir.FsNode{Type: dir.FileTypeDirectory, Name: "dir1", Entries: []*dir.FsNode{}},
			expected: true,
		},
		{
			name: "Equal Directories with Same Entries",
			node1: &dir.FsNode{
				Type: dir.FileTypeDirectory, Name: "dir1", Entries: []*dir.FsNode{
					{Type: dir.FileTypeFile, Name: "file1", Root: "0xabc123", Size: 100},
					{Type: dir.FileTypeSymbolic, Name: "link1", Link: "/path/to/target"},
				},
			},
			node2: &dir.FsNode{
				Type: dir.FileTypeDirectory, Name: "dir1", Entries: []*dir.FsNode{
					{Type: dir.FileTypeFile, Name: "file1", Root: "0xabc123", Size: 100},
					{Type: dir.FileTypeSymbolic, Name: "link1", Link: "/path/to/target"},
				},
			},
			expected: true,
		},
		{
			name: "Different Directories with Different Entries",
			node1: &dir.FsNode{
				Type: dir.FileTypeDirectory, Name: "dir1", Entries: []*dir.FsNode{
					{Type: dir.FileTypeFile, Name: "file1", Root: "0xabc123", Size: 100},
				},
			},
			node2: &dir.FsNode{
				Type: dir.FileTypeDirectory, Name: "dir1", Entries: []*dir.FsNode{
					{Type: dir.FileTypeFile, Name: "file2", Root: "0xdef456", Size: 100},
				},
			},
			expected: false,
		},
		{
			name: "Different Node Types",
			node1: &dir.FsNode{
				Type: dir.FileTypeFile, Name: "file1", Root: "0xabc123", Size: 100},
			node2: &dir.FsNode{
				Type: dir.FileTypeDirectory, Name: "file1", Entries: []*dir.FsNode{}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.node1.Equal(tt.node2)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBuildFileTree(t *testing.T) {
	tempDir := t.TempDir()

	// create test file
	filePath := filepath.Join(tempDir, "testfile.txt")
	err := os.WriteFile(filePath, []byte("content"), 0644)
	assert.NoError(t, err)

	// create symbolic link
	linkPath := filepath.Join(tempDir, "symlink")
	err = os.Symlink(filePath, linkPath)
	assert.NoError(t, err)

	// Create a subdirectory
	subDirPath := filepath.Join(tempDir, "subdir")
	err = os.Mkdir(subDirPath, 0755)
	assert.NoError(t, err)

	// Create a test file inside the subdirectory
	subDirFilePath := filepath.Join(subDirPath, "subdirfile.txt")
	err = os.WriteFile(subDirFilePath, []byte("subdir content"), 0644)
	assert.NoError(t, err)

	// Build the file tree
	var root *dir.FsNode
	t.Run("test building file tree", func(t *testing.T) {
		root, err = dir.BuildFileTree(tempDir)
		assert.NoError(t, err)
		assert.Equal(t, dir.FileTypeDirectory, root.Type)
		assert.Equal(t, root.Name, "/")
		assert.Len(t, root.Entries, 3) // "testfile.txt", "symlink", "subdir"
	})

	t.Run("test subdir file node", func(t *testing.T) {
		subDirNode, found := root.Search("subdir")
		assert.True(t, found)
		assert.Equal(t, dir.FileTypeDirectory, subDirNode.Type)
		assert.Len(t, subDirNode.Entries, 1) // "subdirfile.txt"

		subDirFileNode, found := subDirNode.Search("subdirfile.txt")
		assert.True(t, found)
		assert.Equal(t, dir.FileTypeFile, subDirFileNode.Type)
	})

	t.Run("test file node", func(t *testing.T) {
		node, found := root.Search("testfile.txt")
		assert.True(t, found)
		// Calculate expected hash using core.MerkleRoot
		expectedHash, err := core.MerkleRoot(filePath)
		assert.NoError(t, err)
		assert.Equal(t, expectedHash.Hex(), node.Root)
	})

	t.Run("test symbolic link node", func(t *testing.T) {
		node, found := root.Search("symlink")
		assert.True(t, found)
		assert.Equal(t, dir.FileTypeSymbolic, node.Type)
		assert.Equal(t, filePath, node.Link)
	})
}

func TestTraverse(t *testing.T) {
	// Create a mock directory structure
	root := &dir.FsNode{
		Name: "root",
		Type: dir.FileTypeDirectory,
		Entries: []*dir.FsNode{
			{
				Name: "file1.txt",
				Type: dir.FileTypeFile,
			},
			{
				Name: "subdir",
				Type: dir.FileTypeDirectory,
				Entries: []*dir.FsNode{
					{
						Name: "file2.txt",
						Type: dir.FileTypeFile,
					},
				},
			},
		},
	}

	// Define the expected paths
	expectedPaths := map[string]bool{
		"root":                  false,
		"root/file1.txt":        false,
		"root/subdir":           false,
		"root/subdir/file2.txt": false,
	}

	// Define the action function to check the paths
	actionFunc := func(node *dir.FsNode, path string) error {
		if _, ok := expectedPaths[path]; ok {
			expectedPaths[path] = true
			return nil
		} else {
			return fmt.Errorf("Unexpected path: %s", path)
		}
	}

	// Perform the traversal
	err := root.Traverse(actionFunc)
	assert.NoError(t, err)

	// Verify all expected paths were visited
	for path, visited := range expectedPaths {
		assert.True(t, visited, "Path not visited: %s", path)
	}

	// Define the expected flatten result
	expectedFlattenResult := []struct {
		node *dir.FsNode
		path string
	}{
		{root.Entries[0], "root/file1.txt"},
		{root.Entries[1].Entries[0], "root/subdir/file2.txt"},
	}

	// Test Flatten method
	result, paths := root.Flatten(func(n *dir.FsNode) bool {
		return n.Type == dir.FileTypeFile
	})

	for i, item := range expectedFlattenResult {
		assert.Equal(t, item.node, result[i])
		assert.Equal(t, item.path, paths[i])
	}
}

func TestLocate(t *testing.T) {
	// Setup a sample directory structure
	root := &dir.FsNode{
		Name: "/",
		Type: dir.FileTypeDirectory,
		Entries: []*dir.FsNode{
			{
				Name: "file1.txt",
				Type: dir.FileTypeFile,
			},
			{
				Name: "subdir",
				Type: dir.FileTypeDirectory,
				Entries: []*dir.FsNode{
					{
						Name: "file2.txt",
						Type: dir.FileTypeFile,
					},
					{
						Name: "innerdir",
						Type: dir.FileTypeDirectory,
						Entries: []*dir.FsNode{
							{
								Name: "file3.txt",
								Type: dir.FileTypeFile,
							},
						},
					},
				},
			},
		},
	}

	// Test cases
	tests := []struct {
		name      string
		path      string
		expected  *dir.FsNode
		expectErr bool
	}{
		{
			name:      "locate file in root",
			path:      "file1.txt",
			expected:  root.Entries[0],
			expectErr: false,
		},
		{
			name:      "locate file in subdirectory",
			path:      filepath.Join("subdir", "file2.txt"),
			expected:  root.Entries[1].Entries[0],
			expectErr: false,
		},
		{
			name:      "locate file in nested subdirectory",
			path:      filepath.Join("subdir", "innerdir", "file3.txt"),
			expected:  root.Entries[1].Entries[1].Entries[0],
			expectErr: false,
		},
		{
			name:      "directory not found",
			path:      "nonexistentdir/file.txt",
			expected:  nil,
			expectErr: true,
		},
		{
			name:      "file not found",
			path:      "subdir/nonexistentfile.txt",
			expected:  nil,
			expectErr: true,
		},
		{
			name:      "locate root directory",
			path:      "",
			expected:  root,
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := root.Locate(tc.path)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
