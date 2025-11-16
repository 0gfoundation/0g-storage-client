package dir

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

// FileType represents the file type in the FsNode structure.
type FileType string

const (
	FileTypeFile      FileType = "file"
	FileTypeDirectory FileType = "directory"
	FileTypeSymbolic  FileType = "symbolic"
)

// FsNode represents a node in the filesystem hierarchy.
type FsNode struct {
	Name    string    `json:"name"`              // File or directory name
	Type    FileType  `json:"type"`              // File type of the node
	Root    string    `json:"hash,omitempty"`    // Merkle root hash (only for regular files)
	Size    int64     `json:"size,omitempty"`    // File size in bytes (only for regular files)
	Link    string    `json:"link,omitempty"`    // Symbolic link target (only for symbolic links)
	Entries []*FsNode `json:"entries,omitempty"` // Directory entries (only for directories)
}

// NewDirFsNode creates a new FsNode representing a directory.
func NewDirFsNode(name string, entryNodes []*FsNode) *FsNode {
	sort.Slice(entryNodes, func(i, j int) bool {
		return entryNodes[i].Name < entryNodes[j].Name
	})

	return &FsNode{
		Name:    name,
		Type:    FileTypeDirectory,
		Entries: entryNodes,
	}
}

// NewFileFsNode creates a new FsNode representing a regular file.
func NewFileFsNode(name string, rootHash common.Hash, size int64) *FsNode {
	return &FsNode{
		Name: name,
		Type: FileTypeFile,
		Root: rootHash.Hex(),
		Size: size,
	}
}

// NewSymbolicFsNode creates a new FsNode representing a symbolic link.
func NewSymbolicFsNode(name, link string) *FsNode {
	return &FsNode{
		Name: name,
		Type: FileTypeSymbolic,
		Link: link,
	}
}

// Search looks for a file by name in the current directory node's entries.
func (node *FsNode) Search(fileName string) (*FsNode, bool) {
	i, found := sort.Find(len(node.Entries), func(i int) int {
		return strings.Compare(fileName, node.Entries[i].Name)
	})

	if found {
		return node.Entries[i], true
	}
	return nil, false
}

// Equal compares two FsNode structures for equality.
func (node *FsNode) Equal(rhs *FsNode) bool {
	if node.Type != rhs.Type || node.Name != rhs.Name {
		return false
	}

	switch node.Type {
	case FileTypeFile:
		return node.Root == rhs.Root
	case FileTypeSymbolic:
		return node.Link == rhs.Link
	case FileTypeDirectory:
		if len(node.Entries) != len(rhs.Entries) {
			return false
		}
		for i := 0; i < len(node.Entries); i++ {
			if !node.Entries[i].Equal(rhs.Entries[i]) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// Locate finds a sub-node within the FsNode tree based on the given path.
// The path can be a file or directory, and it should be relative to the current node.
func (node *FsNode) Locate(path string) (*FsNode, error) {
	// Split the path into parts for recursive traversal
	parts := strings.Split(filepath.Clean(path), string(os.PathSeparator))
	// Filter out empty strings
	var filteredParts []string
	for _, part := range parts {
		if len(part) > 0 {
			filteredParts = append(filteredParts, part)
		}
	}

	// Start locating the first part
	return node.locate(filteredParts)
}

// locate is a helper function to recursively find the sub-node
func (node *FsNode) locate(parts []string) (*FsNode, error) {
	// Base case: if the path is empty or dot current, return the current node
	if len(parts) == 0 || (len(parts) == 1 && parts[0] == ".") {
		return node, nil
	}

	// The current part of the path we are looking for
	currentPart := parts[0]

	// If the current node is not a directory, we can't traverse further
	if node.Type != FileTypeDirectory {
		return nil, fmt.Errorf("cannot locate '%s': '%s' is not a directory", currentPart, node.Name)
	}

	// Use the binary search method (Search) to locate the current part
	if entry, found := node.Search(currentPart); found {
		// If this is the final part of the path, return the entry
		if len(parts) == 1 {
			return entry, nil
		}
		// Otherwise, recursively locate in the sub-directory
		return entry.locate(parts[1:])
	}

	// If no entry is found, return an error
	return nil, errors.Errorf("path not found: '%s'", currentPart)
}

// Flatten recursively flattens the FsNode tree into a slice of FsNode pointers and a slice of relative paths.
// The filterFunc is applied to each node to determine if it should be included in the result.
func (node *FsNode) Flatten(filterFunc ...func(*FsNode) bool) (result []*FsNode, relpaths []string) {
	node.Traverse(func(n *FsNode, p string) error {
		if len(filterFunc) == 0 || filterFunc[0](n) {
			result = append(result, n)
			relpaths = append(relpaths, p)
		}
		return nil
	})
	return result, relpaths
}

// Traverse recursively traverses the FsNode tree and applies the provided actionFunc to each node.
// This method only requires the user to handle relative paths.
//
// Parameters:
//
//   - actionFunc: A function that defines the action to perform on each node. The function
//     takes the current node and its relative path as arguments. This function can perform any necessary
//     operations, such as collecting nodes, uploading files, or logging information.
func (node *FsNode) Traverse(actionFunc func(node *FsNode, relativePath string) error) error {
	return node.traverse("", actionFunc)
}

// traverse is a helper function that manages relative paths during the traversal process.
func (node *FsNode) traverse(baseDir string, actionFunc func(node *FsNode, relativePath string) error) error {
	relative := filepath.Join(baseDir, node.Name)

	// Apply the action function to the current node
	if err := actionFunc(node, relative); err != nil {
		return err
	}

	if node.Type != FileTypeDirectory {
		return nil
	}

	// If the node is a directory, recursively traverse its entries
	for _, entry := range node.Entries {
		if err := entry.traverse(relative, actionFunc); err != nil {
			return err
		}
	}

	return nil
}

// BuildFileTree recursively builds a file tree for the specified directory.
func BuildFileTree(path string) (*FsNode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to stat file %s", path)
	}

	if !info.IsDir() {
		return nil, errors.New("file tree building is only supported for directory")
	}

	root, err := build(path)
	if err != nil {
		return nil, err
	}

	// Set root directory name
	root.Name = "/"
	return root, nil
}

// build is a helper function that recursively builds a file tree starting from the specified path.
func build(path string) (*FsNode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to stat file %s", path)
	}

	switch {
	case info.IsDir():
		return buildDirectoryNode(path, info)
	case info.Mode()&os.ModeSymlink != 0:
		return buildSymbolicNode(path, info)
	case info.Mode().IsRegular():
		return buildFileNode(path, info)
	default:
		return nil, errors.New("unsupported file type")
	}
}

// buildDirectoryNode creates an FsNode for a directory, including its contents.
func buildDirectoryNode(path string, info os.FileInfo) (*FsNode, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to read directory %s", path)
	}

	var entryNodes []*FsNode
	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())
		entryNode, err := build(entryPath)
		if err != nil {
			return nil, err
		}
		entryNodes = append(entryNodes, entryNode)
	}
	return NewDirFsNode(info.Name(), entryNodes), nil
}

// buildSymbolicNode creates an FsNode for a symbolic link.
func buildSymbolicNode(path string, info os.FileInfo) (*FsNode, error) {
	link, err := os.Readlink(path)
	if err != nil {
		return nil, errors.WithMessagef(err, "invalid symbolic link %s", path)
	}

	return NewSymbolicFsNode(info.Name(), link), nil
}

// buildFileNode creates an FsNode for a regular file, including its Merkle root hash.
func buildFileNode(path string, info os.FileInfo) (*FsNode, error) {
	if info.Size() == 0 {
		return NewFileFsNode(info.Name(), common.Hash{}, 0), nil
	}

	hash, err := core.MerkleRoot(path)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to calculate merkle root for %s", path)
	}
	return NewFileFsNode(info.Name(), hash, info.Size()), nil
}
