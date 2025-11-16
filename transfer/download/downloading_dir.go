package download

import (
	"os"
	"path/filepath"
	"time"

	"github.com/0gfoundation/0g-storage-client/transfer/dir"
	"github.com/pkg/errors"
)

type DownloadingDir struct {
	filename string // The original directory name before downloading
}

// CreateDownloadingDir creates a temporary downloading directory by renaming the existing directory if it exists
// or by creating a new one if it doesn't. It ensures files are stored in a safe temporary directory.
func CreateDownloadingDir(filename string) (*DownloadingDir, error) {
	tmpDir := filename + downloadingFileSuffix

	// Attempt to rename the existing directory to the temporary downloading directory.
	err := os.Rename(filename, tmpDir)
	if err == nil {
		return &DownloadingDir{filename}, nil
	}

	// If the directory doesn't exist, create the temporary directory.
	if os.IsNotExist(err) {
		if err := os.MkdirAll(tmpDir, 0755); err != nil {
			return nil, errors.WithMessage(err, "failed to create temporary directory")
		}
		return &DownloadingDir{filename}, nil
	}

	return nil, errors.WithMessage(err, "failed to rename existing directory")
}

// Add adds a file, directory, or symbolic link to the downloading directory.
func (directory *DownloadingDir) Add(node *dir.FsNode, relpath string, persist func(path string) error) error {
	savePath := filepath.Join(directory.filename+downloadingFileSuffix, relpath)

	// Use the custom persist function if provided
	if persist != nil {
		return persist(savePath)
	}

	// Handle different file types if no custom persist function is provided.
	switch node.Type {
	case dir.FileTypeFile:
		// Create an empty file (touch) at the save path.
		if err := touchFile(savePath); err != nil {
			return errors.WithMessagef(err, "failed to create empty file %s", savePath)
		}
	case dir.FileTypeDirectory:
		// Create the directory if it doesn't exist.
		if err := os.MkdirAll(savePath, 0755); err != nil {
			return errors.WithMessagef(err, "failed to create directory %s", savePath)
		}
	case dir.FileTypeSymbolic:
		// Create or update a symbolic link at the specified path.
		if err := createOrUpdateSymlink(node.Link, savePath); err != nil {
			return errors.WithMessagef(err, "failed to create symbolic link %s", savePath)
		}
	default:
		return errors.Errorf("unknown file type: %v", node.Type)
	}

	return nil
}

// Seal finalizes the downloading process by renaming the temporary directory back to its original name.
// It should be called after all files have been added to the directory.
func (directory *DownloadingDir) Seal() error {
	tmpDir := directory.filename + downloadingFileSuffix

	// Rename the temporary directory back to the original directory name.
	if err := os.Rename(tmpDir, directory.filename); err != nil {
		return errors.WithMessage(err, "failed to rename directory")
	}

	return nil
}

// createOrUpdateSymlink creates a symlink, replacing any existing one
func createOrUpdateSymlink(target, linkName string) error {
	// Check if the link already exists
	if _, err := os.Lstat(linkName); os.IsNotExist(err) {
		// Create a new symlink if file doesn't exist
		return os.Symlink(target, linkName)
	}

	// Check if it points to the correct target
	existingTarget, err := os.Readlink(linkName)
	if err == nil && existingTarget == target {
		// Symlink already points to the correct target, skip creation
		return nil
	}

	// Otherwises, remove existing symlink or file
	if err := os.Remove(linkName); err != nil {
		return errors.WithMessage(err, "failed to remove old file")
	}

	// Create a new symlink
	return os.Symlink(target, linkName)
}

// touchFile creates or updates the access and modification time of a file.
func touchFile(filePath string) error {
	// Open the file, create it if it doesn't exist
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.WithMessage(err, "failed to create or open file")
	}
	defer file.Close()

	// Update the file's access and modification times to the current time
	currentTime := time.Now()
	if err := os.Chtimes(filePath, currentTime, currentTime); err != nil {
		return errors.WithMessage(err, "failed to change file timestamps")
	}

	return nil
}
