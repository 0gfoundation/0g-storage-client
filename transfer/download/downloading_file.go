package download

import (
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

const downloadingFileSuffix = ".download"

type DownloadingFile struct {
	filename   string
	underlying *os.File
	metadata   *Metadata
}

func CreateDownloadingFile(filename string, root common.Hash, size int64) (_ *DownloadingFile, err error) {
	file, err := os.OpenFile(filename+downloadingFileSuffix, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to open file")
	}

	// The descriptor is only handed over to the returned DownloadingFile on success, so
	// close it on every validation failure below. Root and size mismatches are ordinary
	// occurrences - they happen whenever a download is resumed against a stale
	// .download file - so leaking there accumulates descriptors across retries.
	defer func() {
		if err != nil {
			file.Close()
		}
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to stat file")
	}

	var metadata *Metadata

	if info.Size() == 0 {
		metadata = NewMetadata(root, size)
		if err = metadata.Extend(file); err != nil {
			return nil, errors.WithMessage(err, "Failed to extend metadata")
		}
	} else if metadata, err = LoadMetadata(file); err != nil {
		return nil, errors.WithMessage(err, "Failed to load metadata")
	}

	if metadata.Root != root {
		return nil, errors.Errorf("Root mismatch, expected = %v, actual = %v", root, metadata.Root)
	}

	if metadata.Size != size {
		return nil, errors.Errorf("File size mismatch, expected = %v, actual = %v", size, metadata.Size)
	}

	return &DownloadingFile{filename, file, metadata}, nil
}

func (file *DownloadingFile) Metadata() *Metadata {
	return file.metadata
}

func (file *DownloadingFile) Write(data []byte) error {
	if file.underlying == nil {
		return errors.New("File already sealed")
	}

	return file.metadata.Write(file.underlying, data)
}

func (file *DownloadingFile) Seal() error {
	if file.metadata.Offset < file.metadata.Size {
		return errors.Errorf("Download incompleted, offset = %v, size = %v", file.metadata.Offset, file.metadata.Size)
	}

	if err := file.underlying.Truncate(file.metadata.Size); err != nil {
		return errors.WithMessage(err, "Failed to truncate metadata")
	}

	if err := file.underlying.Close(); err != nil {
		return errors.WithMessage(err, "Failed to close downloading file")
	}

	file.underlying = nil

	if err := os.Rename(file.filename+downloadingFileSuffix, file.filename); err != nil {
		return errors.WithMessage(err, "Failed to rename downloading file")
	}

	return nil
}

func (file *DownloadingFile) Close() error {
	if file.underlying == nil {
		return nil
	}

	return file.underlying.Close()
}
