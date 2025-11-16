package gateway

import "github.com/0gfoundation/0g-storage-client/common/api"

var (
	ErrFileNotFound        = api.NewBusinessError(101, "File not found")
	ErrFilePruned          = api.NewBusinessError(102, "File already pruned")
	ErrFileNotFinalized    = api.NewBusinessError(103, "File not finalized yet")
	ErrFilePathNotFound    = api.NewBusinessError(104, "File path not found")
	ErrFileSizeTooLarge    = api.NewBusinessError(105, "File size too large")
	ErrFileTypeUnsupported = api.NewBusinessError(106, "File type unsupported")
)
