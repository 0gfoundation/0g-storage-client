package transfer

import (
	"context"
	"io"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

// DownloadToWriter streams a full file identified by `root` to w.
//
// Unlike Download, this avoids the temp-file disk hop — useful for HTTP
// gateways and other consumers that want to forward bytes directly to a
// network sink. Segments are fetched sequentially and written in order.
//
// Encryption is NOT supported on this path: encrypted files require buffering
// the full ciphertext to detect the header version and resolve the AES key
// before any plaintext can be emitted, which defeats the streaming property.
// Use the file-based Download for encrypted files.
func (downloader *Downloader) DownloadToWriter(ctx context.Context, root string, w io.Writer, withProof bool) error {
	if downloader.hasDecryptionKey() {
		return errors.New("DownloadToWriter does not support encrypted files — use Download(filename) instead")
	}
	return downloader.downloadRangeToWriter(ctx, root, w, 0, -1, withProof)
}

// DownloadRangeToWriter streams bytes [offset, offset+length) of `root` to w.
//
// length must be > 0. Use DownloadToWriter for full-file streaming. The proof
// path is intentionally excluded: range reads are typically hot-path latency
// reads (e.g. LanceDB manifest lookups) where re-validating merkle proofs
// per request is overkill — full-file Download with withProof=true remains
// the integrity-checked entry point.
func (downloader *Downloader) DownloadRangeToWriter(ctx context.Context, root string, offset, length int64, w io.Writer) error {
	if downloader.hasDecryptionKey() {
		return errors.New("DownloadRangeToWriter does not support encrypted files")
	}
	if length <= 0 {
		return errors.Errorf("length must be positive, got %d", length)
	}
	return downloader.downloadRangeToWriter(ctx, root, w, offset, length, false)
}

// downloadRangeToWriter is the shared implementation for both writer-based
// download paths. length<0 means "to end of file".
func (downloader *Downloader) downloadRangeToWriter(ctx context.Context, root string, w io.Writer, offset, length int64, withProof bool) error {
	hash := common.HexToHash(root)
	info, err := downloader.queryFile(ctx, hash)
	if err != nil {
		return errors.WithMessage(err, "Failed to query file info")
	}

	fileSize := int64(info.Tx.Size)
	if length < 0 {
		length = fileSize - offset
	}
	if offset < 0 || offset > fileSize || offset+length > fileSize {
		return errors.Errorf("range out of bounds: offset=%d length=%d size=%d", offset, length, fileSize)
	}
	if length == 0 {
		return nil
	}

	chunkSize := int64(core.DefaultChunkSize)
	segChunks := uint64(core.DefaultSegmentMaxChunks)

	fileNumChunks := core.NumSplits(fileSize, core.DefaultChunkSize)
	globalStartSeg := info.Tx.StartEntryIndex / segChunks

	endByte := offset + length // exclusive
	startChunk := uint64(offset / chunkSize)
	endChunkExcl := uint64((endByte + chunkSize - 1) / chunkSize)
	if endChunkExcl > fileNumChunks {
		endChunkExcl = fileNumChunks
	}

	startSeg := startChunk / segChunks
	endSeg := (endChunkExcl - 1) / segChunks

	written := int64(0)
	for seg := startSeg; seg <= endSeg; seg++ {
		segStartChunk := seg * segChunks
		segEndChunk := segStartChunk + segChunks
		if segEndChunk > fileNumChunks {
			segEndChunk = fileNumChunks
		}

		data, err := downloader.fetchSegmentBytes(ctx, info.Tx.Seq, hash, seg, globalStartSeg+seg, segStartChunk, segEndChunk, withProof, fileSize)
		if err != nil {
			return errors.WithMessagef(err, "segment %d", seg)
		}

		// Trim chunk-padding from the last segment of the file. Segments are
		// always returned chunk-aligned; the final chunk may have <256 bytes
		// of real data and the rest is zero-padding.
		if segEndChunk == fileNumChunks {
			if lastChunkBytes := fileSize % chunkSize; lastChunkBytes > 0 {
				padding := chunkSize - lastChunkBytes
				data = data[:int64(len(data))-padding]
			}
		}

		// Slice to the byte range within this segment we actually want.
		segByteStart := int64(segStartChunk) * chunkSize
		sliceLo := offset - segByteStart
		if sliceLo < 0 {
			sliceLo = 0
		}
		sliceHi := endByte - segByteStart
		if sliceHi > int64(len(data)) {
			sliceHi = int64(len(data))
		}

		if sliceLo < sliceHi {
			n, werr := w.Write(data[sliceLo:sliceHi])
			if werr != nil {
				return errors.WithMessage(werr, "write to sink")
			}
			written += int64(n)
		}
	}

	if written != length {
		return errors.Errorf("incomplete write: got %d of %d bytes", written, length)
	}
	return nil
}

// fetchSegmentBytes downloads a single segment from any storage node that
// holds it (per shard config) and validates the proof if requested. Tries
// each client in turn; the last error wins on total failure.
func (downloader *Downloader) fetchSegmentBytes(
	ctx context.Context,
	txSeq uint64,
	root common.Hash,
	segIdx, globalSegIdx, startChunk, endChunk uint64,
	withProof bool,
	fileSize int64,
) ([]byte, error) {
	var lastErr error
	for i := 0; i < len(downloader.clients); i++ {
		client := downloader.clients[i]
		if data, err := tryFetchSegment(ctx, client, txSeq, root, segIdx, globalSegIdx, startChunk, endChunk, withProof, fileSize); err == nil {
			if data != nil {
				return data, nil
			}
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, errors.WithMessage(lastErr, "all nodes failed")
	}
	return nil, errors.Errorf("no node served segment %d", segIdx)
}

func tryFetchSegment(
	ctx context.Context,
	client *node.ZgsClient,
	txSeq uint64,
	root common.Hash,
	segIdx, globalSegIdx, startChunk, endChunk uint64,
	withProof bool,
	fileSize int64,
) ([]byte, error) {
	if sc := client.ShardConfig(); sc != nil && sc.NumShard > 0 {
		if globalSegIdx%sc.NumShard != sc.ShardId {
			return nil, nil // this node doesn't shard this segment; not an error
		}
	}
	if withProof {
		sw, err := client.DownloadSegmentWithProofByTxSeq(ctx, txSeq, segIdx)
		if err != nil {
			return nil, err
		}
		if sw == nil {
			return nil, nil
		}
		segRoot, numSegPad := core.PaddedSegmentRoot(segIdx, sw.Data, fileSize)
		if err := sw.Proof.ValidateHash(root, segRoot, segIdx, numSegPad); err != nil {
			return nil, errors.WithMessage(err, "proof validation")
		}
		return sw.Data, nil
	}
	data, err := client.DownloadSegmentByTxSeq(ctx, txSeq, startChunk, endChunk)
	if err != nil {
		return nil, err
	}
	return data, nil
}
