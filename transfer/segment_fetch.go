package transfer

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

// segmentFetchRequest is the parameter bundle for fetchSegmentFromNode.
// Grouped because the per-node fetch needs file-level (TxSeq, Root,
// FileSize), segment-level (SegIdx, GlobalSegIdx, StartChunk, EndChunk),
// and mode (WithProof) inputs — passing them as positional args was a
// 10-arg smell.
type segmentFetchRequest struct {
	// Identifies the file on chain.
	TxSeq    uint64
	Root     common.Hash
	FileSize int64

	// Identifies the segment within the file. SegIdx is the local
	// per-file segment index (also the index used by the proof RPC).
	// GlobalSegIdx is the flow-wide segment index used for shard
	// distribution math: GlobalSegIdx % NumShard == ShardId for nodes
	// that hold this segment.
	SegIdx       uint64
	GlobalSegIdx uint64
	StartChunk   uint64
	EndChunk     uint64

	// WithProof requests a Merkle proof and validates it against Root
	// before returning the data.
	WithProof bool
}

// fetchSegmentFromNode downloads one segment from a single ZgsClient,
// applying the shard-config skip and (optionally) the proof validation.
//
// Return contract:
//
//   - (data, nil)  — segment fetched (and proof validated, if requested)
//   - (nil,  nil)  — this node does not shard the requested segment, OR
//                    the RPC returned a nil segment (treat as "not here";
//                    caller should try the next node)
//   - (nil,  err)  — RPC error, proof-validation error, or missing
//                    ShardConfig on the client
//
// Used by both download_parallel.go (file-based parallel download) and
// downloader_writer.go (io.Writer-based streaming download) so the
// shard-skip and proof-validation paths live in exactly one place.
func fetchSegmentFromNode(ctx context.Context, client *node.ZgsClient, req segmentFetchRequest) ([]byte, error) {
	sc := client.ShardConfig()
	if sc == nil {
		return nil, errors.New("ShardConfig is required on ZgsClient")
	}
	if sc.NumShard > 0 && req.GlobalSegIdx%sc.NumShard != sc.ShardId {
		return nil, nil // this node doesn't shard this segment; not an error
	}

	if req.WithProof {
		sw, err := client.DownloadSegmentWithProofByTxSeq(ctx, req.TxSeq, req.SegIdx)
		if err != nil {
			return nil, err
		}
		if sw == nil {
			return nil, nil
		}
		// Pre-validate the data length against the requested chunk range.
		// download_parallel.go used to enforce this inline; preserve it
		// here so both download paths get the same guarantee.
		if expected := (req.EndChunk - req.StartChunk) * core.DefaultChunkSize; int(expected) != len(sw.Data) {
			return nil, errors.Errorf("downloaded data length mismatch: expected %d, got %d", expected, len(sw.Data))
		}
		segRoot, numSegPad := core.PaddedSegmentRoot(req.SegIdx, sw.Data, req.FileSize)
		if err := sw.Proof.ValidateHash(req.Root, segRoot, req.SegIdx, numSegPad); err != nil {
			return nil, errors.WithMessage(err, "proof validation")
		}
		return sw.Data, nil
	}

	return client.DownloadSegmentByTxSeq(ctx, req.TxSeq, req.StartChunk, req.EndChunk)
}
