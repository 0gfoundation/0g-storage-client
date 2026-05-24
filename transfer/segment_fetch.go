package transfer

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

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
func fetchSegmentFromNode(
	ctx context.Context,
	client *node.ZgsClient,
	txSeq uint64,
	root common.Hash,
	segIdx, globalSegIdx, startChunk, endChunk uint64,
	withProof bool,
	fileSize int64,
) ([]byte, error) {
	sc := client.ShardConfig()
	if sc == nil {
		return nil, errors.New("ShardConfig is required on ZgsClient")
	}
	if sc.NumShard > 0 && globalSegIdx%sc.NumShard != sc.ShardId {
		return nil, nil // this node doesn't shard this segment; not an error
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

	return client.DownloadSegmentByTxSeq(ctx, txSeq, startChunk, endChunk)
}
