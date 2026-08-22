package merkle

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A single-leaf tree yields a proof of Lemma=[root], Path=[] - the one shape where
// the lemma's first and last element coincide. The supplied root still has to be
// checked against it: validateRoot degenerates to comparing Lemma[0] with itself and
// so cannot tell a proven root from an arbitrary one.
func TestProofValidate_SingleLeafRejectsUnprovenRoot(t *testing.T) {
	tree := createTreeByChunks(1)
	proof := tree.ProofAt(0)

	require.Len(t, proof.Lemma, 1, "single-leaf proof shape")
	require.Empty(t, proof.Path, "single-leaf proof shape")

	// The real root must still validate.
	assert.NoError(t, proof.Validate(tree.Root(), createChunkData(0), 0, 1))

	// A root that this proof does not prove must be rejected.
	unproven := common.HexToHash("0xbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad0")
	require.NotEqual(t, tree.Root(), unproven)
	err := proof.Validate(unproven, createChunkData(0), 0, 1)
	assert.ErrorIs(t, err, errProofRootMismatch)
}

// The same guarantee for multi-leaf proofs, which already held.
func TestProofValidate_MultiLeafRejectsUnprovenRoot(t *testing.T) {
	unproven := common.HexToHash("0xbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad0")

	for numChunks := 2; numChunks <= 8; numChunks++ {
		tree := createTreeByChunks(numChunks)
		for i := 0; i < numChunks; i++ {
			proof := tree.ProofAt(i)
			require.NoError(t, proof.Validate(tree.Root(), createChunkData(i), uint64(i), uint64(numChunks)))
			assert.ErrorIs(t, proof.Validate(unproven, createChunkData(i), uint64(i), uint64(numChunks)),
				errProofRootMismatch, "numChunks=%d leaf=%d", numChunks, i)
		}
	}
}
