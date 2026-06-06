package transfer

import (
	"errors"
	"math/big"
	"testing"

	"github.com/0gfoundation/0g-storage-client/contract"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrDataUnavailable_Message(t *testing.T) {
	root := common.HexToHash("0x1234")
	err := &ErrDataUnavailable{Missing: []common.Hash{root}}
	assert.Contains(t, err.Error(), root.Hex())
	assert.Contains(t, err.Error(), "upload")

	var target *ErrDataUnavailable
	assert.True(t, errors.As(error(err), &target))
	assert.Equal(t, []common.Hash{root}, target.Missing)
}

func TestErrSubmitEventNotFound_Message(t *testing.T) {
	h := common.HexToHash("0xabcd")
	err := &ErrSubmitEventNotFound{TxHash: h}
	assert.Contains(t, err.Error(), h.Hex())

	var target *ErrSubmitEventNotFound
	assert.True(t, errors.As(error(err), &target))
}

func TestIsRootAvailable(t *testing.T) {
	assert.False(t, isRootAvailable(nil))
	assert.False(t, isRootAvailable(&node.FileInfo{Finalized: false}))
	assert.False(t, isRootAvailable(&node.FileInfo{Finalized: true, Pruned: true}))
	assert.True(t, isRootAvailable(&node.FileInfo{Finalized: true, Pruned: false}))
}

func newTestFlow(t *testing.T) *contract.FlowContract {
	t.Helper()
	bound, err := contract.NewFlow(common.HexToAddress("0x1"), nil)
	require.NoError(t, err)
	return &contract.FlowContract{Flow: bound}
}

func newTestSubmission(t *testing.T, sizeBytes int) contract.Submission {
	t.Helper()
	data, err := core.NewDataInMemory(make([]byte, sizeBytes))
	require.NoError(t, err)
	sub, err := core.NewFlow(data, []byte{}).CreateSubmission(common.Address{})
	require.NoError(t, err)
	return *sub
}

func buildSubmitLog(t *testing.T, sub contract.Submission) *ethtypes.Log {
	t.Helper()
	parsed, err := contract.FlowMetaData.GetAbi()
	require.NoError(t, err)
	ev := parsed.Events["Submit"]

	// non-indexed args: submissionIndex, startPos, length, submission
	data, err := ev.Inputs.NonIndexed().Pack(
		big.NewInt(0),   // submissionIndex
		big.NewInt(0),   // startPos
		sub.Data.Length, // length
		sub.Data,        // submission (struct)
	)
	require.NoError(t, err)

	identity := sub.Root() // indexed identity == data root
	return &ethtypes.Log{
		Topics: []common.Hash{
			ev.ID,                    // event signature
			common.HexToHash("0x00"), // indexed sender (zero)
			identity,                 // indexed identity
		},
		Data: data,
	}
}

func TestParseSubmissions_DedupesAndVerifiesRoot(t *testing.T) {
	flow := newTestFlow(t)
	sub := newTestSubmission(t, 4096)
	log := buildSubmitLog(t, sub)

	items, err := parseSubmissions(flow, []*ethtypes.Log{log, log}) // duplicate => one item
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, sub.Root(), items[0].Root)
	assert.Equal(t, sub.Data.Length, items[0].Submission.Data.Length)
}

func TestParseSubmissions_NoSubmitLog(t *testing.T) {
	flow := newTestFlow(t)
	items, err := parseSubmissions(flow, []*ethtypes.Log{{Topics: []common.Hash{common.HexToHash("0xdead")}}})
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestFeeForSubmissions(t *testing.T) {
	sub := newTestSubmission(t, 4096)
	price := big.NewInt(7)

	want := new(big.Int).Add(sub.Fee(price), sub.Fee(price))
	got := feeForSubmissions([]ExtendItem{{Submission: sub}, {Submission: sub}}, price)
	assert.Equal(t, want, got)
}
