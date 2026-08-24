package blockchain

import (
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
	rpcprovider "github.com/openweb3/go-rpc-provider"
	"math/big"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// abiEncodedRevert builds the payload a node returns for `revert(msg)`.
func abiEncodedRevert(t *testing.T, msg string) string {
	t.Helper()

	stringType, err := abi.NewType("string", "", nil)
	assert.NoError(t, err)

	packed, err := (abi.Arguments{{Type: stringType}}).Pack(msg)
	assert.NoError(t, err)

	return hexutil.Encode(append([]byte{0x08, 0xc3, 0x79, 0xa0}, packed...))
}

// abiEncodedPanic builds the payload a node returns for a Solidity panic.
func abiEncodedPanic(t *testing.T, code int64) string {
	t.Helper()

	uintType, err := abi.NewType("uint256", "", nil)
	assert.NoError(t, err)

	packed, err := (abi.Arguments{{Type: uintType}}).Pack(big.NewInt(code))
	assert.NoError(t, err)

	return hexutil.Encode(append([]byte{0x4e, 0x48, 0x7b, 0x71}, packed...))
}

func TestRevertReasonFromError(t *testing.T) {
	t.Run("decodes a revert string", func(t *testing.T) {
		err := &rpcprovider.JsonError{
			Code:    3,
			Message: "execution reverted",
			Data:    abiEncodedRevert(t, "Flow: not in the whitelist"),
		}

		assert.Equal(t, "Flow: not in the whitelist", revertReasonFromError(err))
	})

	t.Run("decodes a Solidity panic", func(t *testing.T) {
		err := &rpcprovider.JsonError{
			Code:    3,
			Message: "execution reverted",
			Data:    abiEncodedPanic(t, 0x11),
		}

		// The point is that a panic reads as prose rather than as a bare code.
		assert.Contains(t, revertReasonFromError(err), "overflow")
	})

	t.Run("survives a wrapped error", func(t *testing.T) {
		err := errors.WithMessage(&rpcprovider.JsonError{
			Message: "execution reverted",
			Data:    abiEncodedRevert(t, "Market: insufficient fee"),
		}, "failed to call")

		assert.Equal(t, "Market: insufficient fee", revertReasonFromError(err))
	})

	t.Run("falls back to the node's message when there is no data", func(t *testing.T) {
		err := &rpcprovider.JsonError{Message: "execution reverted"}

		assert.Equal(t, "execution reverted", revertReasonFromError(err))
	})

	t.Run("falls back when the data is not decodable", func(t *testing.T) {
		// A custom error carries a selector we have no ABI for.
		err := &rpcprovider.JsonError{Message: "execution reverted", Data: "0xdeadbeef"}

		reason := revertReasonFromError(err)
		assert.Contains(t, reason, "execution reverted")
		assert.Contains(t, reason, "0xdeadbeef", "the raw data is the only clue left, so it must survive")
	})

	t.Run("falls back for an error that is not from the RPC layer", func(t *testing.T) {
		assert.Equal(t, "connection refused", revertReasonFromError(errors.New("connection refused")))
	})
}
