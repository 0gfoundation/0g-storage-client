package blockchain

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	rpcprovider "github.com/openweb3/go-rpc-provider"
	"github.com/openweb3/web3go"
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

	t.Run("reports nothing for an error that is not from the RPC layer", func(t *testing.T) {
		// "Transaction execution failed, connection refused" would blame the
		// chain for the replay's own transport problem.
		assert.Empty(t, revertReasonFromError(errors.New("connection refused")))
	})
}

// testKey is the well-known Hardhat account 0 key; it signs nothing here, but
// NewWeb3 requires a signer.
const testKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// stubNode answers the two calls revertReason makes. handleCall decides what
// eth_call returns, which is the whole point of each case below.
func stubNode(t *testing.T, txFound bool, handleCall func() (string, *rpcprovider.JsonError), observeCall ...func(params []json.RawMessage)) *web3go.Client {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		assert.NoError(t, json.Unmarshal(body, &req))

		respond := func(result any, rpcErr *rpcprovider.JsonError) {
			payload := map[string]any{"jsonrpc": "2.0", "id": req.ID}
			if rpcErr != nil {
				payload["error"] = map[string]any{
					"code": rpcErr.Code, "message": rpcErr.Message, "data": rpcErr.Data,
				}
			} else {
				payload["result"] = result
			}
			w.Header().Set("Content-Type", "application/json")
			assert.NoError(t, json.NewEncoder(w).Encode(payload))
		}

		switch req.Method {
		case "eth_chainId":
			respond("0x1", nil)
		case "eth_getTransactionByHash":
			if !txFound {
				respond(nil, nil)
				return
			}
			respond(map[string]any{
				"hash":        "0x" + strings.Repeat("11", 32),
				"blockHash":   "0x" + strings.Repeat("22", 32),
				"blockNumber": "0x70",
				"from":        "0xfbe45681ac6c53d5a40475f7526bac1fe7590fb8",
				"to":          "0x33f2cfc729bd870fa54b5032660e06b4cf2a7f94",
				"gas":         "0x2a7ae",
				"gasPrice":    "0x3b9aca00",
				"value":       "0x0",
				"input":       "0xdeadbeef",
				"nonce":       "0x1",
				"r":           "0x1", "s": "0x1", "v": "0x1",
			}, nil)
		case "eth_call":
			for _, observe := range observeCall {
				observe(req.Params)
			}
			result, rpcErr := handleCall()
			respond(result, rpcErr)
		default:
			respond(nil, &rpcprovider.JsonError{Code: -32601, Message: "unsupported: " + req.Method})
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewWeb3(server.URL, testKey)
	assert.NoError(t, err)
	t.Cleanup(client.Close)

	return client
}

func TestRevertReason(t *testing.T) {
	const blockNumber = 112

	t.Run("recovers the reason from a replayed revert", func(t *testing.T) {
		client := stubNode(t, true, func() (string, *rpcprovider.JsonError) {
			return "", &rpcprovider.JsonError{
				Code: 3, Message: "execution reverted", Data: abiEncodedRevert(t, "Flow: invalid submission"),
			}
		})

		reason := revertReason(context.Background(), client, common.Hash{}, blockNumber)
		assert.Equal(t, "Flow: invalid submission", reason)
	})

	t.Run("replays in the block that contains the transaction", func(t *testing.T) {
		// A revert is atomic, so that block's state holds none of the
		// transaction's effects while its context still matches.
		var blockParam string
		client := stubNode(t, true, func() (string, *rpcprovider.JsonError) {
			return "0x", nil
		}, func(params []json.RawMessage) {
			assert.Len(t, params, 2)
			assert.NoError(t, json.Unmarshal(params[1], &blockParam))
		})

		revertReason(context.Background(), client, common.Hash{}, blockNumber)
		assert.Equal(t, "0x70", blockParam, "block %d must be replayed in block %d", blockNumber, blockNumber)
	})

	t.Run("reports nothing when the replay succeeds", func(t *testing.T) {
		// The parent state is not what the transaction ran against, so any reason
		// we invented here would be fiction.
		client := stubNode(t, true, func() (string, *rpcprovider.JsonError) {
			return "0x", nil
		})

		assert.Empty(t, revertReason(context.Background(), client, common.Hash{}, blockNumber))
	})

	t.Run("reports nothing when the transaction cannot be fetched", func(t *testing.T) {
		client := stubNode(t, false, func() (string, *rpcprovider.JsonError) {
			assert.Fail(t, "eth_call must not run once the transaction is unavailable")
			return "0x", nil
		})

		assert.Empty(t, revertReason(context.Background(), client, common.Hash{}, blockNumber))
	})

}

func TestNamedCustomError(t *testing.T) {
	const testABI = `[
		{"type":"error","name":"NotEnoughFee","inputs":[]},
		{"type":"error","name":"BelowLimit","inputs":[{"name":"limit","type":"uint256"},{"name":"who","type":"address"}]}
	]`

	parsed, err := abi.JSON(strings.NewReader(testABI))
	assert.NoError(t, err)
	RegisterCustomErrors(&parsed)

	revertDataFor := func(t *testing.T, name string, args ...any) []byte {
		t.Helper()
		abiError, ok := parsed.Errors[name]
		assert.True(t, ok)
		packed, err := abiError.Inputs.Pack(args...)
		assert.NoError(t, err)
		return append(abiError.ID[:4], packed...)
	}

	t.Run("names an error that carries no arguments", func(t *testing.T) {
		assert.Equal(t, "NotEnoughFee()", namedCustomError(revertDataFor(t, "NotEnoughFee")))
	})

	t.Run("reports the arguments, which carry the detail", func(t *testing.T) {
		data := revertDataFor(t, "BelowLimit", big.NewInt(42), common.HexToAddress("0x1234"))

		named := namedCustomError(data)
		assert.Contains(t, named, "BelowLimit")
		assert.Contains(t, named, "42")
		assert.Contains(t, named, "0x0000000000000000000000000000000000001234")
	})

	t.Run("keeps the name when the arguments are malformed", func(t *testing.T) {
		abiError := parsed.Errors["BelowLimit"]
		truncated := append(abiError.ID[:4], 0x01, 0x02)

		assert.Equal(t, abiError.Sig, namedCustomError(truncated))
	})

	t.Run("reports nothing for a selector nobody registered", func(t *testing.T) {
		assert.Empty(t, namedCustomError([]byte{0xde, 0xad, 0xbe, 0xef}))
	})

	t.Run("reports nothing for data too short to hold a selector", func(t *testing.T) {
		assert.Empty(t, namedCustomError([]byte{0x01, 0x02}))
	})

	t.Run("a registered custom error reaches the reported reason", func(t *testing.T) {
		err := &rpcprovider.JsonError{
			Message: "execution reverted",
			Data:    hexutil.Encode(revertDataFor(t, "NotEnoughFee")),
		}

		assert.Equal(t, "NotEnoughFee()", revertReasonFromError(err))
	})
}

// A dead node or cancelled context fails at the TransactionByHash gate, which
// already returns "" - these pin that the gate keeps doing its job.
func TestRevertReason_TransportFailureIsNotAReason(t *testing.T) {
	client, err := NewWeb3("http://127.0.0.1:1", testKey) // nothing listens here
	assert.NoError(t, err)
	defer client.Close()

	reason := revertReason(context.Background(), client, [32]byte{0x11}, 112)
	assert.Empty(t, reason, "a transport error is about the replay, not the transaction")
}

func TestRevertReason_CancelledContextIsNotAReason(t *testing.T) {
	client := stubNode(t, true, func() (string, *rpcprovider.JsonError) {
		return "0x", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.Empty(t, revertReason(ctx, client, [32]byte{0x11}, 112))
}

// The window the gate does NOT cover: TransactionByHash succeeds, then the
// node refuses eth_call itself. RPC gateways that whitelist methods do exactly
// this. The refusal is about the replay, not the transaction, so reporting it
// as the revert reason would be a confidently wrong diagnosis.
func TestRevertReason_MethodNotFoundIsNotAReason(t *testing.T) {
	client := stubNode(t, true, func() (string, *rpcprovider.JsonError) {
		return "", &rpcprovider.JsonError{
			Code:    -32601,
			Message: "the method eth_call does not exist/is not available",
		}
	})

	assert.Empty(t, revertReason(context.Background(), client, [32]byte{0x11}, 112),
		"a node that cannot replay has said nothing about why the transaction failed")
}
