package node_test

import (
	"fmt"
	"testing"

	"github.com/pkg/errors"

	"github.com/0gfoundation/0g-storage-client/node"
	"gotest.tools/assert"
)

func extractRPCError(err error) *node.RPCError {
	var rpcError *node.RPCError
	if errors.As(err, &rpcError) {
		return rpcError
	}
	return nil
}

func TestErrorAs(t *testing.T) {
	err := fmt.Errorf("123")
	assert.Equal(t, extractRPCError(err) == nil, true)
	err = &node.RPCError{
		Method:  "test",
		URL:     "127.0.0.1:1234",
		Message: "test error",
	}
	assert.DeepEqual(
		t,
		extractRPCError(errors.WithMessage(err, "failed to upload")),
		err,
	)
	assert.DeepEqual(
		t,
		extractRPCError(errors.WithMessage(errors.WithMessage(err, "failed to upload segment"), "Failed to upload file")),
		err,
	)
}
