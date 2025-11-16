package node

import (
	"context"

	"github.com/0gfoundation/0g-storage-client/common/rpc"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
)

type rpcClient struct {
	*rpc.Client
}

func newRpcClient(url string, option ...providers.Option) (*rpcClient, error) {
	inner, err := rpc.NewClient(url, option...)
	if err != nil {
		return nil, err
	}

	client := rpcClient{inner}
	client.HookCallContext(client.rpcErrorMiddleware)

	return &client, nil
}

func (c *rpcClient) wrapError(e error, method string) error {
	if e == nil {
		return nil
	}
	return &RPCError{
		Message: e.Error(),
		Method:  method,
		URL:     c.URL(),
	}
}

func (c *rpcClient) rpcErrorMiddleware(handler providers.CallContextFunc) providers.CallContextFunc {
	return func(ctx context.Context, result interface{}, method string, args ...interface{}) error {
		err := handler(ctx, result, method, args...)
		return c.wrapError(err, method)
	}
}
