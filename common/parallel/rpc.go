package parallel

import (
	"context"
	"time"

	"github.com/0gfoundation/0g-storage-client/node"
	providers "github.com/openweb3/go-rpc-provider/provider_wrapper"
	"github.com/sirupsen/logrus"
)

type RpcOption struct {
	Parallel       SerialOption
	Provider       providers.Option
	ReportInterval time.Duration
}

type RpcResult[T any] struct {
	Data    T
	Err     error
	Latency time.Duration
}

type closable interface {
	Close()
}

// rpcExecutor is used for RPC execution in parallel.
type rpcExecutor[CLIENT closable, T any] struct {
	option         RpcOption
	nodes          []string
	clientFactory  func(string) (CLIENT, error)
	rpcFunc        func(CLIENT, context.Context) (T, error)
	node2Results   map[string]*RpcResult[T]
	lastReportTime time.Time
}

// QueryZgsRpc calls zgs RPC with given nodes in parallel.
func QueryZgsRpc[T any](ctx context.Context, nodes []string, rpcFunc func(*node.ZgsClient, context.Context) (T, error), option ...RpcOption) map[string]*RpcResult[T] {
	var opt RpcOption
	if len(option) > 0 {
		opt = option[0]
	}

	executor := rpcExecutor[*node.ZgsClient, T]{
		option: opt,
		nodes:  nodes,
		clientFactory: func(url string) (*node.ZgsClient, error) {
			return node.NewZgsClient(url, nil, opt.Provider)
		},
		rpcFunc:        rpcFunc,
		node2Results:   make(map[string]*RpcResult[T]),
		lastReportTime: time.Now(),
	}

	// should not return err
	Serial(ctx, &executor, len(nodes), opt.Parallel)

	return executor.node2Results
}

func (executor *rpcExecutor[CLIENT, T]) ParallelDo(ctx context.Context, routine, task int) (interface{}, error) {
	url := executor.nodes[task]
	client, err := executor.clientFactory(url)
	if err != nil {
		return &RpcResult[T]{Err: err}, nil
	}
	defer client.Close()

	var result RpcResult[T]
	start := time.Now()
	result.Data, result.Err = executor.rpcFunc(client, ctx)
	result.Latency = time.Since(start)

	return &result, nil
}

func (executor *rpcExecutor[CLIENT, T]) ParallelCollect(result *Result) error {
	node := executor.nodes[result.Task]
	executor.node2Results[node] = result.Value.(*RpcResult[T])

	if executor.option.ReportInterval > 0 && time.Since(executor.lastReportTime) > executor.option.ReportInterval {
		logrus.WithFields(logrus.Fields{
			"total":     len(executor.nodes),
			"completed": result.Task,
		}).Info("Progress update")

		executor.lastReportTime = time.Now()
	}

	return nil
}
