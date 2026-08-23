package rpc

import (
	"net/http"

	"github.com/ethereum/go-ethereum/node"
	"github.com/openweb3/go-rpc-provider"
	"github.com/sirupsen/logrus"
)

// MustNewHandler creates a http.Handler for the specified RPC apis.
func MustNewHandler(apis map[string]interface{}) http.Handler {
	handler := rpc.NewServer()

	for namespace, impl := range apis {
		if err := handler.RegisterName(namespace, impl); err != nil {
			logrus.WithError(err).WithField("namespace", namespace).Fatal("Failed to register rpc service")
		}
	}

	// enable cors
	return node.NewHTTPHandlerStack(handler, []string{"*"}, []string{"*"}, []byte{})
}

// Start starts a HTTP service until shutdown, reporting why it stopped.
//
// The result must not be discarded: ListenAndServe fails immediately when the endpoint
// cannot be bound - already in use, invalid, no permission - and a caller that ignores
// it carries on as though the service were listening. A clean shutdown reports
// http.ErrServerClosed, which is not an error to the caller and is folded into nil.
func Start(endpoint string, handler http.Handler) error {
	server := http.Server{
		Addr:    endpoint,
		Handler: handler,
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}

	return nil
}

// MustServe starts RPC service until shutdown, exiting if it cannot be served.
func MustServe(endpoint string, apis map[string]interface{}) {
	if err := Start(endpoint, MustNewHandler(apis)); err != nil {
		logrus.WithError(err).WithField("endpoint", endpoint).Fatal("Failed to serve RPC")
	}
}
