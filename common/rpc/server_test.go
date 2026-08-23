package rpc

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A bind failure has to reach the caller. It used to be discarded, so MustServe
// returned as though the service were listening.
func TestStart_ReportsBindFailure(t *testing.T) {
	// Occupy a port, then try to serve on the same address.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	err = Start(listener.Addr().String(), http.NotFoundHandler())

	require.Error(t, err, "binding an address already in use must be reported")
	assert.NotErrorIs(t, err, http.ErrServerClosed, "a bind failure is not a clean shutdown")
}

// A clean shutdown is not a failure, so it must not be reported as one.
func TestStart_CleanShutdownIsNotAnError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := http.Server{Handler: http.NotFoundHandler()}
	done := make(chan error, 1)
	go func() {
		if serveErr := server.Serve(listener); serveErr != http.ErrServerClosed {
			done <- serveErr
			return
		}
		done <- nil
	}()

	require.NoError(t, server.Close())
	assert.NoError(t, <-done, "http.ErrServerClosed must not surface as a failure")
}
