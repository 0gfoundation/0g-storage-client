package node

import (
	"errors"
	"net"
	"net/url"
	"strings"

	zgs_grpc "github.com/0glabs/0g-storage-client/node/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func HTTPToGRPCAddr(httpAddr string) (string, error) {
	u, err := url.Parse(httpAddr)
	if err != nil {
		return "", errors.New("failed to parse HTTP address: " + err.Error())
	}
	host := u.Hostname()
	if host == "" {
		// maybe they passed "1.2.3.4:5678" without scheme
		host, _, err = net.SplitHostPort(u.Path)
		if err != nil {
			return "", errors.New("failed to split host and port: " + err.Error())
		}
	}
	return net.JoinHostPort(host, "50051"), nil
}

func newGrpcClient(url string) (zgs_grpc.ZgsGrpcServiceClient, error) {
	var err error
	grpcEndpoint := url
	if strings.HasPrefix(url, "http") {
		grpcEndpoint, err = HTTPToGRPCAddr(url)
		if err != nil {
			return nil, errors.New("failed to convert HTTP address to gRPC address: " + err.Error())
		}
	}
	conn, err := grpc.Dial(grpcEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logrus.Fatalf("Failed to connect to gRPC server at %s: %v", url, err)
	}
	defer conn.Close()

	client := zgs_grpc.NewZgsGrpcServiceClient(conn)
	if client == nil {
		return nil, errors.New("failed to create gRPC client")
	}

	return client, nil
}
