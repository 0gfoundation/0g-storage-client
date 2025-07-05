package node

import (
	"errors"

	zgs_grpc "github.com/0glabs/0g-storage-client/node/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type grpcClient struct {
	client zgs_grpc.ZgsGrpcServiceClient
	close  func()
	url    string
}

func newGrpcClient(url string) (*grpcClient, error) {
	if url == "" {
		return nil, nil
	}
	conn, err := grpc.Dial(url, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logrus.Fatalf("Failed to connect to gRPC server at %s: %v", url, err)
	}

	client := zgs_grpc.NewZgsGrpcServiceClient(conn)
	if client == nil {
		return nil, errors.New("failed to create gRPC client")
	}

	return &grpcClient{
		client: client,
		close: func() {
			_ = conn.Close()
		},
		url: url,
	}, nil
}

func (c *grpcClient) GrpcURL() string {
	return c.url
}
