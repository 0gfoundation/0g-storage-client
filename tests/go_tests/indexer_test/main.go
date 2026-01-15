package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func runTest() error {
	ctx := context.Background()
	// load args, indexer's trusted & discover node is node[0]
	args := os.Args[1:]
	key := args[0]
	chainUrl := args[1]
	zgsNodeUrls := strings.Split(args[2], ",")
	indexerUrl := args[3]

	w3client := blockchain.MustNewWeb3(chainUrl, key)
	defer w3client.Close()

	// upload by indexer
	data, err := core.NewDataInMemory([]byte("indexer_test_data"))
	if err != nil {
		return errors.WithMessage(err, "failed to initialize data")
	}
	indexerClient, err := indexer.NewClient(indexerUrl, indexer.IndexerClientOption{LogOption: common.LogOption{Logger: logrus.StandardLogger()}})
	if err != nil {
		return errors.WithMessage(err, "failed to initialize indexer client")
	}
	if _, _, err := indexerClient.SplitableUpload(ctx, w3client, data, 1024*1024*1024*4, transfer.UploadOption{
		FinalityRequired: transfer.FileFinalized,
		Method:           "min",
		FullTrusted:      true,
	}); err != nil {
		return errors.WithMessage(err, "failed to upload file")
	}
	tree, err := core.MerkleTree(data)
	if err != nil {
		return errors.WithMessage(err, "failed to build merkle tree")
	}
	root := tree.Root()
	// check file location
	locations, err := indexerClient.GetFileLocations(ctx, root.Hex())
	if err != nil {
		return errors.WithMessage(err, "failed to get file locations")
	}
	if len(locations) != 1 {
		return fmt.Errorf("unexpected file location length: %v", len(locations))
	}
	if locations[0].URL != zgsNodeUrls[0] {
		return fmt.Errorf("unexpected file location: %v", locations[0].URL)
	}
	// upload data to second node
	data, err = core.NewDataInMemory([]byte("indexer_test_data_2"))
	if err != nil {
		return errors.WithMessage(err, "failed to initialize data")
	}
	clients := node.MustNewZgsClients(zgsNodeUrls[1:], nil)
	for _, client := range clients {
		defer client.Close()
	}

	uploader, err := transfer.NewUploaderWithContractConfig(ctx, w3client, &transfer.SelectedNodes{Trusted: clients}, transfer.UploaderConfig{
		LogOption: common.LogOption{Logger: logrus.StandardLogger()},
	})
	if err != nil {
		return errors.WithMessage(err, "failed to initialize uploader")
	}

	if _, _, err := uploader.Upload(context.Background(), data, transfer.UploadOption{
		FinalityRequired: transfer.FileFinalized,
	}); err != nil {
		return errors.WithMessage(err, "failed to upload file")
	}
	tree, err = core.MerkleTree(data)
	if err != nil {
		return errors.WithMessage(err, "failed to build merkle tree")
	}
	root = tree.Root()

	client0 := node.MustNewZgsClient(zgsNodeUrls[0], nil)
	for {
		info, err := client0.GetFileInfo(ctx, root, true)
		if err != nil {
			return errors.WithMessage(err, "failed to get file info")
		}
		if info != nil {
			break
		}
		time.Sleep(time.Second)
	}
	// node list
	_, err = indexerClient.GetShardedNodes(ctx)
	if err != nil {
		return errors.WithMessage(err, "failed to get sharded nodes")
	}
	return nil
}

func main() {
	if err := util.WaitUntil(runTest, time.Minute*3); err != nil {
		logrus.WithError(err).Fatalf("indexer test failed")
	}
}
