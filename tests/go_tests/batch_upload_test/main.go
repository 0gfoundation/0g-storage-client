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
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func runTest() error {
	ctx := context.Background()
	// load args
	args := os.Args[1:]
	key := args[0]
	chainUrl := args[1]
	zgsNodeUrls := strings.Split(args[2], ",")
	indexerUrl := args[3]

	w3client := blockchain.MustNewWeb3(chainUrl, key)
	defer w3client.Close()

	// batch upload
	datas := make([]core.IterableData, 10)
	opts := make([]transfer.UploadOption, 10)
	var err error
	for i := 0; i < 10; i += 1 {
		datas[i], err = core.NewDataInMemory([]byte(fmt.Sprintf("indexer_test_data_%v", i)))
		if err != nil {
			return errors.WithMessage(err, "failed to initialize data")
		}
		opts[i] = transfer.UploadOption{
			FinalityRequired: transfer.FileFinalized,
			Method:           "min",
			FullTrusted:      true,
		}
	}
	indexerClient, err := indexer.NewClient(indexerUrl, indexer.IndexerClientOption{LogOption: common.LogOption{Logger: logrus.StandardLogger()}})
	if err != nil {
		return errors.WithMessage(err, "failed to initialize indexer client")
	}
	_, roots, err := indexerClient.BatchUpload(ctx, w3client, datas, transfer.BatchUploadOption{
		TaskSize:    5,
		DataOptions: opts,
		Method:      "min",
		FullTrusted: true,
	})
	if err != nil {
		return errors.WithMessage(err, "failed to upload file")
	}
	// check file location
	for _, root := range roots {
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
	}
	return nil
}

func main() {
	if err := util.WaitUntil(runTest, time.Minute*3); err != nil {
		logrus.WithError(err).Fatalf("batch upload test failed")
	}
}
