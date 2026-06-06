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
	eth_common "github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// runTest uploads a file, then extends its storage period by the original submit tx hash
// WITHOUT re-uploading, asserting a new (distinct) submit tx is produced and the data is
// still located on storage afterwards.
func runTest() error {
	ctx := context.Background()
	args := os.Args[1:]
	key := args[0]
	chainUrl := args[1]
	zgsNodeUrls := strings.Split(args[2], ",")
	indexerUrl := args[3]

	w3client := blockchain.MustNewWeb3(chainUrl, key)
	defer w3client.Close()

	indexerClient, err := indexer.NewClient(indexerUrl, indexer.IndexerClientOption{LogOption: common.LogOption{Logger: logrus.StandardLogger()}})
	if err != nil {
		return errors.WithMessage(err, "failed to initialize indexer client")
	}
	defer indexerClient.Close()

	// 1. upload a file and capture the submit tx hash(es)
	data, err := core.NewDataInMemory([]byte("extend_storage_test_data_0123456789"))
	if err != nil {
		return errors.WithMessage(err, "failed to initialize data")
	}
	uploadOpt := transfer.UploadOption{
		FinalityRequired: transfer.FileFinalized,
		Method:           "min",
		FullTrusted:      true,
	}
	submitTxs, roots, err := indexerClient.SplitableUpload(ctx, w3client, data, uploadOpt)
	if err != nil {
		return errors.WithMessage(err, "failed to upload file")
	}
	if len(submitTxs) == 0 || len(roots) == 0 {
		return fmt.Errorf("upload returned no submit tx / roots")
	}
	logrus.WithField("submitTxs", submitTxs).WithField("roots", roots).Info("uploaded")

	// 2. extend by the original submit tx hash — no re-upload
	extendTxs, err := indexerClient.ExtendStorage(ctx, w3client, submitTxs, transfer.ExtendOption{
		Method:          "min",
		ExpectedReplica: 1,
		FullTrusted:     true,
	})
	if err != nil {
		return errors.WithMessage(err, "failed to extend storage")
	}
	if len(extendTxs) == 0 {
		return fmt.Errorf("extend returned no tx hashes")
	}
	// 3. the extend tx must be a NEW, distinct submission
	for _, et := range extendTxs {
		for _, ut := range submitTxs {
			if et == ut {
				return fmt.Errorf("extend tx %v equals original submit tx; expected a new submission", et.Hex())
			}
		}
	}
	logrus.WithField("extendTxs", extendTxs).Info("extended storage period")

	// 4. data must still be located on storage (it was never re-uploaded)
	for _, root := range roots {
		locations, err := indexerClient.GetFileLocations(ctx, root.Hex())
		if err != nil {
			return errors.WithMessagef(err, "failed to get file locations for %v after extend", root.Hex())
		}
		if len(locations) == 0 {
			return fmt.Errorf("no locations for %v after extend", root.Hex())
		}
		if locations[0].URL != zgsNodeUrls[0] {
			return fmt.Errorf("unexpected file location: %v", locations[0].URL)
		}
	}

	return nil
}

// checkUnknownTx asserts that extending an unknown submit tx hash returns
// transfer.ErrSubmitEventNotFound (the "cannot recover submission" path).
func checkUnknownTx() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := os.Args[1:]
	key := args[0]
	chainUrl := args[1]
	indexerUrl := args[3]

	w3client := blockchain.MustNewWeb3(chainUrl, key)
	defer w3client.Close()
	indexerClient, err := indexer.NewClient(indexerUrl, indexer.IndexerClientOption{LogOption: common.LogOption{Logger: logrus.StandardLogger()}})
	if err != nil {
		return errors.WithMessage(err, "failed to initialize indexer client")
	}
	defer indexerClient.Close()

	unknown := eth_common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	_, err = indexerClient.ExtendStorage(ctx, w3client, []eth_common.Hash{unknown}, transfer.ExtendOption{Method: "min", ExpectedReplica: 1, FullTrusted: true})
	if err == nil {
		return fmt.Errorf("expected error extending an unknown tx hash, got nil")
	}
	var notFound *transfer.ErrSubmitEventNotFound
	if !errors.As(err, &notFound) {
		return errors.WithMessagef(err, "expected ErrSubmitEventNotFound for unknown tx")
	}
	logrus.Info("unknown-tx extend correctly returned ErrSubmitEventNotFound")
	return nil
}

func main() {
	if err := util.WaitUntil(runTest, time.Minute*3); err != nil {
		logrus.WithError(err).Fatalf("extend storage test failed")
	}
	if err := checkUnknownTx(); err != nil {
		logrus.WithError(err).Fatalf("extend storage negative test failed")
	}
}
