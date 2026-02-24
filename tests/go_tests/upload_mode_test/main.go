package main

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/openweb3/web3go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// fastUploadMaxSize = 256 * 1024 in transfer package
// slowParallelMaxSize = 2 * 1024 * 1024 in transfer package

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

type testCase struct {
	name     string
	dataSize int
	fastMode bool
}

func runTest() error {
	ctx := context.Background()
	args := os.Args[1:]
	key := args[0]
	chainUrl := args[1]
	zgsNodeUrls := strings.Split(args[2], ",")

	w3client := blockchain.MustNewWeb3(chainUrl, key)
	defer w3client.Close()

	cases := []testCase{
		// fast mode + small data (100KB < 256KB) → uploadFast: broadcast by root, no receipt wait
		{"fast_small", 100 * 1024, true},
		// fast mode + large data (300KB > 256KB) → fast overridden, falls to uploadSlow
		{"fast_large", 300 * 1024, true},
		// slow mode + small data (100KB < 2MB) → uploadSlowParallel: parallel tx + upload
		{"slow_small", 100 * 1024, false},
		// slow mode + large data (3MB > 2MB) → uploadSlow sequential: wait receipt then upload
		{"slow_large", 3 * 1024 * 1024, false},
	}

	for _, tc := range cases {
		if err := runCase(ctx, w3client, zgsNodeUrls, tc); err != nil {
			return err
		}
	}

	return nil
}

func runCase(ctx context.Context, w3client *web3go.Client, zgsNodeUrls []string, tc testCase) error {
	logrus.Infof("=== Test: %s (size=%d, fastMode=%v) ===", tc.name, tc.dataSize, tc.fastMode)

	data, err := randomBytes(tc.dataSize)
	if err != nil {
		return errors.WithMessagef(err, "%s: random bytes", tc.name)
	}

	iterData, err := core.NewDataInMemory(data)
	if err != nil {
		return errors.WithMessagef(err, "%s: NewDataInMemory", tc.name)
	}

	uploader, closer, err := transfer.NewUploaderFromConfig(ctx, w3client, transfer.UploaderConfig{
		Nodes:     zgsNodeUrls,
		LogOption: common.LogOption{Logger: logrus.StandardLogger()},
	})
	if err != nil {
		return errors.WithMessagef(err, "%s: NewUploaderFromConfig", tc.name)
	}
	defer closer()

	opt := transfer.UploadOption{
		FastMode:         tc.fastMode,
		SkipTx:           false,
		FinalityRequired: transfer.FileFinalized,
	}

	_, root, err := uploader.Upload(ctx, iterData, opt)
	if err != nil {
		return errors.WithMessagef(err, "%s: Upload failed", tc.name)
	}

	logrus.Infof("%s: uploaded root=%s", tc.name, root.Hex())

	// Verify file is finalized on all 4 sharded nodes
	for _, url := range zgsNodeUrls {
		client, err := node.NewZgsClient(url, nil)
		if err != nil {
			return errors.WithMessagef(err, "%s: NewZgsClient(%s)", tc.name, url)
		}
		info, err := client.GetFileInfo(ctx, root, true)
		client.Close()
		if err != nil {
			return errors.WithMessagef(err, "%s: GetFileInfo on %s", tc.name, url)
		}
		if info == nil {
			return fmt.Errorf("%s: file info nil on %s", tc.name, url)
		}
		if !info.Finalized {
			return fmt.Errorf("%s: not finalized on %s", tc.name, url)
		}
	}

	logrus.Infof("%s: PASSED", tc.name)
	return nil
}

func main() {
	if err := util.WaitUntil(runTest, time.Minute*5); err != nil {
		logrus.WithError(err).Fatalf("upload mode test failed")
	}
}
