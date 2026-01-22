package main

import (
	"context"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/0gfoundation/0g-storage-client/common"
	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/common/util"
	"github.com/0gfoundation/0g-storage-client/core"
	"github.com/0gfoundation/0g-storage-client/core/merkle"
	"github.com/0gfoundation/0g-storage-client/indexer"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func getFileSegments(tree *merkle.Tree, data core.IterableData) (res []node.SegmentWithProof, err error) {
	numChunks := data.NumChunks()
	for segIndex := uint64(0); segIndex < data.NumSegments(); segIndex++ {
		// check segment index
		startIndex := segIndex * core.DefaultSegmentMaxChunks
		if startIndex >= numChunks {
			break
		}
		// get segment
		segment, err := core.ReadAt(data, core.DefaultSegmentSize, int64(segIndex*core.DefaultSegmentSize), data.PaddedSize())
		if err != nil {
			return nil, errors.WithMessage(err, "failed to read segment")
		}
		if startIndex+uint64(len(segment))/core.DefaultChunkSize >= numChunks {
			// last segment has real data
			expectedLen := core.DefaultChunkSize * int(numChunks-startIndex)
			segment = segment[:expectedLen]
		}
		// fill proof
		proof := tree.ProofAt(int(segIndex))
		segWithProof := node.SegmentWithProof{
			Root:     tree.Root(),
			Data:     segment,
			Index:    segIndex,
			Proof:    proof,
			FileSize: uint64(data.Size()),
		}
		res = append(res, segWithProof)
	}

	return res, nil
}

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

	// submit log entry
	bytes, err := randomBytes(core.DefaultSegmentSize*3 + 100)
	if err != nil {
		return errors.WithMessage(err, "failed to generate random bytes")
	}
	data, err := core.NewDataInMemory(bytes)
	if err != nil {
		return errors.WithMessage(err, "failed to initialize data")
	}
	tree, err := core.MerkleTree(data)
	if err != nil {
		return errors.WithMessage(err, "failed to build merkle tree")
	}
	indexerClient, err := indexer.NewClient(indexerUrl, indexer.IndexerClientOption{LogOption: common.LogOption{Logger: logrus.StandardLogger()}})
	if err != nil {
		return errors.WithMessage(err, "failed to initialize indexer client")
	}
	defer indexerClient.Close()
	uploader, err := indexerClient.NewUploaderFromIndexerNodes(ctx, data.NumSegments(), w3client, 1, nil, "min", true)
	if err != nil {
		return errors.WithMessage(err, "failed to initialize uploader")
	}
	sm, err := w3client.GetSignerManager()
	if err != nil {
		return errors.WithMessage(err, "failed to get signer manager")
	}
	submitter := sm.List()[0].Address()
	_, _, err = uploader.SubmitLogEntry(ctx, []core.IterableData{data}, make([][]byte, 1), transfer.SubmitLogEntryOption{
		Submitter: submitter,
		NRetries:  5,
		Step:      15,
	})
	if err != nil {
		return errors.WithMessage(err, "failed to submit log entry")
	}
	// wait for log entry
	var info *node.FileInfo
	zgsClients := node.MustNewZgsClients(zgsNodeUrls, nil)
	for i := range zgsClients {
		zgsClients[i].Close()
	}
waitLoop:
	for tryN, maxTries := 0, 15; tryN < maxTries; tryN++ {
		time.Sleep(time.Second)
		for _, client := range zgsClients {
			info, err = client.GetFileInfo(ctx, tree.Root(), true)
			if err != nil {
				return errors.WithMessage(err, "failed to get file info")
			}
			if info != nil {
				break waitLoop
			}
		}
		if tryN == maxTries-1 {
			return errors.New("failed to get file info after too many retries")
		}
	}

	// upload file segments
	segments, err := getFileSegments(tree, data)
	if err != nil {
		return errors.WithMessage(err, "failed to get file segments")
	}
	if err := indexerClient.UploadFileSegments(ctx, transfer.FileSegmentsWithProof{
		Segments: segments,
		FileInfo: info,
	}, transfer.UploadOption{Method: "min", FullTrusted: true}); err != nil {
		return errors.WithMessage(err, "failed to upload file segments")
	}

	// check upload result
checkLoop:
	for tryN, maxTries := 0, 15; tryN < maxTries; tryN++ {
		time.Sleep(time.Second)
		for _, client := range zgsClients {
			info, err = client.GetFileInfo(ctx, tree.Root(), true)
			if err != nil {
				return errors.WithMessage(err, "failed to get file info")
			}
			if info != nil && info.UploadedSegNum == data.NumSegments() {
				break checkLoop
			}
		}
		if tryN == maxTries-1 {
			return errors.New("failed to get file info to check result after too many retries")
		}
	}

	return nil
}

func main() {
	if err := util.WaitUntil(runTest, time.Minute*3); err != nil {
		logrus.WithError(err).Fatalf("file segments upload test failed")
	}
}
