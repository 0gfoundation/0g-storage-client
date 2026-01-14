package main

import (
	"context"
	"fmt"
	"math"

	"github.com/0gfoundation/0g-storage-client/common/blockchain"
	"github.com/0gfoundation/0g-storage-client/kv"
	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/0gfoundation/0g-storage-client/transfer"
	"github.com/ethereum/go-ethereum/common"
)

const ZgsClientAddr = "http://127.0.0.1:5678"
const BlockchainClientAddr = ""
const PrivKey = ""

func main() {
	zgsClient, err := node.NewZgsClient(ZgsClientAddr, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	blockchainClient := blockchain.MustNewWeb3(BlockchainClientAddr, PrivKey)
	defer blockchainClient.Close()
	blockchain.CustomGasLimit = 1000000

	batcher := kv.NewBatcher(math.MaxUint64, &transfer.SelectedNodes{
		Trusted:    []*node.ZgsClient{zgsClient},
		Discovered: []*node.ZgsClient{},
	}, blockchainClient)
	batcher.Set(common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000f2bd"),
		[]byte("TESTKEY0"),
		[]byte{69, 70, 71, 72, 73},
	)
	batcher.Set(common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000f2bd"),
		[]byte("TESTKEY1"),
		[]byte{74, 75, 76, 77, 78},
	)
	_, err = batcher.Exec(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
}
