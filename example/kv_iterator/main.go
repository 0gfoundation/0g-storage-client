package main

import (
	"context"
	"fmt"

	"github.com/0gfoundation/0g-storage-client/kv"
	"github.com/0gfoundation/0g-storage-client/node"
	ethCommon "github.com/ethereum/go-ethereum/common"
)

const KvClientAddr = "http://127.0.0.1:6789"

func main() {
	ctx := context.Background()
	client := node.MustNewKvClient(KvClientAddr)
	defer client.Close()

	streamId := ethCommon.HexToHash("0x000000000000000000000000000000000000000000000000000000000000f2bd")
	key0 := []byte("TESTKEY")
	key1 := []byte("TESTKEY2")

	kvClient := kv.NewClient(client)
	iter := kvClient.NewIterator(streamId)

	fmt.Println("begin to end:")
	iter.SeekToFirst(ctx)
	for iter.Valid() {
		pair := iter.KeyValue()
		fmt.Printf("%v: %v\n", string(pair.Key), string(pair.Data))
		iter.Next(ctx)
	}

	fmt.Println("end to begin:")
	iter.SeekToLast(ctx)
	for iter.Valid() {
		pair := iter.KeyValue()
		fmt.Printf("%v: %v\n", string(pair.Key), string(pair.Data))
		iter.Prev(ctx)
	}

	fmt.Printf("seek before %v\n", string(key1))
	iter.SeekBefore(ctx, key1)
	pair := iter.KeyValue()
	fmt.Printf("%v: %v\n", string(pair.Key), string(pair.Data))

	fmt.Printf("seek after %v\n", string(key0))
	iter.SeekAfter(ctx, key0)
	pair = iter.KeyValue()
	fmt.Printf("%v: %v\n", string(pair.Key), string(pair.Data))
}
