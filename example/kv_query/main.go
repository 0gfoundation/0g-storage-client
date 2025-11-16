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
	key := []byte("TESTKEY0")
	key1 := []byte("TESTKEY1")
	key2 := []byte("TESTKEY2")
	account := ethCommon.HexToAddress("0x578dd2bfc41bb66e9f0ae0802c613996440c9597")

	kvClient := kv.NewClient(client)
	val, _ := kvClient.GetValue(ctx, streamId, key)
	fmt.Println(string(val.Data))
	val, _ = kvClient.GetValue(ctx, streamId, key1)
	fmt.Println(string(val.Data))
	val, _ = kvClient.GetValue(ctx, streamId, key2)
	fmt.Println(val)
	fmt.Println(kvClient.GetTransactionResult(ctx, 2))
	fmt.Println(kvClient.GetHoldingStreamIds(ctx))
	fmt.Println(kvClient.HasWritePermission(ctx, account, streamId, key))
	fmt.Println(kvClient.IsAdmin(ctx, account, streamId))
	fmt.Println(kvClient.IsSpecialKey(ctx, streamId, key))
	fmt.Println(kvClient.IsWriterOfKey(ctx, account, streamId, key))
	fmt.Println(kvClient.IsWriterOfStream(ctx, account, streamId))
}
