package kv

import (
	"context"
	"math"

	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/common"
)

// Client client to query data from 0g kv node.
type Client struct {
	node *node.KvClient
}

// NewClient creates a new client for kv queries.
func NewClient(node *node.KvClient) *Client {
	return &Client{
		node: node,
	}
}

// NewIterator creates an iterator.
func (c *Client) NewIterator(streamId common.Hash, version ...uint64) *Iterator {
	var v uint64
	v = math.MaxUint64
	if len(version) > 0 {
		v = version[0]
	}
	return &Iterator{
		client:      c,
		streamId:    streamId,
		version:     v,
		currentPair: nil,
	}
}

// GetValue Get value of a given key from kv node.
func (c *Client) GetValue(ctx context.Context, streamId common.Hash, key []byte, version ...uint64) (val *node.Value, err error) {
	var v uint64
	v = math.MaxUint64
	if len(version) > 0 {
		v = version[0]
	}
	val = &node.Value{
		Version: v,
		Data:    make([]byte, 0),
		Size:    0,
	}
	for {
		var seg *node.Value
		seg, err = c.node.GetValue(ctx, streamId, key, uint64(len(val.Data)), maxQuerySize, val.Version)
		if err != nil {
			return
		}
		if val.Version == math.MaxUint64 {
			val.Version = seg.Version
		} else if val.Version != seg.Version {
			val.Version = seg.Version
			val.Data = make([]byte, 0)
		}
		val.Size = seg.Size
		val.Data = append(val.Data, seg.Data...)
		if uint64(len(val.Data)) == val.Size {
			return
		}
	}
}

// Get returns paginated value for the specified stream key.
func (c *Client) Get(ctx context.Context, streamId common.Hash, key []byte, startIndex, length uint64, version ...uint64) (val *node.Value, err error) {
	return c.node.GetValue(ctx, streamId, key, startIndex, length, version...)
}

// GetNext returns paginated key-value of the next key of the specified stream key.
func (c *Client) GetNext(ctx context.Context, streamId common.Hash, key []byte, startIndex, length uint64, inclusive bool, version ...uint64) (val *node.KeyValue, err error) {
	return c.node.GetNext(ctx, streamId, key, startIndex, length, inclusive, version...)
}

// GetPrev returns paginated key-value of the prev key of the specified stream key.
func (c *Client) GetPrev(ctx context.Context, streamId common.Hash, key []byte, startIndex, length uint64, inclusive bool, version ...uint64) (val *node.KeyValue, err error) {
	return c.node.GetPrev(ctx, streamId, key, startIndex, length, inclusive, version...)
}

// GetFirst returns paginated key-value of the first key of the specified stream.
func (c *Client) GetFirst(ctx context.Context, streamId common.Hash, startIndex, length uint64, version ...uint64) (val *node.KeyValue, err error) {
	return c.node.GetFirst(ctx, streamId, startIndex, length, version...)
}

// GetLast returns paginated key-value of the first key of the specified stream.
func (c *Client) GetLast(ctx context.Context, streamId common.Hash, startIndex, length uint64, version ...uint64) (val *node.KeyValue, err error) {
	return c.node.GetLast(ctx, streamId, startIndex, length, version...)
}

// GetTransactionResult query the kv replay status of a given data by sequence id.
func (c *Client) GetTransactionResult(ctx context.Context, txSeq uint64) (result string, err error) {
	return c.node.GetTransactionResult(ctx, txSeq)
}

// GetHoldingStreamIds query the stream ids monitered by the kv node.
func (c *Client) GetHoldingStreamIds(ctx context.Context) (streamIds []common.Hash, err error) {
	return c.node.GetHoldingStreamIds(ctx)
}

// HasWritePermission check if the account is able to write the stream.
func (c *Client) HasWritePermission(ctx context.Context, account common.Address, streamId common.Hash, key []byte, version ...uint64) (hasPermission bool, err error) {
	return c.node.HasWritePermission(ctx, account, streamId, key, version...)
}

// IsAdmin check if the account is the admin of the stream.
func (c *Client) IsAdmin(ctx context.Context, account common.Address, streamId common.Hash, version ...uint64) (isAdmin bool, err error) {
	return c.node.IsAdmin(ctx, account, streamId, version...)
}

// IsSpecialKey check if the key has unique access control.
func (c *Client) IsSpecialKey(ctx context.Context, streamId common.Hash, key []byte, version ...uint64) (isSpecialKey bool, err error) {
	return c.node.IsSpecialKey(ctx, streamId, key, version...)
}

// IsWriterOfKey check if the account can write the special key.
func (c *Client) IsWriterOfKey(ctx context.Context, account common.Address, streamId common.Hash, key []byte, version ...uint64) (isWriter bool, err error) {
	return c.node.IsWriterOfKey(ctx, account, streamId, key, version...)
}

// IsWriterOfStream check if the account is the writer of the stream.
func (c *Client) IsWriterOfStream(ctx context.Context, account common.Address, streamId common.Hash, version ...uint64) (isWriter bool, err error) {
	return c.node.IsWriterOfStream(ctx, account, streamId, version...)
}
