package kv

import (
	"context"
	"errors"

	"github.com/0gfoundation/0g-storage-client/node"
	"github.com/ethereum/go-ethereum/common"
)

var errIteratorInvalid = errors.New("iterator is invalid")

// Iterator to iterate over a kv stream
type Iterator struct {
	client      *Client
	streamId    common.Hash
	version     uint64
	currentPair *node.KeyValue
}

// Valid check if current position is exist
func (iter *Iterator) Valid() bool {
	return iter.currentPair != nil
}

// KeyValue return key-value at current position
func (iter *Iterator) KeyValue() *node.KeyValue {
	return iter.currentPair
}

func (iter *Iterator) move(ctx context.Context, kv *node.KeyValue) error {
	if kv == nil {
		iter.currentPair = nil
		return nil
	}
	value, err := iter.client.GetValue(ctx, iter.streamId, kv.Key, iter.version)
	if err != nil {
		return err
	}
	iter.currentPair = &node.KeyValue{
		Version: value.Version,
		Key:     kv.Key,
		Data:    value.Data,
		Size:    value.Size,
	}
	return nil
}

// SeekBefore seek to the position before given key(inclusive)
func (iter *Iterator) SeekBefore(ctx context.Context, key []byte) error {
	kv, err := iter.client.GetPrev(ctx, iter.streamId, key, 0, 0, true, iter.version)
	if err != nil {
		return err
	}
	return iter.move(ctx, kv)
}

// SeekAfter seek to the position after given key(inclusive)
func (iter *Iterator) SeekAfter(ctx context.Context, key []byte) error {
	kv, err := iter.client.GetNext(ctx, iter.streamId, key, 0, 0, true, iter.version)
	if err != nil {
		return err
	}
	return iter.move(ctx, kv)
}

// SeekToFirst seek to the first position
func (iter *Iterator) SeekToFirst(ctx context.Context) error {
	kv, err := iter.client.GetFirst(ctx, iter.streamId, 0, 0, iter.version)
	if err != nil {
		return err
	}
	return iter.move(ctx, kv)
}

// SeekToLast seek to the last position
func (iter *Iterator) SeekToLast(ctx context.Context) error {
	kv, err := iter.client.GetLast(ctx, iter.streamId, 0, 0, iter.version)
	if err != nil {
		return err
	}
	return iter.move(ctx, kv)
}

// Next move to the next position
func (iter *Iterator) Next(ctx context.Context) error {
	if !iter.Valid() {
		return errIteratorInvalid
	}
	kv, err := iter.client.GetNext(ctx, iter.streamId, iter.currentPair.Key, 0, 0, false, iter.version)
	if err != nil {
		return err
	}
	return iter.move(ctx, kv)
}

// Prev move to the prev position
func (iter *Iterator) Prev(ctx context.Context) error {
	if !iter.Valid() {
		return errIteratorInvalid
	}
	kv, err := iter.client.GetPrev(ctx, iter.streamId, iter.currentPair.Key, 0, 0, false, iter.version)
	if err != nil {
		return err
	}
	return iter.move(ctx, kv)
}
