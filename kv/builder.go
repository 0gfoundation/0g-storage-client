package kv

import (
	"errors"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

const maxSetSize = 1 << 16 // 64K

const maxKeySize = 1 << 24 // 16.7M

const maxQuerySize = 1024 * 256

var errSizeTooLarge = errors.New("size too large")

var errKeyTooLarge = errors.New("key too large")

var errKeyIsEmpty = errors.New("key is empty")

type streamDataBuilder struct {
	version   uint64                            // The version of all read and written keys must be less than this value when the cached KV operations are settled on chain.
	streamIds map[common.Hash]bool              // cached stream ids, used to build tags
	controls  []accessControl                   // cached access control operations
	reads     map[common.Hash]map[string]bool   // cached keys to read
	writes    map[common.Hash]map[string][]byte // cached keys to write
}

// newStreamDataBuilder initialize a stream data builder.
func newStreamDataBuilder(version uint64) *streamDataBuilder {
	return &streamDataBuilder{
		streamIds: make(map[common.Hash]bool),
		controls:  make([]accessControl, 0),
		version:   version,
		reads:     make(map[common.Hash]map[string]bool),
		writes:    make(map[common.Hash]map[string][]byte),
	}
}

// compareStreamKey orders entries by (StreamId, Key) lexicographically.
func compareStreamKey(idA common.Hash, keyA []byte, idB common.Hash, keyB []byte) bool {
	hexA := idA.Hex()
	hexB := idB.Hex()
	if hexA == hexB {
		return hexutil.Encode(keyA) < hexutil.Encode(keyB)
	}
	return hexA < hexB
}

// Build serialize all cached KV operations to StreamData.
func (builder *streamDataBuilder) Build(sorted ...bool) (*StreamData, error) {
	var err error
	data := StreamData{
		Version: builder.version,
	}

	// controls
	if data.Controls, err = builder.buildAccessControl(); err != nil {
		return nil, err
	}

	// reads
	for streamId, keys := range builder.reads {
		for k := range keys {
			key := hexutil.MustDecode(k)
			if len(key) > maxKeySize {
				return nil, errKeyTooLarge
			}
			if len(key) == 0 {
				return nil, errKeyIsEmpty
			}
			data.Reads = append(data.Reads, streamRead{
				StreamId: streamId,
				Key:      key,
			})

			if len(data.Reads) > maxSetSize {
				return nil, errSizeTooLarge
			}
		}
	}

	// writes
	for streamId, keys := range builder.writes {
		for k, d := range keys {
			key := hexutil.MustDecode(k)
			if len(key) > maxKeySize {
				return nil, errKeyTooLarge
			}
			if len(key) == 0 {
				return nil, errKeyIsEmpty
			}
			data.Writes = append(data.Writes, streamWrite{
				StreamId: streamId,
				Key:      key,
				Data:     d,
			})

			if len(data.Writes) > maxSetSize {
				return nil, errSizeTooLarge
			}
		}
	}

	if len(sorted) > 0 {
		if sorted[0] {
			sort.SliceStable(data.Reads, func(i, j int) bool {
				return compareStreamKey(data.Reads[i].StreamId, data.Reads[i].Key, data.Reads[j].StreamId, data.Reads[j].Key)
			})
			sort.SliceStable(data.Writes, func(i, j int) bool {
				return compareStreamKey(data.Writes[i].StreamId, data.Writes[i].Key, data.Writes[j].StreamId, data.Writes[j].Key)
			})
		}
	}

	return &data, nil
}

func (builder *streamDataBuilder) addStreamId(streamId common.Hash) {
	builder.streamIds[streamId] = true
}

func (builder *streamDataBuilder) buildTags(sorted ...bool) []byte {
	var ids []common.Hash

	for k := range builder.streamIds {
		ids = append(ids, k)
	}

	if len(sorted) > 0 {
		if sorted[0] {
			sort.SliceStable(ids, func(i, j int) bool {
				return ids[i].Hex() < ids[j].Hex()
			})
		}
	}

	return createTags(ids...)
}

// SetVersion Set the expected version of keys.
func (builder *streamDataBuilder) SetVersion(version uint64) *streamDataBuilder {
	builder.version = version
	return builder
}

// Watch Cache a read key operation.
func (builder *streamDataBuilder) Watch(streamId common.Hash, key []byte) *streamDataBuilder {
	if keys, ok := builder.reads[streamId]; ok {
		keys[hexutil.Encode(key)] = true
	} else {
		builder.reads[streamId] = make(map[string]bool)
		builder.reads[streamId][hexutil.Encode(key)] = true
	}

	return builder
}

// Set Cache a write key operation.
func (builder *streamDataBuilder) Set(streamId common.Hash, key []byte, data []byte) *streamDataBuilder {
	builder.addStreamId(streamId)

	if keys, ok := builder.writes[streamId]; ok {
		keys[hexutil.Encode(key)] = data
	} else {
		builder.writes[streamId] = make(map[string][]byte)
		builder.writes[streamId][hexutil.Encode(key)] = data
	}

	return builder
}

func (builder *streamDataBuilder) buildAccessControl() ([]accessControl, error) {
	if len(builder.controls) > maxSetSize {
		return nil, errSizeTooLarge
	}

	return builder.controls, nil
}

func (builder *streamDataBuilder) withControl(t accessControlType, streamId common.Hash, account *common.Address, key []byte) *streamDataBuilder {
	builder.addStreamId(streamId)

	builder.controls = append(builder.controls, accessControl{
		Type:     t,
		StreamId: streamId,
		Account:  account,
		Key:      key,
	})

	return builder
}

// GrantAdminRole Cache a GrantAdminRole operation.
func (builder *streamDataBuilder) GrantAdminRole(streamId common.Hash, account common.Address) *streamDataBuilder {
	return builder.withControl(aclTypeGrantAdminRole, streamId, &account, nil)
}

// RenounceAdminRole Cache a RenounceAdminRole operation.
func (builder *streamDataBuilder) RenounceAdminRole(streamId common.Hash) *streamDataBuilder {
	return builder.withControl(aclTypeRenounceAdminRole, streamId, nil, nil)
}

// SetKeyToSpecial Cache a SetKeyToSpecial operation.
func (builder *streamDataBuilder) SetKeyToSpecial(streamId common.Hash, key []byte) *streamDataBuilder {
	return builder.withControl(aclTypeSetKeyToSpecial, streamId, nil, key)
}

// SetKeyToNormal Cache a SetKeyToNormal operation.
func (builder *streamDataBuilder) SetKeyToNormal(streamId common.Hash, key []byte) *streamDataBuilder {
	return builder.withControl(aclTypeSetKeyToNormal, streamId, nil, key)
}

// GrantWriteRole Cache a GrantWriteRole operation.
func (builder *streamDataBuilder) GrantWriteRole(streamId common.Hash, account common.Address) *streamDataBuilder {
	return builder.withControl(aclTypeGrantWriteRole, streamId, &account, nil)
}

// RevokeWriteRole Cache a RevokeWriteRole operation.
func (builder *streamDataBuilder) RevokeWriteRole(streamId common.Hash, account common.Address) *streamDataBuilder {
	return builder.withControl(aclTypeRevokeWriteRole, streamId, &account, nil)
}

// RenounceWriteRole Cache a RenounceWriteRole operation.
func (builder *streamDataBuilder) RenounceWriteRole(streamId common.Hash) *streamDataBuilder {
	return builder.withControl(aclTypeRenounceWriteRole, streamId, nil, nil)
}

// GrantSpecialWriteRole Cache a GrantSpecialWriteRole operation.
func (builder *streamDataBuilder) GrantSpecialWriteRole(streamId common.Hash, key []byte, account common.Address) *streamDataBuilder {
	return builder.withControl(aclTypeGrantSpecialWriteRole, streamId, &account, key)
}

// RevokeSpecialWriteRole Cache a RevokeSpecialWriteRole operation.
func (builder *streamDataBuilder) RevokeSpecialWriteRole(streamId common.Hash, key []byte, account common.Address) *streamDataBuilder {
	return builder.withControl(aclTypeRevokeSpecialWriteRole, streamId, &account, key)
}

// RenounceSpecialWriteRole Cache a RenounceSpecialWriteRole operation.
func (builder *streamDataBuilder) RenounceSpecialWriteRole(streamId common.Hash, key []byte) *streamDataBuilder {
	return builder.withControl(aclTypeRenounceSpecialWriteRole, streamId, nil, key)
}
