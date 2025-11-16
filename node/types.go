package node

import (
	"encoding/json"

	"github.com/0gfoundation/0g-storage-client/common/shard"
	"github.com/0gfoundation/0g-storage-client/core/merkle"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// NetworkProtocolVersion P2P network protocol version.
type NetworkProtocolVersion struct {
	Major uint8 `json:"major"`
	Minor uint8 `json:"minor"`
	Build uint8 `json:"build"`
}

// NetworkIdentity network identity of 0g storage node to distinguish different networks.
type NetworkIdentity struct {
	ChainId                uint64                 `json:"chainId"`
	FlowContractAddress    common.Address         `json:"flowAddress"`
	NetworkProtocolVersion NetworkProtocolVersion `json:"p2pProtocolVersion"`
}

// Status sync status of 0g storage node
type Status struct {
	ConnectedPeers  uint            `json:"connectedPeers"`
	LogSyncHeight   uint64          `json:"logSyncHeight"`
	LogSyncBlock    common.Hash     `json:"logSyncBlock"`
	NextTxSeq       uint64          `json:"nextTxSeq"`
	NetworkIdentity NetworkIdentity `json:"networkIdentity"`
}

// Transaction on-chain transaction about a file
type Transaction struct {
	StreamIds       []*hexutil.Big `json:"streamIds"`       // transaction related stream id, used for KV operations
	Data            []byte         `json:"data"`            // in-place data
	DataMerkleRoot  common.Hash    `json:"dataMerkleRoot"`  // data merkle root
	StartEntryIndex uint64         `json:"startEntryIndex"` // start entry index in on-chain flow contract
	Size            uint64         `json:"size"`            // file size in bytes
	Seq             uint64         `json:"seq"`             // sequence id in on-chain flow contract
}

// FileInfo information about a file responded from 0g storage node
type FileInfo struct {
	Tx             Transaction `json:"tx"`             // on-chain transaction
	Finalized      bool        `json:"finalized"`      // whether the file has been finalized in the storage node
	IsCached       bool        `json:"isCached"`       // whether the file is cached in the storage node
	UploadedSegNum uint64      `json:"uploadedSegNum"` // the number of uploaded segments
	Pruned         bool        `json:"pruned"`         // whether the file has been pruned, and mutually exclusive with Finalized
}

// SegmentWithProof data segment with merkle proof
type SegmentWithProof struct {
	Root     common.Hash  `json:"root"`     // file merkle root
	Data     []byte       `json:"data"`     // segment data
	Index    uint64       `json:"index"`    // segment index
	Proof    merkle.Proof `json:"proof"`    // segment merkle proof
	FileSize uint64       `json:"fileSize"` // file size
}

// FlowProof proof of a sector in flow
type FlowProof struct {
	Lemma []common.Hash `json:"lemma"`
	Path  []bool        `json:"path"`
}

// Value KV value
type Value struct {
	Version uint64 `json:"version"` // key version
	Data    []byte `json:"data"`    // value data
	Size    uint64 `json:"size"`    // value total size
}

// KeyValue KV key and value
type KeyValue struct {
	Version uint64 `json:"version"` // key version
	Key     []byte `json:"key"`     // value key
	Data    []byte `json:"data"`    // value data
	Size    uint64 `json:"size"`    // value total size
}

// FileSyncInfo file sync information
type FileSyncInfo struct {
	ElapsedSecs uint64               `json:"elapsedSecs"`
	Peers       map[PeerState]uint64 `json:"peers"`
	Goal        FileSyncGoal         `json:"goal"`
	NextChunks  uint64               `json:"next_chunks"`
	State       string               `json:"state"`
}

// PeerState network peer status
type PeerState string

const (
	PeerStateFound         PeerState = "Found"
	PeerStateConnecting    PeerState = "Connecting"
	PeerStateConnected     PeerState = "Connected"
	PeerStateDisconnecting PeerState = "Disconnecting"
	PeerStateDisconnected  PeerState = "Disconnected"
)

// FileSyncGoal File sync goal
type FileSyncGoal struct {
	NumChunks  uint64 `json:"numChunks"`
	IndexStart uint64 `json:"indexStart"`
	IndexEnd   uint64 `json:"indexEnd"`
}

// NetworkInfo network information
type NetworkInfo struct {
	PeerId                 string   `json:"peerId"`
	ListenAddresses        []string `json:"listenAddresses"`
	TotalPeers             uint64   `json:"totalPeers"`
	BannedPeers            uint64   `json:"bannedPeers"`
	DisconnectedPeers      uint64   `json:"disconnectedPeers"`
	ConnectedPeers         uint64   `json:"connectedPeers"`
	ConnectedOutgoingPeers uint64   `json:"connectedOutgoingPeers"`
	ConnectedIncomingPeers uint64   `json:"connectedIncomingPeers"`
}

// ClientInfo client information of remote peer
type ClientInfo struct {
	Version  string `json:"version"`
	OS       string `json:"os"`
	Protocol string `json:"protocol"`
	Agent    string `json:"agent"`
}

// PeerConnectionStatus network connection status of remote peer
type PeerConnectionStatus struct {
	Status         string `json:"status"` // connected, disconnecting, disconnected, banned, dialing, unknown
	ConnectionsIn  uint8  `json:"connectionsIn"`
	ConnectionsOut uint8  `json:"connectionsOut"`
	LastSeenSecs   uint64 `json:"lastSeenSecs"`
}

// PeerInfo remote peer information
type PeerInfo struct {
	Client              ClientInfo           `json:"client"`
	ConnectionStatus    PeerConnectionStatus `json:"connectionStatus"`
	ListeningAddresses  []string             `json:"listeningAddresses"`
	SeenIps             []string             `json:"seenIps"`
	IsTrusted           bool                 `json:"isTrusted"`
	ConnectionDirection string               `json:"connectionDirection"` // Incoming/Outgoing/empty
	Enr                 string               `json:"enr"`                 // maybe empty
}

// LocationInfo file location information
type LocationInfo struct {
	Ip          string            `json:"ip"`
	ShardConfig shard.ShardConfig `json:"shardConfig"`
}

// TxSeqOrRoot represents a tx seq or data root.
type TxSeqOrRoot struct {
	TxSeq uint64
	Root  common.Hash
}

// MarshalJSON implements json.Marshaler interface.
func (t TxSeqOrRoot) MarshalJSON() ([]byte, error) {
	if t.Root.Cmp(common.Hash{}) == 0 {
		return json.Marshal(t.TxSeq)
	}

	return json.Marshal(t.Root)
}
