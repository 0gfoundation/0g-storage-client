---
id: sdk
title: Storage SDK
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# 0G Storage SDKs

Build decentralized storage into your applications with our powerful SDKs designed for modern development workflows.

## Available SDKs

- **Go SDK**: Ideal for backend systems and applications built with Go
- **TypeScript SDK**: Perfect for frontend development and JavaScript-based projects

## Core Features

Both SDKs provide a streamlined interface to interact with the 0G Storage network:

- **Upload and Download Files**: Securely store and retrieve data of various sizes and formats
- **Manage Data**: List uploaded files, check their status, and control access permissions
- **Leverage Decentralization**: Benefit from the 0G network's distributed architecture for enhanced data availability, immutability, and censorship resistance

## Quick Start Resources

:::tip Starter Kits Available
Get up and running quickly with our comprehensive starter kits:

- **[TypeScript Starter Kit](https://github.com/0gfoundation/0g-storage-ts-starter-kit)** - Complete examples with Express.js server and CLI tool
- **[Go Starter Kit](https://github.com/0gfoundation/0g-storage-go-starter-kit)** - Ready-to-use examples with Gin server and CLI tool

Both repositories include working examples, API documentation, and everything you need to start building.
:::

<Tabs>
<TabItem value="go" label="Go SDK" default>

## Installation

Install the 0G Storage Client library:

```bash
go get github.com/0gfoundation/0g-storage-client
```

## Setup

### Import Required Packages

```go
import (
    "context"
    "github.com/0gfoundation/0g-storage-client/common/blockchain"
    "github.com/0gfoundation/0g-storage-client/common"
    "github.com/0gfoundation/0g-storage-client/indexer"
    "github.com/0gfoundation/0g-storage-client/transfer"
    "github.com/0gfoundation/0g-storage-client/core"
)
```

### Initialize Clients

Create the necessary clients to interact with the network:

```go
// Create Web3 client for blockchain interactions
w3client := blockchain.MustNewWeb3(evmRpc, privateKey)
defer w3client.Close()

// Create indexer client for node management
indexerClient, err := indexer.NewClient(indRpc, indexer.IndexerClientOption{
    LogOption: common.LogOption{},
})
if err != nil {
    // Handle error
}
```

**Parameters:**
`evmRpc` is the chain RPC endpoint, `privateKey` is your signer key, and `indRpc` is the indexer RPC endpoint. Use the current values published in the network overview docs for your network.

## Core Operations

### Node Selection

Select storage nodes before performing file operations:

```go
nodes, err := indexerClient.SelectNodes(ctx, expectedReplicas, droppedNodes, method, fullTrusted)
if err != nil {
    // Handle error
}
```

**Parameters:**
`ctx` is the context for the operation. `expectedReplicas` is the number of replicas to maintain. `droppedNodes` is a list of nodes to exclude, `method` can be `min`, `max`, `random`, or a positive number string, and `fullTrusted` limits selection to trusted nodes.

### UploadOption Structure

`UploadOption` uses an embedded `TransactionOption` struct for transaction-related fields, and groups remaining fields by purpose:

```go
opt := transfer.UploadOption{
    TransactionOption: transfer.TransactionOption{
        Fee:         fee,         // nil = auto-calculated from on-chain price
        Nonce:       nonce,       // nil = auto
        MaxGasPrice: maxGasPrice, // nil = no limit
        NRetries:    3,
        Step:        15,          // gas price multiplier: step/10 (15 = 1.5x)
    },
    // Data options
    Tags:          tags,
    EncryptionKey: encryptionKey,
    // Upload behavior
    FinalityRequired: transfer.TransactionPacked,
    TaskSize:         10,
    ExpectedReplica:  1,
    // Node selection
    Method:      "min",
    FullTrusted: true,
    // Split / batch
    FragmentSize: 4 * 1024 * 1024 * 1024, // default 4 GiB
    BatchSize:    10,                       // fragments per batch
}
```

When using the SDK, you can pass a zero-valued `UploadOption` and safe defaults are applied automatically:

| Field | Zero Value | Default Applied | Notes |
|-------|-----------|----------------|-------|
| `Method` | `""` | `"random"` | Empty string would break node selection |
| `Tags` | `nil` | `[]byte{}` | nil has different ABI encoding than empty bytes |
| `FinalityRequired` | `0` | `FileFinalized` | Strictest finality (waits for file finalization) |
| `TaskSize` | `0` | `10` | Applied downstream during upload |
| `ExpectedReplica` | `0` | short-circuits | No replica check performed |
| `FastMode` | `false` | disabled | Only applies to single-file `Upload`, not `SplitableUpload` or `BatchUpload` |
| `Fee` | `nil` | auto-calculated | Computed from on-chain price per sector |
| `Nonce` | `nil` | auto | Uses the next available nonce |
| `FragmentSize` | `0` | 4 GiB | Size of fragment when splitting large files (aligned to next power of 2) |
| `BatchSize` | `0` | `10` | Number of fragments to submit in a single batch transaction |

Minimal example with defaults:

```go
// All defaults are safe — only set what you need
opt := transfer.UploadOption{
    FinalityRequired: transfer.TransactionPacked,
}
txHashes, roots, err := indexerClient.SplitableUpload(ctx, w3client, file, opt)
```

### File Upload

Upload files to the network with the indexer client:

```go
file, err := core.Open(filePath)
if err != nil {
    // Handle error
}
defer file.Close()

opt := transfer.UploadOption{
    ExpectedReplica:  1,
    TaskSize:         10,
    SkipTx:           true,
    FinalityRequired: transfer.TransactionPacked,
    FastMode:         true,
    Method:           "min",
    FullTrusted:      true,
}

txHashes, roots, err := indexerClient.SplitableUpload(ctx, w3client, file, opt)
if err != nil {
    // Handle error
}
```

`FragmentSize` (default 4 GiB) controls the split size for large files. `BatchSize` (default 10) controls how many fragments are submitted per batch transaction. The returned `roots` contain the merkle root(s) to download later.

:::note Fast Mode
`FastMode` only applies to single-file uploads via `Upload()`. When using `SplitableUpload()` (which splits large files into fragments and submits them via `BatchUpload`), each batch always waits for the transaction receipt. This is because the receipt is needed to map each fragment's data root to its on-chain sequence number.
:::

### Encrypted File Upload

Encrypt files client-side using AES-256-CTR before uploading. The encryption is applied on-the-fly during upload — the original file is not modified.

```go
file, err := core.Open(filePath)
if err != nil {
    // Handle error
}
defer file.Close()

// 32-byte encryption key
encryptionKey, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

opt := transfer.UploadOption{
    ExpectedReplica:  1,
    TaskSize:         10,
    SkipTx:           true,
    FinalityRequired: transfer.TransactionPacked,
    FastMode:         true,
    Method:           "min",
    FullTrusted:      true,
    EncryptionKey:    encryptionKey,
}

txHashes, roots, err := indexerClient.SplitableUpload(ctx, w3client, file, opt)
if err != nil {
    // Handle error
}
```

:::warning
Save your encryption key securely. Without the exact key used during upload, the file cannot be decrypted.
:::

### Encrypted Fragment Upload

For large files, encryption works with fragment splitting. The file is encrypted first (producing a single encrypted stream with a 17-byte header), then split into fragments. Each fragment is uploaded independently.

```go
file, err := core.Open(filePath)
if err != nil {
    // Handle error
}
defer file.Close()

encryptionKey, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

opt := transfer.UploadOption{
    ExpectedReplica:  1,
    FinalityRequired: transfer.TransactionPacked,
    EncryptionKey:    encryptionKey,
    FragmentSize:     256 * 1024, // 256KB fragments (aligned to next power of 2)
}

// Encrypts the file, then splits the encrypted stream into fragments
txHashes, roots, err := indexerClient.SplitableUpload(ctx, w3client, file, opt)
if err != nil {
    // Handle error
}
// roots contains one merkle root per fragment
```

### File Hash Calculation

Calculate a file's Merkle root hash for identification:

```go
rootHash, err := core.MerkleRoot(filePath)
if err != nil {
    // Handle error
}
fmt.Printf("File hash: %s\n", rootHash.String())
```

:::info Important
Save the root hash - you'll need it to download the file later!
:::

### File Download

Download files from the network:

```go
rootHex := rootHash.String()
err = indexerClient.Download(ctx, rootHex, outputPath, withProof)
if err != nil {
    // Handle error
}
```

`withProof` enables merkle proof verification during download.

### Encrypted File Download

Download and decrypt a file that was uploaded with an encryption key. Works via the indexer client or with explicit nodes:

```go
// Via indexer client (recommended)
encryptionKey, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
indexerClient.WithEncryptionKey(encryptionKey)
err = indexerClient.Download(ctx, rootHex, outputPath, withProof)

// Or via explicit nodes
downloader, err := transfer.NewDownloader(clients, common.LogOption{})
if err != nil {
    // Handle error
}
downloader.WithEncryptionKey(encryptionKey)
err = downloader.Download(ctx, rootHash, outputPath, withProof)
```

The downloaded file is automatically decrypted using the provided key. The encryption header (version + nonce) is stripped and the original plaintext content is written to the output file.

### Hot Storage Download

Download files via the hot storage network for faster retrieval. The hot router selects an available hot node. If the file is cached, it is returned immediately. On a cache miss, a prefetch is sent and the download falls back to the regular path.

```go
import (
    "github.com/0gfoundation/0g-storage-client/node"
    "github.com/0gfoundation/0g-storage-client/transfer"
    "github.com/ethereum/go-ethereum/crypto"
)

// Parse your private key
privateKey, err := crypto.HexToECDSA("your_hex_private_key")
if err != nil {
    // Handle error
}

// Create the hot router client
routerClient := node.NewHotRouterClient("https://hot-router.example.com")

// Create a fallback downloader (indexer or explicit nodes)
indexerClient, err := indexer.NewClient(indRpc, indexer.IndexerClientOption{
    LogOption: common.LogOption{},
})
if err != nil {
    // Handle error
}
defer indexerClient.Close()

// Wrap with HotDownloader
hotDownloader := transfer.NewHotDownloader(routerClient, privateKey, indexerClient)

// Download single file
err = hotDownloader.Download(ctx, rootHex, outputPath, withProof)

// Download fragments
err = hotDownloader.DownloadFragments(ctx, roots, outputPath, withProof)
```

**With encryption:**

```go
encryptionKey, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
hotDownloader := transfer.NewHotDownloader(routerClient, privateKey, indexerClient).
    WithEncryptionKey(encryptionKey)

err = hotDownloader.Download(ctx, rootHex, outputPath, withProof)
```

### Encrypted Fragment Download

Download and decrypt a file that was uploaded with both encryption and fragment splitting:

```go
encryptionKey, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

// Via indexer client
indexerClient.WithEncryptionKey(encryptionKey)
err = indexerClient.DownloadFragments(ctx, roots, outputPath, withProof)

// Or via explicit nodes
downloader, err := transfer.NewDownloader(clients, common.LogOption{})
if err != nil {
    // Handle error
}
downloader.WithEncryptionKey(encryptionKey)
err = downloader.DownloadFragments(ctx, roots, outputPath, withProof)
```

The encryption header is extracted from the first fragment and used to decrypt all fragments with proper CTR offset tracking. The decrypted data is concatenated into the output file.

### Encrypted KV Write

Encrypt the entire stream data using AES-256-CTR before uploading. Pass the encryption key via `UploadOption.EncryptionKey` — the same mechanism used for file encryption. The KV node must be configured with the same key to decrypt and replay the data.

```go
batcher := kv.NewBatcher(version, clients, w3Client)
batcher.Set(streamId, []byte("myKey"), []byte("sensitive value"))

// 32-byte encryption key
encryptionKey, _ := hex.DecodeString("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

opt := transfer.UploadOption{
    EncryptionKey: encryptionKey,
}

txHash, err := batcher.Exec(ctx, opt)
if err != nil {
    // Handle error
}
```

The KV node decrypts the stream data during replay, so reading works normally without an encryption key:

```go
kvClient := kv.NewClient(nodeClient)
val, err := kvClient.GetValue(ctx, streamId, []byte("myKey"))
if err != nil {
    // Handle error
}
// val.Data contains the plaintext value
```

:::warning
The KV node must have the encryption key configured to replay the encrypted stream data.
:::

### KV Batcher Read (Read-Your-Own-Writes)

The batcher supports reading values back before committing. `Get` checks the local write cache first (uncommitted `Set` calls), and falls back to querying the KV node at the batcher's version.

```go
kvClient := kv.NewClient(nodeClient)
batcher := kv.NewBatcher(version, clients, w3Client).WithKVClient(kvClient)

// Write locally
batcher.Set(streamId, []byte("myKey"), []byte("myValue"))

// Read back — returns from local cache, no RPC call
val, err := batcher.Get(ctx, streamId, []byte("myKey"))
if err != nil {
    // Handle error
}
// val.Data == []byte("myValue")

// Read a key not yet set locally — falls back to KV node RPC
val, err = batcher.Get(ctx, streamId, []byte("otherKey"))
```

`WithKVClient` is optional. Without it, `Get` only returns locally cached writes and returns an error for missing keys.

## Best Practices

1. **Error Handling**: Implement proper error handling and cleanup
2. **Context Management**: Use contexts for operation timeouts and cancellation
3. **Resource Cleanup**: Always close clients when done using `defer client.Close()`
4. **Verification**: Enable proof verification for sensitive files
5. **Monitoring**: Track transaction status for important uploads

## Additional Resources

- [Go SDK Repository](https://github.com/0gfoundation/0g-storage-client)
- [Go Starter Kit](https://github.com/0gfoundation/0g-storage-go-starter-kit)

</TabItem>
<TabItem value="typescript" label="TypeScript SDK">

## Installation

Install the SDK and its peer dependency:

```bash
npm install @0glabs/0g-ts-sdk ethers
```

:::note
`ethers` is a required peer dependency for blockchain interactions
:::

## Setup

### Import Required Modules

```javascript
import { ZgFile, Indexer, Batcher, KvClient } from '@0glabs/0g-ts-sdk';
import { ethers } from 'ethers';
```

### Initialize Configuration

```javascript
// Network Constants - Choose your network
// Use the current endpoints from the network overview docs
const RPC_URL = '<blockchain_rpc_endpoint>';
const INDEXER_RPC = '<storage_indexer_endpoint>';

// Initialize provider and signer
const privateKey = 'YOUR_PRIVATE_KEY'; // Replace with your private key
const provider = new ethers.JsonRpcProvider(RPC_URL);
const signer = new ethers.Wallet(privateKey, provider);

// Initialize indexer
const indexer = new Indexer(INDEXER_RPC);
```

## Core Operations

### File Upload

Complete upload workflow:

```javascript
async function uploadFile(filePath) {
  // Create file object from file path
  const file = await ZgFile.fromFilePath(filePath);
  
  // Generate Merkle tree for verification
  const [tree, treeErr] = await file.merkleTree();
  if (treeErr !== null) {
    throw new Error(`Error generating Merkle tree: ${treeErr}`);
  }
  
  // Get root hash for future reference
  console.log("File Root Hash:", tree?.rootHash());
  
  // Upload to network
  const [tx, uploadErr] = await indexer.upload(file, RPC_URL, signer);
  if (uploadErr !== null) {
    throw new Error(`Upload error: ${uploadErr}`);
  }
  
  console.log("Upload successful! Transaction:", tx);
  
  // Always close the file when done
  await file.close();
  
  return { rootHash: tree?.rootHash(), txHash: tx };
}
```

### File Download

Download with optional verification:

```javascript
async function downloadFile(rootHash, outputPath) {
  // withProof = true enables Merkle proof verification
  const err = await indexer.download(rootHash, outputPath, true);
  if (err !== null) {
    throw new Error(`Download error: ${err}`);
  }
  console.log("Download successful!");
}
```

### Key-Value Storage

Store and retrieve key-value data:

```javascript
// Upload data to 0G-KV
async function uploadToKV(streamId, key, value) {
  const [nodes, err] = await indexer.selectNodes(1);
  if (err !== null) {
    throw new Error(`Error selecting nodes: ${err}`);
  }
  
  const batcher = new Batcher(1, nodes, flowContract, RPC_URL);
  
  const keyBytes = Uint8Array.from(Buffer.from(key, 'utf-8'));
  const valueBytes = Uint8Array.from(Buffer.from(value, 'utf-8'));
  batcher.streamDataBuilder.set(streamId, keyBytes, valueBytes);
  
  const [tx, batchErr] = await batcher.exec();
  if (batchErr !== null) {
    throw new Error(`Batch execution error: ${batchErr}`);
  }
  
  console.log("KV upload successful! TX:", tx);
}

// Download data from 0G-KV
async function downloadFromKV(streamId, key) {
  const kvClient = new KvClient("http://3.101.147.150:6789");
  const keyBytes = Uint8Array.from(Buffer.from(key, 'utf-8'));
  const value = await kvClient.getValue(streamId, ethers.encodeBase64(keyBytes));
  return value;
}
```

### Browser Support

For browser environments, use the ESM build:

```html
<script type="module">
  import { Blob, Indexer } from "./dist/zgstorage.esm.js";
  
  // Create file object from blob
  const file = new Blob(blob);
  const [tree, err] = await file.merkleTree();
  if (err === null) {
    console.log("File Root Hash:", tree.rootHash());
  }
</script>
```

### Stream Support

Work with streams for efficient data handling:

```typescript
import { Readable } from 'stream';

// Upload from stream
async function uploadStream() {
  const stream = new Readable();
  stream.push('Hello, 0G Storage!');
  stream.push(null);
  
  const file = await ZgFile.fromStream(stream, 'hello.txt');
  const [tx, err] = await indexer.upload(file, RPC_URL, signer);
  
  if (err === null) {
    console.log("Stream uploaded!");
  }
}

// Download as stream
async function downloadStream(rootHash) {
  const stream = await indexer.downloadFileAsStream(rootHash);
  stream.pipe(fs.createWriteStream('output.txt'));
}
```

## Best Practices

1. **Initialize Once**: Create the indexer once and reuse it for multiple operations
2. **Handle Errors**: Always implement proper error handling for network issues
3. **Use Appropriate Methods**: Use `ZgFile.fromFilePath` for Node.js and `Blob` for browsers
4. **Secure Keys**: Never expose private keys in client-side code
5. **Close Resources**: Remember to call `file.close()` after operations

## Additional Resources

- [TypeScript SDK Repository](https://github.com/0gfoundation/0g-ts-sdk)
- [TypeScript Starter Kit](https://github.com/0gfoundation/0g-storage-ts-starter-kit)

</TabItem>
</Tabs>

---

*Need more control? Consider running your own [storage node](/run-a-node/storage-node) to participate in the network and earn rewards.*
