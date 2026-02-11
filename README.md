# 0G Storage Client

Go implementation for client to interact with storage nodes in 0G Storage network. For more details, please read the [docs](https://docs.0g.ai/build-with-0g/storage-sdk).

[![API Reference](https://pkg.go.dev/badge/github.com/0glabs/0g-storage-client)](https://pkg.go.dev/github.com/0glabs/0g-storage-client)
[![Go Report Card](https://goreportcard.com/badge/github.com/0glabs/0g-storage-client)](https://goreportcard.com/report/github.com/0glabs/0g-storage-client)
[![License](https://img.shields.io/github/license/0glabs/0g-storage-client)](https://github.com/0glabs/0g-storage-client/blob/main/LICENSE)
[![Github Action Workflow](https://github.com/0glabs/0g-storage-client/actions/workflows/go.yml/badge.svg)](https://github.com/0glabs/0g-storage-client/actions/workflows/go.yml)
[![Github Action Workflow](https://github.com/0glabs/0g-storage-client/actions/workflows/tests.yml/badge.svg)](https://github.com/0glabs/0g-storage-client/actions/workflows/tests.yml)

## SDK

Following packages can help applications to integrate with 0g storage network:

- **[core](core)**: provides underlying utilities to build merkle tree for files or iterable data, and defines data padding standard to interact with [Flow contract](contract/contract.go).
- **[node](node)**: defines RPC client structures to facilitate RPC interactions with 0g storage nodes and 0g key-value (KV) nodes.
- **[kv](kv)**: defines structures to interact with 0g storage kv.
- **[transfer](transfer)** : defines data structures and functions for transferring data between local and 0g storage.
- **[indexer](indexer)**: select storage nodes to upload data from indexer which maintains trusted node list. Besides, allow clients to download files via HTTP GET requests.

## CLI

Run `go build` under the root folder to compile the executable binary. There are several commands to interact with 0g storage node.

**Global flags**

Run `./0g-storage-client --help` to view all available commands along with global flags:
```
Flags:
      --gas-limit uint                Custom gas limit to send transaction
      --gas-price uint                Custom gas price to send transaction
  -h, --help                          help for 0g-storage-client
      --log-color-disabled            Force to disable colorful logs
      --log-level string              Log level (default "info")
      --rpc-retry-count int           Retry count for rpc request (default 5)
      --rpc-retry-interval duration   Retry interval for rpc request (default 5s)
      --rpc-timeout duration          Timeout for single rpc request (default 30s)
      --web3-log-enabled              Enable log for web3 RPC
```

**Generate test file**

To generate a file for test purpose, with a fixed file size or random file size (without `--size` option):

```
./0g-storage-client gen --size <file_size_in_bytes>
```

**Upload file**

```
./0g-storage-client upload --url <blockchain_rpc_endpoint> --key <private_key> --indexer <storage_indexer_endpoint> --file <file_path>
```

The client will submit the data segments to the storage nodes which is determined by the indexer according to their shard configurations.

**Download file**
```
./0g-storage-client download --indexer <storage_indexer_endpoint> --root <file_root_hash> --file <output_file_path>
```

If you want to verify the **merkle proof** of downloaded segment, please specify `--proof` option.

**Write to KV**

By indexer:
```
./0g-storage-client kv-write --url <blockchain_rpc_endpoint> --key <private_key> --indexer <storage_indexer_endpoint> --stream-id <stream_id> --stream-keys <stream_keys> --stream-values <stream_values>
```

`--stream-keys` and `--stream-values` are comma separated string list and their length must be equal.

**Read from KV**

```
./0g-storage-client kv-read --node <kv_node_rpc_endpoint> --stream-id <stream_id> --stream-keys <stream_keys>
```

Please pay attention here `--node` is the url of a KV node.

## Indexer

Indexer service provides RPC to index storages nodes in two ways:

- Trusted nodes: well maintained and provides stable service.
- Discovered nodes: discovered in the whole P2P network.

Please refer to the [RPC API](https://docs.0g.ai/run-a-node/testnet-information) documentation for more details.

Besides, the Indexer provides a RESTful API gateway for file downloads and uploads.

### File Download

Files can be downloaded via HTTP GET requests in two ways:

- By transaction sequence number:

```
GET /file?txSeq=7
```

- By file Merkle root:

```
GET /file?root=0x0376e0d95e483b62d5100968ed17fe1b1d84f0bc5d9bda8000cdfd3f39a59927
```

You can also specify the `name` parameter to rename the downloaded file:

```
GET /file?txSeq=7&name=foo.log
```

### File Download Within a Folder

Files within a folder can also be downloaded via HTTP GET requests:

- By transaction sequence number:

```
GET /file/{txSeq}/path/to/file
```

- By file Merkle root:

```
GET /file/{merkleRoot}/path/to/file
```

This allows users to retrieve specific files from within a structured folder stored in the network.

### File Upload

File segments can be uploaded via HTTP POST requests in JSON format:

```
POST /file/segment
```

There are two options for uploading:

- By transaction sequence:

    ```json
    {
        "txSeq": /* Transaction sequence number */,
        "index": /* Segment index (decimal) */,
        "data": "/* Base64-encoded segment data */",
        "proof": {/* Merkle proof object for validation */}
    }
    ```
- By file Merkle root:

    ```json
    {
        "root": "/* Merkle root of the file (in 0x-prefixed hexadecimal) */",
        "index": /* Segment index (decimal) */,
        "data": "/* Base64-encoded segment data */",
        "proof": {/* Merkle proof object for validation */}
    }
    ```

> **Note:** The `proof` field should contain a [`merkle.Proof`](https://github.com/0glabs/0g-storage-client/blob/8780c5020928a79fb60ed7dea26a42d9876ecfae/core/merkle/proof.go#L20) object, which is used to verify the integrity of each segment.

### Query File Info

Users could query file information by `cid` (transaction sequence number or file merkle root):

```
GET /file/info/{cid}
```

or query multiple files in batch:

```
GET /files/info?cid={cid1}&cid={cid2}&cid={cid3}
```

Note, the batch API will return `null` if specified `cid` not found.

### HTTP Response

Basically, the REST APIs return 2 kinds of HTTP status code:

- `200`: success or business error.
- `600`: server internal error.

The HTTP response body is in JSON format, including `code`, `message` and `data`:

```go
type BusinessError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}
```

There are several pre-defined [common errors](/common/api/errors.go) and [business errors](/indexer/gateway/errors.go), and those errors may contain different `data` for detailed error context.
