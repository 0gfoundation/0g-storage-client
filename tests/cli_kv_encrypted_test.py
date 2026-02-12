#!/usr/bin/env python3

from config.node_config import GENESIS_ACCOUNT
from utility.utils import (
    assert_equal,
    wait_until,
)
from client_utility.kv import to_stream_id
from client_test_framework.test_framework import ClientTestFramework

# Fixed 32-byte encryption key (hex-encoded with 0x prefix)
ENCRYPTION_KEY = "0x" + "ab" * 32
# Same key without 0x prefix for KV node config
ENCRYPTION_KEY_HEX = "ab" * 32


class KVEncryptedTest(ClientTestFramework):
    def setup_params(self):
        self.num_blockchain_nodes = 1
        self.num_nodes = 1

    def run_test(self):
        # Set up KV node with encryption key configured for replay
        self.setup_kv_node(
            0,
            [to_stream_id(0)],
            updated_config={"encryption_key": ENCRYPTION_KEY_HEX},
        )
        self.setup_indexer(self.nodes[0].rpc_url, self.nodes[0].rpc_url)

        # Write KV data with encryption via direct node
        self._kv_write_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            self.nodes[0].rpc_url,
            None,
            to_stream_id(0),
            "0,1,2,3,4,5,6,7,8,9,10",
            "0,1,2,3,4,5,6,7,8,9,10",
            encryption_key=ENCRYPTION_KEY,
        )

        # Write KV data with encryption via indexer
        self._kv_write_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            None,
            self.indexer_rpc_url,
            to_stream_id(0),
            "11,12,13,14,15,16,17,18,19,20",
            "11,12,13,14,15,16,17,18,19,20",
            encryption_key=ENCRYPTION_KEY,
        )

        # Wait for KV node to commit both transactions
        wait_until(lambda: self.kv_nodes[0].kv_get_trasanction_result(0) == "Commit")
        wait_until(lambda: self.kv_nodes[0].kv_get_trasanction_result(1) == "Commit")

        # Read back via CLI — no encryption key needed (KV node decrypts during replay)
        res = self._kv_read_use_cli(
            self.kv_nodes[0].rpc_url,
            to_stream_id(0),
            "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21",
        )
        for i in range(21):
            assert_equal(res[str(i)], str(i))
        # Key 21 was never written, should be empty
        assert_equal(res["21"], "")


if __name__ == "__main__":
    KVEncryptedTest().main()
