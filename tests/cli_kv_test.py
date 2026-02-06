#!/usr/bin/env python3

from config.node_config import GENESIS_ACCOUNT
from utility.utils import (
    assert_equal,
    wait_until,
)
from client_utility.kv import to_stream_id
from client_test_framework.test_framework import ClientTestFramework


class KVTest(ClientTestFramework):
    def setup_params(self):
        self.num_blockchain_nodes = 1
        self.num_nodes = 1

    def run_test(self):
        self.setup_kv_node(0, [to_stream_id(0)])
        self.setup_indexer(self.nodes[0].rpc_url, self.nodes[0].rpc_url)
        self._kv_write_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            self.nodes[0].rpc_url,
            None,
            to_stream_id(0),
            "0,1,2,3,4,5,6,7,8,9,10",
            "0,1,2,3,4,5,6,7,8,9,10",
        )
        self._kv_write_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            None,
            self.indexer_rpc_url,
            to_stream_id(0),
            "11,12,13,14,15,16,17,18,19,20",
            "11,12,13,14,15,16,17,18,19,20",
        )
        wait_until(lambda: self.kv_nodes[0].kv_get_trasanction_result(0) == "Commit")
        wait_until(lambda: self.kv_nodes[0].kv_get_trasanction_result(1) == "Commit")
        res = self._kv_read_use_cli(
            self.kv_nodes[0].rpc_url,
            to_stream_id(0),
            "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21",
        )
        for i in range(21):
            assert_equal(res[str(i)], str(i))
        assert_equal(res["21"], "")


if __name__ == "__main__":
    KVTest().main()
