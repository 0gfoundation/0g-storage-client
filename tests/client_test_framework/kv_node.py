import base64
import os

from client_config.node_config import KV_CONFIG
from test_framework.blockchain_node import TestNode
from utility.utils import (
    PortCategory,
    arrange_port,
    initialize_config,
    assert_equal,
)

bytes_per_query = 1024 * 256

KV_NODE_TYPE = 2


class KVNode(TestNode):
    def __init__(
        self,
        index,
        root_dir,
        binary,
        updated_config,
        log_contract_address,
        log,
        rpc_timeout=10,
        stream_ids=None,
    ):
        if stream_ids is None:
            stream_ids = []
        local_conf = KV_CONFIG.copy()

        indexed_config = {
            "stream_ids": stream_ids,
            "rpc_listen_address": f"127.0.0.1:{arrange_port(PortCategory.ZGS_KV_RPC, index)}",
            "log_contract_address": log_contract_address,
            "blockchain_rpc_endpoint": f"http://127.0.0.1:{arrange_port(PortCategory.ZG_ETH_HTTP, 0)}",
            "zgs_node_urls": f"http://127.0.0.1:{arrange_port(PortCategory.ZGS_RPC, 0)}",
            "zgs_admin_url": f"http://127.0.0.1:{arrange_port(PortCategory.ZGS_RPC, 0)}",
        }
        # Set configs for this specific node.
        local_conf.update(indexed_config)
        # Overwrite with personalized configs.
        local_conf.update(updated_config)
        data_dir = os.path.join(root_dir, "zgs_kv" + str(index))
        rpc_url = "http://" + local_conf["rpc_listen_address"]
        super().__init__(
            KV_NODE_TYPE,
            index,
            data_dir,
            rpc_url,
            binary,
            local_conf,
            log,
            rpc_timeout,
        )
        self.rpc_cnt = 0

    def setup_config(self):
        os.mkdir(self.data_dir)
        log_config_path = os.path.join(self.data_dir, self.config["log_config_file"])
        with open(log_config_path, "w") as f:
            f.write("debug")
        initialize_config(self.config_file, self.config)

    def wait_for_rpc_connection(self):
        self._wait_for_rpc_connection(lambda rpc: rpc.kv_getStatus() is not None)

    def start(self):
        self.log.info("Start kv node %d", self.index)
        super().start()

    def check_equal(self, stream_id, key, value, version=None):
        global bytes_per_query
        i = 0
        if value is None:
            self.rpc_cnt += 1
            res = self.kv_get_value(stream_id, key, 0, 1, version)
            assert_equal(b"", base64.b64decode(res["data"].encode("utf-8")))
            assert res["size"] == 0
            return
        while i < len(value):
            self.rpc_cnt += 1
            res = self.kv_get_value(stream_id, key, i, bytes_per_query, version)
            if i + bytes_per_query < len(value):
                assert_equal(
                    base64.b64decode(res["data"].encode("utf-8")),
                    value[i : i + bytes_per_query],
                )
            else:
                assert_equal(base64.b64decode(res["data"].encode("utf-8")), value[i:])
            i += bytes_per_query

    def next(self, stream_id, key, version=None):
        global bytes_per_query
        start_index = 0
        ans = {"data": b""}
        while True:
            res = self.kv_get_next(
                stream_id, key, start_index, bytes_per_query, version
            )
            if res is None:
                return None
            ans["size"] = res["size"]
            ans["key"] = base64.b64decode(res["key"].encode("utf-8")).hex()
            ans["data"] += base64.b64decode(res["data"].encode("utf-8"))
            if len(ans["data"]) == ans["size"]:
                return ans
            start_index += bytes_per_query

    def prev(self, stream_id, key, version=None):
        global bytes_per_query
        start_index = 0
        ans = {"data": b""}
        while True:
            res = self.kv_get_prev(
                stream_id, key, start_index, bytes_per_query, version
            )
            if res is None:
                return None
            ans["size"] = res["size"]
            ans["key"] = base64.b64decode(res["key"].encode("utf-8")).hex()
            ans["data"] += base64.b64decode(res["data"].encode("utf-8"))
            if len(ans["data"]) == ans["size"]:
                return ans
            start_index += bytes_per_query

    def seek_to_first(self, stream_id, version=None):
        global bytes_per_query
        start_index = 0
        ans = {"data": b""}
        while True:
            res = self.kv_get_first(stream_id, start_index, bytes_per_query, version)
            if res is None:
                return None
            ans["size"] = res["size"]
            ans["key"] = base64.b64decode(res["key"].encode("utf-8")).hex()
            ans["data"] += base64.b64decode(res["data"].encode("utf-8"))
            if len(ans["data"]) == ans["size"]:
                return ans
            start_index += bytes_per_query

    def seek_to_last(self, stream_id, version=None):
        global bytes_per_query
        start_index = 0
        ans = {"data": b""}
        while True:
            res = self.kv_get_last(stream_id, start_index, bytes_per_query, version)
            if res is None:
                return None
            ans["size"] = res["size"]
            ans["key"] = base64.b64decode(res["key"].encode("utf-8")).hex()
            ans["data"] += base64.b64decode(res["data"].encode("utf-8"))
            if len(ans["data"]) == ans["size"]:
                return ans
            start_index += bytes_per_query

    def hex_to_segment(self, x):
        return base64.b64encode(bytes.fromhex(x)).decode("utf-8")

    # rpc
    def kv_get_value(self, stream_id, key, start_index, size, version=None):
        return self.rpc.kv_getValue(
            [stream_id, self.hex_to_segment(key), start_index, size, version]
        )

    def kv_get_next(self, stream_id, key, start_index, size, version=None):
        return self.rpc.kv_getNext(
            [stream_id, self.hex_to_segment(key), start_index, size, False, version]
        )

    def kv_get_prev(self, stream_id, key, start_index, size, version=None):
        return self.rpc.kv_getPrev(
            [stream_id, self.hex_to_segment(key), start_index, size, False, version]
        )

    def kv_get_first(self, stream_id, start_index, size, version=None):
        return self.rpc.kv_getFirst([stream_id, start_index, size, version])

    def kv_get_last(self, stream_id, start_index, size, version=None):
        return self.rpc.kv_getLast([stream_id, start_index, size, version])

    def kv_get_trasanction_result(self, tx_seq):
        return self.rpc.kv_getTransactionResult([tx_seq])

    def kv_get_holding_stream_ids(self):
        return self.rpc.kv_getHoldingStreamIds()

    def kv_has_write_permission(self, account, stream_id, key, version=None):
        return self.rpc.kv_hasWritePermission(
            [account, stream_id, self.hex_to_segment(key), version]
        )

    def kv_is_admin(self, account, stream_id, version=None):
        return self.rpc.kv_isAdmin([account, stream_id, version])

    def kv_is_special_key(self, stream_id, key, version=None):
        return self.rpc.kv_isSpecialKey([stream_id, self.hex_to_segment(key), version])

    def kv_is_writer_of_key(self, account, stream_id, key, version=None):
        return self.rpc.kv_isWriterOfKey(
            [account, stream_id, self.hex_to_segment(key), version]
        )

    def kv_is_writer_of_stream(self, account, stream_id, version=None):
        return self.rpc.kv_isWriterOfStream([account, stream_id, version])
