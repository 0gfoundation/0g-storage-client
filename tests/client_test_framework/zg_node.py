import os
import subprocess
import tempfile

from test_framework.blockchain_node import BlockChainNodeType, BlockchainNode
from utility.utils import (
    wait_until,
)
from utility.simple_rpc_proxy import SimpleRpcProxy


def zg_node_init_genesis(binary: str, root_dir: str, num_nodes: int):
    assert num_nodes == 1, "Makefile deploy only supports one blockchain node"

    tests_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    os.environ.setdefault("ZGS_BLOCKCHAIN_RPC_ENDPOINT", "http://127.0.0.1:8545")

    log_file = tempfile.NamedTemporaryFile(
        dir=root_dir, delete=False, prefix="init_genesis_", suffix=".log"
    )
    ret = subprocess.run(
        args=["make", "deploy"],
        cwd=tests_dir,
        stdout=log_file,
        stderr=log_file,
    )
    log_file.close()

    assert ret.returncode == 0, (
        "Failed to deploy 0gchain genesis, see more details in log file: %s"
        % log_file.name
    )


class ZGNode(BlockchainNode):
    def __init__(
        self,
        index,
        root_dir,
        binary,
        updated_config,
        contract_path,
        log,
        rpc_timeout=10,
    ):
        assert index == 0, "Makefile start only supports one blockchain node"

        data_dir = os.path.join(root_dir, "0gchaind", "node" + str(index))
        rpc_url = os.environ.get(
            "ZGS_BLOCKCHAIN_RPC_ENDPOINT", "http://127.0.0.1:8545"
        )
        self._make_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

        super().__init__(
            index,
            data_dir,
            rpc_url,
            binary,
            {},
            contract_path,
            log,
            BlockChainNodeType.ZG,
            rpc_timeout,
        )

    def setup_config(self):
        """Already initialized by Makefile deploy"""

    def start(self):
        self.log.info("Starting 0gchaind via Makefile")
        ret = subprocess.run(
            args=["make", "start"],
            cwd=self._make_dir,
        )
        assert ret.returncode == 0, "Failed to start 0gchaind via Makefile"
        self.running = True

    def stop(self, expected_stderr="", kill=False, wait=True):
        ret = subprocess.run(
            args=["make", "stop"],
            cwd=self._make_dir,
        )
        assert ret.returncode == 0, "Failed to stop 0gchaind via Makefile"
        self.running = False

    def wait_for_rpc_connection(self):
        rpc = SimpleRpcProxy(self.rpc_url, timeout=self.rpc_timeout)

        def check():
            return rpc.eth_syncing() is False

        wait_until(check, timeout=self.rpc_timeout)
        self.rpc_connected = True
        self.rpc = rpc
