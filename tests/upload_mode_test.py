import os

from client_test_framework.test_framework import ClientTestFramework
from config.node_config import GENESIS_PRIV_KEY
from client_utility.run_go_test import run_go_test


class UploadModeTest(ClientTestFramework):
    """
    Tests the 4 upload code paths with 4-node sharding:
      1. fast_small:  FastMode=true,  size < 256KB  → uploadFast (broadcast by root)
      2. fast_large:  FastMode=true,  size > 256KB  → falls to uploadSlow (fast overridden)
      3. slow_small:  FastMode=false, size < 2MB    → uploadSlowParallel
      4. slow_large:  FastMode=false, size > 2MB    → uploadSlow sequential
    """

    def setup_params(self):
        self.num_blockchain_nodes = 1
        self.num_nodes = 4
        self.zgs_node_configs[0] = {
            "db_max_num_sectors": 2**30,
            "shard_position": "0/4",
        }
        self.zgs_node_configs[1] = {
            "db_max_num_sectors": 2**30,
            "shard_position": "1/4",
        }
        self.zgs_node_configs[2] = {
            "db_max_num_sectors": 2**30,
            "shard_position": "2/4",
        }
        self.zgs_node_configs[3] = {
            "db_max_num_sectors": 2**30,
            "shard_position": "3/4",
        }

    def run_test(self):
        test_args = [
            "go",
            "run",
            os.path.join(
                os.path.dirname(__file__), "go_tests", "upload_mode_test", "main.go"
            ),
            GENESIS_PRIV_KEY,
            self.blockchain_nodes[0].rpc_url,
            ",".join([x.rpc_url for x in self.nodes]),
        ]
        run_go_test(self.root_dir, test_args)


if __name__ == "__main__":
    UploadModeTest().main()
