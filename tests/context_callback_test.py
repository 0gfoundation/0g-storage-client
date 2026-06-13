#!/usr/bin/env python3
import os

from client_test_framework.test_framework import ClientTestFramework
from config.node_config import GENESIS_PRIV_KEY
from client_utility.run_go_test import run_go_test


class ContextCallbackTest(ClientTestFramework):
    """E2E for issue #159 — the OnSubmitted broadcast callback + caller-
    context awareness in the upload submit path:

      1. no_receipt   — small upload, no-receipt path: callback fires once
                        at broadcast with the returned hash.
      2. wait_receipt — >2MiB upload, receipt-wait path: same contract.
      3. cancel_preserves_hash — cancel the instant the tx broadcasts; the
                        upload aborts and returns no hash, but the callback
                        captured the broadcast hash and the tx is on chain.
    """

    def setup_params(self):
        self.num_blockchain_nodes = 1
        self.num_nodes = 1
        # Single non-sharded node sized to hold the 3MiB case comfortably.
        self.zgs_node_configs[0] = {
            "db_max_num_sectors": 2**30,
        }

    def run_test(self):
        test_args = [
            "go",
            "run",
            os.path.join(
                os.path.dirname(__file__), "go_tests", "context_callback_test", "main.go"
            ),
            GENESIS_PRIV_KEY,
            self.blockchain_nodes[0].rpc_url,
            ",".join([x.rpc_url for x in self.nodes]),
        ]
        run_go_test(self.root_dir, test_args)


if __name__ == "__main__":
    ContextCallbackTest().main()
