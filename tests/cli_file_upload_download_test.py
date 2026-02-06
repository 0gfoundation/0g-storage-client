#!/usr/bin/env python3

import random
import tempfile

from config.node_config import GENESIS_ACCOUNT
from utility.utils import (
    wait_until,
)
from client_test_framework.test_framework import ClientTestFramework


class FileUploadDownloadTest(ClientTestFramework):
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
        data_size = [
            2,
            255,
            256,
            257,
            1023,
            1024,
            1025,
            256 * 960,
            256 * 1023,
            256 * 1024,
            256 * 1025,
            256 * 2048,
            256 * 16385,
            256 * 1024 * 64,
            256 * 480,
            256 * 1024 * 10,
            1000,
            256 * 960,
            256 * 100,
            256 * 960,
        ]

        for i, v in enumerate(data_size):
            self.__test_upload_download_file(v, i + 1, True)

    def __test_upload_download_file(self, size, submission_index, rand_data=True):
        self.log.info("file size: %d", size)

        file_to_upload = tempfile.NamedTemporaryFile(dir=self.root_dir, delete=False)
        data = random.randbytes(size) if rand_data else b"\x10" * size

        file_to_upload.write(data)
        file_to_upload.close()

        root = self._upload_file_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            file_to_upload,
            skip_tx=False,
        )

        self.log.info("root: %s", root)
        wait_until(lambda: self.contract.num_submissions() == submission_index)

        for node_idx in range(4):
            client = self.nodes[node_idx]
            wait_until(lambda: client.zgs_get_file_info(root) is not None)
            wait_until(lambda: client.zgs_get_file_info(root)["finalized"])

        self._download_file_use_cli(
            ",".join([x.rpc_url for x in self.nodes]), None, root, with_proof=True
        )
        self._download_file_use_cli(
            ",".join([x.rpc_url for x in self.nodes]), None, root, with_proof=False
        )


if __name__ == "__main__":
    FileUploadDownloadTest().main()
