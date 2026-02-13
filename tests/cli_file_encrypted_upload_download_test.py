#!/usr/bin/env python3

import os
import random
import tempfile

from config.node_config import GENESIS_ACCOUNT
from utility.utils import (
    wait_until,
)
from client_test_framework.test_framework import ClientTestFramework

# Fixed 32-byte encryption key (hex-encoded with 0x prefix)
ENCRYPTION_KEY = "0x" + "ab" * 32


class FileEncryptedUploadDownloadTest(ClientTestFramework):
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
            self.__test_encrypted_upload_download_file(v, i + 1)

    def __test_encrypted_upload_download_file(self, size, submission_index):
        self.log.info("encrypted file size: %d", size)

        file_to_upload = tempfile.NamedTemporaryFile(dir=self.root_dir, delete=False)
        data = random.randbytes(size)

        file_to_upload.write(data)
        file_to_upload.close()

        root = self._upload_file_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            file_to_upload,
            skip_tx=False,
            encryption_key=ENCRYPTION_KEY,
        )

        self.log.info("root: %s", root)
        wait_until(lambda: self.contract.num_submissions() == submission_index)

        for node_idx in range(4):
            client = self.nodes[node_idx]
            wait_until(lambda: client.zgs_get_file_info(root) is not None)
            wait_until(lambda: client.zgs_get_file_info(root)["finalized"])

        # Download with encryption key and verify decrypted content matches original
        file_to_download = os.path.join(
            self.root_dir, "download_enc_{}_{}".format(submission_index, size)
        )
        self._download_file_use_cli(
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            root,
            file_to_download=file_to_download,
            with_proof=True,
            remove=False,
            encryption_key=ENCRYPTION_KEY,
        )

        with open(file_to_download, "rb") as f:
            downloaded_data = f.read()
        assert downloaded_data == data, "decrypted data mismatch for size %d" % size
        os.remove(file_to_download)

        # Also test download without proof
        self._download_file_use_cli(
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            root,
            with_proof=False,
            encryption_key=ENCRYPTION_KEY,
        )


if __name__ == "__main__":
    FileEncryptedUploadDownloadTest().main()
