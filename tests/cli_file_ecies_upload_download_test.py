#!/usr/bin/env python3

import os
import random
import tempfile

from config.node_config import GENESIS_ACCOUNT
from utility.utils import (
    wait_until,
)
from client_test_framework.test_framework import ClientTestFramework


def _hex_key(k) -> str:
    """Accept either hex string or bytes; return 0x-prefixed hex string."""
    if isinstance(k, (bytes, bytearray)):
        return "0x" + k.hex()
    s = str(k)
    return s if s.startswith("0x") else "0x" + s


class FileECIESUploadDownloadTest(ClientTestFramework):
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
        # Sizes span: small, chunk boundaries, segment boundaries, cross-fragment.
        data_size = [
            2,
            255,
            256,
            1023,
            1024,
            1025,
            256 * 1024,
            256 * 1024 * 10,
        ]

        for i, v in enumerate(data_size):
            self.__test_ecies_upload_download_file(v, i + 1)

    def __test_ecies_upload_download_file(self, size, submission_index):
        self.log.info("ECIES encrypted file size: %d", size)

        file_to_upload = tempfile.NamedTemporaryFile(dir=self.root_dir, delete=False)
        data = random.randbytes(size)
        file_to_upload.write(data)
        file_to_upload.close()

        # Self-encryption: the same wallet private key (GENESIS_ACCOUNT.key) is used
        # both to sign the on-chain tx (via --key) and, on download, to derive the
        # ECIES AES key (via --private-key + --decrypt).
        priv_hex = _hex_key(GENESIS_ACCOUNT.key)

        root = self._upload_file_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            file_to_upload,
            skip_tx=False,
            encrypt=True,
        )

        self.log.info("root: %s", root)
        wait_until(lambda: self.contract.num_submissions() == submission_index)

        for node_idx in range(4):
            client = self.nodes[node_idx]
            wait_until(lambda: client.zgs_get_file_info(root) is not None)
            wait_until(lambda: client.zgs_get_file_info(root)["finalized"])

        # Download with wallet private key and verify decrypted content matches original.
        file_to_download = os.path.join(
            self.root_dir, "download_ecies_{}_{}".format(submission_index, size)
        )
        self._download_file_use_cli(
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            root,
            file_to_download=file_to_download,
            with_proof=True,
            remove=False,
            decrypt=True,
            private_key=priv_hex,
        )

        with open(file_to_download, "rb") as f:
            downloaded_data = f.read()
        assert downloaded_data == data, "ECIES-decrypted data mismatch for size %d" % size
        os.remove(file_to_download)

        # Also test download without merkle proof.
        self._download_file_use_cli(
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            root,
            with_proof=False,
            decrypt=True,
            private_key=priv_hex,
        )


if __name__ == "__main__":
    FileECIESUploadDownloadTest().main()
