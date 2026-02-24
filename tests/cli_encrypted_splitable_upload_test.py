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

# Fragment size must be >= segment size (256KB = 256 * 1024).
# Use exactly one segment size so the file is split into multiple fragments.
FRAGMENT_SIZE = 256 * 1024  # 256KB = one segment


class EncryptedSplitableUploadTest(ClientTestFramework):
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
        # Set up indexer with all nodes as trusted (no discovery delay)
        trusted = ",".join([x.rpc_url for x in self.nodes])
        self.setup_indexer(trusted, None)

        seg = FRAGMENT_SIZE  # segment size = 256KB
        # (data_size, fragment_size) — encryption adds 17-byte header
        cases = [
            (seg - 17, seg),  # encrypted = seg exactly → 1 fragment
            (seg - 16, seg),  # encrypted = seg + 1 → 2 fragments
            (seg, seg),  # encrypted = seg + 17 → 2 fragments
            (seg * 2 - 17, seg),  # encrypted = 2*seg exactly → 2 fragments
            (seg * 2 - 16, seg),  # encrypted = 2*seg + 1 → 3 fragments
            (1024 * 1024, seg),  # general multi-fragment → 5 fragments
        ]

        submission_count = 0
        for i, (size, frag_size) in enumerate(cases):
            encrypted_size = size + 17  # 17-byte encryption header
            expected_fragments = max(1, -(-encrypted_size // frag_size))
            submission_count = self.__test_encrypted_splitable(
                size=size,
                fragment_size=frag_size,
                expected_fragments=expected_fragments,
                submission_count=submission_count,
                label="case_%d_size_%d_frag_%d" % (i, size, frag_size),
            )

    def __test_encrypted_splitable(
        self, size, fragment_size, expected_fragments, submission_count, label
    ):
        self.log.info(
            "Testing encrypted splitable upload: %s (size=%d, fragment_size=%d, expected_fragments=%d)",
            label,
            size,
            fragment_size,
            expected_fragments,
        )

        file_to_upload = tempfile.NamedTemporaryFile(dir=self.root_dir, delete=False)
        data = random.randbytes(size)
        file_to_upload.write(data)
        file_to_upload.close()

        # Upload via indexer with encryption + fragment size
        roots = self._upload_file_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            None,
            self.indexer_rpc_url,
            file_to_upload,
            fragment_size=fragment_size,
            skip_tx=False,
            encryption_key=ENCRYPTION_KEY,
        )
        self.log.info("roots: %s", roots)

        new_submission_count = submission_count + expected_fragments
        wait_until(
            lambda: self.contract.num_submissions() == new_submission_count,
            timeout=120,
        )

        # Wait for all fragments to finalize on all nodes
        root_list = roots.split(",")
        assert (
            len(root_list) == expected_fragments
        ), "Expected %d fragments but got %d: %s" % (
            expected_fragments,
            len(root_list),
            roots,
        )

        for root in root_list:
            for node_idx in range(4):
                client = self.nodes[node_idx]
                wait_until(
                    lambda: client.zgs_get_file_info(root) is not None,
                    timeout=60,
                )
                wait_until(
                    lambda: client.zgs_get_file_info(root)["finalized"],
                    timeout=60,
                )

        # Download via indexer with encryption key and verify
        file_to_download = os.path.join(
            self.root_dir, "download_enc_split_{}".format(label)
        )

        if expected_fragments == 1:
            # Single fragment: download with --root
            self._download_file_use_cli(
                None,
                self.indexer_rpc_url,
                root=root_list[0],
                file_to_download=file_to_download,
                with_proof=True,
                remove=False,
                encryption_key=ENCRYPTION_KEY,
            )
        else:
            # Multiple fragments: download with --roots
            self._download_file_use_cli(
                None,
                self.indexer_rpc_url,
                roots=roots,
                file_to_download=file_to_download,
                with_proof=True,
                remove=False,
                encryption_key=ENCRYPTION_KEY,
            )

        with open(file_to_download, "rb") as f:
            downloaded_data = f.read()
        assert (
            downloaded_data == data
        ), "decrypted data mismatch for %s (got %d bytes, expected %d bytes)" % (
            label,
            len(downloaded_data),
            len(data),
        )
        os.remove(file_to_download)

        self.log.info("Test %s passed", label)
        return new_submission_count


if __name__ == "__main__":
    EncryptedSplitableUploadTest().main()
