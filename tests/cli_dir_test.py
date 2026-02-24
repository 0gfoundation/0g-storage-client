#!/usr/bin/env python3

import os
import tempfile
import random
import subprocess
import re
import time

from eth_utils import encode_hex
from config.node_config import GENESIS_ACCOUNT
from utility.utils import wait_until
from client_test_framework.test_framework import ClientTestFramework
from splitable_upload_test import files_are_equal


def directories_are_equal(dir1, dir2):
    for root, dirs, files in os.walk(dir1):
        rel_path = os.path.relpath(
            root, dir1
        )  # relative path within the directory structure
        compare_root = os.path.join(dir2, rel_path)

        if not os.path.exists(compare_root):
            return False

        # Compare files
        for file_name in files:
            file1 = os.path.join(root, file_name)
            file2 = os.path.join(compare_root, file_name)

            if os.path.islink(file1) or os.path.islink(file2):
                # Compare symbolic links
                if os.readlink(file1) != os.readlink(file2):
                    return False
            else:
                # Compare regular files
                if not os.path.exists(file2) or not files_are_equal(file1, file2):
                    return False

        # Compare directories
        for dir_name in dirs:
            dir1_sub = os.path.join(root, dir_name)
            dir2_sub = os.path.join(compare_root, dir_name)

            if not os.path.exists(dir2_sub) or not os.path.isdir(dir2_sub):
                return False

            if not directories_are_equal(dir1_sub, dir2_sub):
                return False

    # Finally, ensure the second directory has no extra files or subdirectories
    for root, dirs, files in os.walk(dir2):
        rel_path = os.path.relpath(root, dir2)
        compare_root = os.path.join(dir1, rel_path)

        if not os.path.exists(compare_root):
            return False

    return True


class DirectoryUploadDownloadTest(ClientTestFramework):
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
        self.__test_unencrypted_directory()
        self.__test_encrypted_directory()
        self.__test_fragmented_directory()
        self.__test_encrypted_fragmented_directory()

    def __test_unencrypted_directory(self):
        temp_dir = tempfile.TemporaryDirectory(dir=self.root_dir)
        file_size_range = (512, 8192)  # Random file size within range 512B-8KB

        # Create regular file under the temporary directory
        file_path = os.path.join(temp_dir.name, f"file_0.txt")
        file_size = random.randint(*file_size_range)
        with open(file_path, "wb") as f:
            f.write(os.urandom(file_size))

        # Create subdirectory with files
        subdir_path = os.path.join(temp_dir.name, f"subdir_0")
        os.makedirs(subdir_path)
        sub_file_path = os.path.join(subdir_path, f"subfile_0.txt")
        sub_file_size = random.randint(*file_size_range)
        with open(sub_file_path, "wb") as f:
            f.write(os.urandom(sub_file_size))

        # Create symbolic links
        target = os.path.basename(file_path)  # use a relative path as target
        symlink_path = os.path.join(temp_dir.name, f"symlink_0")
        os.symlink(target, symlink_path)

        self.log.info(
            "Uploading directory '%s' with %d file, %d directory, %d symbolic link",
            temp_dir.name,
            1,
            1,
            1,
        )

        root_hash = self._upload_directory_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            temp_dir,
        )

        self.log.info("Root hash: %s", root_hash)
        wait_until(lambda: self.contract.num_submissions() == 3)

        for node_idx in range(4):
            client = self.nodes[node_idx]
            wait_until(lambda: client.zgs_get_file_info(root_hash) is not None)
            wait_until(lambda: client.zgs_get_file_info(root_hash)["finalized"])

        directory_to_download = os.path.join(self.root_dir, "download")
        self._download_directory_use_cli(
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            root=root_hash,
            with_proof=True,
            dir_to_download=directory_to_download,
            remove=False,
        )
        assert directories_are_equal(temp_dir.name, directory_to_download)

        self.log.info("Unencrypted directory upload/download test passed")

    def __test_encrypted_directory(self):
        encryption_key = "0x" + "ab" * 32

        temp_dir = tempfile.TemporaryDirectory(dir=self.root_dir)

        # Create files of various sizes
        file_sizes = [256, 1024, 4096, 256 * 1024]
        for i, size in enumerate(file_sizes):
            file_path = os.path.join(temp_dir.name, "file_%d.bin" % i)
            with open(file_path, "wb") as f:
                f.write(random.randbytes(size))

        # Create subdirectory with a file
        subdir_path = os.path.join(temp_dir.name, "subdir")
        os.makedirs(subdir_path)
        with open(os.path.join(subdir_path, "nested.bin"), "wb") as f:
            f.write(random.randbytes(2048))

        # Create symbolic link
        os.symlink("file_0.bin", os.path.join(temp_dir.name, "link_0"))

        self.log.info("Uploading encrypted directory '%s'", temp_dir.name)

        submission_count = self.contract.num_submissions()

        root_hash = self._upload_directory_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            temp_dir,
            skip_tx=False,
            encryption_key=encryption_key,
        )

        self.log.info("Root hash: %s", root_hash)

        # 5 files + 1 directory metadata = 6 submissions
        wait_until(
            lambda: self.contract.num_submissions() == submission_count + 6,
            timeout=120,
        )

        for node_idx in range(4):
            client = self.nodes[node_idx]
            wait_until(lambda: client.zgs_get_file_info(root_hash) is not None)
            wait_until(lambda: client.zgs_get_file_info(root_hash)["finalized"])

        # Download with encryption key and verify
        dir_to_download = os.path.join(self.root_dir, "download_encrypted")
        self._download_directory_use_cli(
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            root=root_hash,
            with_proof=True,
            dir_to_download=dir_to_download,
            remove=False,
            encryption_key=encryption_key,
        )
        assert directories_are_equal(
            temp_dir.name, dir_to_download
        ), "Encrypted directory content mismatch"

        self.log.info("Encrypted directory upload/download test passed")

    def __test_fragmented_directory(self):
        """Test directory upload with small fragment size to force file splitting."""
        fragment_size = 262144  # 256KB — one segment, forces splitting for larger files

        temp_dir = tempfile.TemporaryDirectory(dir=self.root_dir)

        # Create a file larger than fragment size so it gets split into multiple roots
        large_file_path = os.path.join(temp_dir.name, "large_file.bin")
        with open(large_file_path, "wb") as f:
            f.write(os.urandom(fragment_size * 3))  # 768KB → 3 fragments

        # Create a small file that fits in a single fragment (no splitting)
        small_file_path = os.path.join(temp_dir.name, "small_file.bin")
        with open(small_file_path, "wb") as f:
            f.write(os.urandom(1024))

        # Create a subdirectory with a file that also gets split
        subdir_path = os.path.join(temp_dir.name, "subdir")
        os.makedirs(subdir_path)
        with open(os.path.join(subdir_path, "split_file.bin"), "wb") as f:
            f.write(os.urandom(fragment_size * 2))  # 512KB → 2 fragments

        self.log.info(
            "Uploading fragmented directory '%s' with fragment_size=%d",
            temp_dir.name,
            fragment_size,
        )

        submission_count = self.contract.num_submissions()

        root_hash = self._upload_directory_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            temp_dir,
            fragment_size=fragment_size,
        )

        self.log.info("Root hash: %s", root_hash)

        # 3 fragments (large_file) + 1 (small_file) + 2 fragments (split_file) + 1 metadata = 7
        wait_until(
            lambda: self.contract.num_submissions() == submission_count + 7,
            timeout=120,
        )

        for node_idx in range(4):
            client = self.nodes[node_idx]
            wait_until(lambda: client.zgs_get_file_info(root_hash) is not None)
            wait_until(lambda: client.zgs_get_file_info(root_hash)["finalized"])

        directory_to_download = os.path.join(self.root_dir, "download_fragmented")
        self._download_directory_use_cli(
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            root=root_hash,
            with_proof=True,
            dir_to_download=directory_to_download,
            remove=False,
        )
        assert directories_are_equal(
            temp_dir.name, directory_to_download
        ), "Fragmented directory content mismatch"

        self.log.info("Fragmented directory upload/download test passed")

    def __test_encrypted_fragmented_directory(self):
        """Test directory upload with encryption AND small fragment size (encrypt-then-split)."""
        encryption_key = "0x" + "cd" * 32
        fragment_size = 262144  # 256KB

        temp_dir = tempfile.TemporaryDirectory(dir=self.root_dir)

        # Create a file larger than fragment size — will be encrypted then split
        large_file_path = os.path.join(temp_dir.name, "large_enc.bin")
        with open(large_file_path, "wb") as f:
            f.write(os.urandom(fragment_size * 2))  # 512KB → 2 fragments after encryption

        # Create a small file that fits in one fragment after encryption
        small_file_path = os.path.join(temp_dir.name, "small_enc.bin")
        with open(small_file_path, "wb") as f:
            f.write(os.urandom(2048))

        # Create a subdirectory with a split file
        subdir_path = os.path.join(temp_dir.name, "subdir")
        os.makedirs(subdir_path)
        with open(os.path.join(subdir_path, "nested_enc.bin"), "wb") as f:
            f.write(os.urandom(fragment_size * 3))  # 768KB → 3 fragments after encryption

        self.log.info(
            "Uploading encrypted+fragmented directory '%s'", temp_dir.name
        )

        submission_count = self.contract.num_submissions()

        root_hash = self._upload_directory_use_cli(
            self.blockchain_nodes[0].rpc_url,
            GENESIS_ACCOUNT.key,
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            temp_dir,
            fragment_size=fragment_size,
            encryption_key=encryption_key,
        )

        self.log.info("Root hash: %s", root_hash)

        # Encryption adds 17-byte header, which may push fragment count up by 1
        # large_enc: ~512KB + 17B encrypted → 3 fragments (crosses 2-segment boundary)
        # small_enc: ~2KB + 17B → 1 fragment
        # nested_enc: ~768KB + 17B encrypted → 4 fragments (crosses 3-segment boundary)
        # metadata: 1 fragment
        # Total: 3 + 1 + 4 + 1 = 9
        wait_until(
            lambda: self.contract.num_submissions() >= submission_count + 9,
            timeout=120,
        )

        for node_idx in range(4):
            client = self.nodes[node_idx]
            wait_until(lambda: client.zgs_get_file_info(root_hash) is not None)
            wait_until(lambda: client.zgs_get_file_info(root_hash)["finalized"])

        dir_to_download = os.path.join(self.root_dir, "download_enc_frag")
        self._download_directory_use_cli(
            ",".join([x.rpc_url for x in self.nodes]),
            None,
            root=root_hash,
            with_proof=True,
            dir_to_download=dir_to_download,
            remove=False,
            encryption_key=encryption_key,
        )
        assert directories_are_equal(
            temp_dir.name, dir_to_download
        ), "Encrypted+fragmented directory content mismatch"

        self.log.info("Encrypted+fragmented directory upload/download test passed")

    def _upload_directory_use_cli(
        self,
        blockchain_node_rpc_url,
        key,
        node_rpc_url,
        indexer_url,
        dir_to_upload,
        fragment_size=None,
        skip_tx=True,
        encryption_key=None,
    ):
        upload_args = [
            self.cli_binary,
            "upload-dir",
            "--url",
            blockchain_node_rpc_url,
            "--key",
            encode_hex(key),
            "--skip-tx=" + str(skip_tx),
            "--log-level",
            "debug",
            "--gas-limit",
            "10000000",
        ]
        if node_rpc_url is not None:
            upload_args.append("--node")
            upload_args.append(node_rpc_url)
        elif indexer_url is not None:
            upload_args.append("--indexer")
            upload_args.append(indexer_url)
        if fragment_size is not None:
            upload_args.append("--fragment-size")
            upload_args.append(str(fragment_size))
        if encryption_key is not None:
            upload_args.append("--encryption-key")
            upload_args.append(encryption_key)

        upload_args.append("--file")
        self.log.info(
            "upload directory with cli: {}".format(upload_args + [dir_to_upload.name])
        )

        output = tempfile.NamedTemporaryFile(
            dir=self.root_dir, delete=False, prefix="zgs_client_output_"
        )
        output_name = output.name
        output_fileno = output.fileno()

        try:
            proc = subprocess.Popen(
                upload_args + [dir_to_upload.name],
                text=True,
                stdout=output_fileno,
                stderr=output_fileno,
            )

            return_code = proc.wait(timeout=60)

            output.seek(0)
            lines = output.readlines()

            ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

            for line in lines:
                line = line.decode("utf-8")
                line_clean = ansi_escape.sub("", line)  # clean ANSI escape sequences
                self.log.debug("line: %s", line_clean)

                if match := re.search(r"rootHash=(0x[a-fA-F0-9]+)", line_clean):
                    root = match.group(1)
                    break
        except Exception as ex:
            self.log.error(
                "Failed to upload directory via CLI tool, output: %s", output_name
            )
            raise ex
        finally:
            output.close()

        assert return_code == 0, "%s upload directory failed, output: %s, log: %s" % (
            self.cli_binary,
            output_name,
            lines,
        )

        return root

    def _download_directory_use_cli(
        self,
        node_rpc_url,
        indexer_url,
        root=None,
        roots=None,
        dir_to_download=None,
        with_proof=True,
        remove=True,
        encryption_key=None,
    ):
        if dir_to_download is None:
            dir_to_download = os.path.join(
                self.root_dir, "download_{}_{}".format(root, time.time())
            )
        download_args = [
            self.cli_binary,
            "download-dir",
            "--file",
            dir_to_download,
            "--proof=" + str(with_proof),
            "--log-level",
            "debug",
        ]
        if root is not None:
            download_args.append("--root")
            download_args.append(root)
        elif roots is not None:
            download_args.append("--roots")
            download_args.append(roots)

        if node_rpc_url is not None:
            download_args.append("--node")
            download_args.append(node_rpc_url)
        elif indexer_url is not None:
            download_args.append("--indexer")
            download_args.append(indexer_url)
        if encryption_key is not None:
            download_args.append("--encryption-key")
            download_args.append(encryption_key)
        self.log.info(
            "download directory with cli: {}".format(download_args + [dir_to_download])
        )

        output = tempfile.NamedTemporaryFile(
            dir=self.root_dir, delete=False, prefix="zgs_client_output_"
        )
        output_name = output.name
        output_fileno = output.fileno()

        try:
            proc = subprocess.Popen(
                download_args,
                text=True,
                stdout=output_fileno,
                stderr=output_fileno,
            )

            return_code = proc.wait(timeout=60)
            output.seek(0)
            lines = output.readlines()
        except Exception as ex:
            self.log.error(
                "Failed to download directory via CLI tool, output: %s", output_name
            )
            raise ex
        finally:
            output.close()

        assert return_code == 0, "%s download directory failed, output: %s, log: %s" % (
            self.cli_binary,
            output_name,
            lines,
        )

        if remove:
            os.remove(dir_to_download)

        return


if __name__ == "__main__":
    DirectoryUploadDownloadTest().main()
