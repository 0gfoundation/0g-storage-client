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

    def _upload_directory_use_cli(
        self,
        blockchain_node_rpc_url,
        key,
        node_rpc_url,
        indexer_url,
        dir_to_upload,
        fragment_size=None,
        skip_tx=True,
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
