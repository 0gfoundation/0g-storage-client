from enum import Enum, unique

from utility.utils import is_windows_platform
from utility.build_binary import __asset_name, __build_from_github, __download_from_github

GITHUB_DOWNLOAD_URL = "https://api.github.com/repos/0gfoundation/0g-storage-node/releases/276222268"

ZGS_BINARY = "zgs_node.exe" if is_windows_platform() else "zgs_node"
KV_BINARY = "zgs_kv.exe" if is_windows_platform() else "zgs_kv"

@unique
class BuildBinaryResult(Enum):
    AlreadyExists = 0
    Installed = 1
    NotInstalled = 2


def build_zgs(dir: str) -> BuildBinaryResult:
    result = __download_from_github(
        dir=dir,
        binary_name=ZGS_BINARY,
        github_url=GITHUB_DOWNLOAD_URL,
        asset_name=__asset_name(ZGS_BINARY, zip=True),
    )
    if result != BuildBinaryResult.NotInstalled:
        return result
    
    return __build_from_github(
        dir=dir,
        binary_name=ZGS_BINARY,
        github_url="https://github.com/0gfoundation/0g-storage-node.git",
        build_cmd="cargo build --release",
        compiled_relative_path=["target", "release"],
    )


def build_kv(dir: str) -> BuildBinaryResult:
    result = __download_from_github(
        dir=dir,
        binary_name=KV_BINARY,
        github_url=GITHUB_DOWNLOAD_URL,
        asset_name=__asset_name(KV_BINARY, zip=True),
    )
    if result != BuildBinaryResult.NotInstalled:
        return result
    
    return __build_from_github(
        dir=dir,
        binary_name=KV_BINARY,
        github_url="https://github.com/0gfoundation/0g-storage-kv.git",
        build_cmd="git submodule update --init --recursive && cargo build --release",
        compiled_relative_path=["target", "release"],
    )
