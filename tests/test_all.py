#!/usr/bin/env python3

import os

from client_utility.build_binary import build_zgs, build_kv
from utility.run_all import run_all

if __name__ == "__main__":
    test_dir = os.path.dirname(__file__)

    tmp_dir = os.path.join(test_dir, "tmp")
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir, exist_ok=True)
    build_zgs(tmp_dir)
    # build_kv(tmp_dir)

    run_all(
        test_dir=os.path.dirname(__file__),
        slow_tests={},
        long_manual_tests={},
        skip_tests={"cli_kv_test.py"}
    )
