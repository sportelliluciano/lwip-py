#!/usr/bin/env python3

import os
import subprocess


LIBLWIP_PATH = os.environ.get("LIBLWIP_PATH") or "./liblwip/build/liblwip.so"


def run_test(test_file):
    env = os.environ
    env["LIBLWIP_PATH"] = LIBLWIP_PATH

    subprocess.run(
        ["python", f"tests/{test_file}"],
        env=env
    )


def run_tests():
    for _, _, files in os.walk("./tests/"):
        for filename in files:
            print(filename)
            if filename.startswith("test_") and filename.endswith(".py"):
                run_test(filename)



if __name__ == "__main__":
    run_tests()
