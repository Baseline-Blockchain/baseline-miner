from __future__ import annotations

import os
import sys

from setuptools import Extension, find_packages, setup


def _ext_modules() -> list[Extension]:
    if os.environ.get("BASELINE_MINER_DISABLE_NATIVE") == "1":
        return []
    extra_args: list[str] = []
    if sys.platform == "win32":
        extra_args.append("/O2")
    else:
        extra_args.append("-O3")
    return [
        Extension(
            "baseline_miner._sha256d",
            sources=["baseline_miner/native/sha256d.c"],
            extra_compile_args=extra_args,
        )
    ]


setup(
    packages=find_packages(),
    ext_modules=_ext_modules(),
)
