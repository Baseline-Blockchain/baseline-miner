from __future__ import annotations

import sys

import platform
import sysconfig

from setuptools import Extension, find_packages, setup


def _ext_modules() -> list[Extension]:
    extra_args: list[str] = []
    machine = platform.machine().lower()
    cflags = sysconfig.get_config_var("CFLAGS") or ""
    universal_macos = "-arch x86_64" in cflags and "-arch arm64" in cflags
    if sys.platform == "win32":
        extra_args.append("/O2")
    else:
        extra_args.extend(["-O3", "-funroll-loops"])
        if not universal_macos:
            if "arm" in machine or "aarch64" in machine:
                extra_args.append("-march=armv8-a+crypto")
            if "x86" in machine or "amd64" in machine or "i386" in machine:
                extra_args.append("-msha")
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
