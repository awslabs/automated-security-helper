# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An environment for a test subprocess that runs ASH and must write nothing outside its temp dir.

Listing scanners and building scan tasks probe, and when a tool is missing install,
each uv-managed scanner, even for scanners a scan excludes; checkov keeps an update
cache; and HOME alone does not move uv's directories when the XDG variables are set.
So a subprocess built with these helpers gets:

* every directory a tool or installer writes to (XDG cache, data, config and bin
  directories, ``UV_TOOL_DIR``, ``UV_TOOL_BIN_DIR``, ``ASH_BIN_PATH``) under *root*;
* ``UV_OFFLINE=1`` and HTTP(S) proxies that refuse every connection, so nothing is
  fetched;
* no usable AWS settings: the config and credentials files are the null device,
  instance metadata is off, and every AWS endpoint is a port that refuses
  connections (:data:`AWS_SETTINGS`). The harness drops the AWS variables it
  inherited first (:func:`without_inherited_aws`), because an inherited
  ``AWS_PROFILE`` or access key would still apply;
* ``UV_CACHE_DIR`` taken from the caller's environment when it is set, so a cache the
  operator chose is read rather than refilled, and otherwise an empty cache under
  *root*;
* stub ``uv``, ``gem`` and ``npm`` executables, put first on PATH with
  :func:`install_refusing_installers`, which exit non-zero without installing
  anything.

HOME and USERPROFILE are left to the harness, which already points them at a temp
directory of its own.
"""

from __future__ import annotations

import os
import platform
import stat
import sys
from pathlib import Path
from typing import Dict, Iterable, Mapping

#: A port nothing listens on, so a proxied connection is refused at once.
REFUSING_PROXY = "http://127.0.0.1:9"

#: AWS settings that give an in-process scan no credentials and no reachable
#: endpoint, whatever the host has configured.
AWS_SETTINGS = {
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    "AWS_EC2_METADATA_DISABLED": "true",
    "AWS_ENDPOINT_URL": REFUSING_PROXY,
    "AWS_REGION": "us-east-1",
}


def without_inherited_aws(env: Mapping[str, str]) -> Dict[str, str]:
    """*env* without any ``AWS_*`` variable, for a harness to apply its own on top."""
    return {key: value for key, value in env.items() if not key.startswith("AWS_")}


#: Installers a scan or a scanner listing can start.
REFUSED_INSTALLERS = ("uv", "gem", "npm")

_TOOL_DIRS = {
    "XDG_CACHE_HOME": "xdg-cache",
    "XDG_DATA_HOME": "xdg-data",
    "XDG_CONFIG_HOME": "xdg-config",
    "XDG_BIN_HOME": "xdg-bin",
    "UV_TOOL_DIR": "uv-tools",
    "UV_TOOL_BIN_DIR": "uv-tool-bin",
    "ASH_BIN_PATH": "ash-bin",
}


def isolated_tool_env(root: Path) -> Dict[str, str]:
    """Variables that keep a subprocess's tools, caches and downloads under *root*."""
    env: Dict[str, str] = {"UV_OFFLINE": "1"}
    for name, sub in _TOOL_DIRS.items():
        path = root / sub
        path.mkdir(parents=True, exist_ok=True)
        env[name] = str(path)
    cache = os.environ.get("UV_CACHE_DIR")
    if not cache:
        cache_dir = root / "uv-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache = str(cache_dir)
    env["UV_CACHE_DIR"] = cache
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env[name] = REFUSING_PROXY
        env[name.lower()] = REFUSING_PROXY
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""
    env.update(AWS_SETTINGS)
    return env


_STUB = (
    "import sys\n"
    "sys.stderr.write('{name} is stubbed in this test and installs nothing\\n')\n"
    "raise SystemExit(1)\n"
)


def install_refusing_installers(
    bin_dir: Path, names: Iterable[str] = REFUSED_INSTALLERS
) -> None:
    """Put a stub for each installer in *bin_dir*, which the harness puts first on PATH.

    An executable launcher on POSIX; a ``.cmd`` shim on Windows, where a shebang script
    cannot be started and executables are found by extension.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        script = bin_dir / f"_stub_{name}.py"
        script.write_text(_STUB.format(name=name), encoding="utf-8")
        if platform.system().lower() == "windows":
            (bin_dir / f"{name}.cmd").write_text(
                f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8"
            )
            continue
        launcher = bin_dir / name
        launcher.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8"
        )
        launcher.chmod(
            launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        )
