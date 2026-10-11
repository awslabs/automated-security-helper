# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The test-subprocess environment keeps every tool write under the test's temp dir.

``tests/utils/isolated_tool_env.py`` is what the plugin-selection and refused-module
harnesses run ASH under. These hold the two properties those harnesses depend on: no
variable that decides where a tool writes points outside the root it was given, and
the installer stubs refuse to install.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.utils.isolated_tool_env import (
    REFUSED_INSTALLERS,
    REFUSING_PROXY,
    install_refusing_installers,
    isolated_tool_env,
)

_WRITE_LOCATIONS = (
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "XDG_BIN_HOME",
    "UV_TOOL_DIR",
    "UV_TOOL_BIN_DIR",
    "ASH_BIN_PATH",
)


def _inside(path: str, root: Path) -> bool:
    return Path(path).resolve().is_relative_to(root.resolve())


def test_every_write_location_is_under_the_root(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
    monkeypatch.setenv("UV_TOOL_DIR", str(Path.home() / ".local" / "share" / "uv"))

    env = isolated_tool_env(tmp_path)

    outside = {
        name: env[name] for name in _WRITE_LOCATIONS if not _inside(env[name], tmp_path)
    }
    assert outside == {}
    assert env["UV_OFFLINE"] == "1"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        assert env[name] == REFUSING_PROXY
    assert env["NO_PROXY"] == "" and env["no_proxy"] == ""


def test_an_operator_uv_cache_is_reused(tmp_path, monkeypatch):
    monkeypatch.setenv("UV_CACHE_DIR", "/operator/uv-cache")

    assert isolated_tool_env(tmp_path)["UV_CACHE_DIR"] == "/operator/uv-cache"


def test_without_an_operator_uv_cache_the_cache_is_under_the_root(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("UV_CACHE_DIR", raising=False)

    assert _inside(isolated_tool_env(tmp_path)["UV_CACHE_DIR"], tmp_path)


@pytest.mark.parametrize("name", REFUSED_INSTALLERS)
def test_an_installer_stub_refuses_and_writes_nothing(tmp_path, name):
    """The stub is what PATH resolves the installer to, and it installs nothing."""
    stubs = tmp_path / "stubs"
    install_refusing_installers(stubs)
    before = sorted(p.name for p in stubs.iterdir())
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    path = os.pathsep.join([str(stubs), os.environ.get("PATH", "")])
    resolved = shutil.which(name, path=path)
    assert resolved is not None and Path(resolved).parent == stubs

    completed = subprocess.run(
        [resolved, "install", "anything"],
        cwd=workdir,
        env={**os.environ, "PATH": path},
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode != 0
    assert "stubbed in this test" in completed.stderr
    assert sorted(p.name for p in stubs.iterdir()) == before
    assert list(workdir.iterdir()) == []
