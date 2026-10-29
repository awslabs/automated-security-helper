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
    isolated_tool_dirs,
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


@pytest.mark.unit
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


@pytest.mark.unit
def test_the_directory_variables_alone_are_every_write_location(tmp_path):
    """What an in-process test sets with monkeypatch: each write location, no more."""
    dirs = isolated_tool_dirs(tmp_path)

    assert sorted(dirs) == sorted(_WRITE_LOCATIONS)
    assert all(_inside(path, tmp_path) for path in dirs.values()), dirs


@pytest.mark.unit
def test_an_operator_uv_cache_is_reused(tmp_path, monkeypatch):
    monkeypatch.setenv("UV_CACHE_DIR", "/operator/uv-cache")

    assert isolated_tool_env(tmp_path)["UV_CACHE_DIR"] == "/operator/uv-cache"


@pytest.mark.unit
def test_without_an_operator_uv_cache_the_cache_is_under_the_root(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("UV_CACHE_DIR", raising=False)

    assert _inside(isolated_tool_env(tmp_path)["UV_CACHE_DIR"], tmp_path)


@pytest.mark.integration
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


_REFUSING_AWS = {
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    "AWS_EC2_METADATA_DISABLED": "true",
    "AWS_ENDPOINT_URL": "http://127.0.0.1:9",
    "AWS_REGION": "us-east-1",
}


@pytest.mark.unit
def test_the_environment_gives_no_usable_aws_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_CONFIG_FILE", str(Path.home() / ".aws" / "config"))

    env = isolated_tool_env(tmp_path)

    assert {name: env.get(name) for name in _REFUSING_AWS} == _REFUSING_AWS


def _harness_envs(tmp_path):
    """The environment each subprocess harness that runs in-process scans builds."""
    from tests.unit.cli.mcp.test_list_scanners_scan_selection import _Sequence
    from tests.unit.plugins.test_refused_plugin_modules import _Run
    from tests.unit.plugins.test_scan_plugin_selection import _Process

    yield "list_scanners _Sequence", _Sequence(tmp_path / "sequence")._env()
    yield "refused modules _Run", _Run(tmp_path / "run").env()
    yield "plugin selection _Process", _Process(tmp_path / "process")._env()


@pytest.mark.unit
def test_each_harness_drops_inherited_aws_settings(tmp_path, monkeypatch):
    """An inherited profile or key would apply even beside the refusing settings."""
    monkeypatch.setenv("AWS_PROFILE", "inherited-profile")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "inherited-key-id")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "inherited-secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "inherited-token")
    monkeypatch.setenv("AWS_DEFAULT_PROFILE", "inherited-default")
    for name in ("sequence", "run", "process"):
        (tmp_path / name).mkdir()

    for harness, env in _harness_envs(tmp_path):
        aws = {name: value for name, value in env.items() if name.startswith("AWS_")}
        assert aws == _REFUSING_AWS, harness
