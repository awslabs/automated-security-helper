# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``uv tool list`` is spawned once per process, not once per read.

Every ``get_tool_installation_info`` read spawned a fresh listing through
``is_tool_installed``, once per scanner per dependency check, for an answer
that does not move inside a scan. The listing is now memoized per uv
executable; an install through the runner and a changed executable forget it,
and a failed listing memoizes nothing.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest
from unittest.mock import patch

from automated_security_helper.utils import uv_tool_runner as module
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
)

pytestmark = pytest.mark.unit

_LISTING = "checkov v3.2.5\n- checkov\nbandit v1.7.9\n- bandit\n"


def _available(runner):
    return patch.object(UVToolRunner, "is_uv_available", return_value=True)


def test_two_reads_share_one_listing(tmp_path):
    runner = UVToolRunner(uv_executable=str(tmp_path / "uv"))
    spawns = []

    def fake_spawn(command, **kwargs):
        spawns.append(command)
        return SimpleNamespace(stdout=_LISTING)

    with _available(runner), patch.object(module, "spawn_run", fake_spawn):
        first = runner.list_available_tools()
        assert runner.is_tool_installed("checkov") is True
        assert runner.is_tool_installed("semgrep") is False

    assert first == ["checkov", "checkov", "bandit", "bandit"]
    assert len(spawns) == 1


def test_forgetting_and_a_new_executable_re_spawn(tmp_path):
    runner = UVToolRunner(uv_executable=str(tmp_path / "uv"))
    spawns = []

    def fake_spawn(command, **kwargs):
        spawns.append(list(command))
        return SimpleNamespace(stdout=_LISTING)

    with _available(runner), patch.object(module, "spawn_run", fake_spawn):
        runner.list_available_tools()
        runner.forget_tool_list()
        runner.list_available_tools()
        assert len(spawns) == 2

        runner.uv_executable = str(tmp_path / "uv2")
        runner.list_available_tools()
        assert len(spawns) == 3
        assert spawns[2][0] == str(tmp_path / "uv2")


def test_an_outside_install_is_seen_through_the_tools_dir_stamp(tmp_path, monkeypatch):
    """An install or uninstall NOBODY told this runner about still invalidates.

    `uv tool install`/`uninstall` create or remove `<tools dir>/<tool>`, which
    moves the directory's mtime whoever runs them -- another runner instance,
    another process, a hand-run uv -- and the memo is keyed on that stamp, so
    the stale listing misses without waiting out the TTL.
    """
    tools_dir = tmp_path / "uv-tools"
    tools_dir.mkdir()
    monkeypatch.setenv("UV_TOOL_DIR", str(tools_dir))
    runner = UVToolRunner(uv_executable=str(tmp_path / "uv"))
    spawns = []

    def fake_spawn(command, **kwargs):
        spawns.append(command)
        return SimpleNamespace(stdout=_LISTING)

    with _available(runner), patch.object(module, "spawn_run", fake_spawn):
        runner.list_available_tools()
        runner.list_available_tools()
        assert len(spawns) == 1

        # The outside install: a new entry under the tools directory.
        (tools_dir / "semgrep").mkdir()
        runner.list_available_tools()
        assert len(spawns) == 2


def test_a_failed_listing_memoizes_nothing(tmp_path):
    runner = UVToolRunner(uv_executable=str(tmp_path / "uv"))
    spawns = []

    def failing_spawn(command, **kwargs):
        spawns.append(command)
        raise subprocess.CalledProcessError(returncode=2, cmd=command)

    with _available(runner), patch.object(module, "spawn_run", failing_spawn):
        with pytest.raises(UVToolRunnerError):
            runner.list_available_tools()
        with pytest.raises(UVToolRunnerError):
            runner.list_available_tools()

    assert len(spawns) == 2
