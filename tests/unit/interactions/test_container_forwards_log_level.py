# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--log-level`` reaches the scan inside the container.

``--debug``, ``--verbose`` and ``--simple`` carry three of the levels inward.
``--log-level`` is forwarded for the others, so ``ERROR``, ``QUIET`` and ``TRACE``
set the inner scan's logging as they set a local scan's.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.core.enums import (
    AshLogLevel,
    ExecutionPhase,
    ExecutionStrategy,
)
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

_IMAGE = "automated-security-helper:non-root"


def _assemble(tmp_path: Path, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "/usr/bin/docker",
        "image_name": _IMAGE,
        "source_dir": tmp_path,
        "output_dir": tmp_path / "out",
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": False,
        "progress": False,
        "verbose": False,
        "simple": False,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [ExecutionPhase.SCAN],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": ExecutionStrategy.PARALLEL,
        "ctx": None,
    }
    kwargs.update(overrides)
    return _assemble_run_command(**kwargs)


def _log_levels(cmd: List[str]) -> List[str]:
    inner = cmd[cmd.index(_IMAGE) + 1 :]
    return [inner[i + 1] for i, arg in enumerate(inner[:-1]) if arg == "--log-level"]


@pytest.mark.parametrize(
    "level",
    [level for level in AshLogLevel if level is not AshLogLevel.INFO],
    ids=lambda level: level.value,
)
def test_the_run_command_forwards_every_non_default_level(level, tmp_path):
    assert _log_levels(_assemble(tmp_path, log_level=level)) == [level.value]


@pytest.mark.parametrize("level", [None, AshLogLevel.INFO], ids=["unset", "INFO"])
def test_the_default_level_adds_nothing(level, tmp_path):
    """Control: INFO is the inner default, and cannot be told from it on the host."""
    assert _log_levels(_assemble(tmp_path, log_level=level)) == []


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in (
        "CI",
        "ASH_IMAGE_NAME",
        "ASH_CONFIG",
        "OCI_RUNNER_WRAPPER",
        "ASH_DEBUG",
        "ASH_VERBOSE",
    ):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    return seen


@pytest.mark.parametrize("level", ["ERROR", "QUIET", "TRACE"])
def test_the_scan_cli_forwards_it_to_the_container(level, commands):
    from automated_security_helper.cli.main import app

    CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-progress",
            "--no-build",
            "--source-dir",
            "src",
            "--output-dir",
            "out",
            "--log-level",
            level,
        ],
    )

    runs = [cmd for cmd in commands if cmd[1] == "run"]
    assert len(runs) == 1, commands
    assert _log_levels(runs[0]) == [level]
