# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--ignore-suppressions`` reaches the scan inside the container.

The host recomputes the exit code from the ``ash.sarif`` the container writes, and
that file carries the suppressions the inner scan applied. So the flag is
forwarded to the inner scan, and its reports and the verdict include the
suppressed findings, as a local scan with the flag does.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


def _assemble(tmp_path: Path, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "/usr/bin/docker",
        "image_name": "automated-security-helper:non-root",
        "source_dir": tmp_path,
        "output_dir": tmp_path / "out",
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": True,
        "progress": False,
        "verbose": False,
        "simple": True,
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


def _inner_args(cmd: List[str]) -> List[str]:
    return cmd[cmd.index("automated-security-helper:non-root") + 1 :]


def test_the_run_command_forwards_ignore_suppressions(tmp_path):
    cmd = _assemble(tmp_path, ignore_suppressions=True)

    assert "--ignore-suppressions" in _inner_args(cmd)


def test_the_run_command_leaves_suppressions_on_by_default(tmp_path):
    """Control."""
    assert "--ignore-suppressions" not in _inner_args(_assemble(tmp_path))


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
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
    # The default image is `non-root`; a Windows host defaults to `ci`
    # (run_ash_container._resolve_build_target), which the tests below do not name.
    monkeypatch.setattr(rac, "_host_is_windows", lambda: False)
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    return seen


@pytest.mark.parametrize(
    ("flag", "forwarded"),
    [
        pytest.param(["--ignore-suppressions"], True, id="given"),
        pytest.param([], False, id="not-given"),
    ],
)
def test_the_scan_cli_forwards_it_to_the_container(flag, forwarded, commands):
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
            *flag,
        ],
    )

    runs = [cmd for cmd in commands if cmd[1] == "run"]
    assert len(runs) == 1, commands
    inner = runs[0][runs[0].index("automated-security-helper:non-root") + 1 :]
    assert ("--ignore-suppressions" in inner) is forwarded
