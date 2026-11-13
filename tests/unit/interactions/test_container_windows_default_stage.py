# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On Windows the default image stage is ``ci``, for both commands, and only the default.

The non-root user cannot write a bind-mounted output directory on Windows, so a
Windows host builds the ``ci`` stage when no stage is asked for, with
``ash build-image`` and with ``ash --mode container`` alike. An explicit
``--build-target`` wins on every platform.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import List

import pytest
from typer.testing import CliRunner

from automated_security_helper.core.enums import BuildTarget
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "Dockerfile").write_text("FROM scratch AS ci\n", encoding="utf-8")
    monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    return seen


def _pretend_windows(monkeypatch, windows: bool) -> None:
    """Make the container runner see a Windows host, or not, and nothing else."""
    monkeypatch.setattr(rac, "_host_is_windows", lambda: windows, raising=False)


def _target(commands: List[List[str]]) -> str:
    builds = [cmd for cmd in commands if cmd[1] == "build"]
    assert len(builds) == 1, commands
    return builds[0][builds[0].index("--target") + 1]


_SCAN = [
    "scan",
    "--mode",
    "container",
    "--no-progress",
    "--no-run",
    "--source-dir",
    "src",
    "--output-dir",
    "out",
    "--ash-revision-to-install",
    "v3.7.0",
]
_BUILD_IMAGE = ["build-image", "--no-run", "--ash-revision-to-install", "v3.7.0"]


@pytest.mark.parametrize("command", [_SCAN, _BUILD_IMAGE], ids=["scan", "build-image"])
@pytest.mark.parametrize(
    ("windows", "target_args", "expected"),
    [
        pytest.param(True, [], "ci", id="windows-default"),
        pytest.param(
            True, ["--build-target", "non-root"], "non-root", id="windows-explicit"
        ),
        pytest.param(True, ["--build-target", "ci"], "ci", id="windows-explicit-ci"),
        pytest.param(False, [], "non-root", id="elsewhere-default"),
        pytest.param(False, ["--build-target", "ci"], "ci", id="elsewhere-explicit"),
    ],
)
def test_the_stage_built(
    command, windows, target_args, expected, commands, monkeypatch
):
    from automated_security_helper.cli import image
    from automated_security_helper.cli.main import app

    _pretend_windows(monkeypatch, windows)
    # `ash build-image` leaves the decision to the container runner.
    host = SimpleNamespace(system=lambda: "Windows" if windows else "Linux")
    monkeypatch.setattr(image, "platform", host, raising=False)

    CliRunner().invoke(app, [*command, *target_args])

    assert _target(commands) == expected


@pytest.mark.parametrize(("windows", "expected"), [(True, "ci"), (False, "non-root")])
def test_the_library_default(windows, expected, monkeypatch):
    _pretend_windows(monkeypatch, windows)

    assert rac._resolve_build_target(None, None) == expected
    assert rac._resolve_build_target(BuildTarget.NON_ROOT, None) == "non-root"
