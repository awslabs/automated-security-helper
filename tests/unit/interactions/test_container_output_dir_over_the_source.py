# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An output directory that is the source directory, or above it, is refused.

Container mode mounts the source read-only at ``/src`` and the output read-write at
``/out``. When the output directory is the source directory or one of its parents,
the ``/out`` mount holds the source tree too, writable, so the scan inside could
write into it. Such a run is refused with exit 3 before anything is built or
mounted, by real paths, so a link to the source counts. An output directory inside
the source (the default ``.ash/ash_output``) or outside it is used as before.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


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
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    return seen


@pytest.fixture
def source(tmp_path) -> Path:
    path = tmp_path / "work" / "project"
    path.mkdir(parents=True)
    return path


def _run(source: Path, output: Path):
    return rac.run_ash_container(
        source_dir=str(source), output_dir=str(output), build=False, run=True
    )


@pytest.mark.parametrize(
    "where",
    ["the-source", "its-parent", "the-filesystem-above-it", "a-link-to-the-source"],
)
def test_an_output_directory_over_the_source_is_refused(
    where, source, commands, tmp_path
):
    if where == "the-source":
        output = source
    elif where == "its-parent":
        output = source.parent
    elif where == "the-filesystem-above-it":
        output = tmp_path
    else:
        output = tmp_path / "out-link"
        output.symlink_to(source, target_is_directory=True)

    result = _run(source, output)

    assert result.returncode == 3, result.stderr
    assert not rac.container_was_started(result)
    assert commands == []
    assert str(source.resolve()) in result.stderr


@pytest.mark.parametrize("where", ["inside-the-source", "beside-it"])
def test_an_output_directory_inside_or_outside_the_source_runs(
    where, source, commands, tmp_path
):
    """Control: the default .ash/ash_output is inside the source."""
    output = (
        source / ".ash" / "ash_output"
        if where == "inside-the-source"
        else (tmp_path / "work" / "out")
    )

    result = _run(source, output)

    assert result.returncode == 0, result.stderr
    assert [cmd[1] for cmd in commands] == ["run"]


def test_the_scan_cli_refuses_it_with_exit_3(source, commands):
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--source-dir",
            str(source),
            "--output-dir",
            str(source.parent),
        ],
    )

    assert result.exit_code == 3, result.output
    assert commands == []


def test_a_build_without_a_run_mounts_nothing_and_is_not_refused(source, commands):
    """Control: --no-run builds the image and mounts no directory."""
    result = rac.run_ash_container(
        source_dir=str(source),
        output_dir=str(source),
        ash_revision_to_install="v3.7.0",
        build=True,
        run=False,
    )

    assert result.returncode == 0, result.stderr
    assert [cmd[1] for cmd in commands] == ["build"]
