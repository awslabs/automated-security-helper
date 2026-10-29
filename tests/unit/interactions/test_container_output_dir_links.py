# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An output directory that is a symlink, or is reached through one, is refused.

Container mode mounts the output directory read-write at ``/out``, so the scan
inside the container writes wherever it leads. A link the scanned repository
commits (``.ash -> /some/host/dir``) would choose that host directory for it.
ASH refuses such a run with exit 3 before it creates, writes or mounts anything:
the output directory itself when it is a symlink, wherever it is, and any symlink
between the source directory and it, with the source taken under its name and
under its real path. A real directory, inside the source or outside it, is used as
before, and so is a source directory reached through a link above it, which is the
operator's own spelling.
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

pytestmark = pytest.mark.unit


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


@pytest.fixture
def elsewhere(tmp_path) -> Path:
    """The directory a link points the output at; nothing may be written to it."""
    path = tmp_path / "elsewhere"
    path.mkdir()
    return path


def _linked_output(where: str, source: Path, elsewhere: Path, tmp_path: Path):
    """Lay out one linked output directory: (the path to pass, the link)."""
    if where == "the-output-directory-is-a-link":
        (source / ".ash").mkdir()
        output = source / ".ash" / "ash_output"
        output.symlink_to(elsewhere, target_is_directory=True)
        return output, output
    if where == "a-directory-on-the-way-is-a-link":
        link = source / ".ash"
        link.symlink_to(elsewhere, target_is_directory=True)
        return link / "ash_output", link
    if where == "an-output-directory-outside-the-source-is-a-link":
        output = tmp_path / "out-link"
        output.symlink_to(elsewhere, target_is_directory=True)
        return output, output
    if where == "a-dangling-link":
        (source / ".ash").mkdir()
        output = source / ".ash" / "ash_output"
        output.symlink_to(tmp_path / "not-there", target_is_directory=True)
        return output, output
    raise AssertionError(where)


LINKED = [
    "the-output-directory-is-a-link",
    "a-directory-on-the-way-is-a-link",
    "an-output-directory-outside-the-source-is-a-link",
    "a-dangling-link",
]


def _run(source: Path, output: Path, **kwargs):
    kwargs.setdefault("build", False)
    kwargs.setdefault("run", True)
    return rac.run_ash_container(
        source_dir=str(source), output_dir=str(output), **kwargs
    )


@pytest.mark.parametrize("where", LINKED)
def test_a_linked_output_directory_is_refused(
    where, source, elsewhere, commands, tmp_path
):
    output, link = _linked_output(where, source, elsewhere, tmp_path)

    result = _run(source, output)

    assert result.returncode == 3, result.stderr
    assert not rac.container_was_started(result)
    assert commands == []
    assert list(elsewhere.iterdir()) == []
    assert link.as_posix() in result.stderr
    assert "/out" in result.stderr


def test_a_link_on_the_way_is_seen_under_the_real_name_of_the_source(
    source, elsewhere, commands, tmp_path
):
    """The source is named through a link above it and the output through its real
    path, so only the real name shows that ``.ash`` is below the source."""
    named = tmp_path / "work-link"
    named.symlink_to(tmp_path / "work", target_is_directory=True)
    (source / ".ash").symlink_to(elsewhere, target_is_directory=True)

    result = _run(named / "project", source / ".ash" / "ash_output")

    assert result.returncode == 3, result.stderr
    assert commands == []
    assert list(elsewhere.iterdir()) == []


@pytest.mark.parametrize("where", ["inside-the-source", "outside-it"])
def test_a_real_output_directory_runs(where, source, commands, tmp_path):
    """Control: the default .ash/ash_output, and a real directory beside the source."""
    output = (
        source / ".ash" / "ash_output"
        if where == "inside-the-source"
        else tmp_path / "work" / "out"
    )

    result = _run(source, output)

    assert result.returncode == 0, result.stderr
    assert [cmd[1] for cmd in commands] == ["run"]
    assert output.is_dir() and not output.is_symlink()


def test_a_source_reached_through_a_link_above_it_runs(source, commands, tmp_path):
    """Control: a link at or above the source is the operator's spelling."""
    named = tmp_path / "work-link"
    named.symlink_to(tmp_path / "work", target_is_directory=True)

    result = _run(named / "project", named / "project" / ".ash" / "ash_output")

    assert result.returncode == 0, result.stderr
    assert [cmd[1] for cmd in commands] == ["run"]
    assert (source / ".ash" / "ash_output").is_dir()


def test_a_build_without_a_run_writes_no_output_and_is_not_refused(
    source, elsewhere, commands, tmp_path
):
    """Control: run=False neither creates nor mounts the output directory."""
    output, _ = _linked_output(
        "a-directory-on-the-way-is-a-link", source, elsewhere, tmp_path
    )

    result = _run(
        source, output, build=True, run=False, ash_revision_to_install="v3.7.0"
    )

    assert result.returncode == 0, result.stderr
    assert [cmd[1] for cmd in commands] == ["build"]
    assert list(elsewhere.iterdir()) == []


def _scan(source: Path, *extra: str):
    return CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--source-dir",
            str(source),
            *extra,
        ],
    )


@pytest.mark.parametrize("run", [True, False], ids=["run", "no-run"])
def test_the_scan_cli_refuses_a_linked_default_output_before_it_writes(
    run, source, elsewhere, commands, tmp_path
):
    """Before the logger opens ash.log in the output directory, so the link target
    stays empty; with --no-run as well, since the log is written either way."""
    _linked_output("a-directory-on-the-way-is-a-link", source, elsewhere, tmp_path)

    result = _scan(source, *([] if run else ["--no-run"]))

    assert result.exit_code == 3, result.output
    assert commands == []
    assert list(elsewhere.iterdir()) == []
    assert (source / ".ash").as_posix() in " ".join(result.output.split())


def test_the_scan_cli_refuses_an_explicit_linked_output_directory(
    source, elsewhere, commands, tmp_path
):
    output, _ = _linked_output(
        "an-output-directory-outside-the-source-is-a-link", source, elsewhere, tmp_path
    )

    result = _scan(source, "--output-dir", str(output))

    assert result.exit_code == 3, result.output
    assert commands == []
    assert list(elsewhere.iterdir()) == []


def test_the_scan_cli_runs_with_a_real_default_output_directory(source, commands):
    """Control: the run is started. Its exit code is about the results the fake
    runner did not write, which is not what this test is about."""
    _scan(source)

    assert [cmd[1] for cmd in commands] == ["run"]
    assert (source / ".ash" / "ash_output").is_dir()
