# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An explicit ``--config`` is checked, and resolved, on the host before the container starts.

- One that names no file refuses the scan with exit 3 before any runner command,
  with container mode's own message (``run_ash_container._unreadable_config``):
  ``Config file not found: <path>. --config (or ASH_CONFIG) has to name an
  existing file: container mode mounts it read-only for the scan inside the
  container.``
- A relative one is resolved against the host's working directory, as a local scan
  resolves it, never against the source directory. The file it names is mounted
  read-only under ``/ash-config`` (or read through ``/src`` when it is inside the
  source directory), and the scan inside is given that container path, never the
  path as typed.

Both ``ash scan --mode container`` and ``ash --mode container`` are driven, with
the runner recorded instead of started.
"""

from __future__ import annotations

from typing import List

import pytest
from typer.testing import CliRunner

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit

ENTRY_POINTS = [
    pytest.param(["scan", "--mode", "container"], id="ash-scan"),
    pytest.param(["--mode", "container"], id="ash"),
]


@pytest.fixture(autouse=True)
def _no_real_runner(monkeypatch):
    def refuse(cmd_list, check=True, debug=False, shell=False, env=None):
        raise AssertionError(f"a real runner command was attempted: {cmd_list}")

    monkeypatch.setattr(rac, "run_cmd_direct", refuse)


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
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    return seen


def _scan(entry: List[str], *extra: str):
    from automated_security_helper.cli.main import app

    return CliRunner().invoke(
        app,
        [
            *entry,
            "--no-build",
            "--no-progress",
            "--source-dir",
            "src",
            "--output-dir",
            "out",
            *extra,
        ],
    )


def _run(commands) -> List[str]:
    runs = [cmd for cmd in commands if cmd[1] == "run"]
    assert len(runs) == 1, commands
    return runs[0]


def _mount_sources(run: List[str]) -> dict:
    mounts = {}
    for i, arg in enumerate(run[:-1]):
        if arg == "--mount":
            fields = dict(part.partition("=")[::2] for part in run[i + 1].split(","))
            mounts[fields["destination"]] = fields["source"]
    return mounts


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_a_missing_config_exits_3_before_the_container_starts(entry, commands):
    result = _scan(entry, "--config", "missing.yaml")

    assert result.exit_code == 3, result.output
    assert commands == []
    assert (
        "Config file not found: missing.yaml. --config (or ASH_CONFIG) has to name "
        "an existing file" in result.output
    )


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_a_relative_config_is_the_hosts_file_not_the_sources(entry, commands, tmp_path):
    (tmp_path / "ash.yaml").write_text("project_name: operator\n", encoding="utf-8")
    (tmp_path / "src" / "ash.yaml").write_text(
        "project_name: repository\n", encoding="utf-8"
    )

    _scan(entry, "--config", "ash.yaml")

    # The recorded run writes no results, so the exit code is not this test's.
    run = _run(commands)
    inner = run[run.index("--config") + 1]
    assert inner == "/ash-config/ash.yaml"
    assert _mount_sources(run)[inner] == str((tmp_path / "ash.yaml").resolve())


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_a_relative_config_inside_the_source_is_read_through_src(
    entry, commands, tmp_path
):
    """Control: the same file the host names, at its place under /src."""
    (tmp_path / "src" / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")

    _scan(entry, "--config", "src/ash.yaml")

    # The recorded run writes no results, so the exit code is not this test's.
    run = _run(commands)
    assert run[run.index("--config") + 1] == "/src/ash.yaml"
    assert "/ash-config/ash.yaml" not in _mount_sources(run)
