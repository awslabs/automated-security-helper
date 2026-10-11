# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan`` with a link already at a report path, run as a child process.

A link at ``reports/ash.sarif`` that led out of the output directory used to make
the SARIF reporter's write fail with the scan still exiting 0, and the link stayed,
so a later step that uploads ``reports/ash.sarif`` read the file it points to. The
runs below are refused instead: exit 1, the link named, its target untouched, and
nothing ASH wrote holds the target's content.

Where the link reaches the report phase
---------------------------------------
``--use-existing`` keeps the reports directory, as ``ash report`` and ``ash merge``
do, so a link there is still there when reports are written. A workspace run never
clears its top-level ``reports/``. A fresh single-directory scan clears
``reports/`` while setting up its directories, link included, before any phase
runs; ``test_a_fresh_scan_clears_a_link_left_in_reports`` pins that, because it is
why the check runs at the start of the report phase rather than earlier.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

MARKER = "TARGET-OF-A-LINK-IN-REPORTS-9d27"

# From this checkout, which `-I` alone would not import; see importing_this_checkout.
DRIVER = importing_this_checkout(
    "from automated_security_helper.cli.main import app\n"
    "sys.argv = ['ash', 'scan', *sys.argv[1:]]\n"
    "app()\n"
)


def _ash_scan(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # Off the network, and wide enough that the console does not wrap the path.
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "2000"})
    return subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            DRIVER,
            *args,
            "--mode",
            "local",
            "--no-progress",
            "--no-fail-on-findings",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        cwd=cwd,
    )


def _console(completed: subprocess.CompletedProcess) -> str:
    """stdout and stderr, without the styling rich keeps under NO_COLOR."""
    return re.sub(r"\x1b\[[0-9;]*m", "", completed.stdout + completed.stderr)


def _outside_target(base: Path) -> Path:
    """A SARIF document outside the output directory, carrying MARKER."""
    target = base / "outside" / "uploaded.sarif"
    target.parent.mkdir(parents=True)
    target.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": MARKER}},
                        "results": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return target


def _single_directory(base: Path) -> tuple[Path, Path]:
    source = base / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = base / "out"
    (output / "reports").mkdir(parents=True)
    return source, output


def _write_existing_results(output: Path) -> None:
    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(indent=2, by_alias=True),
        encoding="utf-8",
    )


def _files_holding_marker(output: Path) -> List[str]:
    """Regular files under ``output`` whose content includes MARKER. Links are not followed."""
    holding = []
    for root, _dirs, files in os.walk(output):
        for name in files:
            path = Path(root) / name
            if path.is_symlink():
                continue
            if MARKER in path.read_text(encoding="utf-8", errors="replace"):
                holding.append(path.as_posix())
    return holding


def test_a_scan_of_existing_results_with_a_linked_sarif_report_exits_non_zero(tmp_path):
    source, output = _single_directory(tmp_path)
    _write_existing_results(output)
    target = _outside_target(tmp_path)
    before = target.read_bytes()
    link = output / "reports" / "ash.sarif"
    link.symlink_to(target)

    completed = _ash_scan(
        tmp_path,
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--use-existing",
    )

    console = _console(completed)
    assert completed.returncode == 1, console[-4000:]
    assert f"{link.as_posix()} is a symlink" in console, console[-4000:]
    assert link.is_symlink()
    assert target.read_bytes() == before
    assert _files_holding_marker(output) == []


def test_a_scan_of_existing_results_replaces_a_regular_sarif_report(tmp_path):
    """The positive control: a regular file at the name is overwritten as before."""
    source, output = _single_directory(tmp_path)
    _write_existing_results(output)
    report = output / "reports" / "ash.sarif"
    report.write_text("left by an earlier run", encoding="utf-8")

    completed = _ash_scan(
        tmp_path,
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--use-existing",
    )

    assert completed.returncode == 0, _console(completed)[-4000:]
    assert report.is_file() and not report.is_symlink()
    assert "runs" in json.loads(report.read_text(encoding="utf-8"))


def test_a_fresh_scan_clears_a_link_left_in_reports(tmp_path):
    """Directory setup removes reports/ with the link in it, so nothing reaches it."""
    source, output = _single_directory(tmp_path)
    target = _outside_target(tmp_path)
    before = target.read_bytes()
    report = output / "reports" / "ash.sarif"
    report.symlink_to(target)

    completed = _ash_scan(
        tmp_path,
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--phases",
        "report",
    )

    assert completed.returncode == 0, _console(completed)[-4000:]
    assert report.is_file() and not report.is_symlink()
    assert target.read_bytes() == before
    assert _files_holding_marker(output) == []


def test_a_workspace_scan_with_a_linked_report_is_refused_before_any_project(tmp_path):
    workspace = tmp_path / "ws"
    for key in ("api", "web"):
        (workspace / key / "src").mkdir(parents=True)
        (workspace / key / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = workspace / "fixture.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}), encoding="utf-8"
    )
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    target = _outside_target(tmp_path)
    before = target.read_bytes()
    link = output / "reports" / "ash.sarif"
    link.symlink_to(target)

    completed = _ash_scan(
        tmp_path,
        "--workspace",
        str(workspace_file),
        "--output-dir",
        str(output),
        "--phases",
        "report",
    )

    console = _console(completed)
    assert completed.returncode == 1, console[-4000:]
    assert f"{link.as_posix()} is a symlink" in console, console[-4000:]
    assert target.read_bytes() == before
    assert link.is_symlink()
    # Refused before any project ran.
    assert not (output / "projects").exists()
    assert _files_holding_marker(output) == []


@pytest.mark.parametrize("target", ["a directory", "nothing"])
@pytest.mark.parametrize("run", ["fresh", "existing results"])
def test_a_reports_directory_that_is_a_link_refuses_the_scan(tmp_path, target, run):
    """A link at ``reports/`` itself is refused, naming it, before ASH creates or clears it.

    Linked to a directory or dangling, in a fresh scan (which clears ``reports/``
    while setting up its directories) and with ``--use-existing`` (which keeps it).
    """
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    outside = tmp_path / "outside"
    if target == "a directory":
        outside.mkdir()
        (outside / "keep.txt").write_text("unchanged", encoding="utf-8")
    reports = output / "reports"
    reports.symlink_to(outside, target_is_directory=True)
    extra = ["--use-existing"] if run == "existing results" else ["--phases", "report"]
    if run == "existing results":
        _write_existing_results(output)

    completed = _ash_scan(
        tmp_path, "--source-dir", str(source), "--output-dir", str(output), *extra
    )

    console = _console(completed)
    assert completed.returncode == 1, console[-4000:]
    expected = f"reports directory {reports.as_posix()} is a symlink"
    assert expected in console, console[-4000:]
    assert "Traceback" not in console, console[-4000:]
    assert reports.is_symlink()
    if target == "a directory":
        assert sorted(path.name for path in outside.iterdir()) == ["keep.txt"]
    else:
        assert not outside.exists()
