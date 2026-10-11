# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` refuses when a file the reporter writes itself is already a link.

``ash report`` prints the report, but a reporter that writes files of its own
writes them to the reports directory: the unused-suppressions reporter writes its
markdown copy there. A link at that name is refused before the reporter runs, as a
scan refuses it, and the command exits 1 naming it. Run as a child process so the
real plugin loading and the real reporter run.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

# From this checkout, which `-I` alone would not import; see importing_this_checkout.
DRIVER = importing_this_checkout(
    "from automated_security_helper.cli.main import app\n"
    "sys.argv = ['ash', 'report', *sys.argv[1:]]\n"
    "app()\n"
)


def _ash_report(cwd: Path, output: Path, report_format: str):
    env = dict(os.environ)
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "2000"})
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            DRIVER,
            "--format",
            report_format,
            "--output-dir",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
        cwd=cwd,
    )
    console = re.sub(r"\x1b\[[0-9;]*m", "", completed.stdout + completed.stderr)
    return completed.returncode, console


def _output_with_results(base: Path) -> Path:
    output = base / "out"
    (output / "reports").mkdir(parents=True)
    (output / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(indent=2, by_alias=True),
        encoding="utf-8",
    )
    return output


def _markdown_name(base: Path) -> str:
    """What the unused-suppressions reporter writes beside its report, found by running it."""
    output = _output_with_results(base)
    returncode, console = _ash_report(base, output, "unused-suppressions")
    assert returncode == 0, console[-4000:]
    written = [path.name for path in (output / "reports").iterdir()]
    assert len(written) == 1, written
    return written[0]


def test_a_link_at_a_file_the_reporter_writes_refuses_the_command(tmp_path):
    name = _markdown_name(tmp_path / "clean")
    output = _output_with_results(tmp_path)
    outside = tmp_path / "outside.md"
    outside.write_text("unchanged", encoding="utf-8")
    link = output / "reports" / name
    link.symlink_to(outside)

    returncode, console = _ash_report(tmp_path, output, "unused-suppressions")

    assert returncode == 1, console[-4000:]
    assert f"{link.as_posix()} is a symlink" in console, console[-4000:]
    assert outside.read_text(encoding="utf-8") == "unchanged"
    assert link.is_symlink()


def test_a_link_at_a_name_the_reporter_does_not_write_is_not_examined(tmp_path):
    """``ash report --format sarif`` writes nothing in reports/, so a link there is no matter."""
    output = _output_with_results(tmp_path)
    outside = tmp_path / "outside.sarif"
    outside.write_text("unchanged", encoding="utf-8")
    (output / "reports" / "ash.sarif").symlink_to(outside)

    returncode, console = _ash_report(tmp_path, output, "sarif")

    assert returncode == 0, console[-4000:]
    assert outside.read_text(encoding="utf-8") == "unchanged"
