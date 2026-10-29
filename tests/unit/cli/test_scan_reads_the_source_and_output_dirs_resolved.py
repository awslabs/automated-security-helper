# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan`` compares --source-dir and --output-dir resolved, and refuses a
source directory the scan would clear.

The collision guard compared the two absolute spellings as text, so an output
directory spelled ``src/../src``, or reached through a link, read as different
from the source directory it named, and the scan then cleared ``reports/``,
``scanners/``, ``converted/`` and ``analysis/`` inside the tree it scanned. And
nothing checked whether the source directory was one of those cleared
directories: ``--source-dir reports --output-dir .`` deleted the tree it was asked
to scan before scanning it.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from automated_security_helper.cli.scan import run_ash_scan_cli_command
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.utils.output_dir_links import OUTPUT_WORKING_DIRS

pytestmark = pytest.mark.unit

_NEEDS_SYMLINKS = pytest.mark.skipif(
    os.name == "nt", reason="a symbolic link needs a privilege on Windows"
)


@pytest.fixture(autouse=True)
def _here(tmp_path, monkeypatch):
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()


def _scan(**kwargs) -> MagicMock:
    """Run the command with run_ash_scan replaced; the replacement is returned."""
    context = MagicMock(resilient_parsing=False, invoked_subcommand=None)
    with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
        run_ash_scan_cli_command(context, **kwargs)
    return run


def _refused(**kwargs) -> int:
    """Run the command with run_ash_scan replaced; the exit code it refused with."""
    context = MagicMock(resilient_parsing=False, invoked_subcommand=None)
    with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
        with pytest.raises(typer.Exit) as refused:
            run_ash_scan_cli_command(context, **kwargs)
    run.assert_not_called()
    return refused.value.exit_code


class TestTheCollisionGuardReadsResolvedPaths:
    def test_the_same_directory_spelled_through_dot_dot_is_moved(self):
        run = _scan(source_dir="src", output_dir="src/../src")

        _, kwargs = run.call_args
        assert Path(kwargs["output_dir"]) == Path("src/../src/.ash/ash_output")

    @_NEEDS_SYMLINKS
    def test_the_same_directory_reached_through_a_link_is_moved(self, tmp_path):
        (tmp_path / "link").symlink_to(tmp_path / "src")

        run = _scan(source_dir="src", output_dir="link")

        _, kwargs = run.call_args
        assert Path(kwargs["output_dir"]) == Path("link/.ash/ash_output")

    def test_a_different_output_directory_is_kept(self):
        run = _scan(source_dir="src", output_dir="out")

        _, kwargs = run.call_args
        assert kwargs["output_dir"] == "out"


class TestASourceDirectoryTheScanWouldClearIsRefused:
    @pytest.mark.parametrize("cleared", OUTPUT_WORKING_DIRS)
    def test_a_cleared_directory_as_the_source(self, tmp_path, cleared, capsys):
        (tmp_path / "out" / cleared).mkdir(parents=True)

        code = _refused(source_dir=f"out/{cleared}", output_dir="out")

        assert code == ASH_EXIT_USAGE_ERROR
        err = capsys.readouterr().err
        assert "which the scan removes" in err, err
        assert f"out/{cleared}" in err, err

    def test_a_directory_inside_a_cleared_one_as_the_source(self, tmp_path):
        (tmp_path / "out" / "reports" / "deep").mkdir(parents=True)

        assert _refused(source_dir="out/reports/deep", output_dir="out") == (
            ASH_EXIT_USAGE_ERROR
        )

    def test_the_working_directory_as_the_output(self, tmp_path):
        (tmp_path / "reports").mkdir()

        assert _refused(source_dir="reports", output_dir=".") == ASH_EXIT_USAGE_ERROR

    def test_the_default_output_directory_inside_the_source_is_not_refused(self):
        run = _scan(source_dir="src")

        _, kwargs = run.call_args
        assert Path(kwargs["output_dir"]) == Path("src/.ash/ash_output")
