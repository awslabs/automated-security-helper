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

    @_NEEDS_SYMLINKS
    def test_a_link_to_itself_as_the_output_directory_is_refused_not_a_traceback(
        self, tmp_path
    ):
        """Resolving a link that leads back to itself raised (RuntimeError before
        Python 3.13); the comparison now falls back to the absolute spelling and the
        output directory refusal names the link."""
        (tmp_path / "loop").symlink_to(tmp_path / "loop")

        assert _refused(source_dir="src", output_dir="loop") == ASH_EXIT_USAGE_ERROR


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


class TestAnOutputDirectoryThatWouldClearTheScannedTreeIsRefused:
    """The other direction: the output directory inside the source directory, with
    a working directory of the scan's name already holding the tree's own files.
    The scan removed it before it started."""

    @pytest.mark.parametrize("cleared", OUTPUT_WORKING_DIRS)
    def test_a_tree_directory_at_a_cleared_name(self, tmp_path, cleared, capsys):
        (tmp_path / "src" / "docs" / cleared).mkdir(parents=True)
        (tmp_path / "src" / "docs" / cleared / "index.md").write_text("# docs\n")

        code = _refused(source_dir="src", output_dir="src/docs")

        assert code == ASH_EXIT_USAGE_ERROR
        err = capsys.readouterr().err
        assert "already holds files that are not ASH's" in err, err
        assert f"docs/{cleared}" in err, err

    def test_an_empty_directory_at_a_cleared_name_is_not_refused(self, tmp_path):
        (tmp_path / "src" / "docs" / "reports").mkdir(parents=True)

        run = _scan(source_dir="src", output_dir="src/docs")

        assert run.call_args.kwargs["output_dir"] == "src/docs"

    @pytest.mark.parametrize(
        "marker, text",
        [
            ("ash_aggregated_results.json", "{}\n"),
            ("ash.log", "a previous run\n"),
            (
                ".gitignore",
                "# ASH's output directory, not part of the scanned tree.\n*\n",
            ),
        ],
    )
    def test_an_output_directory_ash_wrote_before_is_still_cleared(
        self, tmp_path, marker, text
    ):
        out = tmp_path / "src" / "out"
        (out / "reports").mkdir(parents=True)
        (out / "reports" / "ash.summary.txt").write_text("old\n")
        (out / marker).write_text(text)

        run = _scan(source_dir="src", output_dir="src/out")

        assert run.call_args.kwargs["output_dir"] == "src/out"

    def test_the_default_output_directory_with_old_results_is_not_refused(
        self, tmp_path
    ):
        old = tmp_path / "src" / ".ash" / "ash_output" / "scanners"
        old.mkdir(parents=True)
        (old / "bandit.json").write_text("{}\n")

        run = _scan(source_dir="src")

        assert Path(run.call_args.kwargs["output_dir"]) == Path("src/.ash/ash_output")

    def test_an_output_directory_outside_the_source_is_not_refused(self, tmp_path):
        (tmp_path / "out" / "reports").mkdir(parents=True)
        (tmp_path / "out" / "reports" / "old.html").write_text("<p>old</p>\n")

        run = _scan(source_dir="src", output_dir="out")

        assert run.call_args.kwargs["output_dir"] == "out"
