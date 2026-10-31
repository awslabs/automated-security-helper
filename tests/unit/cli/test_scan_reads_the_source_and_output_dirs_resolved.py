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
from automated_security_helper.utils.output_dir_links import (
    OUTPUT_GITIGNORE_TEXT,
    OUTPUT_WORKING_DIRS,
)

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
            (
                "ash_aggregated_results.json",
                '{"name": "ASH Scan Report", "description": "", "metadata": {}}\n',
            ),
            (
                "ash.log",
                "2026-10-30 00:12:34,567\tINFO\tscan.py:12\tLogging to tabular file \n",
            ),
            (
                "ash.log.jsonl",
                (
                    '{"timestamp": "2026-10-30 00:12:34,567", "level": "INFO", '
                    '"filename": "scan.py", "lineno": 12, "message": "started"}\n'
                ),
            ),
            pytest.param(".gitignore", OUTPUT_GITIGNORE_TEXT, id="gitignore"),
            pytest.param(
                ".gitignore",
                OUTPUT_GITIGNORE_TEXT.replace("\n", "\r\n"),
                id="gitignore-crlf",
            ),
        ],
    )
    def test_an_output_directory_ash_wrote_before_is_still_cleared(
        self, tmp_path, marker, text
    ):
        """The ``.gitignore`` is written in text mode, so on Windows ASH's own
        copy has ``\\r\\n`` line ends; the marker is the text, not the bytes."""
        out = tmp_path / "src" / "out"
        (out / "reports").mkdir(parents=True)
        (out / "reports" / "ash.summary.txt").write_text("old\n")
        (out / marker).write_bytes(text.encode("utf-8"))

        run = _scan(source_dir="src", output_dir="src/out")

        assert run.call_args.kwargs["output_dir"] == "src/out"

    @pytest.mark.parametrize(
        "marker, text",
        [
            ("ash.log", "notes about the ash tree\n"),
            ("ash_aggregated_results.json", "[]\n"),
            ("ash-scan-set-files-list.txt", "a.py\n"),
        ],
    )
    def test_a_tree_file_at_a_marker_name_does_not_make_it_ashs(
        self, tmp_path, marker, text, capsys
    ):
        """The marker is read by its content: a user file named ash.log beside a
        real reports/ read as ASH's by name alone, and the scan cleared it."""
        docs = tmp_path / "src" / "docs"
        (docs / "reports").mkdir(parents=True)
        (docs / "reports" / "index.md").write_text("# docs\n")
        (docs / marker).write_text(text)

        code = _refused(source_dir="src", output_dir="src/docs")

        assert code == ASH_EXIT_USAGE_ERROR
        assert "already holds files that are not ASH's" in capsys.readouterr().err

    @_NEEDS_SYMLINKS
    def test_a_link_at_a_marker_name_counts_for_nothing(self, tmp_path):
        docs = tmp_path / "src" / "docs"
        (docs / "reports").mkdir(parents=True)
        (docs / "reports" / "index.md").write_text("# docs\n")
        real_log = tmp_path / "elsewhere.log"
        real_log.write_text("2026-10-30 00:12:34,567\tINFO\tscan.py:12\tx \n")
        (docs / "ash.log").symlink_to(real_log)

        assert _refused(source_dir="src", output_dir="src/docs") == ASH_EXIT_USAGE_ERROR

    @pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="a mode-0 directory is still readable by root and on Windows",
    )
    def test_an_unreadable_cleared_directory_is_refused_not_skipped(
        self, tmp_path, capsys
    ):
        """An unreadable reports/ read as empty, so no refusal was given; the clear
        then failed on the same permission with a traceback."""
        docs = tmp_path / "src" / "docs"
        (docs / "reports").mkdir(parents=True)
        (docs / "reports").chmod(0o000)
        try:
            code = _refused(source_dir="src", output_dir="src/docs")
        finally:
            (docs / "reports").chmod(0o755)

        assert code == ASH_EXIT_USAGE_ERROR
        err = capsys.readouterr().err
        assert "cannot be read (PermissionError)" in err, err

    @pytest.mark.parametrize(
        "output_dir, refusal",
        [
            pytest.param(
                "src/afile", "Output directory is not a directory", id="a-file"
            ),
            pytest.param(
                "src/afile/out",
                "Output directory cannot be created",
                id="under-a-file",
            ),
        ],
    )
    def test_an_output_path_that_is_a_file_is_refused_as_that(
        self, tmp_path, capsys, output_dir, refusal
    ):
        """A file inside the tree, or a path under one, is not a directory the
        scan could write into at all; it is refused as that, the line every
        runner prints alike, not as a working directory that cannot be read."""
        (tmp_path / "src" / "afile").write_text("not a directory\n")

        code = _refused(source_dir="src", output_dir=output_dir)

        assert code == ASH_EXIT_USAGE_ERROR
        err = capsys.readouterr().err
        assert refusal in err, err
        assert "cannot be read" not in err, err

    def test_a_refused_tree_directory_is_not_probed_for_writing_first(self, tmp_path):
        """The output directory's own refusal probes a directory that exists by
        making and removing a file in it. A directory of the tree's that the scan
        refuses to clear is refused before that probe, so nothing is written into
        the tree, not even for a moment; a path that is not a directory (a file in
        the tree) is still asked of the probe first, which refuses it as a file."""
        docs = tmp_path / "src" / "docs"
        (docs / "reports").mkdir(parents=True)
        (docs / "reports" / "index.md").write_text("# docs\n")
        (tmp_path / "src" / "afile").write_text("not a directory\n")
        probed: list[str] = []

        def recording(output_dir):
            probed.append(str(output_dir))
            return "Output directory is not a directory: afile"

        with patch("automated_security_helper.cli.scan.output_dir_refusal", recording):
            assert _refused(source_dir="src", output_dir="src/docs") == (
                ASH_EXIT_USAGE_ERROR
            )
            assert probed == [], probed
            assert _refused(source_dir="src", output_dir="src/afile") == (
                ASH_EXIT_USAGE_ERROR
            )
            assert probed == ["src/afile"], probed

    def test_an_output_path_whose_directory_check_raises_is_still_settled(
        self, tmp_path, monkeypatch
    ):
        """Before CPython 3.13, Path.is_dir() re-raises the PermissionError of an
        unsearchable directory on the way (3.13 answers False). Either way the
        output directory's own refusal is the one that names the reason, so the
        check's error is read as "not a directory that exists" and the run goes
        on to that refusal, never to a traceback."""
        real_is_dir = Path.is_dir

        def raising(self, *args, **kwargs):
            if self.name == "out":
                raise PermissionError(13, "Permission denied", str(self))
            return real_is_dir(self, *args, **kwargs)

        monkeypatch.setattr(Path, "is_dir", raising)

        run = _scan(source_dir="src", output_dir="out")

        assert run.call_args.kwargs["output_dir"] == "out"

    @pytest.mark.skipif(
        os.name == "nt" or os.geteuid() == 0,
        reason="a directory mode is not honored for root or on Windows",
    )
    def test_an_output_path_under_an_unsearchable_directory_is_refused(
        self, tmp_path, capsys
    ):
        blocked = tmp_path / "src" / "blocked"
        blocked.mkdir()
        blocked.chmod(0o000)
        try:
            code = _refused(source_dir="src", output_dir="src/blocked/out")
        finally:
            blocked.chmod(0o755)

        assert code == ASH_EXIT_USAGE_ERROR
        err = capsys.readouterr().err
        assert "Output directory cannot be created" in err, err
        assert "Permission denied" in err, err

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
