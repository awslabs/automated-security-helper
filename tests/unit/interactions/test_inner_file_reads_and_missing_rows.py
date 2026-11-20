# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Review findings in ``run_ash_scan``'s coverage rows and file reads.

* A ``FAILED (MISSING on some files)`` row is a MISSING row for the console
  advice, and its payload reason is ``missing_dependencies``.
* The inner run's results file and the SARIF report are opened without
  following a link and checked as regular files on the descriptor, so a link
  swapped in after the lstat check is not read.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

from automated_security_helper.interactions import run_ash_scan as ras

pytestmark = pytest.mark.unit

ROW = ("tool-a", "FAILED (MISSING on some files)")


def test_one_predicate_reads_both_missing_shapes():
    assert ras._row_is_missing("MISSING")
    assert ras._row_is_missing("MISSING (the tool is absent)")
    assert ras._row_is_missing("FAILED (MISSING on some files)")
    assert not ras._row_is_missing("ERROR")
    assert not ras._row_is_missing("FAILED")


def test_the_reason_token_for_a_missing_tree_is_missing_dependencies():
    assert ras.incomplete_scanner_reason("FAILED", missing_dependencies=True) == (
        "missing_dependencies"
    )
    assert (
        ras.incomplete_scanner_reason("FAILED", partial=True, missing_dependencies=True)
        == "missing_dependencies"
    )
    assert ras.incomplete_scanner_reason("FAILED") == "partial_coverage"


def test_the_payload_reason_follows_the_missing_tree_row():
    incomplete = ras.ScanIncompleteness(
        scanners=(ROW,),
        observed=(("tool-a", "FAILED"),),
        missing_dependencies=("tool-a",),
    )

    (row,) = incomplete.to_payload()["incomplete_scanners"]

    assert row["reason"] == "missing_dependencies"


def test_a_run_whose_only_gap_is_a_missing_tree_gets_the_per_reason_advice(
    monkeypatch, capsys
):
    printed = []
    console = MagicMock()
    console.print = lambda *a, **k: printed.append(str(a[0]))
    monkeypatch.setattr(ras, "global_console", lambda: console)
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(
        subprocess_utils, "ignored_relative_bin_path", lambda: "rel/bin"
    )

    ras.print_incompleteness_message(
        [ROW], [], missing_reasons={"tool-a": "the rule pack could not be loaded"}
    )

    out = capsys.readouterr().out
    assert "Act on each MISSING scanner's reason" in out
    assert any("relative path" in line for line in printed), printed


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks and O_NOFOLLOW")
def test_a_link_swapped_in_after_the_check_is_not_read_back(tmp_path, monkeypatch):
    real = tmp_path / "elsewhere.json"
    real.write_text("{}", encoding="utf-8")
    link = tmp_path / "ash_aggregated_results.json"
    os.symlink(real, link)
    # The lstat check passed (a regular file was there), then the swap.
    monkeypatch.setattr(
        ras, "_refuse_an_inner_file_that_is_not_regular", lambda *a: None
    )
    logger = MagicMock()

    with pytest.raises(SystemExit) as exited:
        ras._read_back_inner_results(link, logger)

    assert exited.value.code == 1
    assert "Could not read results file" in logger.error.call_args.args[0]


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks and O_NOFOLLOW")
def test_a_regular_results_file_is_still_read(tmp_path, monkeypatch):
    path = tmp_path / "plain.txt"
    path.write_text("héllo", encoding="utf-8")

    with ras._open_a_regular_file_for_text(path) as handle:
        assert handle.read() == "héllo"


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks and O_NOFOLLOW")
def test_the_opener_refuses_a_link_and_a_pipe(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    os.symlink(real, link)
    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)

    with pytest.raises(OSError):
        ras._open_a_regular_file_for_text(link)
    with pytest.raises(OSError):
        ras._open_a_regular_file_for_text(fifo)


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks and O_NOFOLLOW")
def test_the_sarif_count_does_not_read_a_link_swapped_in_after_the_check(
    tmp_path, monkeypatch
):
    from automated_security_helper.base import reporter_plugin

    reports = tmp_path / "out" / "reports"
    reports.mkdir(parents=True)
    real = tmp_path / "elsewhere.sarif"
    real.write_text(
        '{"runs": [{"results": [{"level": "error", "ruleId": "r"}]}]}',
        encoding="utf-8",
    )
    link = reports / "ash.sarif"
    os.symlink(real, link)
    monkeypatch.setattr(ras, "_is_a_regular_report_file", lambda path: True)
    monkeypatch.setattr(reporter_plugin, "confined_report_path", lambda d, n: link)
    monkeypatch.setattr(
        ras, "report_file_written_as", lambda results, kind: "ash.sarif"
    )
    monkeypatch.setattr(ras, "get_unified_scanner_metrics", lambda asharp_model: [])
    opened = []
    real_open = ras._open_a_regular_file_for_text

    def spy(path):
        opened.append(path)
        return real_open(path)

    monkeypatch.setattr(ras, "_open_a_regular_file_for_text", spy)
    opts = ras.ScanOptions(source_dir=tmp_path, output_dir=tmp_path / "out")

    count = ras._gating_actionable_count(MagicMock(), opts, True)

    assert opened == [link], "the report was not opened through the guarded opener"
    assert count == 0, "the linked file's findings were counted"
