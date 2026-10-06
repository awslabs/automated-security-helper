# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: ``ash scan`` refuses unusable input with a message and exit 1.

* A ``--source-dir`` that does not exist was not refused at all. A real scan
  ran over nothing, every scanner found no files, and it could exit 0 -- the
  same answer as a clean scan of the directory the operator meant.

It now exits 1, the code scan already uses for a refused shard selection
(``_fail_shard_selection``): 2 means "actionable findings", so a usage error
that exited 2 would read to a CI gate as a scan that found problems.
"""

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

RUN_ASH_SCAN = "automated_security_helper.cli.scan.run_ash_scan"
USAGE_ERROR_EXIT = 1


@pytest.fixture
def runner():
    return CliRunner()


def _assert_refused(result, *fragments):
    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    # A clean exit, not an exception escaping the command.
    assert isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.output
    for fragment in fragments:
        assert fragment in result.stderr, result.stderr


class TestNonexistentSourceDir:
    def test_is_refused_before_any_scan_runs(self, runner, tmp_path):
        missing = tmp_path / "does-not-exist"
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--source-dir",
                    str(missing),
                    "--output-dir",
                    str(tmp_path / "o"),
                ],
            )
        _assert_refused(result, "Source directory does not exist", str(missing))
        mock_run.assert_not_called()

    def test_from_the_environment_is_refused_too(self, runner, tmp_path, monkeypatch):
        missing = tmp_path / "also-missing"
        monkeypatch.setenv("ASH_SOURCE_DIR", str(missing))
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(app, ["scan", "--output-dir", str(tmp_path / "o")])
        _assert_refused(result, "ASH_SOURCE_DIR", str(missing))
        mock_run.assert_not_called()

    def test_a_file_is_refused(self, runner, tmp_path):
        a_file = tmp_path / "file.py"
        a_file.write_text("x = 1\n", encoding="utf-8")
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--source-dir",
                    str(a_file),
                    "--output-dir",
                    str(tmp_path / "o"),
                ],
            )
        _assert_refused(result, "is not a directory", str(a_file))
        mock_run.assert_not_called()

    def test_an_existing_directory_still_scans(self, runner, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--source-dir",
                    str(source),
                    "--output-dir",
                    str(tmp_path / "o"),
                ],
            )
        assert result.exit_code == 0, result.output
        assert mock_run.call_args.kwargs["source_dir"] == str(source)
