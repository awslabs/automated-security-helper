# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: ``ash scan`` refuses unusable input with a message, not a traceback.

* ``--use-existing`` with no existing results raised an uncaught ``ValueError``,
  so the operator got a traceback and whatever exit code the interpreter chose.
* A ``--source-dir`` that does not exist was not refused at all. A real scan
  ran over nothing, every scanner found no files, and it could exit 0 -- the
  same answer as a clean scan of the directory the operator meant.
* A ``--base-ref`` starting with ``-`` went to ``git diff`` as an option, not a
  revision (see ``tests/unit/utils/test_base_ref.py``).
* ``--ignore-suppressions`` with ``--use-existing`` ran and kept the stored
  suppressions: the results the report is made from were written with ASH's
  suppressions applied, and the scan phase the flag changes is the one
  ``--use-existing`` skips. The combination is refused, naming both flags.

A missing ``--source-dir`` is a mistyped argument, so it exits
``ASH_EXIT_USAGE_ERROR``, the code a refused shard selection
(``_fail_shard_selection``) and click's own usage errors exit with: 2 means
"actionable findings", so a usage error that exited 2 would read to a CI gate as
a scan that found problems. ``--use-existing`` with no results is a state problem,
not a mistake in the command line -- the results are not there yet -- so it exits 1,
as ``ash report`` does for missing results.
"""

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit

RUN_ASH_SCAN = "automated_security_helper.cli.scan.run_ash_scan"
USAGE_ERROR_EXIT = ASH_EXIT_USAGE_ERROR


@pytest.fixture
def runner():
    return CliRunner()


def _assert_refused(result, *fragments, code=USAGE_ERROR_EXIT):
    assert result.exit_code == code, result.output
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
        # The same text as for --source-dir: it names the case and the path, and no
        # option, so every surface can give it (utils/directory_refusals.py).
        _assert_refused(result, f"Source directory does not exist: {missing}")
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


class TestUseExistingWithoutResults:
    def test_is_refused_with_a_message_not_a_traceback(self, runner, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--source-dir",
                    str(source),
                    "--output-dir",
                    str(output),
                    "--use-existing",
                ],
            )
        _assert_refused(
            result,
            "--use-existing",
            (output / "ash_aggregated_results.json").as_posix(),
            code=1,
        )
        mock_run.assert_not_called()

    def test_existing_results_are_still_used(self, runner, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        results = output / "ash_aggregated_results.json"
        results.write_text("{}", encoding="utf-8")
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--source-dir",
                    str(source),
                    "--output-dir",
                    str(output),
                    "--use-existing",
                ],
            )
        assert result.exit_code == 0, result.output
        assert mock_run.call_args.kwargs["existing_results"] == results.as_posix()


class TestIgnoreSuppressionsWithUseExisting:
    """The two flags together are a mistake in the command line, so the usage code.

    The results are present, so the refusal is this one and not the missing-results
    state refusal above (which exits 1 and names only ``--use-existing``).
    """

    def _invoke(self, runner, tmp_path, *flags):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        (output / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
        with patch(RUN_ASH_SCAN) as mock_run:
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--source-dir",
                    str(source),
                    "--output-dir",
                    str(output),
                    *flags,
                ],
            )
        return result, mock_run

    def test_the_combination_is_refused_naming_both_flags(self, runner, tmp_path):
        result, mock_run = self._invoke(
            runner, tmp_path, "--use-existing", "--ignore-suppressions"
        )
        _assert_refused(result, "--ignore-suppressions", "--use-existing")
        mock_run.assert_not_called()

    def test_ignore_suppressions_alone_still_reaches_the_scan(self, runner, tmp_path):
        result, mock_run = self._invoke(runner, tmp_path, "--ignore-suppressions")
        assert result.exit_code == 0, result.output
        assert mock_run.call_args.kwargs["ignore_suppressions"] is True
        assert mock_run.call_args.kwargs["existing_results"] is None


class TestBaseRef:
    def _invoke(self, runner, tmp_path, *extra):
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
                    *extra,
                ],
            )
        return result, mock_run

    @pytest.mark.parametrize("base_ref", ["-p", "--output=x", "--upload-pack=x"])
    def test_an_option_like_value_is_refused_before_any_scan_runs(
        self, runner, tmp_path, base_ref
    ):
        result, mock_run = self._invoke(
            runner, tmp_path, "--changed-files-only", "--base-ref", base_ref
        )
        _assert_refused(result, "--base-ref", repr(base_ref), "starts with '-'")
        mock_run.assert_not_called()

    def test_from_the_environment_is_refused_too(self, runner, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_BASE_REF", "-p")
        result, mock_run = self._invoke(runner, tmp_path, "--changed-files-only")
        _assert_refused(result, "--base-ref", "'-p'")
        mock_run.assert_not_called()

    def test_a_value_that_breaks_the_ref_name_rules_is_refused(self, runner, tmp_path):
        result, mock_run = self._invoke(
            runner, tmp_path, "--changed-files-only", "--base-ref", "main..HEAD"
        )
        _assert_refused(result, "--base-ref", "'main..HEAD'")
        mock_run.assert_not_called()

    @pytest.mark.parametrize("base_ref", ["origin/main", "v1.2.3", "HEAD~1"])
    def test_a_revision_reaches_the_scan(self, runner, tmp_path, base_ref):
        result, mock_run = self._invoke(
            runner, tmp_path, "--changed-files-only", "--base-ref", base_ref
        )
        assert result.exit_code == 0, result.output
        assert mock_run.call_args.kwargs["base_ref"] == base_ref
        assert mock_run.call_args.kwargs["changed_files_only"] is True

    def test_without_changed_files_only_the_value_is_not_used_so_not_checked(
        self, runner, tmp_path, monkeypatch
    ):
        """No diff runs, so a value set for other jobs (ASH_BASE_REF) is ignored."""
        monkeypatch.setenv("ASH_BASE_REF", "-p")
        result, mock_run = self._invoke(runner, tmp_path)
        assert result.exit_code == 0, result.output
        assert mock_run.call_args.kwargs["changed_files_only"] is False
