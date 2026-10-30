# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What snyk-code's own ``scan()`` records and refuses, per target.

- ``_hold`` raised out of ``_stage_source`` when the copy's directory could not be
  opened for the lock, before the copy's removal was registered.
- A scan-set line was stripped of every trailing newline, so a file whose name
  ends in one was copied under another name.
- Exit 3 ("no supported files") was graded SKIPPED even when files of the scan
  set had been refused from the copy, so snyk may have been given none of the
  supported files the tree holds.
- A results file left by an earlier run was read as this run's when snyk wrote
  none.
- The SARIF invocation was recorded before ``_post_scan`` ran, so the first
  target's record carried no end time.
- A run the subprocess layer flagged was graded on its exit code and file.
- ``errors`` and ``output`` were not reset per target.
- A target refused before snyk started kept the previous target's end time.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
    _hold,
    _scan_set_name,
)

pytestmark = pytest.mark.unit

SNYK_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "SnykCode", "rules": [{"id": "python/X"}]}},
            "results": [
                {
                    "ruleId": "python/X",
                    "level": "error",
                    "message": {"text": "x"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "main.py"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


@pytest.fixture
def context(tmp_path: Path, monkeypatch) -> PluginContext:
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.py").write_text("print(1)\n")
    output = tmp_path / "output"
    (output / "converted").mkdir(parents=True)
    fake = tmp_path / "bin" / "snyk"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: str(fake))
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )


def _scanner(context: PluginContext) -> SnykCodeScanner:
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    scanner.dependencies_satisfied = True
    return scanner


def _responds(response: dict, document: dict | None = None):
    """A snyk run that writes ``document`` to the SARIF path named in the argv when
    given, records the code as ``_run_subprocess`` does, and answers ``response``."""

    def _side_effect(self, command, **kwargs):
        if document is not None:
            destination = next(
                arg.split("=", 1)[1]
                for arg in command
                if str(arg).startswith("--sarif-file-output=")
            )
            Path(destination).write_text(json.dumps(document), encoding="utf-8")
        code = response.get("returncode")
        if isinstance(code, int) and code >= 0:
            self.exit_code = max(self.exit_code or 0, code)
        return response

    return _side_effect


def _scan(context, response: dict, document: dict | None = None):
    scanner = _scanner(context)
    with patch.object(
        SnykCodeScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_responds(response, document),
    ):
        result = scanner.scan(target=context.source_dir, target_type="source")
    return scanner, result


# --- helpers ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="flock is POSIX")
def test_a_directory_that_cannot_be_opened_for_the_lock_is_unlocked_not_raised(
    tmp_path, monkeypatch
):
    """Only the one directory's open is refused; the control shows the lock is
    still taken elsewhere, so a None is the refusal's doing and not a flock that
    never ran."""
    refused = tmp_path / "refused"
    other = tmp_path / "other"
    refused.mkdir()
    other.mkdir()
    real_open = os.open

    def refuse(path, *args, **kwargs):
        if Path(path) == refused:
            raise OSError("open refused")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(snyk_code_scanner.os, "open", refuse)

    assert _hold(refused) is None
    held = _hold(other)
    try:
        assert held is not None
    finally:
        if held is not None:
            os.close(held)


def test_a_scan_set_line_loses_one_line_ending_and_nothing_more():
    assert _scan_set_name("a.js\n") == "a.js"
    assert _scan_set_name("a.js\n\n") == "a.js\n"
    assert _scan_set_name("a.js ") == "a.js "
    assert _scan_set_name("a.js") == "a.js"


# --- exit 3 with refused files --------------------------------------------------------


def test_exit_three_after_refused_files_fails_the_target_instead_of_skipping_it(
    context,
):
    def staged(self, target, ignore_paths, cleanup):
        self._staged_refused = 2
        return target

    with patch.object(
        SnykCodeScanner, "_stage_source", autospec=True, side_effect=staged
    ):
        scanner, result = _scan(context, {"stdout": "", "stderr": "", "returncode": 3})

    assert result is True
    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1


def test_control_exit_three_with_every_file_copied_evaluated_nothing(context):
    scanner, result = _scan(context, {"stdout": "", "stderr": "", "returncode": 3})

    assert result is True
    assert scanner.targets_attempted == 0
    assert scanner.targets_failed == 0


def test_the_refused_count_is_reset_per_target(context):
    """Refusals on the source target, then the converted target (never staged, so
    nothing refused) exits 3: the second is SKIPPED, not failed on the first's
    count. The second scan runs the real _stage_source path (none for a converted
    target), so the reset is the product's, not the patch's."""
    scanner = _scanner(context)

    def staged(self, target, ignore_paths, cleanup):
        self._staged_refused = 2
        return target

    exit_three = _responds({"stdout": "", "stderr": "", "returncode": 3})
    with (
        patch.object(
            SnykCodeScanner, "_stage_source", autospec=True, side_effect=staged
        ),
        patch.object(
            SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=exit_three
        ),
    ):
        scanner.scan(target=context.source_dir, target_type="source")

    assert scanner.targets_failed == 1

    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=exit_three
    ):
        scanner.scan(target=context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1


# --- a refused target's end time -------------------------------------------------------


def test_a_refused_target_records_its_own_end_time(context):
    """The refusals ran ahead of the handler that resets end_time for a failed run,
    so a converted target refused after the source target ran kept the source's
    end time: an end before its start."""
    scanner, _ = _scan(
        context, {"stdout": "", "stderr": "", "returncode": 0}, SNYK_SARIF
    )
    after_the_source = scanner.end_time
    assert after_the_source is not None

    def refuse(self, target):
        raise ScannerError("refused for the test")

    with (
        patch.object(
            SnykCodeScanner, "_refuse_links_leaving", autospec=True, side_effect=refuse
        ),
        pytest.raises(ScannerError, match="refused for the test"),
    ):
        scanner.scan(target=context.work_dir, target_type="converted")

    assert scanner.end_time is not None
    assert scanner.end_time > after_the_source


# --- the results file and the record --------------------------------------------------


def test_a_results_file_left_by_an_earlier_run_is_not_read_as_this_runs(context):
    scanner = _scanner(context)
    stale = Path(scanner.results_dir) / "source" / "results_sarif.sarif"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text(json.dumps(SNYK_SARIF), encoding="utf-8")
    given: list[str] = []

    def writes_nothing(self, command, **kwargs):
        given.extend(
            str(arg).split("=", 1)[1]
            for arg in command
            if str(arg).startswith("--sarif-file-output=")
        )
        return {"stdout": "", "stderr": "", "returncode": 0}

    with patch.object(
        SnykCodeScanner, "_run_subprocess", autospec=True, side_effect=writes_nothing
    ):
        result = scanner.scan(target=context.source_dir, target_type="source")

    # The path cleared is the one snyk is given, read from the argv rather than
    # assumed from another scanner's layout.
    assert [Path(p) for p in given] == [stale]
    assert result is None
    assert not stale.exists()


def test_the_first_targets_invocation_carries_this_runs_end_time(context):
    scanner, report = _scan(
        context, {"stdout": "", "stderr": "", "returncode": 0}, SNYK_SARIF
    )

    assert hasattr(report, "runs"), type(report)
    (invocation,) = report.runs[0].invocations
    assert invocation.endTimeUtc is not None
    assert scanner.end_time is not None


def test_a_run_whose_output_could_not_be_recorded_is_not_graded_on_its_file(context):
    with pytest.raises(ScannerError) as raised:
        _scan(
            context,
            {"returncode": 0, "post_run_error": True, "error": "disk full"},
            SNYK_SARIF,
        )

    assert "could not record" in str(raised.value)


def test_a_timed_out_run_is_reported_as_a_timeout(context):
    with pytest.raises(ScannerError) as raised:
        _scan(context, {"returncode": -9, "timed_out": True})

    assert "timed out" in str(raised.value)
    assert "No such file" not in str(raised.value)


def test_the_tool_lines_are_reset_per_target(context):
    scanner = _scanner(context)
    scanner.errors = ["stderr of the previous target"]
    scanner.output = ["stdout of the previous target"]

    with patch.object(
        SnykCodeScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_responds({"stdout": "", "stderr": "", "returncode": 3}),
    ):
        scanner.scan(target=context.source_dir, target_type="source")

    assert scanner.errors == []
    assert scanner.output == []
