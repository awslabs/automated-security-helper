# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What trivy-repo's own ``scan()`` records and refuses, per target.

``TrivyRepoScanner.scan`` overrides the template's ``scan()``, and had drifted
from it in these readings:

- the parameters were not in the base ``scan()``'s order, so a caller passing them
  by position gave the config as the ignore paths;
- a run the subprocess layer flagged (timed out, could not start, output not
  recorded, ended by a foreign signal) was graded on its exit code and file;
- the SARIF invocation was recorded before the run, so it lacked the flags
  ``_run_subprocess`` adds in place and carried the previous target's end time;
- ``errors`` and ``output`` were not reset per target, so a failed converted-target
  run recorded the source target's stderr as its own;
- a results file left by an earlier run was read as this run's when trivy wrote
  none;
- a trivy found only inside the scanned tree was reported as "not found", not as
  refused, and offline trivy-repo never checked for a vulnerability database;
- the ``module_dir`` refusal spelled the resolved path, which can carry an
  environment value;
- the default ``ignore_unfixed: true`` withheld findings with nothing said; then
  the warning said "(the default)" for an option the operator had written, and was
  repeated on every read of the options;
- a scan that raised left the previous target's end time in place, and an empty
  target kept the previous target's start time;
- the catch-all error was not redacted, where the syft scanner's is.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base import scanner_plugin
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base as trivy_base,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.utils import content_db_staleness as staleness

pytestmark = pytest.mark.unit

EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": []}],
}

ONE_FINDING_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Trivy", "rules": [{"id": "CVE-2026-1"}]}},
            "results": [
                {
                    "ruleId": "CVE-2026-1",
                    "ruleIndex": 0,
                    "level": "error",
                    "message": {"text": "Package: a\nInstalled Version: 1\n"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "requirements.txt"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


@pytest.fixture(autouse=True)
def _online(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    for name in ("TRIVY_CONFIG", "TRIVY_IGNOREFILE", "TRIVY_SECRET_CONFIG"):
        monkeypatch.delenv(name, raising=False)


def _scanner(tmp_path: Path, **options) -> TrivyRepoScanner:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    (context.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    options.setdefault("ignore_unfixed", False)
    scanner = TrivyRepoScanner(
        context=context,
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options)),
    )
    scanner.dependencies_satisfied = True
    return scanner


def _run_double(response: dict, document: dict | None, *, append: list | None = None):
    """A trivy double: writes ``document`` to the ``--output`` path when given,
    appends ``append`` to the argv in place as ``_run_subprocess`` adds flags, and
    answers ``response``."""

    def run(command, results_dir=None, env=None, timeout=None, **kwargs):
        if document is not None:
            out = Path(command[command.index("--output") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(document), encoding="utf-8")
        for token in append or []:
            command.append(token)
        return response

    return run


def _post_scan(scanner):
    def post(target=None, target_type=None, **kwargs):
        scanner.end_time = datetime.now(timezone.utc)

    return post


def _scan(scanner, run, *args, **kwargs):
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan", side_effect=_post_scan(scanner)),
        patch.object(scanner, "_run_subprocess", side_effect=run),
    ):
        if args:
            return scanner.scan(*args, **kwargs)
        return scanner.scan(
            target=Path(scanner.context.source_dir), target_type="source", **kwargs
        )


# --- the signature -----------------------------------------------------------------


def test_the_parameters_are_in_the_base_scans_order(tmp_path, monkeypatch):
    """target, target type, the global ignore paths, then the config: a caller
    passing them by position as the base declares them is read right.

    Falsy values in both slots would pass with the parameters in either order, so
    the ignore list is non-empty and the config a sentinel, and each is traced to
    where it lands: the config in ``_pre_scan``'s keyword, the ignore list in the
    call that turns it into ``--skip-dirs`` tokens, and that token in the argv.
    """
    scanner = _scanner(tmp_path)
    sentinel = object()
    ignore = [object()]
    given: dict = {}

    def skip_dirs(target, source_dir=None, ignore_paths=None):
        given["ignore_paths"] = ignore_paths
        return ["ignored-dir"]

    monkeypatch.setattr(trivy_base, "trivy_skip_dirs", skip_dirs)
    monkeypatch.setattr(trivy_base, "trivy_skip_files", lambda *a, **k: [])
    commands: list = []

    def run(command, results_dir=None, env=None, timeout=None, **kwargs):
        commands.append(list(command))
        out = Path(command[command.index("--output") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(EMPTY_SARIF), encoding="utf-8")
        return {"returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True) as pre,
        patch.object(scanner, "_post_scan", side_effect=_post_scan(scanner)),
        patch.object(scanner, "_run_subprocess", side_effect=run),
    ):
        report = scanner.scan(
            Path(scanner.context.source_dir), "source", ignore, sentinel
        )

    assert hasattr(report, "runs"), type(report)
    assert pre.call_args.kwargs["config"] is sentinel
    assert given["ignore_paths"] == ignore
    (command,) = commands
    assert "--skip-dirs=ignored-dir" in command, command


# --- flagged responses --------------------------------------------------------------


def test_a_run_whose_output_could_not_be_recorded_is_not_graded_on_its_file(tmp_path):
    scanner = _scanner(tmp_path)

    with pytest.raises(ScannerError) as raised:
        _scan(
            scanner,
            _run_double(
                {"returncode": 0, "post_run_error": True, "error": "disk full"},
                ONE_FINDING_SARIF,
            ),
        )

    assert "could not record" in str(raised.value)


def test_a_timed_out_run_is_reported_as_a_timeout(tmp_path):
    scanner = _scanner(tmp_path)

    with pytest.raises(ScannerError) as raised:
        _scan(scanner, _run_double({"returncode": -9, "timed_out": True}, None))

    message = str(raised.value)
    assert "timed out" in message
    assert "No such file" not in message


def test_a_run_a_foreign_signal_ended_did_not_finish(tmp_path):
    scanner = _scanner(tmp_path)

    with pytest.raises(ScannerError) as raised:
        _scan(
            scanner,
            _run_double(
                {"returncode": -15, "signaled": True, "error": "ended by SIGTERM"},
                EMPTY_SARIF,
            ),
        )

    assert "did not finish" in str(raised.value)


# --- the invocation record ----------------------------------------------------------


def test_the_invocation_records_the_command_as_it_ran_and_this_runs_end_time(tmp_path):
    """``_run_subprocess`` adds its flags to the argv in place; the record is taken
    after the run, with the end time ``_post_scan`` set for this run."""
    scanner = _scanner(tmp_path)
    scanner.end_time = None

    report = _scan(
        scanner,
        _run_double({"returncode": 0}, EMPTY_SARIF, append=["--exit-code=0"]),
    )

    (invocation,) = report.runs[0].invocations
    assert "--exit-code=0" in (invocation.arguments or [])
    assert invocation.endTimeUtc is not None


def test_the_tool_lines_are_reset_per_target(tmp_path):
    scanner = _scanner(tmp_path)
    scanner.errors = ["stderr of the previous target"]
    scanner.output = ["stdout of the previous target"]

    _scan(scanner, _run_double({"returncode": 0}, EMPTY_SARIF))

    assert scanner.errors == []
    assert scanner.output == []


# --- a stale results file -----------------------------------------------------------


def test_a_results_file_left_by_an_earlier_run_is_not_read_as_this_runs(tmp_path):
    scanner = _scanner(tmp_path)
    stale = Path(scanner.results_dir) / "source" / "results_sarif.sarif"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text(json.dumps(ONE_FINDING_SARIF), encoding="utf-8")

    report = _scan(scanner, _run_double({"returncode": 0}, None))

    assert report is None
    assert not stale.exists()


# --- dependencies -------------------------------------------------------------------


def test_a_trivy_refused_inside_the_scanned_tree_is_recorded_as_refused(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: None)
    monkeypatch.setattr(
        scanner_plugin,
        "in_tree_refusal",
        lambda command: f"a {command} inside the scanned tree was refused",
    )
    scanner = _scanner(tmp_path)

    assert scanner.validate_plugin_dependencies() is False
    assert scanner.dependency_unavailable_reason == (
        "a trivy inside the scanned tree was refused"
    )


def test_control_a_trivy_missing_from_path_records_no_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: None)
    monkeypatch.setattr(scanner_plugin, "in_tree_refusal", lambda command: None)
    scanner = _scanner(tmp_path)

    assert scanner.validate_plugin_dependencies() is False
    assert not scanner.dependency_unavailable_reason


def test_offline_without_a_database_trivy_repo_is_missing_with_the_reason(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")

    def no_db(ctx):
        raise ValueError("no trivy database was found")

    monkeypatch.setattr(staleness, "_built_from_trivy", no_db)
    scanner = _scanner(tmp_path, offline=True)

    assert scanner.validate_plugin_dependencies() is False
    assert "no vulnerability database" in scanner.dependency_unavailable_reason
    assert "no trivy database was found" in scanner.dependency_unavailable_reason


def test_control_offline_with_a_database_trivy_repo_is_satisfied(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")
    monkeypatch.setattr(staleness, "_built_from_trivy", lambda ctx: (None, "x"))

    assert _scanner(tmp_path, offline=True).validate_plugin_dependencies() is True


# --- the module_dir refusal ---------------------------------------------------------


def test_a_module_dir_that_is_not_a_directory_is_refused_by_key_alone(tmp_path):
    missing = tmp_path / "operator" / "zz-modules-not-here"
    scanner = _scanner(tmp_path, module_dir=str(missing))

    with pytest.raises(ScannerError) as raised:
        scanner._pinned_config_args()

    message = str(raised.value)
    assert "scanners.trivy-repo.options.module_dir" in message
    assert "zz-modules-not-here" not in message


# --- the default ignore_unfixed -----------------------------------------------------


def test_the_default_ignore_unfixed_says_once_what_it_withholds(tmp_path, caplog):
    """The default is true, unlike the builtin trivy scanner's, and the warning is
    given once per scanner, not once per target: ``_process_config_options`` runs
    from the scanner's construction, and trivy-repo's ``scan()`` does not run it
    again, so two scans add no line."""
    assert TrivyRepoScannerConfigOptions().ignore_unfixed is True

    with caplog.at_level("WARNING"):
        scanner = _scanner(tmp_path, ignore_unfixed=True)
        _scan(scanner, _run_double({"returncode": 0}, EMPTY_SARIF))
        _scan(scanner, _run_double({"returncode": 0}, EMPTY_SARIF))

    withheld = [m for m in caplog.messages if "ignore_unfixed" in m and "withheld" in m]
    assert len(withheld) == 1, caplog.messages


def test_control_ignore_unfixed_off_is_not_warned_about(tmp_path, caplog):
    with caplog.at_level("WARNING"):
        _scanner(tmp_path, ignore_unfixed=False)

    assert "ignore_unfixed" not in caplog.text


def test_the_ignore_unfixed_warning_says_whether_the_option_was_written(
    tmp_path, caplog
):
    """The warning said "(the default)" for an option the operator had set to true."""
    with caplog.at_level("WARNING"):
        _scanner(tmp_path, ignore_unfixed=True)

    (written,) = [m for m in caplog.messages if "ignore_unfixed" in m]
    assert "set in the configuration" in written
    assert "the default" not in written

    caplog.clear()
    with caplog.at_level("WARNING"):
        TrivyRepoScanner(
            context=_scanner(tmp_path).context, config=TrivyRepoScannerConfig()
        )

    (default,) = [m for m in caplog.messages if "ignore_unfixed" in m]
    assert "(the default)" in default
    assert "set in the configuration" not in default


def test_the_ignore_unfixed_warning_is_given_once_however_often_the_options_are_read(
    tmp_path, caplog
):
    """The builtin trivy scanner's scan() reads the options per target; the line
    is per scanner, as the construction-time test above has it per scan."""
    with caplog.at_level("WARNING"):
        scanner = _scanner(tmp_path, ignore_unfixed=True)
        scanner._process_config_options()
        scanner._process_config_options()

    withheld = [m for m in caplog.messages if "ignore_unfixed" in m and "withheld" in m]
    assert len(withheld) == 1, caplog.messages


# --- times ---------------------------------------------------------------------------


def test_a_scan_that_raises_records_its_own_end_time(tmp_path):
    scanner = _scanner(tmp_path)
    scanner.end_time = None

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_resolve_arguments", side_effect=RuntimeError("boom")),
    ):
        with pytest.raises(ScannerError, match="boom"):
            scanner.scan(target=Path(scanner.context.source_dir), target_type="source")

    assert scanner.end_time is not None


def test_the_catch_all_error_is_redacted(tmp_path):
    """The syft scanner's pin, for trivy-repo: an exception in the scan that quotes
    a value the scanner redacts (an OSError naming the TRIVY_SECRET_CONFIG or
    TRIVY_IGNOREFILE file) must not come out as is."""
    scanner = _scanner(tmp_path)

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_values_to_redact", return_value=("zz-secret-value",)),
        patch.object(
            scanner,
            "_resolve_arguments",
            side_effect=RuntimeError("cannot read zz-secret-value here"),
        ),
    ):
        with pytest.raises(ScannerError) as raised:
            scanner.scan(target=Path(scanner.context.source_dir), target_type="source")

    assert "Trivy scan failed" in str(raised.value)
    assert "zz-secret-value" not in str(raised.value)


def test_a_values_hook_that_raises_leaves_the_error_text_out(tmp_path):
    """With no usable answer from the hook nothing can be redacted, so the error
    carries the hook's failure and not the text, as the command record does."""
    scanner = _scanner(tmp_path)

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_values_to_redact", side_effect=KeyError("hook")),
        patch.object(
            scanner,
            "_resolve_arguments",
            side_effect=RuntimeError("cannot read zz-secret-value here"),
        ),
    ):
        with pytest.raises(ScannerError) as raised:
            scanner.scan(target=Path(scanner.context.source_dir), target_type="source")

    message = str(raised.value)
    assert "Trivy scan failed" in message
    assert "zz-secret-value" not in message
    assert "values hook" in message


def test_an_empty_target_does_not_keep_the_previous_targets_start_time(tmp_path):
    scanner = _scanner(tmp_path)
    scanner.start_time = datetime.now(timezone.utc)
    empty = tmp_path / "empty"
    empty.mkdir()

    with patch.object(scanner, "_post_scan"):
        assert scanner.scan(target=empty, target_type="converted") is True

    assert scanner.start_time is None
