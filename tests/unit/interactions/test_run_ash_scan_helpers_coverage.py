# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""run_ash_scan's per-mode helpers, config discovery, and exit-code derivation.

Why this file exists
--------------------
``run_ash_scan.py`` decides three things a caller cares about and nothing else
tells them: which config file was used, what the process will exit with, and --
in container mode -- whether a results file came back at all. The existing suite
covers the happy single-directory local path. What was untested is every branch
that only runs when something is off: a corrupt SARIF report on disk, a
container that exited non-zero, a results file that will not parse, a scan
restricted to changed files, precommit mode's scanner injection.

The exit-code contract these tests pin (``core/constants.ASH_EXIT_CODES``):
0 success, 1 scan errors, 2 actionable findings, 3 invalid config, 4 workspace
definition or policy error.

A note on assertions
--------------------
``sys.exit`` raises ``SystemExit``, which derives from ``BaseException`` and is
therefore *not* caught by ``pytest.raises(Exception)``. Every exit here is
asserted with ``pytest.raises(SystemExit)`` and an equality check on
``.value.code``, never a substring search for a digit -- a temp path can contain
any digit, so ``"2" in message`` proves nothing.

Doubles used here
-----------------
``_RecordingLogger`` and ``_StubOrchestrator`` implement only the members the
production code calls. A bare ``Mock`` would fabricate the rest, which would let
a call to a method that does not exist pass silently.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.enums import (
    AshLogLevel,
    ExecutionPhase,
    RunMode,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    _filter_results_to_changed_files,
    _print_summary,
    _resolve_config_fail_on_findings,
    _resolve_log_level,
    _run_container_mode,
    _run_local_mode,
    _severity_filters_finding,
    run_ash_scan,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.subprocess_utils import create_completed_process


# Rich styles its output with ANSI escapes, and it styles *inside* a phrase --
# "ERROR (1) Exiting" comes out with codes wrapped around each parenthesis and
# each digit. A substring search against the raw capture therefore fails on text
# that is on screen, so every assertion on rich output goes through _plain.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------


class _RecordingLogger:
    """Captures what the production code logged, per level.

    Only the six levels run_ash_scan uses are defined, including the custom
    ``verbose`` level ASH adds. A call to any other level is an AttributeError.
    """

    def __init__(self):
        self.records: Dict[str, List[str]] = {
            "verbose": [],
            "debug": [],
            "info": [],
            "warning": [],
            "error": [],
            "exception": [],
        }

    def verbose(self, message):
        self.records["verbose"].append(str(message))

    def debug(self, message):
        self.records["debug"].append(str(message))

    def info(self, message):
        self.records["info"].append(str(message))

    def warning(self, message):
        self.records["warning"].append(str(message))

    def error(self, message):
        self.records["error"].append(str(message))

    def exception(self, message):
        self.records["exception"].append(str(message))

    def all_messages(self) -> str:
        return "\n".join(
            message for messages in self.records.values() for message in messages
        )


class _StubOrchestrator:
    """Stands in for ASHScanOrchestrator: only .config and .execute_scan are read."""

    def __init__(self, results, config=None, raises: BaseException | None = None):
        self.config = config
        self._results = results
        self._raises = raises
        self.executed_phases: List[str] | None = None

    def execute_scan(self, phases):
        self.executed_phases = list(phases)
        if self._raises is not None:
            raise self._raises
        return self._results


@pytest.fixture
def logger() -> _RecordingLogger:
    return _RecordingLogger()


def _opts(source_dir: Path, output_dir: Path, **overrides: Any) -> ScanOptions:
    return ScanOptions(source_dir=source_dir, output_dir=output_dir, **overrides)


def _sarif_with_uris(*uris: str) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        {
                            "ruleId": "R1",
                            "level": "error",
                            "message": {"text": "fixture"},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                            ],
                        }
                        for uri in uris
                    ],
                }
            ],
        }
    )


# ---------------------------------------------------------------------------
# _severity_filters_finding
# ---------------------------------------------------------------------------


class TestSeverityFiltersFinding:
    def test_a_suppressed_finding_never_qualifies(self):
        """Suppression outranks severity: an error-level suppression is not actionable."""
        result = SimpleNamespace(suppressions=[{"kind": "external"}], level="error")
        assert _severity_filters_finding(result, 1) is False

    def test_an_error_qualifies_at_the_high_threshold(self):
        result = SimpleNamespace(suppressions=[], level="error")
        assert _severity_filters_finding(result, 3) is True

    def test_a_note_does_not_qualify_at_the_high_threshold(self):
        result = SimpleNamespace(suppressions=[], level="note")
        assert _severity_filters_finding(result, 3) is False


# ---------------------------------------------------------------------------
# _resolve_config_fail_on_findings
# ---------------------------------------------------------------------------


class TestResolveConfigFailOnFindings:
    def test_a_config_beside_the_source_is_discovered(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text(
            "project_name: discovered\nfail_on_findings: false\n", encoding="utf-8"
        )
        opts = _opts(tmp_path, tmp_path / "out")

        assert _resolve_config_fail_on_findings(opts) is False

    def test_a_config_under_the_dot_ash_directory_is_discovered(self, tmp_path):
        dot_ash = tmp_path / ".ash"
        dot_ash.mkdir()
        (dot_ash / "ash.yaml").write_text(
            "project_name: nested\nfail_on_findings: true\n", encoding="utf-8"
        )
        opts = _opts(tmp_path, tmp_path / "out")

        assert _resolve_config_fail_on_findings(opts) is True

    def test_no_config_yields_none_rather_than_a_default(self, tmp_path):
        """None means "the config did not say", which is not the same as False."""
        opts = _opts(tmp_path, tmp_path / "out")

        assert _resolve_config_fail_on_findings(opts) is None

    def test_an_explicit_config_path_skips_discovery(self, tmp_path):
        explicit = tmp_path / "custom.yaml"
        explicit.write_text(
            "project_name: explicit\nfail_on_findings: false\n", encoding="utf-8"
        )
        (tmp_path / ".ash.yaml").write_text(
            "project_name: ignored\nfail_on_findings: true\n", encoding="utf-8"
        )
        opts = _opts(tmp_path, tmp_path / "out", config=explicit.as_posix())

        assert _resolve_config_fail_on_findings(opts) is False


# ---------------------------------------------------------------------------
# _resolve_log_level
# ---------------------------------------------------------------------------


class TestResolveLogLevel:
    def test_verbose_wins_over_everything(self, tmp_path):
        opts = _opts(tmp_path, tmp_path / "out", verbose=True, debug=True, quiet=True)
        assert _resolve_log_level(opts) == AshLogLevel.VERBOSE

    def test_debug_wins_over_quiet(self, tmp_path):
        opts = _opts(tmp_path, tmp_path / "out", debug=True, quiet=True)
        assert _resolve_log_level(opts) == AshLogLevel.DEBUG

    def test_quiet_collapses_to_error(self, tmp_path):
        opts = _opts(tmp_path, tmp_path / "out", quiet=True)
        assert _resolve_log_level(opts) == AshLogLevel.ERROR

    def test_an_explicit_level_is_returned_unchanged(self, tmp_path):
        opts = _opts(tmp_path, tmp_path / "out", log_level=AshLogLevel.INFO)
        assert _resolve_log_level(opts) == AshLogLevel.INFO


# ---------------------------------------------------------------------------
# _run_container_mode
# ---------------------------------------------------------------------------


@pytest.fixture
def container_result(monkeypatch):
    """Install the CompletedProcess that run_ash_container will appear to return."""

    def install(returncode=0, stdout="", stderr=""):
        result = create_completed_process(
            args=["docker", "run"],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )
        monkeypatch.setattr(ras, "run_ash_container", lambda **kwargs: result)
        return result

    return install


class TestRunContainerModeChangedFiles:
    def test_changed_files_only_warns_and_scans_everything(
        self, container_result, logger, tmp_path, capsys
    ):
        """The container has no git history for the host's base ref."""
        container_result(returncode=0)
        results_file = tmp_path / "out" / "ash_aggregated_results.json"
        results_file.parent.mkdir(parents=True)
        results_file.write_text(
            AshAggregatedResults().model_dump_json(), encoding="utf-8"
        )
        opts = _opts(tmp_path, tmp_path / "out", changed_files_only=True)

        _run_container_mode(opts, logger)

        assert any(
            "--changed-files-only is not supported in container mode" in message
            for message in logger.records["warning"]
        )


class TestRunContainerModeBuildOnly:
    def test_build_only_exits_zero_on_success(self, container_result, logger, tmp_path):
        """With --no-run there is no results file, so the build status is the verdict."""
        container_result(returncode=0)
        opts = _opts(tmp_path, tmp_path / "out", run=False)

        with pytest.raises(SystemExit) as excinfo:
            _run_container_mode(opts, logger)

        assert excinfo.value.code == 0

    def test_build_only_propagates_the_container_return_code(
        self, container_result, logger, tmp_path, capsys
    ):
        container_result(returncode=125, stdout="build log", stderr="build broke")
        opts = _opts(tmp_path, tmp_path / "out", run=False, debug=True)

        with pytest.raises(SystemExit) as excinfo:
            _run_container_mode(opts, logger)

        assert excinfo.value.code == 125
        assert any(
            "Container execution failed with code 125" in message
            for message in logger.records["error"]
        )
        assert "build broke" in _plain(capsys.readouterr().out)


class TestRunContainerModeResultsFile:
    def test_a_valid_results_file_is_parsed_and_returned(
        self, container_result, logger, tmp_path
    ):
        container_result(returncode=0)
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        (output_dir / "ash_aggregated_results.json").write_text(
            AshAggregatedResults(
                additional_reports={"marker": "round-tripped"}
            ).model_dump_json(),
            encoding="utf-8",
        )
        opts = _opts(tmp_path, output_dir)

        results = _run_container_mode(opts, logger)

        assert isinstance(results, AshAggregatedResults)
        assert results.additional_reports["marker"] == "round-tripped"

    def test_an_unparseable_results_file_exits_one(
        self, container_result, logger, tmp_path
    ):
        container_result(returncode=0)
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        (output_dir / "ash_aggregated_results.json").write_text(
            "{ not valid json", encoding="utf-8"
        )
        opts = _opts(tmp_path, output_dir)

        with pytest.raises(SystemExit) as excinfo:
            _run_container_mode(opts, logger)

        assert excinfo.value.code == 1
        assert any(
            "Failed to parse results file" in message
            for message in logger.records["error"]
        )

    def test_a_missing_results_file_exits_one(self, container_result, logger, tmp_path):
        """The container reported success but wrote nothing; that is a scan error."""
        container_result(returncode=0)
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        opts = _opts(tmp_path, output_dir)

        with pytest.raises(SystemExit) as excinfo:
            _run_container_mode(opts, logger)

        assert excinfo.value.code == 1
        assert any(
            "Results file not found at" in message
            for message in logger.records["error"]
        )

    def test_debug_reports_the_container_command_and_stream_sizes(
        self, container_result, logger, tmp_path, capsys
    ):
        container_result(returncode=0, stdout="abcde")
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        (output_dir / "ash_aggregated_results.json").write_text(
            AshAggregatedResults().model_dump_json(), encoding="utf-8"
        )
        opts = _opts(tmp_path, output_dir, debug=True)

        _run_container_mode(opts, logger)

        out = _plain(capsys.readouterr().out)
        assert "Debug: Container Command" in out
        assert "Stdout length: 5" in out


# ---------------------------------------------------------------------------
# _run_local_mode
# ---------------------------------------------------------------------------


@pytest.fixture
def local_orchestrator(monkeypatch):
    """Replace ASHScanOrchestrator.create and record the kwargs it was handed."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    recorded: Dict[str, Any] = {"create_kwargs": [], "orchestrator": None}

    def install(results=None, config=None, raises: BaseException | None = None):
        orchestrator = _StubOrchestrator(results, config=config, raises=raises)
        recorded["orchestrator"] = orchestrator

        def fake_create(**kwargs):
            recorded["create_kwargs"].append(kwargs)
            return orchestrator

        monkeypatch.setattr(ASHScanOrchestrator, "create", staticmethod(fake_create))
        return recorded

    return install


class TestRunLocalModeConfigDiscovery:
    def test_a_discovered_config_is_passed_to_the_orchestrator(
        self, local_orchestrator, logger, tmp_path
    ):
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: discovered\n", encoding="utf-8")
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(results=AshAggregatedResults())
        opts = _opts(tmp_path, output_dir)

        _run_local_mode(opts, logger)

        assert recorded["create_kwargs"][0]["config_path"] == config_file.as_posix()
        assert any(
            "Using config file found at" in message
            for message in logger.records["info"]
        )

    def test_config_overrides_are_announced_and_forwarded(
        self, local_orchestrator, logger, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(results=AshAggregatedResults())
        opts = _opts(
            tmp_path, output_dir, config_overrides=["global_settings.x=1", "y=2"]
        )

        _run_local_mode(opts, logger)

        assert recorded["create_kwargs"][0]["config_overrides"] == [
            "global_settings.x=1",
            "y=2",
        ]
        assert any(
            "Applying 2 configuration overrides" in message
            for message in logger.records["info"]
        )


class TestRunLocalModePrecommit:
    def test_precommit_adds_the_fast_scanner_set(
        self, local_orchestrator, logger, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(results=AshAggregatedResults())
        opts = _opts(tmp_path, output_dir, mode=RunMode.precommit, scanners=["grype"])

        _run_local_mode(opts, logger)

        enabled = set(recorded["create_kwargs"][0]["enabled_scanners"])
        assert {
            "bandit",
            "detect-secrets",
            "checkov",
            "cdk-nag",
            "npm-audit",
            "grype",
        } <= enabled

    def test_local_mode_does_not_add_the_fast_scanner_set(
        self, local_orchestrator, logger, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(results=AshAggregatedResults())
        opts = _opts(tmp_path, output_dir, mode=RunMode.local, scanners=["grype"])

        _run_local_mode(opts, logger)

        assert recorded["create_kwargs"][0]["enabled_scanners"] == ["grype"]


class TestRunLocalModePhases:
    def test_an_empty_phase_list_falls_back_to_the_standard_three(
        self, local_orchestrator, logger, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(results=AshAggregatedResults())
        opts = _opts(tmp_path, output_dir, phases=[])

        _run_local_mode(opts, logger)

        assert recorded["orchestrator"].executed_phases == [
            "convert",
            "scan",
            "report",
        ]

    def test_inspect_is_appended_when_requested_by_flag(
        self, local_orchestrator, logger, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(results=AshAggregatedResults())
        opts = _opts(tmp_path, output_dir, phases=[ExecutionPhase.SCAN], inspect=True)

        _run_local_mode(opts, logger)

        assert recorded["orchestrator"].executed_phases == ["scan", "inspect"]


class TestRunLocalModeChangedFiles:
    def test_results_and_the_sarif_report_are_both_narrowed(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """Filtering only the in-memory model would leave a stale report on disk."""
        from automated_security_helper.utils import get_scan_set

        monkeypatch.setattr(
            get_scan_set, "get_changed_files", lambda base_ref, cwd: ["changed.py"]
        )
        output_dir = tmp_path / "out"
        (output_dir / "reports").mkdir(parents=True)
        sarif_path = output_dir / "reports" / "ash.sarif"
        sarif_path.write_text("stale placeholder", encoding="utf-8")

        results = AshAggregatedResults(
            sarif=_sarif_with_uris("changed.py", "untouched.py")
        )
        local_orchestrator(results=results)
        opts = _opts(tmp_path, output_dir, changed_files_only=True)

        returned, _ = _run_local_mode(opts, logger)

        uris = [
            result.locations[0].physicalLocation.root.artifactLocation.uri
            for result in returned.sarif.runs[0].results
        ]
        assert uris == ["changed.py"]

        rewritten = sarif_path.read_text(encoding="utf-8")
        assert "changed.py" in rewritten
        assert "untouched.py" not in rewritten

    def test_no_changed_files_leaves_the_results_alone(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """git returning None means "scan everything", not "scan nothing"."""
        from automated_security_helper.utils import get_scan_set

        monkeypatch.setattr(
            get_scan_set, "get_changed_files", lambda base_ref, cwd: None
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        results = AshAggregatedResults(
            sarif=_sarif_with_uris("changed.py", "untouched.py")
        )
        local_orchestrator(results=results)
        opts = _opts(tmp_path, output_dir, changed_files_only=True)

        returned, _ = _run_local_mode(opts, logger)

        assert len(returned.sarif.runs[0].results) == 2


class TestRunLocalModeResultPersistence:
    def test_the_aggregated_results_are_written_to_the_output_dir(
        self, local_orchestrator, logger, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(
            results=AshAggregatedResults(additional_reports={"marker": "written"})
        )
        opts = _opts(tmp_path, output_dir)

        _run_local_mode(opts, logger)

        written = json.loads(
            (output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
        )
        assert written["additional_reports"]["marker"] == "written"

    def test_a_non_model_result_is_serialised_as_plain_json(
        self, local_orchestrator, logger, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(results={"plain": "dict"})
        opts = _opts(tmp_path, output_dir)

        _run_local_mode(opts, logger)

        written = json.loads(
            (output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
        )
        assert written == {"plain": "dict"}

    def test_the_orchestrator_config_fail_on_findings_is_returned(
        self, local_orchestrator, logger, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(
            results=AshAggregatedResults(),
            config=SimpleNamespace(fail_on_findings=False),
        )
        opts = _opts(tmp_path, output_dir)

        _, config_fail_on_findings = _run_local_mode(opts, logger)

        assert config_fail_on_findings is False


class TestRunLocalModeFailure:
    def test_an_unexpected_error_exits_one(
        self, local_orchestrator, logger, tmp_path, capsys
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(raises=RuntimeError("scanner exploded"))
        opts = _opts(tmp_path, output_dir)

        with pytest.raises(SystemExit) as excinfo:
            _run_local_mode(opts, logger)

        assert excinfo.value.code == 1
        assert logger.records["exception"], "the traceback should have been logged"
        assert "ERROR (1) Exiting due to exception" in _plain(capsys.readouterr().out)

    def test_an_invalid_config_exits_three(
        self, local_orchestrator, logger, tmp_path, capsys
    ):
        from automated_security_helper.core.exceptions import (
            ASHConfigValidationError,
        )

        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(raises=ASHConfigValidationError("bad threshold"))
        opts = _opts(tmp_path, output_dir)

        with pytest.raises(SystemExit) as excinfo:
            _run_local_mode(opts, logger)

        assert excinfo.value.code == 3
        assert "ERROR (3) Invalid configuration" in _plain(capsys.readouterr().out)

    def test_the_offline_env_var_is_removed_even_when_the_scan_fails(
        self, local_orchestrator, logger, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(raises=RuntimeError("scanner exploded"))
        opts = _opts(tmp_path, output_dir, offline=True)

        with pytest.raises(SystemExit):
            _run_local_mode(opts, logger)

        assert "ASH_OFFLINE" not in os.environ


# ---------------------------------------------------------------------------
# _compute_exit_code
# ---------------------------------------------------------------------------


@pytest.fixture
def unified_metrics(monkeypatch):
    """Fix what get_unified_scanner_metrics reports, so counts are deterministic."""

    def install(actionable: int):
        metrics = [SimpleNamespace(actionable=actionable)]
        monkeypatch.setattr(
            ras, "get_unified_scanner_metrics", lambda asharp_model: metrics
        )
        return metrics

    return install


class TestComputeExitCodeNoResults:
    def test_no_results_is_a_scan_error_not_a_clean_pass(self, tmp_path):
        opts = _opts(tmp_path, tmp_path / "out")
        assert _compute_exit_code(None, opts) == 1


class TestComputeExitCodeFailOnFindings:
    def test_fail_on_findings_off_returns_zero_despite_findings(
        self, unified_metrics, tmp_path
    ):
        unified_metrics(9)
        opts = _opts(tmp_path, tmp_path / "out", fail_on_findings=False)

        assert _compute_exit_code(AshAggregatedResults(), opts) == 0

    def test_the_cli_value_outranks_the_config_value(self, unified_metrics, tmp_path):
        unified_metrics(9)
        opts = _opts(tmp_path, tmp_path / "out", fail_on_findings=False)

        assert (
            _compute_exit_code(
                AshAggregatedResults(), opts, config_fail_on_findings=True
            )
            == 0
        )

    def test_the_config_value_is_used_when_the_cli_is_silent(
        self, unified_metrics, tmp_path
    ):
        unified_metrics(9)
        opts = _opts(tmp_path, tmp_path / "out", fail_on_findings=None)

        assert (
            _compute_exit_code(
                AshAggregatedResults(), opts, config_fail_on_findings=False
            )
            == 0
        )


class TestComputeExitCodeCorruptSarif:
    def test_an_unreadable_sarif_report_falls_back_to_the_unified_metrics(
        self, unified_metrics, tmp_path
    ):
        """A corrupt report on disk must not silently zero the finding count.

        min_severity is "none" here so the later severity filter is skipped
        entirely: a default AshAggregatedResults carries one SARIF run with no
        results, which that filter reads as "nothing qualifies" and would zero
        the count for a reason unrelated to the corrupt file.
        """
        unified_metrics(3)
        output_dir = tmp_path / "out"
        (output_dir / "reports").mkdir(parents=True)
        (output_dir / "reports" / "ash.sarif").write_text(
            "{ truncated", encoding="utf-8"
        )
        opts = _opts(tmp_path, output_dir, min_severity="none")

        assert _compute_exit_code(AshAggregatedResults(), opts) == 2

    def test_a_readable_sarif_report_overrides_the_unified_metrics(
        self, unified_metrics, tmp_path
    ):
        """The persisted report is authoritative: it serialises every suppression."""
        unified_metrics(3)
        output_dir = tmp_path / "out"
        (output_dir / "reports").mkdir(parents=True)
        (output_dir / "reports" / "ash.sarif").write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "results": [
                                {"level": "error", "suppressions": [{"kind": "x"}]},
                                {"level": "note"},
                            ]
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        opts = _opts(tmp_path, output_dir, min_severity="none")

        # One finding is suppressed and the other is a note, which is below the
        # default MEDIUM threshold, so nothing is actionable.
        assert _compute_exit_code(AshAggregatedResults(), opts) == 0


class TestComputeExitCodeMinSeverity:
    def test_nothing_at_or_above_min_severity_clears_the_finding_count(
        self, unified_metrics, tmp_path
    ):
        """Every finding is suppressed, so none of them qualifies."""
        unified_metrics(3)
        results = SimpleNamespace(
            ash_config=None,
            sarif=SimpleNamespace(
                runs=[
                    SimpleNamespace(
                        results=[
                            SimpleNamespace(
                                suppressions=[{"kind": "external"}], level="error"
                            )
                        ]
                    )
                ]
            ),
        )
        opts = _opts(tmp_path, tmp_path / "out", min_severity="low")

        assert _compute_exit_code(results, opts) == 0

    def test_an_unreadable_sarif_model_fails_open_and_keeps_the_findings(
        self, unified_metrics, tmp_path
    ):
        """A result missing the fields the filter reads must not zero the count."""
        unified_metrics(3)
        results = SimpleNamespace(
            ash_config=None,
            sarif=SimpleNamespace(runs=[SimpleNamespace(results=[object()])]),
        )
        opts = _opts(tmp_path, tmp_path / "out", min_severity="low")

        assert _compute_exit_code(results, opts) == 2

    def test_a_qualifying_finding_keeps_the_exit_code_at_two(
        self, unified_metrics, tmp_path
    ):
        unified_metrics(3)
        results = SimpleNamespace(
            ash_config=None,
            sarif=SimpleNamespace(
                runs=[
                    SimpleNamespace(
                        results=[SimpleNamespace(suppressions=[], level="error")]
                    )
                ]
            ),
        )
        opts = _opts(tmp_path, tmp_path / "out", min_severity="high")

        assert _compute_exit_code(results, opts) == 2


# ---------------------------------------------------------------------------
# _print_summary
# ---------------------------------------------------------------------------


class TestPrintSummary:
    def test_config_warnings_are_surfaced_above_the_next_steps(self, tmp_path, capsys):
        results = SimpleNamespace(
            validation_checkpoints=[
                {"type": "config_warning", "message": "scanner-x is unknown"},
                {"type": "other", "message": "not a warning"},
            ]
        )
        opts = _opts(tmp_path, tmp_path / "out")

        _print_summary(results, opts, time.time(), actionable_findings=0)

        out = _plain(capsys.readouterr().out)
        assert "CONFIGURATION WARNING" in out
        assert "scanner-x is unknown" in out
        assert "not a warning" not in out

    def test_quiet_suppresses_the_next_steps_but_not_the_findings_notice(
        self, tmp_path, capsys
    ):
        opts = _opts(tmp_path, tmp_path / "out", quiet=True)

        _print_summary(None, opts, time.time(), actionable_findings=4)

        out = _plain(capsys.readouterr().out)
        assert "Next Steps" not in out
        assert "Actionable findings detected" in out

    def test_no_findings_means_no_investigation_block(self, tmp_path, capsys):
        opts = _opts(tmp_path, tmp_path / "out")

        _print_summary(None, opts, time.time(), actionable_findings=0)

        out = _plain(capsys.readouterr().out)
        assert "Next Steps" in out
        assert "Actionable findings detected" not in out


# ---------------------------------------------------------------------------
# _filter_results_to_changed_files
# ---------------------------------------------------------------------------


class TestFilterResultsToChangedFiles:
    def test_a_finding_with_no_physical_location_is_always_kept(self, tmp_path):
        """An unlocatable finding cannot be shown to be outside the change set."""
        results = AshAggregatedResults(
            sarif=SarifReport.model_validate(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "ASH"}},
                            "results": [
                                {
                                    "ruleId": "R1",
                                    "level": "error",
                                    "message": {"text": "no location"},
                                    "locations": [{"id": 0}],
                                }
                            ],
                        }
                    ],
                }
            )
        )

        filtered = _filter_results_to_changed_files(results, set(), tmp_path)

        assert len(filtered.sarif.runs[0].results) == 1

    def test_a_finding_with_no_locations_at_all_is_kept(self, tmp_path):
        results = AshAggregatedResults(
            sarif=SarifReport.model_validate(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "ASH"}},
                            "results": [
                                {
                                    "ruleId": "R1",
                                    "level": "error",
                                    "message": {"text": "project-wide"},
                                }
                            ],
                        }
                    ],
                }
            )
        )

        filtered = _filter_results_to_changed_files(results, set(), tmp_path)

        assert len(filtered.sarif.runs[0].results) == 1

    def test_a_file_uri_is_normalised_before_comparison(self, tmp_path):
        changed = tmp_path / "changed.py"
        changed.write_text("x = 1\n", encoding="utf-8")
        results = AshAggregatedResults(
            sarif=_sarif_with_uris("file://" + changed.as_posix(), "untouched.py")
        )

        filtered = _filter_results_to_changed_files(
            results, {changed.resolve()}, tmp_path
        )

        uris = [
            result.locations[0].physicalLocation.root.artifactLocation.uri
            for result in filtered.sarif.runs[0].results
        ]
        assert uris == ["file://" + changed.as_posix()]

    def test_results_without_sarif_runs_are_returned_untouched(self, tmp_path):
        results = AshAggregatedResults()
        assert _filter_results_to_changed_files(results, set(), tmp_path) is results


# ---------------------------------------------------------------------------
# run_ash_scan -- the exit-code-1 announcement
# ---------------------------------------------------------------------------


class TestRunAshScanScanErrorExit:
    def test_a_scan_that_produced_no_results_announces_and_exits_one(
        self, monkeypatch, tmp_path, capsys
    ):
        """_compute_exit_code returns 1 for None results; run_ash_scan must say so."""
        monkeypatch.setattr(ras, "_setup_logger", lambda opts: _RecordingLogger())
        monkeypatch.setattr(ras, "_run_local_mode", lambda opts, logger: (None, None))

        with pytest.raises(SystemExit) as excinfo:
            run_ash_scan(
                source_dir=tmp_path,
                output_dir=tmp_path / "out",
                mode=RunMode.local,
                show_summary=True,
            )

        assert excinfo.value.code == 1
        assert "ERROR (1) Exiting due to exception" in _plain(capsys.readouterr().out)
