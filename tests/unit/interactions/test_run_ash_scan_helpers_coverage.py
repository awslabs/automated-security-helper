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
0 success, 1 scan errors, 2 actionable findings, 3 invalid config or refused input,
4 workspace definition or policy error.

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
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.enums import (
    AshLogLevel,
    ExecutionPhase,
    RunMode,
    ScannerStatus,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.changed_files import (
    filter_results_to_changed_files,
)
from automated_security_helper.interactions.run_ash_scan import (
    PRECOMMIT_MODE_SCANNERS,
    ScanOptions,
    _compute_exit_code,
    _print_summary,
    _resolve_config_fail_on_findings,
    _resolve_log_level,
    _run_container_mode,
    _run_local_mode,
    _severity_filters_finding,
    run_ash_scan,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.utils.helpers import sarif_report_written
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.utils.env_assertions import environ_names


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

    Each method accepts and discards ``**kwargs`` because ``logging.Logger`` does
    too, and production code passes ``extra=NO_MARKUP`` on the messages that carry
    subprocess output. Recording only the message keeps the assertions unchanged;
    rejecting the keyword would make this double stricter than the thing it
    stands in for.
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

    def verbose(self, message, **kwargs):
        self.records["verbose"].append(str(message))

    def debug(self, message, **kwargs):
        self.records["debug"].append(str(message))

    def info(self, message, **kwargs):
        self.records["info"].append(str(message))

    def warning(self, message, **kwargs):
        self.records["warning"].append(str(message))

    def error(self, message, **kwargs):
        # An error logged with its traceback is recorded as logger.exception's.
        key = "exception" if kwargs.get("exc_info") else "error"
        self.records[key].append(str(message))

    def exception(self, message, **kwargs):
        self.records["exception"].append(str(message))

    def all_messages(self) -> str:
        return "\n".join(
            message for messages in self.records.values() for message in messages
        )


class _StubOrchestrator:
    """Stands in for ASHScanOrchestrator: .config, .add_metadata,
    .restrict_to_changed_files and .execute_scan."""

    def __init__(self, results, config=None, raises: BaseException | None = None):
        self.config = config
        self._results = results
        self._raises = raises
        self.executed_phases: List[str] | None = None
        self.added_metadata: Dict[str, Any] = {}
        self.changed_files = None

    def add_metadata(self, **values):
        self.added_metadata.update(values)

    def restrict_to_changed_files(self, changed_files):
        self.changed_files = changed_files

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


@pytest.mark.unit
class TestSeverityFiltersFinding:
    """``properties=None`` is on every stand-in because the real SARIF ``Result``
    always carries the field, and the severity resolver now reads it -- a stand-in
    without it was modelling a shape that cannot reach this function."""

    def test_a_suppressed_finding_never_qualifies(self):
        """Suppression outranks severity: an error-level suppression is not actionable."""
        result = SimpleNamespace(
            suppressions=[{"kind": "external"}], level="error", properties=None
        )
        assert _severity_filters_finding(result, 1) is False

    def test_an_error_qualifies_at_the_high_threshold(self):
        result = SimpleNamespace(suppressions=[], level="error", properties=None)
        assert _severity_filters_finding(result, 3) is True

    def test_a_note_does_not_qualify_at_the_high_threshold(self):
        result = SimpleNamespace(suppressions=[], level="note", properties=None)
        assert _severity_filters_finding(result, 3) is False


# ---------------------------------------------------------------------------
# _resolve_config_fail_on_findings
# ---------------------------------------------------------------------------


@pytest.mark.unit
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


@pytest.mark.unit
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
    """Install the CompletedProcess that run_ash_container will appear to return.

    ``results_content`` is written to ``<output_dir>/ash_aggregated_results.json`` while
    the fake container "runs". It has to be written there rather than by the test before
    the call, because ``_run_container_mode`` now removes any results file that predates
    the invocation -- a pre-seeded file is exactly what a previous run leaves behind, and
    the whole point of the removal is that the two cannot be told apart afterwards.
    The file then gets the completion marker the in-container run writes, as that run
    would (utils/inner_run_outcome.py).
    """
    from tests.utils.helpers import mark_inner_run_completed

    def install(returncode=0, stdout="", stderr="", results_content=None):
        result = create_completed_process(
            args=["docker", "run"],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

        def fake_run_ash_container(**kwargs):
            if results_content is not None:
                output_dir = Path(kwargs["output_dir"])
                output_dir.mkdir(parents=True, exist_ok=True)
                results_file = output_dir.joinpath("ash_aggregated_results.json")
                results_file.write_text(results_content, encoding="utf-8")
                # A file that does not parse stays as written.
                mark_inner_run_completed(results_file, kwargs["outer_run_id"])
            return result

        monkeypatch.setattr(ras, "run_ash_container", fake_run_ash_container)
        return result

    return install


@pytest.mark.unit
class TestRunContainerModeChangedFiles:
    def test_changed_files_only_warns_and_scans_everything(
        self, container_result, logger, tmp_path, capsys
    ):
        """The container has no git history for the host's base ref."""
        container_result(
            returncode=0, results_content=AshAggregatedResults().model_dump_json()
        )
        opts = _opts(tmp_path, tmp_path / "out", changed_files_only=True)

        _run_container_mode(opts, logger)

        assert any(
            "--changed-files-only is not supported in container mode" in message
            for message in logger.records["warning"]
        )


@pytest.mark.unit
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


@pytest.mark.unit
class TestRunContainerModeResultsFile:
    def test_a_valid_results_file_is_parsed_and_returned(
        self, container_result, logger, tmp_path
    ):
        container_result(
            returncode=0,
            results_content=AshAggregatedResults(
                additional_reports={"marker": "round-tripped"}
            ).model_dump_json(),
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        opts = _opts(tmp_path, output_dir)

        results = _run_container_mode(opts, logger)

        assert isinstance(results, AshAggregatedResults)
        assert results.additional_reports["marker"] == "round-tripped"

    def test_an_unparseable_results_file_exits_one(
        self, container_result, logger, tmp_path
    ):
        container_result(returncode=0, results_content="{ not valid json")
        output_dir = tmp_path / "out"
        output_dir.mkdir()
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
        container_result(
            returncode=0,
            stdout="abcde",
            results_content=AshAggregatedResults().model_dump_json(),
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()
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


@pytest.mark.unit
class TestRunLocalModeConfigDiscovery:
    def test_discovery_is_left_to_the_orchestrators_resolution(
        self, local_orchestrator, logger, tmp_path
    ):
        """No second discovery here: the resolution that loads the file finds it.

        run_ash_scan does not discover the file itself, pass its path on and log
        "Using config file found at" before anything has read it.
        """
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: discovered\n", encoding="utf-8")
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(results=AshAggregatedResults())
        opts = _opts(tmp_path, output_dir)

        _run_local_mode(opts, logger)

        assert recorded["create_kwargs"][0]["config_path"] is None
        assert not any(
            "config" in message.lower() and "using" in message.lower()
            for message in logger.records["info"]
        ), logger.records["info"]

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


@pytest.mark.unit
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
        # Equal, not a superset: .pre-commit-hooks.yaml is checked against
        # PRECOMMIT_MODE_SCANNERS (tests/unit/test_pre_commit_hooks_manifest.py),
        # so the preset must add exactly that list and nothing beside it.
        assert enabled == set(PRECOMMIT_MODE_SCANNERS) | {"grype"}
        assert set(PRECOMMIT_MODE_SCANNERS) == {
            "bandit",
            "detect-secrets",
            "checkov",
            "cdk-nag",
            "npm-audit",
        }

    def test_local_mode_does_not_add_the_fast_scanner_set(
        self, local_orchestrator, logger, tmp_path
    ):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(results=AshAggregatedResults())
        opts = _opts(tmp_path, output_dir, mode=RunMode.local, scanners=["grype"])

        _run_local_mode(opts, logger)

        assert recorded["create_kwargs"][0]["enabled_scanners"] == ["grype"]


@pytest.mark.unit
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


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(  # nosec B603 B607 -- list args, no shell, fixture repo only
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _commit_base_then_change(repo: Path, changed: Path) -> None:
    """A throwaway repository with a ``base-ref`` branch and one change on top."""
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "branch", "-f", "base-ref")
    changed.write_text("print('changed')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")


@pytest.fixture
def git_available() -> bool:
    probe = subprocess.run(  # nosec B603 B607 -- probing for git on PATH
        ["git", "--version"], capture_output=True, text=True, check=False, timeout=30
    )
    return probe.returncode == 0


@pytest.mark.integration
class TestRunLocalModeChangedFiles:
    """What run_ash_scan computes for --changed-files-only and hands the engine.

    run_ash_scan resolves the changed-file set; the scan engine filters the
    results with it before the summary counts and the reports are written
    (test_changed_files_only_narrows_every_report.py covers that end to end).
    These tests pin the set and the metadata handed to the orchestrator, and,
    where the point is which findings survive, apply the same filter to the set.
    """

    @pytest.fixture(autouse=True)
    def _git_stops_at_tmp(self, tmp_path, monkeypatch):
        """tmp_path is the top git and the nesting walk see.

        These cells pin scan_source for repositories they build under
        tmp_path, so an ancestor of the basetemp -- a developer checkout
        that ignores it, say -- must not relabel them
        (tests/utils/git_isolation.py)."""
        from tests.utils.git_isolation import isolate_git_at

        isolate_git_at(tmp_path, monkeypatch)

    @staticmethod
    def _repository_root(tmp_path: Path):
        from tests.utils.git_isolation import excluding_repository_at

        return excluding_repository_at(tmp_path / "root")

    @staticmethod
    def _handed(recorded):
        """The changed-file set and the metadata local mode gave the orchestrator.

        Both after ``create`` returned (restrict_to_changed_files, add_metadata),
        never to ``create`` itself: working them out starts git, and ``create`` is
        where a command line ASH refuses stops.
        """
        kwargs = recorded["create_kwargs"][0]
        assert "changed_files" not in kwargs and "metadata" not in kwargs, kwargs
        orchestrator = recorded["orchestrator"]
        return orchestrator.changed_files, orchestrator.added_metadata

    def test_the_diff_is_anchored_on_the_repository_root(
        self, local_orchestrator, logger, tmp_path, git_available
    ):
        """A source dir below the repository root is the geometry that broke.

        ``git diff --name-only`` prints repository-root-relative paths whatever
        directory it ran in, so a change to ``services/api/app.py`` arrives as
        that string even when git ran in ``<repo>/services/api``. Joining it onto
        the source dir yielded ``<repo>/services/api/services/api/app.py``, while
        ``filter_results_to_changed_files`` resolves the SARIF side's
        source-relative ``app.py`` to ``<repo>/services/api/app.py``. The two sets
        could not intersect, so the filter dropped every finding.
        """
        if not git_available:
            pytest.skip("git is not available on PATH")

        repo = tmp_path / "repo"
        source_dir = repo / "services" / "api"
        source_dir.mkdir(parents=True)
        (source_dir / "app.py").write_text("print('a')\n", encoding="utf-8")
        (source_dir / "untouched.py").write_text("print('u')\n", encoding="utf-8")
        _commit_base_then_change(repo, source_dir / "app.py")

        output_dir = tmp_path / "out"
        (output_dir / "reports").mkdir(parents=True)
        results = AshAggregatedResults(sarif=_sarif_with_uris("app.py", "untouched.py"))
        recorded = local_orchestrator(results=results)
        opts = _opts(
            source_dir, output_dir, changed_files_only=True, base_ref="base-ref"
        )

        _run_local_mode(opts, logger)

        changed, metadata = self._handed(recorded)
        assert changed == {(source_dir / "app.py").resolve()}
        assert metadata == {"changed_files_only": True, "scan_source": "services/api"}
        filtered = filter_results_to_changed_files(results, changed, source_dir)
        uris = [
            result.locations[0].physicalLocation.root.artifactLocation.uri
            for result in filtered.sarif.runs[0].results
        ]
        assert uris == ["app.py"]

    def test_a_diff_outside_the_source_dir_reports_nothing(
        self, local_orchestrator, logger, tmp_path, git_available
    ):
        """An empty changed set reports nothing, because that is what was asked.

        A change to ``<repo>/docs/README.md`` is outside a source dir of
        ``<repo>/services/api``, so the changed set is empty. ``--changed-files-only``
        is a request to scope to the diff, and nothing in the diff is in scope, so
        the honest answer is an empty report -- not the whole subtree, which would
        be ignoring the flag the operator passed. An empty set is therefore a
        filter that matches nothing, distinct from ``None``, which means git could
        not answer and the documented fallback is a full scan.

        The empty set is handed to the engine as such, and run_ash_scan does not
        rewrite ``ash.sarif`` after the report phase: the reports are written
        once, already filtered.
        """
        if not git_available:
            pytest.skip("git is not available on PATH")

        repo = tmp_path / "repo"
        source_dir = repo / "services" / "api"
        source_dir.mkdir(parents=True)
        (source_dir / "app.py").write_text("print('a')\n", encoding="utf-8")
        docs = repo / "docs"
        docs.mkdir()
        (docs / "README.md").write_text("base\n", encoding="utf-8")
        _commit_base_then_change(repo, docs / "README.md")

        output_dir = tmp_path / "out"
        (output_dir / "reports").mkdir(parents=True)
        sarif_path = output_dir / "reports" / "ash.sarif"
        sarif_path.write_text("stale placeholder", encoding="utf-8")
        results = AshAggregatedResults(sarif=_sarif_with_uris("app.py"))
        recorded = local_orchestrator(results=results)
        opts = _opts(
            source_dir, output_dir, changed_files_only=True, base_ref="base-ref"
        )

        _run_local_mode(opts, logger)

        changed, metadata = self._handed(recorded)
        assert changed == set()
        assert metadata == {"changed_files_only": True, "scan_source": "services/api"}
        filtered = filter_results_to_changed_files(results, changed, source_dir)
        assert filtered.sarif.runs[0].results == []
        assert sarif_path.read_text(encoding="utf-8") == "stale placeholder"

    def test_a_finding_outside_the_source_dir_is_not_revived_by_the_diff(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """Pins what dropping out-of-tree diff entries buys, now that it is subtle.

        ``--source-dir`` and ``--changed-files-only`` are two scopings and the
        operator asked for both, so the reported set is their intersection. A
        scanner that escapes the scan root -- a ``../`` URI that
        ``sanitize_sarif_paths`` did not make source-relative -- must not be
        reported just because its file is in the diff.

        Without the source-dir narrowing this is the one input whose outcome
        differs: the changed set would carry ``<repo>/docs/README.md`` and the
        escaping URI would resolve onto it and be kept. Every other input reaches
        the same answer either way, which is why this test exists rather than a
        more natural one.

        The URI needs both ``..`` segments, and an earlier draft with one was a
        test that could not fail for its own condition: from
        ``<repo>/services/api``, ``../docs/README.md`` resolves to
        ``<repo>/services/docs/README.md``, which is in neither set, so it passed
        whether or not the narrowing was there. The mutation control is what
        caught that.
        """
        from automated_security_helper.utils import get_scan_set

        repo = tmp_path / "repo"
        source_dir = repo / "services" / "api"
        source_dir.mkdir(parents=True)
        (repo / "docs").mkdir()
        monkeypatch.setattr(
            get_scan_set,
            "get_changed_files",
            lambda base_ref, cwd: [Path("docs/README.md")],
        )
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: repo
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        results = AshAggregatedResults(sarif=_sarif_with_uris("../../docs/README.md"))
        recorded = local_orchestrator(results=results)
        opts = _opts(source_dir, output_dir, changed_files_only=True)

        _run_local_mode(opts, logger)

        changed, _ = self._handed(recorded)
        assert changed == set()
        filtered = filter_results_to_changed_files(results, changed, source_dir)
        assert filtered.sarif.runs[0].results == []

    def test_an_unknown_repository_root_scans_everything(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """The root is the only anchor, so without it the gate must not guess.

        Reachable when ``git rev-parse --show-toplevel`` times out while the diff
        itself succeeded. Joining onto the source dir instead is the mis-join this
        class of defect is made of, and it silently reports nothing.
        """
        from automated_security_helper.utils import get_scan_set

        monkeypatch.setattr(
            get_scan_set, "get_changed_files", lambda base_ref, cwd: [Path("app.py")]
        )
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: None
        )
        # The warning carries the diagnosed cause, whatever it is; pinned here so
        # the test does not depend on whether tmp_path sits inside a repository.
        monkeypatch.setattr(
            get_scan_set,
            "git_repository_root_problem",
            lambda path, **kwargs: f"{path.as_posix()} is not inside a git repository",
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(
            results=AshAggregatedResults(
                sarif=_sarif_with_uris("app.py", "untouched.py")
            )
        )
        opts = _opts(tmp_path, output_dir, changed_files_only=True)

        returned, _ = _run_local_mode(opts, logger)

        # No changed set; the marker is still written, as an explicit False, so a
        # full scan is told apart from results that predate the marker. With no
        # repository root, scan_source is the scanned directory's own path.
        assert self._handed(recorded) == (
            None,
            {
                "changed_files_only": False,
                "scan_source": tmp_path.resolve().as_posix(),
            },
        )
        assert len(returned.sarif.runs[0].results) == 2
        assert any(
            "not inside a git repository" in message
            for message in logger.records["warning"]
        )

    def test_a_problem_with_rich_markup_in_it_is_printed_verbatim(
        self, local_orchestrator, monkeypatch, tmp_path
    ):
        """git's own first stderr line, or a path, may read as a closing Rich tag."""
        import io

        from rich.console import Console
        from rich.logging import RichHandler

        from automated_security_helper.utils import get_scan_set
        from automated_security_helper.utils.log import ASH_LOGGER

        problem = "git could not read the repository root of /src/a[/x] (fatal: [/x])"
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: None
        )
        monkeypatch.setattr(
            get_scan_set, "git_repository_root_problem", lambda path, **kwargs: problem
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(
            results=AshAggregatedResults(sarif=_sarif_with_uris("app.py"))
        )
        opts = _opts(tmp_path, output_dir, changed_files_only=True)
        buffer = io.StringIO()
        handler = RichHandler(
            console=Console(file=buffer, width=400, color_system=None),
            markup=True,
            show_time=False,
            show_path=False,
        )
        saved = list(ASH_LOGGER.handlers)
        ASH_LOGGER.handlers = [handler]
        try:
            _run_local_mode(opts, ASH_LOGGER)
        finally:
            ASH_LOGGER.handlers = saved
        printed = " ".join(buffer.getvalue().split())
        assert problem in printed, printed
        assert "reporting every finding" in printed, printed

    @pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
    def test_a_missing_git_is_named_rather_than_the_repository(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """git absent said "is not inside a git repository" about a repository."""
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run([shutil.which("git"), "init", "-q", str(repo)], check=True)  # nosec B603
        empty = tmp_path / "empty-path"
        empty.mkdir()
        monkeypatch.setenv("PATH", str(empty))
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(
            results=AshAggregatedResults(sarif=_sarif_with_uris("app.py"))
        )
        opts = _opts(repo, output_dir, changed_files_only=True)

        _run_local_mode(opts, logger)

        warned = " ".join(logger.records["warning"])
        assert "git is not installed or not on PATH" in warned, warned
        assert "not inside a git repository" not in warned

    def test_the_changed_set_reaches_the_engine_and_no_report_is_rewritten(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """The filter runs once, in the engine, before any report is written.

        run_ash_scan hands the set to the engine and leaves the reports alone.
        Filtering the returned results after the report phase and rewriting
        ``ash.sarif`` from them would leave every other report and the summary
        counts unfiltered.
        """
        from automated_security_helper.utils import get_scan_set

        monkeypatch.setattr(
            get_scan_set, "get_changed_files", lambda base_ref, cwd: ["changed.py"]
        )
        # The source dir is the repository root in this geometry, which is what
        # the stub root asserts; test_the_diff_is_anchored_on_the_repository_root
        # covers the case where the two differ. The stand-in root is a real
        # repository below the isolation fixture's top, so the nesting walk can
        # be asked about it.
        root = self._repository_root(tmp_path)
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: root
        )
        output_dir = tmp_path / "out"
        (output_dir / "reports").mkdir(parents=True)
        sarif_path = output_dir / "reports" / "ash.sarif"
        sarif_path.write_text("stale placeholder", encoding="utf-8")
        recorded = local_orchestrator(
            results=AshAggregatedResults(
                sarif=_sarif_with_uris("changed.py", "untouched.py")
            )
        )
        opts = _opts(root, output_dir, changed_files_only=True)

        returned, _ = _run_local_mode(opts, logger)

        changed, metadata = self._handed(recorded)
        assert changed == {(root / "changed.py").resolve()}
        assert metadata == {"changed_files_only": True, "scan_source": "."}
        # What the engine returned is passed on untouched.
        assert len(returned.sarif.runs[0].results) == 2
        assert sarif_path.read_text(encoding="utf-8") == "stale placeholder"

    def test_no_changed_files_leaves_the_results_alone(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """git returning None means "scan everything", not "scan nothing"."""
        from automated_security_helper.utils import get_scan_set

        monkeypatch.setattr(
            get_scan_set, "get_changed_files", lambda base_ref, cwd: None
        )
        # A real root, so this exercises the "diff unavailable" fallback rather
        # than the "root unavailable" one that would also reach a full scan. A
        # real repository below the isolation fixture's top, so the nesting
        # walk can be asked about it.
        root = self._repository_root(tmp_path)
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: root
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(
            results=AshAggregatedResults(
                sarif=_sarif_with_uris("changed.py", "untouched.py")
            )
        )
        opts = _opts(root, output_dir, changed_files_only=True)

        returned, _ = _run_local_mode(opts, logger)

        # No changed set; the marker is still written, as an explicit False, so a
        # full scan is told apart from results that predate the marker.
        assert self._handed(recorded) == (
            None,
            {"changed_files_only": False, "scan_source": "."},
        )
        assert len(returned.sarif.runs[0].results) == 2

    def test_without_the_flag_nothing_is_handed_over(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        from automated_security_helper.utils import get_scan_set

        # A real repository below the isolation fixture's top, so scan_source
        # does not depend on where tmp_path sits.
        root = self._repository_root(tmp_path)
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: root
        )
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        recorded = local_orchestrator(results=AshAggregatedResults())

        _run_local_mode(_opts(root, output_dir), logger)

        # No changed set; the marker is still written, as an explicit False, so a
        # full scan is told apart from results that predate the marker.
        assert self._handed(recorded) == (
            None,
            {"changed_files_only": False, "scan_source": "."},
        )


@pytest.mark.skipif(
    os.name == "nt", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.unit
class TestChangedFilesSarifRewriteIsNotWrittenThroughALink:
    """The rewrite of ``reports/ash.sarif`` refuses a link there, as reports do.

    With no reporter selected that writes ``ash.sarif`` (``--output-formats yaml``),
    the report phase does not examine that name, so the rewrite is where a link
    there is met. Replacing it would remove the link without a word, and the exit
    code check that refuses a link at that name would then find a regular file.
    """

    @pytest.mark.parametrize("target", ["outside", "inside"])
    def test_a_link_at_the_sarif_report_refuses_the_run(
        self, local_orchestrator, logger, monkeypatch, tmp_path, target
    ):
        from automated_security_helper.utils import get_scan_set

        monkeypatch.setattr(
            get_scan_set, "get_changed_files", lambda base_ref, cwd: ["changed.py"]
        )
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: tmp_path
        )
        output_dir = tmp_path / "out"
        reports = output_dir / "reports"
        reports.mkdir(parents=True)
        pointed_at = (
            tmp_path / "outside.sarif"
            if target == "outside"
            else reports / "kept.sarif"
        )
        pointed_at.write_text("unchanged", encoding="utf-8")
        link = reports / "ash.sarif"
        link.symlink_to(pointed_at)
        local_orchestrator(
            results=AshAggregatedResults(
                sarif=_sarif_with_uris("changed.py", "untouched.py")
            )
        )
        opts = _opts(tmp_path, output_dir, changed_files_only=True)

        with pytest.raises(SystemExit) as refused:
            _run_local_mode(opts, logger)

        assert refused.value.code == 1
        assert f"{link.as_posix()} is a symlink" in getattr(refused.value, "reason", "")
        assert link.is_symlink()
        assert pointed_at.read_text(encoding="utf-8") == "unchanged"


@pytest.mark.unit
class TestChangedFilesRewriteLeavesAnEarlierRunsSarif:
    def test_a_sarif_report_this_run_did_not_write_is_not_rewritten(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """--use-existing with no SARIF reporter: reports/ash.sarif is an earlier run's."""
        from automated_security_helper.utils import get_scan_set

        monkeypatch.setattr(
            get_scan_set, "get_changed_files", lambda base_ref, cwd: ["changed.py"]
        )
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: tmp_path
        )
        output_dir = tmp_path / "out"
        (output_dir / "reports").mkdir(parents=True)
        sarif = output_dir / "reports" / "ash.sarif"
        sarif.write_text("an earlier run's report", encoding="utf-8")
        results = AshAggregatedResults(
            sarif=_sarif_with_uris("changed.py", "untouched.py")
        )
        results.validation_checkpoints.append(
            {"type": "reports_written", "metadata": {"files": ["ash.csv"]}}
        )
        local_orchestrator(results=results)
        opts = _opts(tmp_path, output_dir, changed_files_only=True)

        _run_local_mode(opts, logger)

        assert sarif.read_text(encoding="utf-8") == "an earlier run's report"

    def test_the_sarif_reporters_own_file_is_rewritten_under_its_name(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """An extension can move the SARIF report aside and put another at ash.sarif."""
        from automated_security_helper.utils import get_scan_set

        monkeypatch.setattr(
            get_scan_set, "get_changed_files", lambda base_ref, cwd: ["changed.py"]
        )
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: tmp_path
        )
        output_dir = tmp_path / "out"
        reports = output_dir / "reports"
        reports.mkdir(parents=True)
        (reports / "ash.sarif").write_text("another reporter's file", encoding="utf-8")
        renamed = reports / "ash.sarif.orig"
        renamed.write_text("unfiltered", encoding="utf-8")
        results = AshAggregatedResults(
            sarif=_sarif_with_uris("changed.py", "untouched.py")
        )
        results.validation_checkpoints.append(
            {
                "type": "reports_written",
                "metadata": {
                    "files": ["ash.sarif", "ash.sarif.orig"],
                    "formats": {"ash.sarif": "cyclonedx", "ash.sarif.orig": "sarif"},
                },
            }
        )
        local_orchestrator(results=results)
        opts = _opts(tmp_path, output_dir, changed_files_only=True)

        _run_local_mode(opts, logger)

        rewritten = renamed.read_text(encoding="utf-8")
        assert "changed.py" in rewritten and "untouched.py" not in rewritten
        assert (reports / "ash.sarif").read_text(
            encoding="utf-8"
        ) == "another reporter's file"


@pytest.mark.unit
class TestARunWithoutAReportPhaseRecordsNoReports:
    def test_the_results_say_no_report_file_was_written(
        self, local_orchestrator, logger, tmp_path
    ):
        """As for ``--phases convert --phases scan``: no report phase, no record.

        A ``reports/ash.sarif`` something other than a reporter wrote is then not
        read as this run's report.
        """
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(results=AshAggregatedResults())

        _run_local_mode(_opts(tmp_path, output_dir), logger)

        written = json.loads(
            (output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
        )
        # The record also carries the token of the process that wrote it, which
        # this test does not compare.
        assert [
            {key: checkpoint["metadata"][key] for key in ("files", "formats")}
            for checkpoint in written["validation_checkpoints"]
            if checkpoint.get("type") == "reports_written"
        ] == [{"files": [], "formats": {}}]


@pytest.mark.unit
class TestChangedFilesSarifRewriteIsNotSkippedSilently:
    def test_a_sarif_report_the_rewrite_may_not_write_refuses_the_run(
        self, local_orchestrator, logger, monkeypatch, tmp_path
    ):
        """Skipping the rewrite would leave the unfiltered ash.sarif as the report.

        ``confined_report_path`` refuses the name only when ``reports/`` or the file
        is a link, which is refused just before; the check that remains is for the
        state changing between the two.
        """
        from automated_security_helper.base import reporter_plugin
        from automated_security_helper.utils import get_scan_set

        monkeypatch.setattr(
            get_scan_set, "get_changed_files", lambda base_ref, cwd: ["changed.py"]
        )
        monkeypatch.setattr(
            get_scan_set, "git_repository_root", lambda path, **kwargs: tmp_path
        )
        monkeypatch.setattr(
            reporter_plugin, "confined_report_path", lambda report_dir, filename: None
        )
        output_dir = tmp_path / "out"
        (output_dir / "reports").mkdir(parents=True)
        sarif = output_dir / "reports" / "ash.sarif"
        sarif.write_text("unfiltered", encoding="utf-8")
        local_orchestrator(
            results=AshAggregatedResults(
                sarif=_sarif_with_uris("changed.py", "untouched.py")
            )
        )
        opts = _opts(tmp_path, output_dir, changed_files_only=True)

        with pytest.raises(SystemExit) as refused:
            _run_local_mode(opts, logger)

        assert refused.value.code == 1
        assert sarif.as_posix() in getattr(refused.value, "reason", "")


@pytest.mark.unit
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


@pytest.mark.unit
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

    @pytest.mark.parametrize(
        "error_class, code",
        [
            ("ASHConfigValidationError", 3),
            ("ScannerSelectionError", 5),
            ("RuntimeError", 1),
        ],
    )
    def test_markup_in_the_error_is_printed_as_text(
        self, local_orchestrator, logger, tmp_path, capsys, error_class, code
    ):
        """An ignore path "/x[/bold]" is refused with a message quoting it, printed
        as text: read as Rich markup, that closing tag would raise MarkupError, a
        traceback and exit 1, whatever the refusal's own exit code."""
        from automated_security_helper.core import exceptions

        error = getattr(exceptions, error_class, None) or RuntimeError
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        local_orchestrator(raises=error("The path '/x[/bold]' of an ignore path"))
        opts = _opts(tmp_path, output_dir)

        with pytest.raises(SystemExit) as excinfo:
            _run_local_mode(opts, logger)

        assert excinfo.value.code == code
        assert "'/x[/bold]'" in _plain(capsys.readouterr().out)

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

        assert "ASH_OFFLINE" not in environ_names()


# ---------------------------------------------------------------------------
# _compute_exit_code
# ---------------------------------------------------------------------------


@pytest.fixture
def unified_metrics(monkeypatch):
    """Fix what get_unified_scanner_metrics reports, so counts are deterministic.

    ``scanner_name`` and ``status`` are here because ``_compute_exit_code`` reads
    this same function twice: once for ``actionable``, and once through
    ``_incomplete_scanners``, which reads the other two. PASSED, so the
    completeness gate finds nothing incomplete and these cases keep measuring
    what they are named for -- fail-on-findings and min-severity -- rather than
    picking up the incomplete-scan exit code. The classes that exercise the gate
    itself set the status they need explicitly.
    """

    def install(actionable: int):
        metrics = [
            SimpleNamespace(
                actionable=actionable,
                scanner_name="fake-scanner",
                status=ScannerStatus.PASSED.value,
            )
        ]
        monkeypatch.setattr(
            ras, "get_unified_scanner_metrics", lambda asharp_model: metrics
        )
        return metrics

    return install


@pytest.mark.unit
class TestComputeExitCodeNoResults:
    def test_no_results_is_a_scan_error_not_a_clean_pass(self, tmp_path):
        opts = _opts(tmp_path, tmp_path / "out")
        assert _compute_exit_code(None, opts) == 1


@pytest.mark.unit
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


@pytest.mark.unit
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
        assert (
            _compute_exit_code(sarif_report_written(AshAggregatedResults()), opts) == 0
        )


@pytest.mark.unit
class TestComputeExitCodeMinSeverity:
    def test_nothing_at_or_above_min_severity_clears_the_finding_count(
        self, unified_metrics, tmp_path
    ):
        """Every finding is suppressed, so none of them qualifies."""
        unified_metrics(3)
        results = SimpleNamespace(
            ash_config=None,
            additional_reports={},
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
            additional_reports={},
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
            additional_reports={},
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


@pytest.mark.unit
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
# filter_results_to_changed_files
# ---------------------------------------------------------------------------


@pytest.mark.unit
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

        filtered = filter_results_to_changed_files(results, set(), tmp_path)

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

        filtered = filter_results_to_changed_files(results, set(), tmp_path)

        assert len(filtered.sarif.runs[0].results) == 1

    def test_a_file_uri_is_normalised_before_comparison(self, tmp_path):
        changed = tmp_path / "changed.py"
        changed.write_text("x = 1\n", encoding="utf-8")
        results = AshAggregatedResults(
            sarif=_sarif_with_uris("file://" + changed.as_posix(), "untouched.py")
        )

        filtered = filter_results_to_changed_files(
            results, {changed.resolve()}, tmp_path
        )

        uris = [
            result.locations[0].physicalLocation.root.artifactLocation.uri
            for result in filtered.sarif.runs[0].results
        ]
        assert uris == ["file://" + changed.as_posix()]

    def test_results_without_sarif_runs_are_returned_untouched(self, tmp_path):
        results = AshAggregatedResults()
        assert filter_results_to_changed_files(results, set(), tmp_path) is results


# ---------------------------------------------------------------------------
# run_ash_scan -- the exit-code-1 announcement
# ---------------------------------------------------------------------------


@pytest.mark.unit
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
