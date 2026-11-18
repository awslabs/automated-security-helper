# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--mode precommit`` defaults the reports to what the hook reads.

Why this file exists
--------------------
A precommit run wrote the full default report set (every enabled reporter) on
every commit, while the hook (.pre-commit-hooks.yaml) consumes the exit code
and the console: the exit code is derived from the persisted SARIF report
(``_gating_actionable_count`` reads the file because it serializes every
suppression pass), and the text summary is the one report a committer opens
after a failed hook. The other report files cost each commit reporter setup
and writes that nothing reads.

The default under test (``run_ash_scan._precommit_output_formats``), lowest to
highest:

1. Precommit mode with no explicit choice anywhere writes
   ``PRECOMMIT_MODE_OUTPUT_FORMATS`` (text, sarif). Every other mode keeps the
   full configured set (an empty format list means "no filter").
2. A config file that sets ``output_formats``, or configures anything under
   ``reporters`` (including through ``--config-overrides``), keeps today's
   behavior unchanged: the mode default must never filter out a reporter the
   operator explicitly enabled.
3. ``--output-formats`` on the command line is handed through as given.

No scanner runs here: the orchestrator's ``create`` is replaced and recorded,
exactly as test_scanner_selection_flags.py does for the scanner selection.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.constants import PRECOMMIT_MODE_OUTPUT_FORMATS
from automated_security_helper.core.enums import ExportFormat, RunMode
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _precommit_output_formats,
    _run_local_mode,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


class _RecordingLogger:
    """Only the members the format resolution calls; a Mock would fabricate more."""

    def __init__(self) -> None:
        self.records: Dict[str, List[str]] = {
            "verbose": [],
            "debug": [],
            "info": [],
            "warning": [],
            "error": [],
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
        self.records["error"].append(str(message))


class _StubOrchestrator:
    def __init__(self, results):
        self.config = None
        self._results = results
        self.added_metadata: Dict[str, Any] = {}

    def add_metadata(self, **values):
        self.added_metadata.update(values)

    def restrict_to_changed_files(self, changed_files):
        pass

    def execute_scan(self, phases):
        return self._results


@pytest.fixture
def logger() -> _RecordingLogger:
    return _RecordingLogger()


@pytest.fixture
def local_orchestrator(monkeypatch):
    """Replace ASHScanOrchestrator.create and record the kwargs it was handed."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    recorded: Dict[str, Any] = {"create_kwargs": []}

    def fake_create(**kwargs):
        recorded["create_kwargs"].append(kwargs)
        return _StubOrchestrator(AshAggregatedResults())

    monkeypatch.setattr(ASHScanOrchestrator, "create", staticmethod(fake_create))
    return recorded


def _opts(source_dir: Path, output_dir: Path, **overrides: Any) -> ScanOptions:
    output_dir.mkdir(exist_ok=True)
    return ScanOptions(source_dir=source_dir, output_dir=output_dir, **overrides)


def _config_file(tmp_path: Path, body: str) -> str:
    path = tmp_path / "reports.ash.yaml"
    path.write_text(body, encoding="utf-8")
    return str(path)


#: What the mode default resolves to, spelled as the enum the orchestrator takes.
_MODE_DEFAULT = [ExportFormat(name) for name in PRECOMMIT_MODE_OUTPUT_FORMATS]


class TestPrecommitOutputFormatDefault:
    def test_the_mode_default_names_the_two_reports_the_hook_reads(self):
        """The exit code reads the persisted SARIF report; text is the summary."""
        assert PRECOMMIT_MODE_OUTPUT_FORMATS == ("text", "sarif")

    def test_precommit_with_no_choice_defaults_to_the_hook_reports(
        self, tmp_path, logger
    ):
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.precommit)

        assert _precommit_output_formats(opts, logger) == _MODE_DEFAULT

    def test_other_modes_keep_the_full_report_set(self, tmp_path, logger):
        """An empty list is 'no filter': every enabled reporter runs."""
        for mode in (RunMode.local, RunMode.container):
            opts = _opts(tmp_path, tmp_path / "out", mode=mode)

            assert _precommit_output_formats(opts, logger) == []

    def test_cli_output_formats_win_unchanged(self, tmp_path, logger):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            output_formats=[ExportFormat.MARKDOWN],
        )

        assert _precommit_output_formats(opts, logger) == [ExportFormat.MARKDOWN]

    def test_a_config_that_sets_output_formats_wins_unchanged(self, tmp_path, logger):
        config = _config_file(
            tmp_path,
            "project_name: t\noutput_formats:\n  - markdown\n",
        )
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.precommit, config=config)

        assert _precommit_output_formats(opts, logger) == []

    def test_a_config_that_configures_a_reporter_wins_unchanged(self, tmp_path, logger):
        """A reporter the operator enabled must run: the mode default's format
        allowlist would silently filter it out, so any ``reporters`` section
        keeps the full set."""
        config = _config_file(
            tmp_path,
            "project_name: t\nreporters:\n  markdown:\n    enabled: true\n",
        )
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.precommit, config=config)

        assert _precommit_output_formats(opts, logger) == []

    def test_a_reporters_config_override_wins_unchanged(self, tmp_path, logger):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            config_overrides=["reporters.markdown.enabled=true"],
        )

        assert _precommit_output_formats(opts, logger) == []

    def test_an_output_formats_override_wins_unchanged(self, tmp_path, logger):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            config_overrides=["output_formats=[markdown]"],
        )

        assert _precommit_output_formats(opts, logger) == []

    def test_a_config_that_chooses_nothing_keeps_the_mode_default(
        self, tmp_path, logger
    ):
        """A config file that exists but says nothing about reports is not a
        report choice."""
        config = _config_file(tmp_path, "project_name: t\n")
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.precommit, config=config)

        assert _precommit_output_formats(opts, logger) == _MODE_DEFAULT


class TestLocalModeHandsTheFormatsToTheOrchestrator:
    def test_precommit_hands_the_mode_default(
        self, tmp_path, logger, local_orchestrator
    ):
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.precommit)

        _run_local_mode(opts, logger)

        created = local_orchestrator["create_kwargs"][0]
        assert created["output_formats"] == _MODE_DEFAULT

    def test_local_mode_hands_the_empty_no_filter_list(
        self, tmp_path, logger, local_orchestrator
    ):
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.local)

        _run_local_mode(opts, logger)

        created = local_orchestrator["create_kwargs"][0]
        assert created["output_formats"] == []

    def test_precommit_hands_cli_formats_through(
        self, tmp_path, logger, local_orchestrator
    ):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            output_formats=[ExportFormat.HTML],
        )

        _run_local_mode(opts, logger)

        created = local_orchestrator["create_kwargs"][0]
        assert created["output_formats"] == [ExportFormat.HTML]
