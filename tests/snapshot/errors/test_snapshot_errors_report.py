# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ashx report`` prints, and exits with, when it cannot produce a report."""

from __future__ import annotations

from pathlib import Path

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)


def _results_in(directory: Path) -> None:
    """A results file of a scan that found nothing, which every reporter can read."""
    directory.mkdir(parents=True, exist_ok=True)
    results = AshAggregatedResults()
    results.ash_config = AshConfig(project_name="snapshot")
    (directory / "ash_aggregated_results.json").write_text(
        results.model_dump_json(), encoding="utf-8"
    )


def test_unknown_reporter(run_cli, snapshot, in_tmp):
    _results_in(in_tmp / "out")
    assert run_cli(["report", "--format", "pdf", "--output-dir", "out"]) == snapshot


def test_no_results_file(run_cli, snapshot):
    assert run_cli(["report", "--output-dir", "out"]) == snapshot


def test_results_file_is_not_results(run_cli, snapshot, in_tmp):
    (in_tmp / "out").mkdir()
    (in_tmp / "out" / "ash_aggregated_results.json").write_text(
        '{"scanner_results": 7}', encoding="utf-8"
    )
    assert run_cli(["report", "--output-dir", "out"]) == snapshot


def test_invalid_configuration(run_cli, snapshot, in_tmp):
    _results_in(in_tmp / "out")
    (in_tmp / "bad.yaml").write_text(
        "project_name: snapshot\nfail_on_findings: sometimes\n", encoding="utf-8"
    )
    assert (
        run_cli(["report", "--config", "bad.yaml", "--output-dir", "out"]) == snapshot
    )


def test_reporter_returned_nothing(run_cli, snapshot, in_tmp, monkeypatch):
    # A reporter returns None when it could not build its artefact at all; the
    # built-in text reporter stands in for any of them.
    monkeypatch.setattr(TextReporter, "report", lambda self, model: None)
    _results_in(in_tmp / "out")
    assert run_cli(["report", "--format", "text", "--output-dir", "out"]) == snapshot


def test_reporter_raised(run_cli, snapshot, in_tmp, monkeypatch):
    def _raise(self, model):
        raise RuntimeError("simulated reporter failure")

    monkeypatch.setattr(TextReporter, "report", _raise)
    _results_in(in_tmp / "out")
    assert run_cli(["report", "--format", "text", "--output-dir", "out"]) == snapshot
