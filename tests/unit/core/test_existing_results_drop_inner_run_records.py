# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--use-existing`` reads only results that hold a scan, without the run's own records.

A container or nix run's inner run records in its results file that it completed,
and the report phase records the report files it wrote (utils/inner_run_outcome.py).
Those records describe that run. ``--use-existing`` reads the file back for a new
run, so they are dropped when the results are loaded, before any reporter sees
them: ``ash.yaml``, which carries the whole model, does not repeat them, while the
results' other checkpoints remain.

A results file that holds no scan is refused rather than reported on: one that
records a refused run, as a refused inner run of an earlier build of this branch
wrote, or one with no scanner results, as a run that stopped before its scan
phase recorded anything leaves (a release up to v3.7.1 writes such a file after
its scan phase). Reported on, either read as a clean scan and exited 0.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.inner_run_outcome import ExistingResultsRefused

#: One scanner's entry, which is what a scan phase records for every scanner it
#: considered, skipped ones included.
SCANNED = {"bandit": {"source": {"scanner_name": "bandit", "status": "PASSED"}}}


def _results_file(output: Path, **fields) -> Path:
    document = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
    document.update(fields)
    output.mkdir(parents=True, exist_ok=True)
    results = output / "ash_aggregated_results.json"
    results.write_text(json.dumps(document), encoding="utf-8")
    return results


def _report_from(tmp_path: Path, results: Path) -> Path:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=results.parent,
        existing_results_path=results,
        output_formats=[ExportFormat.YAML],
        config_overrides=["reporters.yaml.enabled=true"],
        show_progress=False,
        offline=True,
    ).execute_scan(phases=["report"])
    return results.parent / "reports"


def test_reports_from_existing_results_do_not_carry_an_earlier_runs_records(
    tmp_path,
):
    results = _results_file(
        tmp_path / "out",
        scanner_results=SCANNED,
        validation_checkpoints=[
            {"type": "run_completed", "metadata": {"run_id": "1" * 32}},
            {
                "type": "reports_written",
                "metadata": {"files": ["EARLIER-REPORT-MARKER"]},
            },
            {
                "type": "config_warning",
                "severity": "warning",
                "message": "OTHER-CHECKPOINT-MARKER",
                "metadata": {},
            },
        ],
    )

    reports = _report_from(tmp_path, results)

    report = (reports / "ash.yaml").read_text(encoding="utf-8")
    assert "OTHER-CHECKPOINT-MARKER" in report
    assert "run_completed" not in report
    assert "EARLIER-REPORT-MARKER" not in report


@pytest.mark.parametrize(
    "fields",
    [
        {
            "validation_checkpoints": [
                {
                    "type": "report_path_refused",
                    "severity": "error",
                    "message": "EARLIER-REFUSAL-MARKER",
                    "metadata": {"run_id": "0" * 32},
                }
            ]
        },
        {
            "scanner_results": SCANNED,
            "validation_checkpoints": [
                {
                    "type": "report_path_refused",
                    "message": "EARLIER-REFUSAL-MARKER",
                    "metadata": {"run_id": "0" * 32},
                }
            ],
        },
    ],
    ids=["refusal only", "refusal beside scanner results"],
)
def test_existing_results_that_record_a_refused_run_are_refused(tmp_path, fields):
    results = _results_file(tmp_path / "out", **fields)

    with pytest.raises(ExistingResultsRefused) as refused:
        _report_from(tmp_path, results)

    message = str(refused.value)
    assert results.as_posix() in message, message
    assert "refused" in message, message
    assert "without --use-existing" in message, message
    assert not (tmp_path / "out" / "reports" / "ash.yaml").exists()


def test_existing_results_without_scanner_results_are_refused(tmp_path):
    """As a release up to v3.7.1 leaves after its scan phase: name and config only."""
    output = tmp_path / "out"
    output.mkdir()
    results = output / "ash_aggregated_results.json"
    results.write_text(
        json.dumps({"name": "ASH Scan Report", "description": "d", "ash_config": None}),
        encoding="utf-8",
    )

    with pytest.raises(ExistingResultsRefused) as refused:
        _report_from(tmp_path, results)

    assert "holds no scanner results" in str(refused.value), str(refused.value)
    assert not (output / "reports" / "ash.yaml").exists()


def test_a_refusal_only_results_file_then_use_existing_exits_3(tmp_path):
    """Through ``ash scan --use-existing``'s own path, which used to exit 0 here.

    3, as for any input ASH cannot use: the file holds no scan to report on.
    """
    from unittest.mock import MagicMock

    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )

    source = tmp_path / "src"
    source.mkdir()
    results = _results_file(
        tmp_path / "out",
        validation_checkpoints=[
            {
                "type": "report_path_refused",
                "message": "EARLIER-REFUSAL-MARKER",
                "metadata": {"run_id": "0" * 32},
            }
        ],
    )

    with pytest.raises(SystemExit) as exited:
        _run_local_mode(
            ScanOptions(
                source_dir=source,
                output_dir=results.parent,
                existing_results=results.as_posix(),
                output_formats=["yaml"],
                offline=True,
                progress=False,
            ),
            MagicMock(),
        )

    assert exited.value.code == 3
