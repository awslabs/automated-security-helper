# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reports written from existing results do not repeat an earlier run's run records.

A container or nix run's inner run records in its results file that it completed,
or that its reports were refused, for the outer process to read back
(utils/inner_run_outcome.py). Those records describe that run. ``--use-existing``
reads the file back for a new run, so they are dropped when the results are
loaded, before any reporter sees them: ``ash.yaml``, which carries the whole
model, does not repeat them, while the results' other checkpoints remain.
"""

from __future__ import annotations

import json

from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults


def test_reports_from_existing_results_do_not_carry_an_earlier_runs_records(
    tmp_path,
):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    document = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
    document["validation_checkpoints"] = [
        {
            "type": "report_path_refused",
            "severity": "error",
            "message": "EARLIER-REFUSAL-MARKER",
            "metadata": {"run_id": "0" * 32},
        },
        {"type": "run_completed", "metadata": {"run_id": "1" * 32}},
        {
            "type": "config_warning",
            "severity": "warning",
            "message": "OTHER-CHECKPOINT-MARKER",
            "metadata": {},
        },
    ]
    results = output / "ash_aggregated_results.json"
    results.write_text(json.dumps(document), encoding="utf-8")

    ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=output,
        existing_results_path=results,
        output_formats=[ExportFormat.YAML],
        config_overrides=["reporters.yaml.enabled=true"],
        show_progress=False,
        offline=True,
    ).execute_scan(phases=["report"])

    report = (output / "reports" / "ash.yaml").read_text(encoding="utf-8")
    assert "OTHER-CHECKPOINT-MARKER" in report
    assert "EARLIER-REFUSAL-MARKER" not in report
    assert "run_completed" not in report
