# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan --inspect`` analyzes the SARIF of the scan it ran, wherever that went.

The inspect phase called ``analyze_sarif_fields(output_dir=...)`` without
``sarif_dir``, and that function defaults ``sarif_dir`` to ``.ash/ash_output`` under
the working directory. With ``--output-dir`` set elsewhere it analyzed whatever an
earlier scan had left under the working directory, or found nothing and wrote no
analysis, while the scan's own ``analysis/`` directory was created empty.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

from automated_security_helper.core.phases.inspect_phase import InspectPhase


def _write_sarif(output_dir: Path, marker: str) -> None:
    """A SARIF file whose one result carries the top-level field *marker*."""
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "bandit"}},
                "results": [
                    {
                        "ruleId": "B101",
                        "message": {"text": "x"},
                        marker: MARKER_VALUES[marker],
                    }
                ],
            }
        ],
    }
    reports = output_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "ash.sarif").write_text(json.dumps(sarif), encoding="utf-8")


# Two result fields the analysis lists by name, one per scan, so the analysis says
# which SARIF it read.
MARKER_VALUES = {"kind": "fail", "rank": 50.0}


def _run(output_dir: Path) -> Path:
    context = MagicMock()
    context.output_dir = output_dir
    phase = InspectPhase(plugin_context=context)
    phase._execute_phase(aggregated_results=AshAggregatedResults())
    return output_dir / "analysis" / "sarif_fields.json"


@pytest.mark.parametrize("cwd_has_older_output", [False, True])
def test_the_analysis_is_of_the_scans_own_output_directory(
    tmp_path, monkeypatch, cwd_has_older_output
):
    output_dir = tmp_path / "ci-out"
    _write_sarif(output_dir, "kind")
    cwd = tmp_path / "checkout"
    cwd.mkdir()
    if cwd_has_older_output:
        _write_sarif(cwd / ".ash" / "ash_output", "rank")
    monkeypatch.chdir(cwd)

    fields_file = _run(output_dir)

    assert fields_file.is_file(), "no analysis was written for the scan's own SARIF"
    fields = json.loads(fields_file.read_text(encoding="utf-8"))
    assert "runs[].results[].kind" in fields, sorted(fields)
    assert "runs[].results[].rank" not in fields, sorted(fields)
