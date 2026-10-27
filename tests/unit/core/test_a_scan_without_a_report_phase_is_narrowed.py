# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--changed-files-only`` narrows a scan that runs no report phase.

Why this exists
---------------
The scan engine drops findings outside the changed files in two places: at the
start of the report phase, and at the end of the scan phase, for a run whose
phases stop at ``scan`` (``ash scan --phases scan``). That run writes no
reports, but run_ash_scan still writes the results file and takes the verdict
from these results. Only the report-phase drop was tested, so removing the
scan-phase one survived the test suite. This runs the scan phase alone, with a
stand-in ScanPhase that returns findings in a changed and an unchanged file.
"""

from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.execution_engine import ScanExecutionEngine
from automated_security_helper.schemas.sarif_schema_model import SarifReport


class _ScanPhaseReturningTwoFindings:
    """Stands in for ScanPhase: no scanner runs, two findings come back."""

    def __init__(self, **kwargs):
        self._completed_scanners = []
        self._shard_assignment = None

    def execute(self, aggregated_results=None, **kwargs):
        aggregated_results.sarif = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ASH"}},
                        "results": [
                            {
                                "ruleId": f"R-{uri}",
                                "level": "error",
                                "message": {"text": "finding"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": uri}
                                        }
                                    }
                                ],
                            }
                            for uri in ("changed.py", "untouched.py")
                        ],
                    }
                ],
            }
        )
        return aggregated_results


def _scan_only(tmp_path: Path, monkeypatch, changed_files):
    monkeypatch.setattr(
        "automated_security_helper.core.execution_engine.ScanPhase",
        _ScanPhaseReturningTwoFindings,
    )
    source = tmp_path / "src"
    source.mkdir()
    engine = ScanExecutionEngine(
        context=PluginContext(
            source_dir=source, output_dir=tmp_path / "out", config=get_default_config()
        ),
        show_progress=False,
        show_summary=False,
        changed_files=(
            None
            if changed_files is None
            else {(source / f).resolve() for f in changed_files}
        ),
    )
    results = engine.execute_phases(phases=["scan"])
    return [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in results.sarif.runs[0].results
    ]


def test_the_scan_phase_alone_returns_only_the_changed_files_findings(
    tmp_path, monkeypatch
):
    assert _scan_only(tmp_path, monkeypatch, ["changed.py"]) == ["changed.py"]


def test_without_a_changed_set_nothing_is_dropped(tmp_path, monkeypatch):
    assert _scan_only(tmp_path, monkeypatch, None) == ["changed.py", "untouched.py"]
