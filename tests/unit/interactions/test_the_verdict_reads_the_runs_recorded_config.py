# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The findings verdict reads the configuration the run recorded.

``_compute_exit_code``'s fail_on_findings fallback read only a separate
pre-read of the config file (made before the run, for the container command
line) and then the default. The two reads can diverge: a file unreadable
during the pre-read alone answers None there, while the run's own load
succeeds, so a scan whose config turned findings-gating off was still gated
by the default and exited 2 (measured with the read denied for the pre-read
and allowed after). The pre-read decides when it answered; the run's
recorded configuration stands in when it did not; the default gates only
when neither did. The pre-read keeps its place deliberately: in container
mode the host passes its pre-read to the inner run, so the recorded field
can differ from the verdict the host acted on.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

#: One finding the exit code counts as actionable under the default threshold.
_FINDING = {
    "ruleId": "RULE-1",
    "level": "error",
    "kind": "fail",
    "message": {"text": "RULE-1 finding"},
    "properties": {"scanner_name": "detect-secrets", "issue_severity": "CRITICAL"},
    "locations": [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/rule_1.py"},
                "region": {"startLine": 1},
            }
        }
    ],
}


def _results(recorded: Optional[bool]) -> AshAggregatedResults:
    """A completed scan with one actionable finding, whose run recorded a
    configuration with the given fail_on_findings, or no configuration."""
    config = None
    if recorded is not None:
        config = AshConfig(project_name="project", fail_on_findings=recorded)
    model = AshAggregatedResults(ash_config=config)
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "ASH"}}, "results": [_FINDING]}],
        }
    )
    model.scanner_results["detect-secrets"] = ScannerTargetStatusInfo(
        status=ScannerStatus.PASSED,
        excluded=False,
        dependencies_satisfied=True,
    )
    return model


def _exit_code(
    tmp_path: Path,
    recorded: Optional[bool],
    pre_read: Optional[bool],
    cli: Optional[bool] = None,
) -> int:
    output_dir = tmp_path / "out"
    reports = output_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "ash.sarif").write_text(
        json.dumps({"version": "2.1.0", "runs": [{"results": [_FINDING]}]}),
        encoding="utf-8",
    )
    opts = ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        fail_on_findings=cli,
    )
    return _compute_exit_code(
        _results(recorded),
        opts,
        config_fail_on_findings=pre_read,
        report_sarif_written_this_run=True,
    )


@pytest.mark.parametrize(
    "recorded, pre_read, expected",
    [
        # The recorded configuration decides when the pre-read answered
        # nothing (the measured window).
        (False, None, 0),
        (True, None, 2),
        # A pre-read that answered keeps its place: it read the same file,
        # and the callers that pass one (ash merge, local mode) pass the
        # recorded value itself.
        (False, True, 2),
        (None, False, 0),
        (None, True, 2),
        # Neither read answered: the default gates.
        (None, None, 2),
    ],
)
def test_the_verdict_reads_the_runs_recorded_config(
    tmp_path, recorded, pre_read, expected
):
    assert _exit_code(tmp_path, recorded, pre_read) == expected


def test_the_operators_own_flag_still_wins(tmp_path):
    """--fail-on-findings on the command line outranks both reads."""
    assert _exit_code(tmp_path, recorded=False, pre_read=None, cli=True) == 2
    assert _exit_code(tmp_path, recorded=True, pre_read=None, cli=False) == 0
