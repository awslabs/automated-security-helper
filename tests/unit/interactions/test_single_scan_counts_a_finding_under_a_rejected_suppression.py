# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression hides a finding only when it is in effect, in every single-scan read.

SARIF 3.35.4: a suppression whose ``state`` is ``rejected`` or ``underReview`` has
not taken effect. The flat finding, the OCSF record and the workspace verdict read
a result's suppressions through ``sarif_utils.suppressions_in_effect``; the exit
code's SARIF count (``_compute_exit_code``), the ``--min-severity`` gate
(``_severity_filters_finding``) and the per-scanner statistics
(``ScannerStatisticsCalculator.extract_sarif_counts_for_scanner``) read any
non-empty list as suppressed. So a finding whose only suppression a reviewer had
rejected was hidden from the exit code and the summary table while the same scan's
workspace verdict counted it, and ``ash --source-dir P`` exited 0 over it. A
rejected suppression was never an approval: the finding counts, the fail-closed
side.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.interactions.run_ash_scan import (
    _SEVERITY_RANK,
    _compute_exit_code,
    _severity_filters_finding,
)

pytestmark = pytest.mark.unit


def _suppression(state: str | None) -> dict:
    suppression = {"kind": "external", "justification": "awaiting review"}
    if state is not None:
        suppression["state"] = state
    return suppression


def _opts(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    return ScanOptions(source_dir=tmp_path / "src", output_dir=tmp_path / "out")


def _results_and_sarif_file(tmp_path, state: str | None):
    """A real ``AshAggregatedResults`` plus the ``ash.sarif`` a scan would leave.

    Both halves carry the same single HIGH bandit finding with one suppression in
    the given *state*, because ``_compute_exit_code`` reads both: the unified
    metrics from the model and the SARIF count from the file.
    """
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerStatusInfo,
    )
    from automated_security_helper.schemas.sarif_schema_model import (
        Level,
        Message,
        Message1,
        PropertyBag,
        Result,
        Run,
        SarifReport,
        Tool,
        ToolComponent,
    )

    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()

    results = AshAggregatedResults()
    results.ash_config = AshConfig.model_validate(
        {
            "project_name": "suppression-state",
            "global_settings": {"severity_threshold": "MEDIUM"},
            "scanners": {},
        }
    )
    results.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                results=[
                    Result(
                        ruleId="BANDIT-1",
                        level=Level.error,
                        message=Message(root=Message1(text="finding")),
                        properties=PropertyBag(
                            scanner_name="bandit", issue_severity="HIGH"
                        ),
                        suppressions=[_suppression(state)],
                    )
                ],
            )
        ],
    )
    results.scanner_results["bandit"] = ScannerStatusInfo()

    sarif_file = tmp_path / "out" / "reports" / "ash.sarif"
    sarif_file.parent.mkdir(parents=True, exist_ok=True)
    sarif_file.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ASH", "version": "1.0"}},
                        "results": [
                            {
                                "ruleId": "BANDIT-1",
                                "level": "error",
                                "message": {"text": "finding"},
                                "properties": {
                                    "scanner_name": "bandit",
                                    "issue_severity": "HIGH",
                                },
                                "suppressions": [_suppression(state)],
                            }
                        ],
                    }
                ],
            }
        )
    )
    return results


class TestTheExitCodeCountsAFindingWhoseSuppressionIsNotInEffect:
    @pytest.mark.parametrize("state", ["rejected", "underReview"])
    def test_a_suppression_not_in_effect_fails_the_scan(self, tmp_path, state):
        results = _results_and_sarif_file(tmp_path, state)

        # RED at the base: the SARIF count skipped every result with a non-empty
        # suppressions list, and the unified metrics counted it suppressed, so the
        # scan exited 0 over a HIGH finding nobody had approved hiding.
        assert _compute_exit_code(results, _opts(tmp_path)) == 2

    @pytest.mark.parametrize("state", [None, "accepted"])
    def test_a_suppression_in_effect_still_hides_the_finding(self, tmp_path, state):
        """Control: an accepted or stateless suppression hides it, as before."""
        results = _results_and_sarif_file(tmp_path, state)

        assert _compute_exit_code(results, _opts(tmp_path)) == 0


class TestTheMinSeverityGateCountsAFindingWhoseSuppressionIsNotInEffect:
    @pytest.mark.parametrize("state", ["rejected", "underReview"])
    def test_a_suppression_not_in_effect_keeps_the_finding_in_the_count(self, state):
        result = SimpleNamespace(
            suppressions=[_suppression(state)],
            level="error",
            properties={"issue_severity": "HIGH"},
        )

        # RED at the base: any non-empty suppressions list read as suppressed.
        assert _severity_filters_finding(result, _SEVERITY_RANK["high"]) is True

    @pytest.mark.parametrize("state", [None, "accepted"])
    def test_a_suppression_in_effect_leaves_the_finding_out(self, state):
        result = SimpleNamespace(
            suppressions=[_suppression(state)],
            level="error",
            properties={"issue_severity": "HIGH"},
        )

        assert _severity_filters_finding(result, _SEVERITY_RANK["high"]) is False


class TestTheScannerStatisticsCountAFindingWhoseSuppressionIsNotInEffect:
    def _model(self, state: str | None):
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import (
            Level,
            Message,
            Message1,
            PropertyBag,
            Result,
            Run,
            SarifReport,
            Tool,
            ToolComponent,
        )

        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()
        model = AshAggregatedResults()
        model.ash_config = get_default_config()
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=[
                        Result(
                            ruleId="RULE1",
                            level=Level.error,
                            message=Message(root=Message1(text="Critical issue")),
                            properties=PropertyBag(scanner_name="test_scanner"),
                            suppressions=[_suppression(state)],
                        )
                    ],
                )
            ],
        )
        return model

    @pytest.mark.parametrize("state", ["rejected", "underReview"])
    def test_a_suppression_not_in_effect_counts_under_its_severity(self, state):
        suppressed, critical, *_ = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                self._model(state), "test_scanner"
            )
        )

        # RED at the base: suppressed 1, critical 0; the summary table and the
        # unified metrics' actionable count hid a finding nobody had approved hiding.
        assert (suppressed, critical) == (0, 1)

    @pytest.mark.parametrize("state", [None, "accepted"])
    def test_a_suppression_in_effect_counts_as_suppressed(self, state):
        suppressed, critical, *_ = (
            ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                self._model(state), "test_scanner"
            )
        )

        assert (suppressed, critical) == (1, 0)
