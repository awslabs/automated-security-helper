# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The exit code and the summary table must judge findings by the same threshold.

``_compute_exit_code`` asks two sources for the actionable count and keeps the
second: ``get_unified_scanner_metrics``, which resolves a per-scanner
``options.severity_threshold`` and records ``threshold_source == "config"``, and a
re-read of ``reports/ash.sarif`` that applied ``global_settings.severity_threshold``
to every run. A scanner configured stricter than the global setting therefore had
its findings counted by the report and ignored by the exit code -- and the exit
code is the entire contract for a CI gate.

The ``--min-severity`` filter had a second, narrower version of the same problem:
it was the only severity resolver in ASH that ignored ``properties.issue_severity``,
and it spelled ``error -> high`` where ``utils.sarif_utils`` spells
``error -> critical``.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from automated_security_helper.interactions.run_ash_scan import (
    _SEVERITY_RANK,
    _compute_exit_code,
    _severity_filters_finding,
)
from automated_security_helper.utils.sarif_utils import _resolve_result_severity


def _opts(tmp_path, min_severity="low"):
    from automated_security_helper.interactions.run_ash_scan import ScanOptions

    return ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        min_severity=min_severity,
    )


def _sarif_result(scanner_name: str, level: str, issue_severity: str) -> dict:
    return {
        "ruleId": f"{scanner_name.upper()}-1",
        "level": level,
        "message": {"text": "finding"},
        "properties": {
            "scanner_name": scanner_name,
            "issue_severity": issue_severity,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


def _results_and_sarif_file(tmp_path, scanner_config: dict, level, issue_severity):
    """A real ``AshAggregatedResults`` plus the ``ash.sarif`` a scan would leave.

    Both halves carry the same single finding, because the defect is that the two
    counts disagree about one input -- a fixture that fed them different findings
    could not distinguish a threshold disagreement from a content one.
    """
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerStatusInfo,
    )
    from automated_security_helper.schemas.sarif_schema_model import (
        ArtifactLocation,
        Level,
        Location,
        Message,
        Message1,
        PhysicalLocation,
        PhysicalLocation2,
        PropertyBag,
        Region,
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
            "project_name": "severity-parity",
            "global_settings": {"severity_threshold": "MEDIUM"},
            "scanners": scanner_config,
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
                        level=Level(level),
                        message=Message(root=Message1(text="finding")),
                        properties=PropertyBag(
                            scanner_name="bandit", issue_severity=issue_severity
                        ),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation(
                                    root=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri="src/app.py"
                                        ),
                                        region=Region(startLine=1),
                                    )
                                )
                            )
                        ],
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
                        "results": [_sarif_result("bandit", level, issue_severity)],
                    }
                ],
            }
        )
    )
    return results


class TestTheExitCodeHonorsPerScannerThresholds:
    def test_a_scanner_stricter_than_the_global_setting_fails_the_scan(self, tmp_path):
        """``bandit`` gates on ALL; the finding is INFO; the global setting is MEDIUM.

        ``get_unified_scanner_metrics`` counts it because ``bandit``'s own
        threshold is ALL. The SARIF re-read did not, because it applied MEDIUM to
        every run and then overwrote the unified count outright, so the scan exited
        0 while the summary table showed the finding as actionable.
        """
        results = _results_and_sarif_file(
            tmp_path,
            scanner_config={"bandit": {"options": {"severity_threshold": "ALL"}}},
            level="none",
            issue_severity="INFO",
        )

        assert _compute_exit_code(results, _opts(tmp_path)) == 2

    def test_the_global_setting_still_governs_a_scanner_that_overrides_nothing(
        self, tmp_path
    ):
        """The other direction, so the fix is not just "count more".

        No per-scanner override, a LOW finding, MEDIUM globally: still clean.
        """
        results = _results_and_sarif_file(
            tmp_path,
            scanner_config={},
            level="note",
            issue_severity="LOW",
        )

        assert _compute_exit_code(results, _opts(tmp_path)) == 0

    def test_a_scanner_looser_than_the_global_setting_does_not_fail_the_scan(
        self, tmp_path
    ):
        """``bandit`` gates on CRITICAL; the finding is MEDIUM; globally MEDIUM.

        The re-read counted it, because MEDIUM qualified globally. Both counts now
        agree that the scanner the operator relaxed reports nothing actionable.
        """
        results = _results_and_sarif_file(
            tmp_path,
            scanner_config={"bandit": {"options": {"severity_threshold": "CRITICAL"}}},
            level="warning",
            issue_severity="MEDIUM",
        )

        assert _compute_exit_code(results, _opts(tmp_path)) == 0


class TestTheMinSeverityFilterResolvesSeverityLikeEverythingElse:
    def test_an_explicit_severity_above_the_level_qualifies(self):
        """``issue_severity`` outranks the SARIF level, the fail-closed direction.

        Grype reports a CRITICAL vulnerability at ``level: warning``. Read by level
        alone that is MEDIUM, so ``--min-severity high`` zeroed the whole actionable
        count and the scan exited 0 over a critical finding.
        """
        result = SimpleNamespace(
            suppressions=[],
            level="warning",
            properties={"issue_severity": "CRITICAL"},
        )

        assert _severity_filters_finding(result, _SEVERITY_RANK["high"]) is True

    def test_an_explicit_severity_below_the_level_does_not_qualify(self):
        """And the loosening direction, which is the same rule applied honestly.

        ``--min-severity high`` says "do not fail me for anything below high". A
        finding whose own severity is LOW must not hold the exit code open just
        because its SARIF level is ``error``.
        """
        result = SimpleNamespace(
            suppressions=[],
            level="error",
            properties={"issue_severity": "LOW"},
        )

        assert _severity_filters_finding(result, _SEVERITY_RANK["high"]) is False

    def test_the_error_level_resolves_the_way_sarif_utils_resolves_it(self):
        """One spelling of ``error``, not two.

        This filter said ``error -> high`` and ``utils.sarif_utils`` says
        ``error -> critical``. The two happen to share a rank on the
        ``--min-severity`` scale -- SARIF cannot distinguish them -- so the
        assertion worth making is that both name the same severity, which is what
        would have caught the divergence before a caller relied on it.
        """
        result = SimpleNamespace(suppressions=[], level="error", properties=None)

        assert _resolve_result_severity(result) == "critical"
        assert _severity_filters_finding(result, _SEVERITY_RANK["critical"]) is True

    @pytest.mark.parametrize("level", ["none", None])
    def test_a_level_carrying_no_severity_still_grades_as_low(self, level):
        """Unchanged, and asserted because the rewrite routes it differently.

        A missing or ``none`` level used to fall through a ``.get(level, "low")``
        default; it now resolves to ``info``, which is absent from the
        ``--min-severity`` scale and falls back to the same rank. Identical
        outcome, reached two ways, so it needs pinning.
        """
        result = SimpleNamespace(suppressions=[], level=level, properties=None)

        assert _severity_filters_finding(result, _SEVERITY_RANK["low"]) is True
        assert _severity_filters_finding(result, _SEVERITY_RANK["medium"]) is False

    def test_a_suppressed_finding_never_qualifies(self):
        """Suppression outranks severity, however the severity was resolved."""
        result = SimpleNamespace(
            suppressions=[{"kind": "external"}],
            level="error",
            properties={"issue_severity": "CRITICAL"},
        )

        assert _severity_filters_finding(result, _SEVERITY_RANK["low"]) is False
