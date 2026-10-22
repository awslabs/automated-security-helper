# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``actionable_only`` keeps the findings that make a scan exit 2, and no others.

Why this file exists
--------------------
``get_scan_results(actionable_only=True)`` dropped suppressed findings and kept
every other one, so a finding below the severity threshold the scan was judged
by was listed as actionable. The scan's own exit code does not count it:
``run_ash_scan._compute_exit_code`` counts an unsuppressed finding only when it is
at or above the threshold of its scanner, which is the scanner's own
``options.severity_threshold`` when it sets one and
``global_settings.severity_threshold`` otherwise. A threshold the client passes
to ``run_ash_scan`` reaches both. So an agent gating on ``findings_count`` failed
a scan that exits 0, and was told to fix findings the scan reports only as
information.

actionable_only keeps findings that are unsuppressed AND at or above the
threshold the scan was judged by, the set that decides exit 2.

Every test here runs the real tool over a results file written the way ASH
writes one, with the config the scan resolved in it. The last class asks
``_compute_exit_code`` itself about each finding, so the two answers are compared
rather than restated.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.cli.mcp_server import get_scan_results

#: The config the scans below were judged by: HIGH globally, bandit at its own
#: CRITICAL, semgrep at its own LOW. detect-secrets sets none, so HIGH applies.
GLOBAL = "HIGH"
SCANNER_THRESHOLDS = {"bandit": "CRITICAL", "semgrep": "LOW"}


def _finding(
    rule: str,
    scanner: Optional[str],
    severity: Optional[str],
    level: str = "note",
    suppressed: bool = False,
) -> Dict[str, Any]:
    """A SARIF result. With no severity the level decides, as it does for exit 2."""
    properties: Dict[str, Any] = {}
    if scanner is not None:
        properties["scanner_name"] = scanner
    if severity is not None:
        properties["issue_severity"] = severity
    result: Dict[str, Any] = {
        "ruleId": rule,
        "level": level,
        "kind": "fail",
        "message": {"text": f"{rule} finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"src/{rule.lower()}.py"},
                    "region": {"startLine": 1},
                }
            }
        ],
    }
    if properties:
        result["properties"] = properties
    if suppressed:
        result["suppressions"] = [{"kind": "external", "justification": "test"}]
    return result


#: rule id -> (finding, whether the scan's exit code counts it)
CASES: Dict[str, tuple] = {
    "AT-GLOBAL": (_finding("AT-GLOBAL", "detect-secrets", "HIGH"), True),
    "BELOW-GLOBAL": (_finding("BELOW-GLOBAL", "detect-secrets", "MEDIUM"), False),
    "SUPPRESSED": (
        _finding("SUPPRESSED", "detect-secrets", "CRITICAL", suppressed=True),
        False,
    ),
    # A scanner's own threshold decides its findings, either way.
    "AT-BANDIT": (_finding("AT-BANDIT", "bandit", "CRITICAL"), True),
    "BELOW-BANDIT": (_finding("BELOW-BANDIT", "bandit", "HIGH"), False),
    "AT-SEMGREP": (_finding("AT-SEMGREP", "semgrep", "LOW"), True),
    "BELOW-SEMGREP": (_finding("BELOW-SEMGREP", "semgrep", "INFO"), False),
    # No issue_severity: the SARIF level decides. error is CRITICAL, warning MEDIUM.
    "LEVEL-ERROR": (_finding("LEVEL-ERROR", "detect-secrets", None, "error"), True),
    "LEVEL-WARNING": (
        _finding("LEVEL-WARNING", "detect-secrets", None, "warning"),
        False,
    ),
    # No scanner named: the global threshold applies.
    "UNNAMED": (_finding("UNNAMED", None, "HIGH"), True),
}


def _model(findings: List[Dict[str, Any]]):
    """The results of a scan judged by the config above, as ASH builds them."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerTargetStatusInfo,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    config = AshConfig.model_validate(
        {
            "project_name": "project",
            "global_settings": {"severity_threshold": GLOBAL},
            "scanners": {
                name: {"enabled": True, "options": {"severity_threshold": threshold}}
                for name, threshold in SCANNER_THRESHOLDS.items()
            },
        }
    )
    model = AshAggregatedResults(ash_config=config)
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "ASH"}}, "results": findings}],
        }
    )
    # Every scanner that ran has an entry, as in a real scan, so the completeness
    # gate passes and the exit code is decided by the findings.
    for name in ("bandit", "semgrep", "detect-secrets"):
        model.scanner_results[name] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED,
            excluded=False,
            dependencies_satisfied=True,
        )
    return model


def _write(output_dir: Path, findings: List[Dict[str, Any]]):
    """The results file and reports/ash.sarif, which the exit code reads."""
    model = _model(findings)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )
    reports = output_dir / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "ash.sarif").write_text(
        json.dumps({"version": "2.1.0", "runs": [{"results": findings}]}),
        encoding="utf-8",
    )
    return model


@pytest.fixture
def root(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    return tmp_path


async def _listed(output_dir: Path, **filters: Any) -> List[str]:
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    result = await get_scan_results(
        ctx, output_dir=str(output_dir), actionable_only=True, **filters
    )
    assert "error" not in result, result
    assert result["findings_count"] == len(result["findings"]), result
    return sorted(finding["rule_id"] for finding in result["findings"])


async def _listed_from(root: Path, *rules: str) -> List[str]:
    output_dir = root / "project" / ".ash" / "ash_output"
    _write(output_dir, [CASES[rule][0] for rule in rules])
    return await _listed(output_dir)


@pytest.mark.asyncio
class TestWhatActionableOnlyLists:
    async def test_an_unsuppressed_finding_below_the_threshold_is_left_out(self, root):
        assert await _listed_from(root, "BELOW-GLOBAL", "AT-GLOBAL") == ["AT-GLOBAL"]

    async def test_an_unsuppressed_finding_at_the_threshold_is_listed(self, root):
        assert await _listed_from(root, "AT-GLOBAL") == ["AT-GLOBAL"]

    async def test_a_suppressed_finding_is_left_out(self, root):
        assert await _listed_from(root, "SUPPRESSED", "AT-GLOBAL") == ["AT-GLOBAL"]


@pytest.mark.asyncio
class TestTheThresholdIsTheOneTheScanWasJudgedBy:
    async def test_a_scanners_own_stricter_threshold_decides_its_findings(self, root):
        """bandit's HIGH finding is at the global HIGH and below bandit's CRITICAL."""
        assert await _listed_from(root, "AT-BANDIT", "BELOW-BANDIT") == ["AT-BANDIT"]

    async def test_a_scanners_own_looser_threshold_decides_its_findings(self, root):
        """semgrep's LOW finding is below the global HIGH and at semgrep's LOW."""
        assert await _listed_from(root, "AT-SEMGREP", "BELOW-SEMGREP") == ["AT-SEMGREP"]

    async def test_the_level_decides_a_finding_that_names_no_severity(self, root):
        assert await _listed_from(root, "LEVEL-ERROR", "LEVEL-WARNING") == [
            "LEVEL-ERROR"
        ]

    async def test_a_finding_that_names_no_scanner_is_judged_by_the_global(self, root):
        assert await _listed_from(root, "UNNAMED") == ["UNNAMED"]

    async def test_the_whole_set_together(self, root):
        expected = sorted(rule for rule, (_f, counts) in CASES.items() if counts)
        assert await _listed_from(root, *CASES) == expected

    async def test_severities_narrow_the_actionable_set_further(self, root):
        """``severities="medium"`` selects nothing here: no MEDIUM finding is actionable."""
        output_dir = root / "project" / ".ash" / "ash_output"
        _write(output_dir, [finding for finding, _counts in CASES.values()])

        assert await _listed(output_dir, severities="medium") == []
        assert await _listed(output_dir, severities="high") == [
            "AT-GLOBAL",
            "UNNAMED",
        ]


@pytest.mark.asyncio
async def test_the_thresholds_read_to_judge_the_findings_are_not_in_the_response(
    root,
):
    """They are read to build the list, like the SARIF, and dropped with it."""
    output_dir = root / "project" / ".ash" / "ash_output"
    _write(output_dir, [CASES["AT-GLOBAL"][0]])
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    result = await get_scan_results(
        ctx, output_dir=str(output_dir), actionable_only=True
    )

    assert "sarif" not in result["raw_results"], sorted(result["raw_results"])
    assert "severity_thresholds" not in result["raw_results"], sorted(
        result["raw_results"]
    )


@pytest.mark.asyncio
class TestTheListIsTheSetThatDecidesExit2:
    """Each finding, alone in a scan: listed exactly when the scan exits 2.

    Asked of ``_compute_exit_code`` rather than written down here, so a change to
    either rule that leaves the other behind fails.
    """

    @pytest.mark.parametrize("rule", list(CASES))
    async def test_listed_exactly_when_the_exit_code_counts_it(self, root, rule):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        output_dir = root / rule / ".ash" / "ash_output"
        model = _write(output_dir, [CASES[rule][0]])

        exit_code = _compute_exit_code(
            model, ScanOptions(source_dir=root / rule, output_dir=output_dir), None
        )
        listed = await _listed(output_dir)

        assert exit_code in (0, 2), exit_code
        assert (rule in listed) == (exit_code == 2), (rule, listed, exit_code)
        assert (exit_code == 2) == CASES[rule][1], (rule, exit_code)
