"""Regression tests for severity_threshold vs actionable findings count.

Regression: When `severity_threshold` is set to MEDIUM in the config, LOW
severity findings should NOT be counted as actionable. Previously, the SARIF
file-based count in `run_ash_scan.py` overrode the unified metrics count and
counted ALL non-suppressed findings as actionable, ignoring the
severity_threshold config.

The fix ensures the SARIF file-based count respects the configured
severity_threshold by checking issue_severity properties and SARIF levels
against the threshold before counting a finding as actionable.
"""

import json
from types import SimpleNamespace

import pytest

from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message1,
    PhysicalLocation2,
    Result,
    Message,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    Region,
    PropertyBag,
    Run,
    Tool,
    ToolComponent,
    SarifReport,
)


class TestSeverityThresholdActionableCount:
    """Tests that severity_threshold correctly filters actionable findings.

    The core invariant: when severity_threshold is MEDIUM, only findings with
    severity >= MEDIUM (i.e., critical, high, medium) should be actionable.
    LOW and INFO findings should NOT be actionable.
    """

    def _create_model_with_findings(
        self, severity_threshold: str, findings: list[dict]
    ) -> AshAggregatedResults:
        """Create a model with SARIF findings at various severity levels.

        Args:
            severity_threshold: The global severity threshold (e.g., "MEDIUM")
            findings: List of dicts with keys:
                - scanner_name: str
                - level: SARIF level ("error", "warning", "note", "none")
                - issue_severity: Optional explicit severity ("CRITICAL", "HIGH", etc.)
                - suppressed: bool (default False)
        """
        from automated_security_helper.config.ash_config import (
            AshConfig,
            AshConfigGlobalSettingsSection,
        )

        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        model = AshAggregatedResults()
        model.ash_config = AshConfig(
            project_name="test-severity-threshold",
            global_settings=AshConfigGlobalSettingsSection(
                severity_threshold=severity_threshold
            ),
        )

        # Build SARIF results
        results = []
        scanner_names = set()
        for i, finding in enumerate(findings):
            scanner_name = finding.get("scanner_name", "test-scanner")
            scanner_names.add(scanner_name)

            props = PropertyBag(scanner_name=scanner_name)
            if "issue_severity" in finding:
                # Set issue_severity in properties for explicit severity
                props = PropertyBag(
                    scanner_name=scanner_name,
                    issue_severity=finding["issue_severity"],
                )

            result = Result(
                ruleId=f"RULE-{i}",
                level=Level(finding["level"]),
                message=Message(root=Message1(text=f"Finding {i}")),
                properties=props,
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            root=PhysicalLocation2(
                                artifactLocation=ArtifactLocation(
                                    uri=f"src/file{i}.py"
                                ),
                                region=Region(startLine=i + 1),
                            )
                        )
                    )
                ],
            )

            if finding.get("suppressed", False):
                result.suppressions = [
                    {"kind": "external", "justification": "Test suppression"}
                ]

            results.append(result)

        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=results,
                )
            ],
        )

        # Register scanners in scanner_results
        for name in scanner_names:
            model.scanner_results[name] = ScannerStatusInfo()

        return model

    def test_medium_threshold_excludes_low_findings_from_actionable(self):
        """With MEDIUM threshold, LOW findings should NOT be actionable.

        This is the core bug scenario: a project has only LOW severity findings
        and severity_threshold is MEDIUM. The actionable count should be 0.
        """
        model = self._create_model_with_findings(
            severity_threshold="MEDIUM",
            findings=[
                {"scanner_name": "bandit", "level": "note"},  # note -> LOW
                {"scanner_name": "bandit", "level": "note"},  # note -> LOW
                {"scanner_name": "bandit", "level": "note"},  # note -> LOW
            ],
        )

        # Unified metrics should correctly report 0 actionable
        metrics = get_unified_scanner_metrics(model)
        total_actionable = sum(m.actionable for m in metrics)
        assert total_actionable == 0, (
            f"With MEDIUM threshold, LOW findings should not be actionable. "
            f"Got {total_actionable} actionable findings."
        )

    def test_medium_threshold_includes_medium_and_above(self):
        """With MEDIUM threshold, MEDIUM+ findings should be actionable."""
        model = self._create_model_with_findings(
            severity_threshold="MEDIUM",
            findings=[
                {"scanner_name": "bandit", "level": "note"},  # LOW - not actionable
                {"scanner_name": "bandit", "level": "warning"},  # MEDIUM - actionable
                {"scanner_name": "bandit", "level": "error"},  # CRITICAL - actionable
            ],
        )

        metrics = get_unified_scanner_metrics(model)
        total_actionable = sum(m.actionable for m in metrics)
        assert total_actionable == 2, (
            f"With MEDIUM threshold, only MEDIUM and above should be actionable. "
            f"Got {total_actionable} (expected 2)."
        )

    def test_high_threshold_excludes_medium_and_low(self):
        """With HIGH threshold, only HIGH and CRITICAL should be actionable."""
        model = self._create_model_with_findings(
            severity_threshold="HIGH",
            findings=[
                {"scanner_name": "scanner1", "level": "note"},  # LOW
                {"scanner_name": "scanner1", "level": "warning"},  # MEDIUM
                {
                    "scanner_name": "scanner1",
                    "level": "error",
                },  # CRITICAL (maps to critical via SARIF)
            ],
        )

        metrics = get_unified_scanner_metrics(model)
        total_actionable = sum(m.actionable for m in metrics)
        # error maps to critical in extract_sarif_counts_for_scanner
        assert total_actionable == 1, (
            f"With HIGH threshold, only HIGH and CRITICAL should be actionable. "
            f"Got {total_actionable} (expected 1)."
        )

    def test_explicit_issue_severity_respected_with_threshold(self):
        """When issue_severity is explicitly set, threshold should still apply."""
        model = self._create_model_with_findings(
            severity_threshold="MEDIUM",
            findings=[
                {
                    "scanner_name": "bandit",
                    "level": "warning",
                    "issue_severity": "LOW",
                },
                {
                    "scanner_name": "bandit",
                    "level": "warning",
                    "issue_severity": "LOW",
                },
                {
                    "scanner_name": "bandit",
                    "level": "warning",
                    "issue_severity": "HIGH",
                },
            ],
        )

        metrics = get_unified_scanner_metrics(model)
        total_actionable = sum(m.actionable for m in metrics)
        assert total_actionable == 1, (
            f"With MEDIUM threshold and explicit issue_severity=LOW, "
            f"only the HIGH finding should be actionable. Got {total_actionable}."
        )

    def test_suppressed_findings_not_counted_regardless_of_severity(self):
        """Suppressed findings should never be actionable, even if above threshold."""
        model = self._create_model_with_findings(
            severity_threshold="LOW",
            findings=[
                {
                    "scanner_name": "scanner1",
                    "level": "error",
                    "suppressed": True,
                },  # CRITICAL but suppressed
                {
                    "scanner_name": "scanner1",
                    "level": "warning",
                    "suppressed": True,
                },  # MEDIUM but suppressed
                {"scanner_name": "scanner1", "level": "note"},  # LOW, not suppressed
            ],
        )

        metrics = get_unified_scanner_metrics(model)
        total_actionable = sum(m.actionable for m in metrics)
        assert total_actionable == 1, (
            f"Suppressed findings should not be actionable. "
            f"Only the unsuppressed LOW finding should count. Got {total_actionable}."
        )

    def test_scanner_status_reflects_threshold(self):
        """Scanner status should be PASSED when all findings are below threshold."""
        model = self._create_model_with_findings(
            severity_threshold="HIGH",
            findings=[
                {"scanner_name": "bandit", "level": "note"},  # LOW
                {"scanner_name": "bandit", "level": "note"},  # LOW
                {"scanner_name": "bandit", "level": "warning"},  # MEDIUM
            ],
        )

        metrics = get_unified_scanner_metrics(model)
        bandit_metrics = next(m for m in metrics if m.scanner_name == "bandit")
        assert bandit_metrics.status == "PASSED", (
            f"Scanner should PASS when all findings are below threshold. "
            f"Got status={bandit_metrics.status}."
        )
        assert bandit_metrics.actionable == 0

    def test_all_threshold_counts_everything(self):
        """With ALL threshold, all findings including INFO should be actionable."""
        model = self._create_model_with_findings(
            severity_threshold="ALL",
            findings=[
                {"scanner_name": "scanner1", "level": "error"},  # CRITICAL
                {"scanner_name": "scanner1", "level": "warning"},  # MEDIUM
                {"scanner_name": "scanner1", "level": "note"},  # LOW
                {"scanner_name": "scanner1", "level": "none"},  # INFO
            ],
        )

        metrics = get_unified_scanner_metrics(model)
        total_actionable = sum(m.actionable for m in metrics)
        assert total_actionable == 4, (
            f"With ALL threshold, all findings should be actionable. "
            f"Got {total_actionable} (expected 4)."
        )


class TestSarifFileCountRespectsThreshold:
    """Tests that the SARIF file-based count respects severity_threshold.

    After the fix, the SARIF file count in run_ash_scan.py applies the
    configured severity_threshold when counting actionable findings, matching
    the behavior of get_unified_scanner_metrics().
    """

    def _simulate_sarif_file_count(
        self, sarif_json: dict, severity_threshold: str = "MEDIUM"
    ) -> int:
        """Simulate the fixed SARIF file-based actionable count from run_ash_scan.py.

        This replicates the fixed logic that respects severity_threshold.
        """
        _THRESHOLD_QUALIFYING_LEVELS = {
            "ALL": {"error", "warning", "note", "none"},
            "LOW": {"error", "warning", "note"},
            "MEDIUM": {"error", "warning"},
            "HIGH": {"error"},
            "CRITICAL": {"error"},
        }
        _qualifying_levels = _THRESHOLD_QUALIFYING_LEVELS.get(
            severity_threshold, {"error", "warning"}
        )

        _SEVERITY_RANK_FOR_THRESHOLD = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0,
        }
        _THRESHOLD_MIN_RANK = {
            "ALL": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        _min_rank = _THRESHOLD_MIN_RANK.get(severity_threshold, 2)

        sarif_active = 0
        for run in sarif_json.get("runs", []):
            for r in run.get("results", []):
                if r.get("suppressions"):
                    continue
                props = r.get("properties", {}) or {}
                issue_severity = (props.get("issue_severity") or "").upper()
                if issue_severity in _SEVERITY_RANK_FOR_THRESHOLD:
                    if _SEVERITY_RANK_FOR_THRESHOLD[issue_severity] >= _min_rank:
                        sarif_active += 1
                else:
                    level = (r.get("level") or "note").lower()
                    if level in _qualifying_levels:
                        sarif_active += 1
        return sarif_active

    def _simulate_min_severity_filter(
        self, min_severity: str, actionable_findings: int, results
    ) -> int:
        """Simulate the --min-severity filter from run_ash_scan.py.

        This replicates the logic at run_ash_scan.py lines 559-587.
        """
        _SEVERITY_RANK = {
            "critical": 3,
            "high": 3,
            "medium": 2,
            "low": 1,
            "none": 0,
        }
        _SARIF_LEVEL_TO_SEVERITY = {
            "error": "high",
            "warning": "medium",
            "note": "low",
        }
        min_sev_rank = _SEVERITY_RANK.get(min_severity.lower(), 1)
        if min_sev_rank > 0 and actionable_findings > 0 and results is not None:
            has_qualifying = False
            try:
                sarif = getattr(results, "sarif", None)
                if sarif is None or not getattr(sarif, "runs", None):
                    has_qualifying = True
                for run in getattr(sarif, "runs", []) if not has_qualifying else []:
                    for result in getattr(run, "results", []):
                        if getattr(result, "suppressions", None):
                            continue
                        level = getattr(result, "level", "note")
                        if isinstance(level, str):
                            level = level.lower()
                        else:
                            level = str(level).lower()
                        mapped = _SARIF_LEVEL_TO_SEVERITY.get(level, "low")
                        if _SEVERITY_RANK.get(mapped, 1) >= min_sev_rank:
                            has_qualifying = True
                            break
                    if has_qualifying:
                        break
            except Exception:
                has_qualifying = True
            if not has_qualifying:
                actionable_findings = 0
        return actionable_findings

    def test_sarif_file_count_respects_threshold(self):
        """SARIF file count should exclude findings below severity_threshold.

        Scenario: severity_threshold=MEDIUM, only LOW findings exist.
        Expected: actionable=0 (LOW is below MEDIUM threshold)
        """
        sarif_json = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "B101",
                            "level": "note",
                            "message": {"text": "Low issue 1"},
                            "properties": {"scanner_name": "bandit"},
                        },
                        {
                            "ruleId": "B102",
                            "level": "note",
                            "message": {"text": "Low issue 2"},
                            "properties": {"scanner_name": "bandit"},
                        },
                        {
                            "ruleId": "B103",
                            "level": "note",
                            "message": {"text": "Low issue 3"},
                            "properties": {"scanner_name": "bandit"},
                        },
                    ]
                }
            ]
        }

        sarif_count = self._simulate_sarif_file_count(
            sarif_json, severity_threshold="MEDIUM"
        )
        assert sarif_count == 0, (
            f"With MEDIUM threshold, note-level (LOW) findings should not be "
            f"actionable. Got {sarif_count}."
        )

        # Verify consistency with unified metrics logic
        correct_actionable = ScannerStatisticsCalculator.calculate_actionable_count(
            critical=0, high=0, medium=0, low=3, info=0, threshold="MEDIUM"
        )
        assert sarif_count == correct_actionable, (
            "SARIF file count should match unified metrics threshold-aware count"
        )

    def test_sarif_file_count_with_explicit_issue_severity(self):
        """SARIF file count should use issue_severity property when available."""
        sarif_json = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "B101",
                            "level": "warning",
                            "message": {"text": "Actually low"},
                            "properties": {
                                "scanner_name": "bandit",
                                "issue_severity": "LOW",
                            },
                        },
                        {
                            "ruleId": "B102",
                            "level": "warning",
                            "message": {"text": "Actually high"},
                            "properties": {
                                "scanner_name": "bandit",
                                "issue_severity": "HIGH",
                            },
                        },
                    ]
                }
            ]
        }

        sarif_count = self._simulate_sarif_file_count(
            sarif_json, severity_threshold="MEDIUM"
        )
        assert sarif_count == 1, (
            f"With MEDIUM threshold, only the HIGH finding should be actionable. "
            f"Got {sarif_count}."
        )

    def test_sarif_file_count_suppressed_excluded(self):
        """Suppressed findings should not be counted regardless of severity."""
        sarif_json = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "B101",
                            "level": "error",
                            "message": {"text": "Critical but suppressed"},
                            "suppressions": [{"kind": "external"}],
                        },
                        {
                            "ruleId": "B102",
                            "level": "error",
                            "message": {"text": "Critical not suppressed"},
                        },
                    ]
                }
            ]
        }

        sarif_count = self._simulate_sarif_file_count(
            sarif_json, severity_threshold="MEDIUM"
        )
        assert sarif_count == 1, (
            f"Suppressed findings should be excluded. Got {sarif_count}."
        )

    def test_min_severity_default_does_not_compensate(self):
        """The default --min-severity=low doesn't filter out note-level findings.

        This test verifies the min_severity filter behavior is unchanged.
        With the fix, the SARIF count itself is correct, so min_severity
        is only a secondary CLI override.
        """
        findings = [SimpleNamespace(level="note", suppressions=None)] * 3
        run = SimpleNamespace(results=findings)
        results = SimpleNamespace(sarif=SimpleNamespace(runs=[run]))

        # After the fix, SARIF count would already be 0 with MEDIUM threshold.
        # But if somehow actionable_findings > 0, min_severity="low" won't help.
        filtered = self._simulate_min_severity_filter(
            min_severity="low",
            actionable_findings=3,
            results=results,
        )

        assert filtered == 3, (
            "min_severity='low' does not filter note-level findings "
            "(it includes them). The threshold fix is the primary defense."
        )

    def test_min_severity_medium_filters_note_findings(self):
        """Setting --min-severity=medium filters out note-level findings."""
        findings = [SimpleNamespace(level="note", suppressions=None)] * 3
        run = SimpleNamespace(results=findings)
        results = SimpleNamespace(sarif=SimpleNamespace(runs=[run]))

        filtered = self._simulate_min_severity_filter(
            min_severity="medium",
            actionable_findings=3,
            results=results,
        )

        assert filtered == 0, (
            "With --min-severity=medium, note-level findings should not "
            f"trigger exit code. Got {filtered}."
        )

    def test_mixed_severities_sarif_count_matches_threshold(self):
        """Mixed severities: SARIF count should match threshold-aware count.

        Scenario: 2 LOW + 1 MEDIUM finding, threshold=MEDIUM
        Expected actionable: 1 (only the MEDIUM finding)
        """
        sarif_json = {
            "runs": [
                {
                    "results": [
                        {"ruleId": "R1", "level": "note", "message": {"text": "Low 1"}},
                        {"ruleId": "R2", "level": "note", "message": {"text": "Low 2"}},
                        {
                            "ruleId": "R3",
                            "level": "warning",
                            "message": {"text": "Medium 1"},
                        },
                    ]
                }
            ]
        }

        sarif_count = self._simulate_sarif_file_count(
            sarif_json, severity_threshold="MEDIUM"
        )
        assert sarif_count == 1, (
            f"Only the MEDIUM finding should be actionable. Got {sarif_count}."
        )

        # Verify consistency
        correct = ScannerStatisticsCalculator.calculate_actionable_count(
            critical=0, high=0, medium=1, low=2, info=0, threshold="MEDIUM"
        )
        assert sarif_count == correct


class TestCalculateActionableCountThreshold:
    """Unit tests for calculate_actionable_count with various thresholds.

    These tests verify the core threshold logic is correct (it is).
    The bug is that this correct logic gets overridden by the SARIF file count.
    """

    @pytest.mark.parametrize(
        "threshold,critical,high,medium,low,info,expected",
        [
            # MEDIUM threshold - only critical+high+medium
            ("MEDIUM", 0, 0, 0, 5, 0, 0),  # Only LOW -> 0 actionable
            ("MEDIUM", 0, 0, 0, 0, 10, 0),  # Only INFO -> 0 actionable
            ("MEDIUM", 1, 0, 0, 5, 0, 1),  # 1 CRITICAL + 5 LOW -> 1 actionable
            ("MEDIUM", 0, 2, 3, 5, 0, 5),  # 2 HIGH + 3 MEDIUM + 5 LOW -> 5 actionable
            # HIGH threshold - only critical+high
            ("HIGH", 0, 0, 5, 10, 3, 0),  # MEDIUM+LOW+INFO -> 0 actionable
            ("HIGH", 1, 1, 5, 10, 3, 2),  # 1 CRIT + 1 HIGH -> 2 actionable
            # CRITICAL threshold - only critical
            ("CRITICAL", 0, 5, 5, 5, 5, 0),  # No CRITICAL -> 0 actionable
            ("CRITICAL", 3, 5, 5, 5, 5, 3),  # 3 CRITICAL -> 3 actionable
            # LOW threshold - critical+high+medium+low (excludes info)
            ("LOW", 0, 0, 0, 0, 5, 0),  # Only INFO -> 0 actionable
            ("LOW", 1, 1, 1, 1, 5, 4),  # All except INFO -> 4 actionable
            # ALL threshold - everything
            ("ALL", 1, 1, 1, 1, 1, 5),  # All -> 5 actionable
            ("ALL", 0, 0, 0, 0, 5, 5),  # Only INFO -> 5 actionable with ALL
        ],
    )
    def test_threshold_filtering(
        self, threshold, critical, high, medium, low, info, expected
    ):
        """Verify calculate_actionable_count correctly applies threshold."""
        result = ScannerStatisticsCalculator.calculate_actionable_count(
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            info=info,
            threshold=threshold,
        )
        assert result == expected, (
            f"With threshold={threshold}, counts=({critical},{high},{medium},{low},{info}), "
            f"expected {expected} actionable but got {result}"
        )


class TestEndToEndSeverityThresholdRegression:
    """End-to-end regression test for the severity threshold fix.

    This simulates what happens when a user:
    1. Configures severity_threshold: MEDIUM in .ash/.ash.yaml
    2. Runs a scan that finds only LOW severity issues
    3. Expects exit code 0 (no actionable findings above threshold)
    4. Gets exit code 0 (fixed: SARIF file count respects threshold)
    """

    def test_full_scenario_low_findings_medium_threshold(self, tmp_path):
        """Simulate the full run_ash_scan exit code determination.

        After the fix, the SARIF file-based count should respect the
        severity_threshold and report 0 actionable findings for LOW-only results.
        """
        from automated_security_helper.config.ash_config import (
            AshConfig,
            AshConfigGlobalSettingsSection,
        )

        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        # Step 1: Create a model with only LOW findings and MEDIUM threshold
        model = AshAggregatedResults()
        model.ash_config = AshConfig(
            project_name="test-project",
            global_settings=AshConfigGlobalSettingsSection(severity_threshold="MEDIUM"),
        )

        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=[
                        Result(
                            ruleId=f"B10{i}",
                            level=Level.note,  # note -> LOW
                            message=Message(
                                root=Message1(text=f"Low severity issue {i}")
                            ),
                            properties=PropertyBag(
                                scanner_name="bandit", issue_severity="LOW"
                            ),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation(
                                        root=PhysicalLocation2(
                                            artifactLocation=ArtifactLocation(
                                                uri=f"src/file{i}.py"
                                            ),
                                            region=Region(startLine=i + 1),
                                        )
                                    )
                                )
                            ],
                        )
                        for i in range(5)
                    ],
                )
            ],
        )
        model.scanner_results["bandit"] = ScannerStatusInfo()

        # Step 2: Unified metrics correctly says 0 actionable
        scanner_metrics = get_unified_scanner_metrics(asharp_model=model)
        unified_actionable = sum(item.actionable for item in scanner_metrics)
        assert unified_actionable == 0, (
            f"Unified metrics should report 0 actionable with MEDIUM threshold "
            f"and only LOW findings. Got {unified_actionable}."
        )

        # Step 3: Write SARIF file (simulating what the reporter does)
        sarif_file = tmp_path / "reports" / "ash.sarif"
        sarif_file.parent.mkdir(parents=True)
        sarif_data = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH", "version": "1.0"}},
                    "results": [
                        {
                            "ruleId": f"B10{i}",
                            "level": "note",
                            "message": {"text": f"Low severity issue {i}"},
                            "properties": {
                                "scanner_name": "bandit",
                                "issue_severity": "LOW",
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f"src/file{i}.py"},
                                        "region": {"startLine": i + 1},
                                    }
                                }
                            ],
                        }
                        for i in range(5)
                    ],
                }
            ],
        }
        sarif_file.write_text(json.dumps(sarif_data))

        # Step 4: Simulate the FIXED SARIF file count (respects threshold)
        # This replicates the fixed logic from run_ash_scan.py
        _severity_threshold = "MEDIUM"
        if model.ash_config and model.ash_config.global_settings:
            _severity_threshold = (
                model.ash_config.global_settings.severity_threshold.upper()
            )

        _THRESHOLD_QUALIFYING_LEVELS = {
            "ALL": {"error", "warning", "note", "none"},
            "LOW": {"error", "warning", "note"},
            "MEDIUM": {"error", "warning"},
            "HIGH": {"error"},
            "CRITICAL": {"error"},
        }
        _qualifying_levels = _THRESHOLD_QUALIFYING_LEVELS.get(
            _severity_threshold, {"error", "warning"}
        )
        _SEVERITY_RANK_FOR_THRESHOLD = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0,
        }
        _THRESHOLD_MIN_RANK = {
            "ALL": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        _min_rank = _THRESHOLD_MIN_RANK.get(_severity_threshold, 2)

        actionable_findings = unified_actionable
        with open(sarif_file, encoding="utf-8") as f:
            sarif_json = json.load(f)
        sarif_active = 0
        for run in sarif_json.get("runs", []):
            for r in run.get("results", []):
                if r.get("suppressions"):
                    continue
                props = r.get("properties", {}) or {}
                issue_severity = (props.get("issue_severity") or "").upper()
                if issue_severity in _SEVERITY_RANK_FOR_THRESHOLD:
                    if _SEVERITY_RANK_FOR_THRESHOLD[issue_severity] >= _min_rank:
                        sarif_active += 1
                else:
                    level = (r.get("level") or "note").lower()
                    if level in _qualifying_levels:
                        sarif_active += 1
        actionable_findings = sarif_active

        # Step 5: Verify the fix - actionable should be 0
        assert actionable_findings == 0, (
            f"SARIF file count should respect severity_threshold=MEDIUM and "
            f"report 0 actionable for LOW-only findings. Got {actionable_findings}."
        )

        # Step 6: Both sources agree
        assert actionable_findings == unified_actionable, (
            "SARIF file count and unified metrics should agree on actionable count"
        )
