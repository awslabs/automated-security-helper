"""TDD: Reproduce the exact suppression timing bug.

The offline CI job shows 14 unsuppressed findings despite ignore_paths matching.
This test simulates the full flow:
1. Scanner produces SARIF with findings
2. sanitize_sarif_paths normalizes URIs
3. apply_suppressions_to_sarif drops findings matching ignore_paths
4. merge_sarif_report reconstructs Result objects into aggregated SARIF
5. Final suppression pass on aggregated SARIF
6. get_unified_scanner_metrics counts actionable findings

The bug: somewhere between steps 3 and 6, findings reappear or aren't suppressed.
"""

import sys
from pathlib import Path

import pytest
from unittest.mock import MagicMock

from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import SarifReport, Run, Result
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    sanitize_sarif_paths,
)
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.models.asharp_model import AshAggregatedResults


def _make_finding(uri: str, rule_id: str = "CKV_AWS_56") -> dict:
    return {
        "ruleId": rule_id,
        "message": {"text": f"Finding {rule_id}"},
        "level": "warning",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 3},
            }
        }],
    }


def _make_sarif(*findings_dicts) -> SarifReport:
    run_dict = {
        "tool": {"driver": {"name": "checkov", "version": "3.2.0"}},
        "results": list(findings_dicts),
    }
    return SarifReport(runs=[Run(**run_dict)])


_SOURCE_DIR = "D:\\repo" if sys.platform == "win32" else "/src"
_OUTPUT_DIR = "D:\\out" if sys.platform == "win32" else "/out"


def _prefix(relative_path: str) -> str:
    """Prefix a relative path with the platform source dir + /."""
    sep = "/" if sys.platform != "win32" else "/"
    return f"{_SOURCE_DIR.replace(chr(92), sep)}/{relative_path}"


def _make_context(ignore_paths: list[str], source_dir: str = _SOURCE_DIR):
    ctx = MagicMock()
    ctx.source_dir = Path(source_dir)
    ctx.output_dir = Path(_OUTPUT_DIR)
    ctx.ignore_suppressions = False
    ctx.config = MagicMock()
    ctx.config.global_settings = MagicMock()
    ctx.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=p, reason="test") for p in ignore_paths
    ]
    ctx.config.global_settings.suppressions = []
    return ctx


class TestSuppressionTimingBug:
    """Reproduce the exact sequence that causes 14 findings to escape suppression."""

    def test_step1_sanitize_strips_source_prefix(self):
        """Verify sanitize_sarif_paths strips the source_dir prefix from URIs."""
        if sys.platform == "win32":
            source_dir = "D:\\repo"
            finding_uri = "D:/repo/tests/test_data/scanners/cdk/foo.yaml"
        else:
            source_dir = "/src"
            finding_uri = "/src/tests/test_data/scanners/cdk/foo.yaml"

        sarif = _make_sarif(_make_finding(finding_uri))
        sanitized = sanitize_sarif_paths(sarif, source_dir)
        uri = sanitized.runs[0].results[0].locations[0].physicalLocation.root.artifactLocation.uri
        assert uri == "tests/test_data/scanners/cdk/foo.yaml", f"Got: {uri}"

    def test_step2_suppress_drops_ignored_finding(self):
        """After sanitization, apply_suppressions drops the finding."""
        sarif = _make_sarif(_make_finding(_prefix("tests/test_data/scanners/cdk/foo.yaml")))
        sanitized = sanitize_sarif_paths(sarif, _SOURCE_DIR)
        ctx = _make_context(["tests/test_data/**"])
        result = apply_suppressions_to_sarif(sanitized, ctx)
        remaining = result.runs[0].results
        assert len(remaining) == 0, f"Expected 0, got {len(remaining)}"

    def test_step3_merge_reconstructs_results(self):
        """merge_sarif_report creates NEW Result objects via model_dump + reconstruct."""
        sarif = _make_sarif(
            _make_finding("tests/test_data/scanners/cdk/foo.yaml"),
            _make_finding("automated_security_helper/cli/scan.py"),
        )
        aggregated = SarifReport(runs=[Run(
            tool=sarif.runs[0].tool,
            results=[],
        )])
        aggregated.merge_sarif_report(sarif)
        assert len(aggregated.runs[0].results) == 2

    def test_step4_suppress_then_merge_loses_suppression(self):
        """THE BUG: Does suppress → merge cause dropped findings to reappear?

        If apply_suppressions drops a finding (removes from results list),
        and THEN merge_sarif_report is called, the dropped finding should
        NOT reappear in the aggregated SARIF.
        """
        # Simulate per-scanner flow: sanitize → suppress → merge
        sarif = _make_sarif(
            _make_finding(_prefix("tests/test_data/scanners/cdk/foo.yaml")),
            _make_finding(_prefix("automated_security_helper/cli/scan.py")),
        )
        ctx = _make_context(["tests/test_data/**"])

        # Step 1: Sanitize (like scan_phase.py:801)
        sanitized = sanitize_sarif_paths(sarif, _SOURCE_DIR)

        # Step 2: Suppress (like scan_phase.py:812) — should drop test_data finding
        suppressed = apply_suppressions_to_sarif(sanitized, ctx)
        assert len(suppressed.runs[0].results) == 1, (
            f"After suppress, expected 1 result (scan.py only), got {len(suppressed.runs[0].results)}"
        )

        # Step 3: Merge into aggregated (like scan_phase.py:1512)
        aggregated = SarifReport(runs=[Run(
            tool=sarif.runs[0].tool,
            results=[],
        )])
        aggregated.merge_sarif_report(suppressed)

        # The test_data finding should NOT reappear
        assert len(aggregated.runs[0].results) == 1, (
            f"After merge, expected 1 result, got {len(aggregated.runs[0].results)}"
        )

    def test_step5_full_flow_metrics_show_zero_actionable(self):
        """End-to-end: sanitize → suppress → merge → metrics should be 0 actionable
        for findings on ignored paths."""
        sarif = _make_sarif(
            _make_finding("/src/tests/test_data/scanners/cdk/foo.yaml"),
        )
        ctx = _make_context(["tests/test_data/**"])

        sanitized = sanitize_sarif_paths(sarif, "/src")
        suppressed = apply_suppressions_to_sarif(sanitized, ctx)

        # Build aggregated model
        model = AshAggregatedResults()
        model.sarif = SarifReport(runs=[Run(
            tool=sarif.runs[0].tool,
            results=[],
        )])
        model.sarif.merge_sarif_report(suppressed)

        # Count actionable via unified metrics
        metrics = get_unified_scanner_metrics(asharp_model=model)
        total_actionable = sum(m.actionable for m in metrics)
        assert total_actionable == 0, (
            f"Expected 0 actionable after full flow, got {total_actionable}"
        )

    def test_step6_double_process_results_flow(self):
        """Simulate _process_results calling sanitize+suppress AGAIN after _execute_scanner.

        scan_phase.py does:
        1. _execute_scanner: sanitize(801) → suppress(812) → store in container
        2. _process_results: sanitize(1433) → suppress(1439) → merge(1512)

        Does the second sanitize+suppress on already-processed data cause issues?
        """
        sarif = _make_sarif(
            _make_finding("/src/tests/test_data/scanners/cdk/foo.yaml"),
            _make_finding("/src/automated_security_helper/cli/scan.py"),
        )
        ctx = _make_context(["tests/test_data/**"])

        # First pass (like _execute_scanner)
        sanitized1 = sanitize_sarif_paths(sarif, "/src")
        suppressed1 = apply_suppressions_to_sarif(sanitized1, ctx)
        assert len(suppressed1.runs[0].results) == 1

        # Second pass (like _process_results) on the SAME object
        sanitized2 = sanitize_sarif_paths(suppressed1, "/src")
        suppressed2 = apply_suppressions_to_sarif(sanitized2, ctx)
        assert len(suppressed2.runs[0].results) == 1

        # Merge
        aggregated = SarifReport(runs=[Run(
            tool=sarif.runs[0].tool,
            results=[],
        )])
        aggregated.merge_sarif_report(suppressed2)
        assert len(aggregated.runs[0].results) == 1

        # The remaining finding should be scan.py (not test_data)
        uri = aggregated.runs[0].results[0].locations[0].physicalLocation.root.artifactLocation.uri
        assert "scan.py" in uri, f"Expected scan.py, got: {uri}"
