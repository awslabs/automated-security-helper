"""Regression coverage: in-memory Pydantic suppression state is reliable.

DA followup #44 — restore SARIF re-read regression test coverage.

Background: test_run_ash_scan_decomposed.py::test_actionable_findings_with_fail_on_findings_returns_two
was modified to set mock_results.sarif = None, bypassing the SARIF traversal that
would catch the original "Pydantic in-memory suppression state isn't reliable" concern.

The claim in the bc261ef commit message is that get_unified_scanner_metrics() re-derives
all counts from the final SARIF model via ScannerStatisticsCalculator, which reads
result.suppressions reliably through the Pydantic field accessor (not a stale __dict__
key). The prior disk re-read was masking the issue rather than fixing it.

These tests falsify that claim by exercising the previous failure mode directly:

  1. Build real AshAggregatedResults with known suppressed findings.
  2. Verify the in-memory suppression state is correctly read by _compute_exit_code.
  3. Verify that adding a suppression entry IS reflected in actionable count without
     any disk roundtrip.
  4. Verify the results model is not mutated by _compute_exit_code.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
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


def _make_sarif_result(scanner_name: str, level: Level, suppressed: bool) -> Result:
    """Build a minimal SARIF Result with optional suppression."""
    return Result(
        ruleId="TEST-001",
        level=level,
        message=Message(root=Message1(text="test finding")),
        properties=PropertyBag(scanner_name=scanner_name),
        suppressions=[{"kind": "external", "justification": "test"}] if suppressed else None,
    )


def _make_results_with_suppressed_findings(
    unsuppressed_count: int,
    suppressed_count: int,
    scanner_name: str = "test_scanner",
) -> AshAggregatedResults:
    """Return AshAggregatedResults with a mix of live and suppressed findings."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.default_config import get_default_config

    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()

    results = AshAggregatedResults()
    results.ash_config = get_default_config()
    results.scanner_results[scanner_name] = ScannerTargetStatusInfo(status="FAILED")

    sarif_results = []
    for _ in range(unsuppressed_count):
        sarif_results.append(
            _make_sarif_result(scanner_name, Level.error, suppressed=False)
        )
    for _ in range(suppressed_count):
        sarif_results.append(
            _make_sarif_result(scanner_name, Level.error, suppressed=True)
        )

    results.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                results=sarif_results,
            )
        ],
    )
    return results


class TestInMemorySuppressionStateIsReliable:
    def test_suppressed_findings_not_counted_as_actionable(self, tmp_path):
        """Suppressed SARIF findings must not contribute to actionable count.

        This is the core assertion: if in-memory suppression state were unreliable,
        suppressed findings would be counted as actionable and _compute_exit_code
        would return 2 instead of 0.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        # All 3 findings are suppressed — actionable count must be 0.
        results = _make_results_with_suppressed_findings(
            unsuppressed_count=0, suppressed_count=3
        )

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            fail_on_findings=True,
        )

        with pytest.raises(Exception) if False else __import__("contextlib").nullcontext():
            code = _compute_exit_code(results, opts)

        assert code == 0, (
            "All findings are suppressed; _compute_exit_code must return 0, "
            "not 2. If it returns 2, in-memory suppression state is broken."
        )

    def test_mixed_findings_only_unsuppressed_count_as_actionable(self, tmp_path):
        """Only unsuppressed findings should drive the exit code to 2."""
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        # 2 actionable + 5 suppressed.
        results = _make_results_with_suppressed_findings(
            unsuppressed_count=2, suppressed_count=5
        )

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            fail_on_findings=True,
        )

        code = _compute_exit_code(results, opts)

        assert code == 2, (
            "2 unsuppressed findings with fail_on_findings=True must yield exit code 2."
        )

    def test_adding_suppression_reflected_without_disk_roundtrip(self, tmp_path):
        """Mutating suppressions in-memory must be visible to _compute_exit_code.

        This falsifies the old claim that disk re-read was necessary: if we
        programmatically mark a finding suppressed in memory, the count must
        drop to 0 actionable — no disk write/read required.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        results = _make_results_with_suppressed_findings(
            unsuppressed_count=1, suppressed_count=0
        )

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            fail_on_findings=True,
        )

        # Baseline: 1 unsuppressed → exit 2.
        code_before = _compute_exit_code(results, opts)
        assert code_before == 2

        # Now suppress the finding in memory.
        run = results.sarif.runs[0]
        run.results[0].suppressions = [{"kind": "external", "justification": "added in test"}]

        # After in-memory mutation: 0 unsuppressed → exit 0.
        code_after = _compute_exit_code(results, opts)
        assert code_after == 0, (
            "After suppressing the finding in memory, _compute_exit_code must return 0. "
            "If it still returns 2, the function is not reading the in-memory state."
        )


class TestComputeExitCodeDoesNotMutateResults:
    def test_in_memory_results_not_mutated_during_exit_code_computation(self, tmp_path):
        """_compute_exit_code must not mutate the AshAggregatedResults model.

        This is the canonical approach-a test from DA followup #44: build results
        with known suppressed findings, deepcopy a baseline, call _compute_exit_code,
        then assert the model_dump() is unchanged.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        results = _make_results_with_suppressed_findings(
            unsuppressed_count=1, suppressed_count=2
        )

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            fail_on_findings=True,
        )

        # Snapshot the model state before the call.
        baseline = results.model_dump(mode="python", exclude={"sarif", "cyclonedx"})

        _compute_exit_code(results, opts)

        after = results.model_dump(mode="python", exclude={"sarif", "cyclonedx"})

        assert baseline == after, (
            "_compute_exit_code must not mutate AshAggregatedResults. "
            "If baseline != after, the function has unexpected side effects."
        )

    def test_compute_exit_code_reads_sarif_suppression_not_dict_key(self, tmp_path):
        """_compute_exit_code path through get_unified_scanner_metrics reads result.suppressions.

        ScannerStatisticsCalculator.extract_sarif_counts_for_scanner checks
        `result.suppressions and len(result.suppressions) > 0` — the Pydantic
        field accessor, not a raw dict key. This test confirms that a Result
        with suppressions=[] (empty list) is treated as unsuppressed (actionable).
        """
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.default_config import get_default_config
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _compute_exit_code,
        )

        AshConfig.model_rebuild()
        AshAggregatedResults.model_rebuild()

        results = AshAggregatedResults()
        results.ash_config = get_default_config()
        results.scanner_results["s"] = ScannerTargetStatusInfo(status="FAILED")

        # suppressions=[] means not suppressed (empty list is falsy in the check).
        results.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                    results=[
                        Result(
                            ruleId="R1",
                            level=Level.error,
                            message=Message(root=Message1(text="issue")),
                            properties=PropertyBag(scanner_name="s"),
                            suppressions=[],  # empty → not suppressed
                        )
                    ],
                )
            ],
        )

        opts = ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            fail_on_findings=True,
        )

        code = _compute_exit_code(results, opts)
        assert code == 2, "Finding with empty suppressions list must be counted as actionable."
