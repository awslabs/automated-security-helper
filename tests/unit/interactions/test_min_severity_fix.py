"""Regression tests for #40: --min-severity must filter the exit code.

The severity-filtering block at the end of ``run_ash_scan`` maps SARIF
levels to ASH severity ranks and zeros out ``actionable_findings`` when no
finding meets the threshold.  These tests exercise that logic directly
without running the full scan orchestrator.
"""

from types import SimpleNamespace


# ---------------------------------------------------------------------------
# Inline replica of the severity-filtering block from run_ash_scan.py
# (lines 466-487).  Extracting it here keeps the tests fast and isolated.
# ---------------------------------------------------------------------------
def _filter_actionable(min_severity: str, actionable_findings: int, results) -> int:
    """Return the effective actionable_findings count after severity filtering.

    This mirrors the logic in ``run_ash_scan`` without side-effects.
    """
    _SEVERITY_RANK = {"critical": 3, "high": 3, "medium": 2, "low": 1, "none": 0}
    _SARIF_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low"}

    min_sev_rank = _SEVERITY_RANK.get(min_severity.lower(), 1)
    if min_sev_rank > 0 and actionable_findings > 0 and results is not None:
        has_qualifying = False
        try:
            for run in getattr(results, "runs", []):
                for result in getattr(run, "results", []):
                    level = getattr(result, "level", "note")
                    if isinstance(level, str):
                        level = level.lower()
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


def _make_results(levels):
    """Build a minimal results object with the given SARIF levels."""
    findings = [SimpleNamespace(level=lv) for lv in levels]
    run = SimpleNamespace(results=findings)
    return SimpleNamespace(runs=[run])


class TestMinSeverityFiltering:
    """The severity filter must zero-out actionable_findings when nothing qualifies."""

    def test_high_threshold_ignores_note_findings(self):
        results = _make_results(["note", "note"])
        count = _filter_actionable("high", actionable_findings=2, results=results)
        assert count == 0, "note-level findings should not trigger exit code at high threshold"

    def test_low_threshold_keeps_note_findings(self):
        results = _make_results(["note"])
        count = _filter_actionable("low", actionable_findings=1, results=results)
        assert count == 1, "note-level findings should trigger exit code at low threshold"

    def test_high_threshold_keeps_error_findings(self):
        results = _make_results(["error"])
        count = _filter_actionable("high", actionable_findings=1, results=results)
        assert count == 1, "error-level findings should trigger exit code at high threshold"

    def test_medium_threshold_ignores_note_but_keeps_warning(self):
        results = _make_results(["note", "warning"])
        count = _filter_actionable("medium", actionable_findings=2, results=results)
        assert count == 2, "warning-level finding qualifies at medium threshold"

    def test_no_findings_stays_zero(self):
        results = _make_results([])
        count = _filter_actionable("high", actionable_findings=0, results=results)
        assert count == 0, "zero actionable findings must remain zero"
