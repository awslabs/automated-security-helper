"""The collector's verdict: three answers from ``ash merge``, and when exit 1 is not one.

``ash merge`` exits 0 for a clean scan, 2 for findings, and 1 both for a scan that
finished with partial coverage and for an error during execution. The collector
separates the last two by reading the merged report, and these tests drive
``collect.main`` against a stand-in ``ash merge`` that writes a chosen report and
exits a chosen code, so each mapping is measured through the real index walk and
the real termination message rather than by calling the mapping function alone.
"""

from __future__ import annotations

import builtins
import json
import sys
import textwrap
from pathlib import Path

import pytest

from ash_operator.attempts import run_prefix
from ash_operator.constants import (
    PHASE_CLEAN,
    PHASE_FINDINGS,
    PHASE_INCOMPLETE,
    PHASE_REFUSED,
)
from ash_operator.entrypoints import collect
from tests.test_attempts import publish

FAKE_MERGE = textwrap.dedent(
    """
    import json, os, sys
    argv = sys.argv[1:]
    out = argv[argv.index("--output-dir") + 1]
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "ash_aggregated_results.json"), "w") as handle:
        handle.write(os.environ["FAKE_MERGED_REPORT"])
    sys.exit(int(os.environ["FAKE_MERGE_EXIT"]))
    """
)


def merged_report(statuses: dict[str, str], *, actionable: int) -> str:
    return json.dumps(
        {
            "metadata": {
                "summary_stats": {"total": actionable, "actionable": actionable, "suppressed": 0},
                "merged_shard_count": 2,
                "merged_shard_indices": [0, 1],
            },
            "scanner_results": {
                name: {"status": status, "finding_count": 0} for name, status in statuses.items()
            },
        }
    )


def run_collector(tmp_path: Path, monkeypatch, *, exit_code: int, report: str) -> tuple[int, dict]:
    prefix = run_prefix(str(tmp_path / "results"), "uid-under-test")
    for index in (0, 1):
        publish(prefix, index, f"job-{index}-a", shard_count=2)
    script = tmp_path / "fake_merge.py"
    script.write_text(FAKE_MERGE)
    monkeypatch.setenv("FAKE_MERGED_REPORT", report)
    monkeypatch.setenv("FAKE_MERGE_EXIT", str(exit_code))
    termination = tmp_path / "termination-log"
    returned = collect.main(
        [
            "--prefix",
            prefix,
            "--shard-count",
            "2",
            "--merge-output",
            str(tmp_path / "merged"),
            "--termination-message-path",
            str(termination),
            "--",
            sys.executable,
            str(script),
        ]
    )
    return returned, json.loads(termination.read_text())


class TestTheThreeAnswers:
    def test_exit_zero_is_clean(self, tmp_path, monkeypatch):
        code, summary = run_collector(
            tmp_path,
            monkeypatch,
            exit_code=0,
            report=merged_report({"bandit": "PASSED", "detect-secrets": "PASSED"}, actionable=0),
        )
        assert code == 0
        assert summary["phase"] == PHASE_CLEAN
        # True only from ASH's own rule. Without ASH the collector can see scanner
        # statuses alone, so it reports coverage as unknown rather than complete.
        expected = {"ash-coverage-rule": True, "scanner-statuses": None}
        assert summary["coverageComplete"] is expected[summary["coverageSource"]]

    def test_exit_zero_without_ash_reports_coverage_unknown(self, tmp_path, monkeypatch):
        block_ash_import(monkeypatch)
        code, summary = run_collector(
            tmp_path,
            monkeypatch,
            exit_code=0,
            report=merged_report({"bandit": "PASSED", "detect-secrets": "PASSED"}, actionable=0),
        )
        assert code == 0
        assert summary["phase"] == PHASE_CLEAN
        assert summary["coverageSource"] == "scanner-statuses"
        assert summary["coverageComplete"] is None

    def test_exit_one_without_ash_and_no_visible_gap_is_still_refused(self, tmp_path, monkeypatch):
        block_ash_import(monkeypatch)
        code, summary = run_collector(
            tmp_path,
            monkeypatch,
            exit_code=1,
            report=merged_report({"bandit": "PASSED", "detect-secrets": "PASSED"}, actionable=0),
        )
        assert code == 1
        assert summary["phase"] == PHASE_REFUSED

    def test_exit_two_is_findings(self, tmp_path, monkeypatch):
        code, summary = run_collector(
            tmp_path,
            monkeypatch,
            exit_code=2,
            report=merged_report({"bandit": "FAILED", "detect-secrets": "PASSED"}, actionable=3),
        )
        assert code == 2
        assert summary["phase"] == PHASE_FINDINGS
        assert summary["findings"]["actionable"] == 3

    def test_exit_one_over_a_gap_is_incomplete_and_keeps_its_partial_results(
        self, tmp_path, monkeypatch
    ):
        code, summary = run_collector(
            tmp_path,
            monkeypatch,
            exit_code=1,
            report=merged_report({"bandit": "FAILED", "grype": "MISSING"}, actionable=2),
        )
        assert code == 1
        assert summary["phase"] == PHASE_INCOMPLETE
        assert summary["coverageComplete"] is False
        assert any("grype" in gap for gap in summary["coverageGaps"]), summary["coverageGaps"]
        assert summary["findings"]["actionable"] == 2
        assert summary["refusal"] is None

    def test_exit_one_with_no_gap_is_refused(self, tmp_path, monkeypatch):
        # ASH's "error during execution" after the merged report was written. There
        # is no partial result to report, so this must not read as Incomplete.
        code, summary = run_collector(
            tmp_path,
            monkeypatch,
            exit_code=1,
            report=merged_report({"bandit": "PASSED", "detect-secrets": "PASSED"}, actionable=0),
        )
        assert code == 1
        assert summary["phase"] == PHASE_REFUSED
        assert "names no coverage gap" in summary["refusal"]


class TestCoverageAssessment:
    def test_ash_answers_when_it_is_importable(self):
        pytest.importorskip(
            "automated_security_helper.core.resource_management.scan_tracking",
            reason=(
                "ASH is not importable here, so ASH's own coverage rule did not run. "
                "A real gap in coverage, not a pass."
            ),
        )
        report = json.loads(merged_report({"bandit": "PASSED", "grype": "MISSING"}, actionable=0))
        coverage = collect.assess_coverage(report)
        assert coverage["source"] == "ash-coverage-rule"
        assert coverage["complete"] is False
        assert coverage["gaps"] == ["scanner grype: missing_dependencies"]

    def test_every_scanner_skipped_is_a_gap_not_a_clean_scan(self, monkeypatch):
        block_ash_import(monkeypatch)
        report = json.loads(merged_report({"bandit": "SKIPPED", "grype": "SKIPPED"}, actionable=0))
        coverage = collect.assess_coverage(report)
        assert coverage == {
            "complete": False,
            "source": "scanner-statuses",
            "gaps": ["no scanner ran"],
        }

    def test_the_fallback_names_its_source(self, monkeypatch):
        block_ash_import(monkeypatch)
        report = json.loads(merged_report({"bandit": "PASSED", "grype": "ERROR"}, actionable=0))
        coverage = collect.assess_coverage(report)
        assert coverage["source"] == "scanner-statuses"
        assert coverage["complete"] is False
        assert coverage["gaps"] == ["scanner grype: ERROR"]

    def test_the_fallback_never_certifies_complete_coverage(self, monkeypatch):
        # Scanner statuses cannot see a converter, rule or content-database gap, so
        # every scanner PASSED is "no gap visible here", not "complete".
        block_ash_import(monkeypatch)
        report = json.loads(merged_report({"bandit": "PASSED", "grype": "FAILED"}, actionable=1))
        coverage = collect.assess_coverage(report)
        assert coverage == {"complete": None, "source": "scanner-statuses", "gaps": []}

    def test_an_unrecognized_status_is_a_gap(self, monkeypatch):
        block_ash_import(monkeypatch)
        report = json.loads(merged_report({"bandit": "QUARANTINED"}, actionable=0))
        assert collect.assess_coverage(report)["complete"] is False

    def test_a_report_with_no_scanners_cannot_be_assessed(self, monkeypatch):
        block_ash_import(monkeypatch)
        assert collect.assess_coverage({"scanner_results": {}})["complete"] is None


def block_ash_import(monkeypatch) -> None:
    """Make ``automated_security_helper`` unimportable, as in a uv-tool ASH image."""
    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.startswith("automated_security_helper"):
            raise ImportError(f"blocked for the test: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)


class TestVerdictPhase:
    @pytest.mark.parametrize(
        ("exit_code", "coverage", "phase"),
        [
            (0, True, PHASE_CLEAN),
            (0, False, PHASE_CLEAN),
            (2, True, PHASE_FINDINGS),
            (2, False, PHASE_FINDINGS),
            (1, False, PHASE_INCOMPLETE),
            (1, True, PHASE_REFUSED),
            (1, None, PHASE_REFUSED),
            (3, False, PHASE_REFUSED),
            (None, True, PHASE_REFUSED),
        ],
    )
    def test_the_mapping(self, exit_code, coverage, phase):
        assert collect.verdict_phase(exit_code=exit_code, coverage_complete=coverage) == phase
