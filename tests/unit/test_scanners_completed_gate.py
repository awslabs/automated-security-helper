# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for .github/scripts/assert_scanners_completed.py.

``tests/unit/test_external_target_scan_gate.py`` is the precedent for testing a gate
script that lives outside the package.

What this file pins so far
--------------------------
The set-level assertion: at least one scanner must have executed. Every status is
judged individually elsewhere in the script, and SKIPPED has to stay tolerated
there, so a results file in which *every* entry is SKIPPED passed the per-scanner
loop while having measured nothing.

The controls matter as much as the failing case. A script rewritten to return 1
unconditionally would satisfy the first test here and break every real job, so a
narrowed run and one shard of a sharded run are pinned as passing.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = REPO_ROOT / ".github" / "scripts" / "assert_scanners_completed.py"


def _load_gate():
    """Import the gate by path.

    ``.github/scripts`` is not a package and cannot be imported as one. Registered
    in ``sys.modules`` under a name of its own so nothing else in the worker picks
    up a half-initialised module.
    """
    spec = importlib.util.spec_from_file_location(
        "ash_assert_scanners_completed", GATE_PATH
    )
    assert spec is not None and spec.loader is not None, GATE_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _write(tmp_path, scanner_results, summary_stats=None):
    """Write a results file carrying *scanner_results* and return its path."""
    payload = {"scanner_results": scanner_results}
    if summary_stats is not None:
        payload["metadata"] = {"summary_stats": summary_stats}
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run(path):
    """Invoke ``main`` with *path* as the sole positional argument."""
    argv = sys.argv
    sys.argv = ["assert_scanners_completed.py", str(path)]
    try:
        return gate.main()
    finally:
        sys.argv = argv


def _entry(status, **extra):
    record = {"status": status, "dependencies_satisfied": True, "excluded": False}
    record.update(extra)
    return record


class TestNothingRanIsAFailure:
    def test_every_scanner_skipped_fails(self, tmp_path, capsys):
        """The regression a typo in --scanners produces.

        Measured on this tree: ``ash scan --scanners detect_secrets`` -- underscore,
        where the registered name is ``detect-secrets`` -- matched no scanner, so all
        ten took the not-selected path and the results file held ten SKIPPED entries
        with zero findings. Every status was individually legitimate, so the
        per-scanner loop found nothing to report, and this script returned 0 for a
        job that had scanned nothing.
        """
        path = _write(
            tmp_path,
            {
                name: _entry("SKIPPED", excluded=True)
                for name in ("bandit", "cfn-nag", "detect-secrets", "grype")
            },
        )
        code = _run(path)
        assert code == 1
        out = capsys.readouterr().out
        assert "SKIPPED" in out, (
            "the message has to say what the statuses actually were, or an operator "
            f"reads it as an infrastructure failure rather than a selection one: {out!r}"
        )


class TestRunsThatDidMeasureSomethingPass:
    """Controls. A gate rewritten to fail unconditionally passes the test above."""

    def test_a_narrowed_run_succeeds(self, tmp_path):
        """One scanner selected, the rest SKIPPED -- what --scanners is for.

        This is the case the gate must not fire on, and it is why "every scanner
        SKIPPED" rather than "any scanner SKIPPED" is the rule.
        """
        path = _write(
            tmp_path,
            {
                "bandit": _entry("PASSED"),
                **{
                    name: _entry("SKIPPED", excluded=True)
                    for name in ("cfn-nag", "grype", "syft")
                },
            },
        )
        assert _run(path) == 0

    def test_one_shard_of_a_sharded_run_succeeds(self, tmp_path):
        """A shard records the other shards' scanners as SKIPPED and still ran."""
        path = _write(
            tmp_path,
            {
                "bandit": _entry("PASSED"),
                "checkov": _entry("FAILED", finding_count=1),
                **{
                    name: _entry("SKIPPED", excluded=True)
                    for name in ("grype", "semgrep", "syft", "npm-audit")
                },
            },
        )
        assert _run(path) == 0

    def test_a_failed_scanner_counts_as_having_run(self, tmp_path):
        """FAILED means the scanner ran and found something.

        The finding count carries that verdict, not this gate. A gate that treated
        FAILED as "did not run" would fire on every run that found a real issue.
        """
        path = _write(tmp_path, {"bandit": _entry("FAILED", finding_count=3)})
        assert _run(path) == 0


@pytest.mark.parametrize("status", ["PASSED", "FAILED"])
def test_ran_statuses_are_exactly_the_two_that_mean_the_scanner_executed(status):
    """Pins the constant, not a behaviour already covered above.

    Spelled out so that adding a third "this counts as having run" status is a
    deliberate edit here rather than a side effect elsewhere.
    """
    assert status in gate.RAN_STATUSES
    assert set(gate.RAN_STATUSES) == {"PASSED", "FAILED"}
