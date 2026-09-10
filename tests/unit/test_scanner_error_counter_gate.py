# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for .github/actions/run-scan-test/count_scanner_errors.py.

Why this file exists
--------------------
That counter decides whether a scan is reported as failed. Five CI steps read its
exit code, across bash, PowerShell and Python legs, and it replaced a `grep -c
"ERROR"` thresholded at `-gt 1` that could pass with exactly one real scanner error
present. A check whose whole purpose is to refuse a silent pass is worth very little
if nothing proves it still refuses one, so the behaviors below are pinned here rather
than left to a hand probe that only ever ran once.

Every case in this file was run by hand against the script before being committed.
Committing them changes nothing about what they measure; it changes who has to
remember to run them.

Following a convention rather than starting one
----------------------------------------------
The counter lives under `.github/`, not in `scripts/`, but the testing problem is the
same one `tests/unit/test_external_target_scan_gate.py` and
`tests/unit/test_multi_project_attribution_gate.py` already solved for
`scripts/verify_external_target_scan.py` and
`scripts/verify_multi_project_attribution.py`: the target is a standalone file in a
directory that is not an importable package. Both load it by path with
`importlib.util.spec_from_file_location` rather than mutating `sys.path`, and both are
named `test_<subject>_gate.py`. This file does the same, for the same reasons.

Placement note: this has to live under `tests/` to run at all. `pytest.ini` sets
`testpaths = tests` and CI invokes a bare `uv run pytest`, so a test file next to the
script under `.github/` would be collected by nothing and would be a test that cannot
fail.

What is pinned, and why each case
---------------------------------
Counting: zero, one and two scanners at ERROR. One is the case that matters most --
it is the exact off-by-one the old `-gt 1` threshold let through, because with the
`TextReporter` legend line absent a single real error counted as 1 and the threshold
was false.

Normalization: `"error"` lowercase and `"ScannerStatus.ERROR"` both count. A change in
how the enum serializes must not quietly turn every comparison false.

Both record shapes: `status` at the top level (`ScannerTargetStatusInfo`) and nested
`source.status` (`ScannerStatusInfo`). A counter that understood one shape would
under-count against the other.

Reading status rather than prose: a scanner *named* `error-prone-scanner` whose status
is PASSED must not count. The old grep over the rendered report could not tell a
scanner name from a status.

Refusing to inspect nothing: a missing `scanner_results`, an empty one, and a
non-empty one whose every entry is not an object all exit non-zero. The last is the
leaf-level case; the container is a perfectly good non-empty mapping, so only the
per-entry check catches it.

`--count-only` exits 0 at every count, because it exists to probe the counter. It
still exits non-zero when the input was not readable, since there is no count to
report in that case.

Failure modes these do not cover
--------------------------------
* These call `main()` in-process against temporary JSON files. They do not prove the
  five CI steps invoke the script correctly or read its exit code, which is static
  YAML and belongs to whatever checks that.
* Renaming the leaf `status` field is not guarded, here or in the script. Hundreds of
  ASH unit tests read that field, so a rename reddens the suite far earlier than this
  counter, and a redundant guard is one neither side tests.
* No case here runs a real scan, so nothing proves the aggregated results file
  actually carries either record shape at runtime. The shapes are read from the
  models, and `test_external_target_scan_gate.py` makes the same trade.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COUNTER_PATH = (
    REPO_ROOT / ".github" / "actions" / "run-scan-test" / "count_scanner_errors.py"
)


def _load_counter():
    """Import the counter by path.

    `.github/actions/run-scan-test/` is not a package and is not importable as one,
    and mutating `sys.path` at import time would leak into every other test sharing
    this xdist worker. Registering the module in `sys.modules` under its own name
    keeps `from __future__ import annotations` resolvable inside it.
    """
    spec = importlib.util.spec_from_file_location(
        "ash_count_scanner_errors", COUNTER_PATH
    )
    assert spec is not None and spec.loader is not None, COUNTER_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


counter = _load_counter()


def _scanner(status):
    """A scanner record in the ScannerTargetStatusInfo shape, status at top level."""
    return {"status": status, "finding_count": 0, "actionable_finding_count": 0}


def _run(tmp_path, capsys, payload, *argv):
    """Write `payload` as JSON, run `main` over it, return (exit, stdout, stderr)."""
    results = tmp_path / "ash_aggregated_results.json"
    results.write_text(json.dumps(payload), encoding="utf-8")
    exit_code = counter.main([str(results), *argv])
    captured = capsys.readouterr()
    return exit_code, captured.out.strip(), captured.err


# ------------------------------------------------------------------ #
# Positive control
# ------------------------------------------------------------------ #
class TestTheCounterWasActuallyLoaded:
    """A loader that silently produced a stub would make every case below vacuous."""

    def test_the_module_exposes_what_these_tests_call(self):
        for name in ("main", "count_scanner_errors", "normalize_status"):
            assert callable(getattr(counter, name, None)), (
                f"{COUNTER_PATH} did not load a callable '{name}'; every assertion "
                "in this file would be inspecting the wrong object"
            )


# ------------------------------------------------------------------ #
# Counting: 0, 1 and 2 scanners at ERROR
# ------------------------------------------------------------------ #
class TestErrorCounts:
    def test_zero_errors_prints_zero_and_exits_zero(self, tmp_path, capsys):
        payload = {
            "scanner_results": {
                "bandit": _scanner("PASSED"),
                "semgrep": _scanner("PASSED"),
            }
        }
        exit_code, out, err = _run(tmp_path, capsys, payload)
        assert (exit_code, out) == (0, "0")
        assert "No scanner reported status ERROR." in err

    def test_one_error_exits_one(self, tmp_path, capsys):
        """The off-by-one the old `-gt 1` threshold let through.

        This is the single most important case in the file. With the legend line
        absent, one real scanner error grepped to a count of 1, `-gt 1` was false,
        and the step passed while a scanner had broken.
        """
        payload = {
            "scanner_results": {
                "bandit": _scanner("ERROR"),
                "semgrep": _scanner("PASSED"),
            }
        }
        exit_code, out, err = _run(tmp_path, capsys, payload)
        assert (exit_code, out) == (1, "1")
        assert "bandit (via status)" in err

    def test_two_errors_exits_one(self, tmp_path, capsys):
        payload = {
            "scanner_results": {
                "bandit": _scanner("ERROR"),
                "semgrep": _scanner("ERROR"),
                "checkov": _scanner("PASSED"),
            }
        }
        exit_code, out, err = _run(tmp_path, capsys, payload)
        assert (exit_code, out) == (1, "2")
        assert "bandit (via status)" in err
        assert "semgrep (via status)" in err


# ------------------------------------------------------------------ #
# --count-only exits 0 at every count
# ------------------------------------------------------------------ #
class TestCountOnly:
    @pytest.mark.parametrize("errors", [0, 1, 2])
    def test_count_only_exits_zero_and_still_prints_the_count(
        self, tmp_path, capsys, errors
    ):
        names = ["bandit", "semgrep", "checkov"]
        payload = {
            "scanner_results": {
                name: _scanner("ERROR" if index < errors else "PASSED")
                for index, name in enumerate(names)
            }
        }
        exit_code, out, _ = _run(tmp_path, capsys, payload, "--count-only")
        assert exit_code == 0, (
            "--count-only must exit 0 whatever the count, so a probe can read the "
            "number without the exit code standing in for it"
        )
        assert out == str(errors)


# ------------------------------------------------------------------ #
# Status normalization
# ------------------------------------------------------------------ #
class TestStatusNormalization:
    def test_lowercase_error_counts(self, tmp_path, capsys):
        payload = {"scanner_results": {"bandit": _scanner("error")}}
        exit_code, out, _ = _run(tmp_path, capsys, payload)
        assert (exit_code, out) == (1, "1")

    def test_stringified_enum_counts(self, tmp_path, capsys):
        """`str()` on the enum yields "ScannerStatus.ERROR" rather than "ERROR"."""
        payload = {"scanner_results": {"bandit": _scanner("ScannerStatus.ERROR")}}
        exit_code, out, _ = _run(tmp_path, capsys, payload)
        assert (exit_code, out) == (1, "1")


# ------------------------------------------------------------------ #
# Both record shapes
# ------------------------------------------------------------------ #
class TestNestedTargetShape:
    def test_nested_source_status_counts(self, tmp_path, capsys):
        """ScannerStatusInfo nests per-target records instead of a top-level status."""
        payload = {
            "scanner_results": {
                "bandit": {
                    "source": {"status": "ERROR"},
                    "converted": {"status": "PASSED"},
                }
            }
        }
        exit_code, out, err = _run(tmp_path, capsys, payload)
        assert (exit_code, out) == (1, "1")
        assert "source.status" in err, (
            "the report must name which field produced the verdict, not just count"
        )


# ------------------------------------------------------------------ #
# Reading status, not prose
# ------------------------------------------------------------------ #
class TestScannerNamesAreNotStatuses:
    def test_a_scanner_named_for_errors_does_not_count_when_it_passed(
        self, tmp_path, capsys
    ):
        """The old grep over the rendered report could not make this distinction."""
        payload = {
            "scanner_results": {
                "error-prone-scanner": _scanner("PASSED"),
                "bandit": _scanner("PASSED"),
            }
        }
        exit_code, out, _ = _run(tmp_path, capsys, payload)
        assert (exit_code, out) == (0, "0"), (
            "a scanner whose NAME contains 'error' but whose status is PASSED must "
            "not be counted; only the status field decides"
        )


# ------------------------------------------------------------------ #
# Refusing to inspect nothing
# ------------------------------------------------------------------ #
class TestRefusesToReportZeroFromNothing:
    def test_missing_scanner_results_exits_nonzero(self, tmp_path, capsys):
        exit_code, out, err = _run(tmp_path, capsys, {"metadata": {}})
        assert exit_code != 0
        assert out != "0", "a payload with no scanner_results must not report 0 errors"
        assert "scanner_results" in err

    def test_empty_scanner_results_exits_nonzero(self, tmp_path, capsys):
        exit_code, out, err = _run(tmp_path, capsys, {"scanner_results": {}})
        assert exit_code != 0
        assert out != "0", "an empty scanner_results must not report 0 errors"
        assert "empty" in err

    def test_all_entries_non_mapping_exits_nonzero_with_a_named_reason(
        self, tmp_path, capsys
    ):
        """The leaf-level hole: the container is fine, every entry inside is not.

        `scanner_results` here is a non-empty mapping, so every container check
        passes. Before the per-entry check existed, each entry failed the object test,
        was skipped, and the script printed 0 and exited 0 -- even though two of the
        three entries carry status ERROR. That is the same silent pass the container
        checks above prevent, reached one level in.
        """
        payload = {
            "scanner_results": {
                "bandit": [_scanner("ERROR")],
                "semgrep": [_scanner("PASSED")],
                "detect-secrets": [_scanner("ERROR")],
            }
        }
        exit_code, out, err = _run(tmp_path, capsys, payload)
        assert exit_code != 0, (
            "a non-empty scanner_results whose every entry is unreadable must not "
            "report zero errors: nothing was inspected, so nothing was cleared"
        )
        assert out != "0", (
            "stdout carries the count for a caller to capture, so it must not say 0 "
            "when no entry was read"
        )
        for name in ("bandit", "semgrep", "detect-secrets"):
            assert name in err, (
                f"the failure must name the unreadable entry '{name}' so a "
                f"maintainer can see which records changed shape. Got: {err!r}"
            )

    def test_a_single_non_mapping_entry_is_enough_to_refuse(self, tmp_path, capsys):
        """No threshold, deliberately.

        "Fail only when every entry is unreadable" would be another offset of the
        kind that made the old `grep -c` wrong, and it would let a partial
        serialization change under-count in silence.
        """
        payload = {
            "scanner_results": {
                "bandit": _scanner("PASSED"),
                "semgrep": ["not", "a", "record"],
            }
        }
        exit_code, _, err = _run(tmp_path, capsys, payload)
        assert exit_code != 0
        assert "semgrep" in err

    def test_an_object_entry_with_no_status_exits_nonzero(self, tmp_path, capsys):
        """The nastier leaf case: every entry is an object, none declares a status.

        Nothing looks wrong on the way through. Each entry passes the object check,
        then `normalize_status(None)` is "", which compares unequal to "ERROR", so
        every entry reads as "not an error" and is cleared. Count 0, exit 0, and not
        one scanner's status was read.

        The asymmetry against the case above is what makes this a defect rather than
        a judgement call: an entry of `[]` failed loudly while an entry of `{}` passed
        silently, and both had measured exactly nothing.
        """
        payload = {
            "scanner_results": {
                "bandit": {"finding_count": 0},
                "semgrep": {"finding_count": 0},
            }
        }
        exit_code, out, err = _run(tmp_path, capsys, payload)
        assert exit_code != 0, (
            "entries that are objects but declare no status were never inspected, so "
            "they must not be reported as clean"
        )
        assert out != "0"
        for name in ("bandit", "semgrep"):
            assert name in err, (
                f"the failure must name '{name}' so a maintainer can see which "
                f"records carry no status. Got: {err!r}"
            )

    def test_a_renamed_status_field_is_caught_without_being_special_cased(
        self, tmp_path, capsys
    ):
        """A leaf rename lands with a sweep of the tests that read the old name.

        This file used to argue that a rename needed no guard here because the wider
        ASH suite would redden first. That argument lives in other files and fails in
        the one case that matters, which is a rename landing together with the sweep.
        The readability check covers it without naming the field.
        """
        payload = {
            "scanner_results": {
                "bandit": {"scan_status": "ERROR"},
                "semgrep": {"scan_status": "PASSED"},
            }
        }
        exit_code, out, _ = _run(tmp_path, capsys, payload)
        assert exit_code != 0, (
            "a record whose status moved to a different key reads as non-ERROR at "
            "every field this counter knows, so it must be refused, not cleared"
        )
        assert out != "0"

    def test_a_null_status_is_not_a_passing_status(self, tmp_path, capsys):
        """An explicit null is as unread as a missing key."""
        payload = {"scanner_results": {"bandit": {"status": None}}}
        exit_code, _, err = _run(tmp_path, capsys, payload)
        assert exit_code != 0
        assert "bandit" in err

    def test_a_nested_record_with_no_status_is_refused(self, tmp_path, capsys):
        """source/converted present but carrying no status is still nothing read."""
        payload = {
            "scanner_results": {
                "bandit": {"source": {"finding_count": 0}, "converted": {}}
            }
        }
        exit_code, _, err = _run(tmp_path, capsys, payload)
        assert exit_code != 0
        assert "bandit" in err

    def test_count_only_still_refuses_an_unreadable_entry(self, tmp_path, capsys):
        """--count-only relaxes the count, never the readability requirement."""
        payload = {"scanner_results": {"bandit": [_scanner("ERROR")]}}
        exit_code, _, err = _run(tmp_path, capsys, payload, "--count-only")
        assert exit_code != 0, (
            "--count-only exits 0 for any count, but an unreadable entry has no "
            "count to report"
        )
        assert "bandit" in err


# ------------------------------------------------------------------ #
# The tuple contract, for callers that read it instead of the exit code
# ------------------------------------------------------------------ #
class TestProblemsAlwaysMeanAZeroCount:
    """A partial count would look authoritative while totalling only what was read.

    main() never prints the count when problems are present, so no CI step can be
    misled today. This pins the contract for the next caller, which may read the
    tuple directly.
    """

    def test_a_mixed_payload_reports_no_count_and_names_both_findings(self):
        """One readable entry at ERROR, one unreadable entry, in the same payload."""
        count, offenders, problems = counter.count_scanner_errors(
            {
                "scanner_results": {
                    "bandit": _scanner("ERROR"),
                    "semgrep": {"finding_count": 0},
                }
            }
        )
        assert problems, "the unreadable entry must be reported"
        assert (count, offenders) == (0, {}), (
            "whenever problems is non-empty the count must be 0 and offenders empty, "
            "uniformly with the whole-payload and empty-container checks; a caller "
            f"must not receive a partial total. Got {count} and {offenders}"
        )
        joined = " ".join(problems)
        assert "semgrep" in joined, "the unreadable entry must be named"
        assert "bandit" in joined, (
            "the ERROR found among the readable entries must still be reported, not "
            f"dropped along with the count. Got: {problems}"
        )
