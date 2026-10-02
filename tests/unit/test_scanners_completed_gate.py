# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for .github/scripts/assert_scanners_completed.py.

Why this file exists
--------------------
The script's own docstring argues that "a gate that cannot fail is worse than no gate,
because its green is read as evidence" -- and it shipped with no tests, which is the
same position the five in-line guards it replaced were in. Each of those was broken in
a way that made it pass unconditionally or nearly so, one of them by reading a JSON
path that does not exist, and none had a test that would have said so.

``tests/unit/test_external_target_scan_gate.py`` is the precedent for testing a gate
script that lives outside the package.

Both directions, deliberately
-----------------------------
Half of these assert the gate fires -- absent file, malformed JSON, an ERROR entry, a
MISSING entry, an unreadable status, a status from another version, and a results file
where nothing ran. The other half assert it does not fire on a healthy run: a narrowed
``--scanners`` run, one shard of a sharded run, and a scanner that found something.
Without that second half, a script rewritten to ``return 1`` unconditionally would
pass every test here and break every job in the repository.
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


class TestUnreadableInputIsAFailure:
    """A gate that cannot read its input must fail, not shrug.

    The predecessor that read ``scanners`` keyed by ``result`` -- a path that does not
    exist -- resolved to null under PowerShell's default non-strict mode, so its loop
    body never ran and the step reported success unconditionally. These pin the
    opposite: every way of failing to get usable data is exit 1.
    """

    def test_absent_results_file_fails(self, tmp_path, capsys):
        code = _run(tmp_path / "nope.json")
        assert code == 1
        assert "not found" in capsys.readouterr().out

    def test_malformed_json_fails(self, tmp_path, capsys):
        path = tmp_path / "ash_aggregated_results.json"
        path.write_text("{not json", encoding="utf-8")

        code = _run(path)
        assert code == 1
        assert "Could not read" in capsys.readouterr().out

    def test_a_results_file_with_no_scanner_results_key_fails(self, tmp_path):
        path = tmp_path / "ash_aggregated_results.json"
        path.write_text(json.dumps({"metadata": {}}), encoding="utf-8")
        assert _run(path) == 1

    def test_an_empty_scanner_results_map_fails(self, tmp_path):
        """Zero scanners produce zero findings, which looks exactly like a clean scan."""
        assert _run(_write(tmp_path, {})) == 1

    def test_a_scanner_results_value_of_the_wrong_shape_fails(self, tmp_path):
        """A list where a mapping belongs is not a scanner that ran."""
        path = tmp_path / "ash_aggregated_results.json"
        path.write_text(json.dumps({"scanner_results": ["bandit"]}), encoding="utf-8")
        assert _run(path) == 1

    def test_an_entry_with_no_status_fails(self, tmp_path, capsys):
        """An entry whose status cannot be read is not evidence the scanner ran."""
        path = _write(tmp_path, {"bandit": _entry("PASSED"), "grype": {}})
        assert _run(path) == 1
        assert "grype" in capsys.readouterr().out

    def test_a_null_entry_fails(self, tmp_path):
        path = tmp_path / "ash_aggregated_results.json"
        path.write_text(
            json.dumps({"scanner_results": {"bandit": _entry("PASSED"), "syft": None}}),
            encoding="utf-8",
        )
        assert _run(path) == 1


class TestIncompleteScannersAreAFailure:
    def test_one_missing_scanner_fails_and_is_named(self, tmp_path, capsys):
        """MISSING is the status the guard this script replaced could not see.

        Four of the five predecessors grepped the prose report for the substring
        "ERROR", which does not match MISSING, so a cell where four of ten scanners
        never ran passed. On one measured pull-request run four green check runs each
        carried three or four MISSING scanners at under a millisecond each, and in the
        cells where those scanners did run one of them reported 82 findings.

        The name has to appear in the output or an operator cannot tell which tool to
        install.
        """
        path = _write(
            tmp_path,
            {
                "bandit": _entry("PASSED"),
                "cfn-nag": _entry("MISSING", dependencies_satisfied=False),
            },
        )
        code = _run(path)
        assert code == 1
        out = capsys.readouterr().out
        assert "cfn-nag" in out
        assert "MISSING" in out

    def test_one_error_scanner_fails_and_is_named(self, tmp_path, capsys):
        path = _write(
            tmp_path, {"bandit": _entry("PASSED"), "checkov": _entry("ERROR")}
        )
        assert _run(path) == 1
        assert "checkov" in capsys.readouterr().out

    def test_the_count_of_incomplete_scanners_is_reported(self, tmp_path, capsys):
        """The summary line has to agree with the per-scanner lines above it."""
        path = _write(
            tmp_path,
            {
                "bandit": _entry("PASSED"),
                "cfn-nag": _entry("MISSING"),
                "grype": _entry("MISSING"),
                "syft": _entry("ERROR"),
            },
        )
        assert _run(path) == 1
        assert "3 of 4 scanners did not complete" in capsys.readouterr().out


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


class TestUnknownStatusesFailClosed:
    """The verdict is an allowlist of known-good statuses, not a denylist of bad ones.

    A results file written by a different ASH version can carry a status this script
    has never heard of. Classifying it as complete because it is not one of the two
    known-bad names means a future rename of ERROR silently disarms the gate -- and
    the whole reason this script exists is that its five predecessors were each
    disarmed in some equally quiet way.
    """

    @pytest.mark.parametrize("status", ["PARTIALLY_COMPLETED", "TIMED_OUT", "Passed"])
    def test_a_status_this_version_does_not_know_fails(self, tmp_path, status, capsys):
        path = _write(tmp_path, {"bandit": _entry("PASSED"), "semgrep": _entry(status)})
        assert _run(path) == 1
        assert "semgrep" in capsys.readouterr().out

    def test_the_complete_statuses_are_exactly_the_three_that_are_tolerated(self):
        assert set(gate.COMPLETE_STATUSES) == {"PASSED", "FAILED", "SKIPPED"}


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


class TestSummaryStatsReconciliation:
    """The counter cross-check warns; it must never be the verdict.

    ERROR had no counter at all for a while, so the four totals summed to fewer than
    the scanners in the run on exactly the runs that mattered. The reconciliation
    exists to say so out loud, but a gate keyed on the totals rather than on
    per-scanner status is the defect being avoided, not the fix -- a count cannot name
    the scanner an operator has to go and fix.
    """

    def test_a_short_tally_warns_without_failing(self, tmp_path, capsys):
        path = _write(
            tmp_path,
            {"bandit": _entry("PASSED"), "semgrep": _entry("PASSED")},
            summary_stats={
                "passed": 1,
                "failed": 0,
                "missing": 0,
                "skipped": 0,
                "error": 0,
            },
        )
        code = _run(path)
        out = capsys.readouterr().out
        assert code == 0, "a miscounted tally is a warning, not the verdict"
        assert "::warning::" in out and "incomplete tally" in out

    def test_clean_counters_do_not_warn(self, tmp_path, capsys):
        path = _write(
            tmp_path,
            {"bandit": _entry("PASSED"), "semgrep": _entry("FAILED")},
            summary_stats={
                "passed": 1,
                "failed": 1,
                "missing": 0,
                "skipped": 0,
                "error": 0,
            },
        )
        assert _run(path) == 0
        assert "::warning::" not in capsys.readouterr().out

    def test_a_non_integer_counter_is_ignored_rather_than_crashing(self, tmp_path):
        """The reconciliation is a nicety and must not become a new way to fail."""
        path = _write(
            tmp_path,
            {"bandit": _entry("PASSED")},
            summary_stats={"passed": "1", "failed": 0, "missing": 0, "skipped": 0},
        )
        assert _run(path) == 0

    def test_counters_that_read_clean_cannot_rescue_an_error_scanner(
        self, tmp_path, capsys
    ):
        """The measured shape: bandit=ERROR with every counter reading zero.

        A gate keyed on ``summary_stats.missing`` reads 0 and passes. The per-scanner
        read fails. This pins which of the two this script does.
        """
        path = _write(
            tmp_path,
            {"bandit": _entry("ERROR"), "semgrep": _entry("PASSED")},
            summary_stats={
                "passed": 1,
                "failed": 0,
                "missing": 0,
                "skipped": 0,
                "error": 0,
            },
        )
        assert _run(path) == 1
        assert "bandit" in capsys.readouterr().out


def test_the_gate_script_is_where_the_workflows_expect_it():
    """A gate at the wrong path is a step that fails for the wrong reason.

    Cheap, and it is the one thing these tests cannot detect indirectly: every
    assertion here loads the script through the same constant, so a move would make
    the whole file error at collection rather than report a missing gate.
    """
    assert GATE_PATH.is_file(), GATE_PATH


@pytest.mark.parametrize("status", ["PASSED", "FAILED"])
def test_ran_statuses_are_exactly_the_two_that_mean_the_scanner_executed(status):
    """Pins the constant, not a behaviour already covered above.

    Spelled out so that adding a third "this counts as having run" status is a
    deliberate edit here rather than a side effect elsewhere.
    """
    assert status in gate.RAN_STATUSES
    assert set(gate.RAN_STATUSES) == {"PASSED", "FAILED"}


def _write_with_metadata(tmp_path, scanner_results, **metadata):
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(
        json.dumps({"scanner_results": scanner_results, "metadata": metadata}),
        encoding="utf-8",
    )
    return path


class TestTheRosterIsAnIndependentDenominator:
    """The gate builds its universe from the dict it is handed, and that was all.

    It carried no expected roster, so it could only fail on the rows present: eight
    of ten scanners printed "All 8 scanners accounted for; none incomplete" and
    returned 0. The two that never registered were absent from the numerator and
    from the denominator at once, so no arithmetic over that dict could notice them.

    ``metadata.expected_scanners`` is written by ASH from the configuration's
    declared scanner roster rather than from the plugins that resolved, which is why
    comparing against it is not the same question as comparing the rows to each
    other.
    """

    def test_an_expected_scanner_with_no_row_fails(self, tmp_path, capsys):
        path = _write_with_metadata(
            tmp_path,
            {"bandit": _entry("PASSED")},
            expected_scanners=["bandit", "grype", "syft"],
        )

        assert _run(path) == 1
        out = capsys.readouterr().out
        assert "grype" in out
        assert "syft" in out

    def test_a_complete_roster_passes(self, tmp_path):
        path = _write_with_metadata(
            tmp_path,
            {"bandit": _entry("PASSED"), "grype": _entry("SKIPPED")},
            expected_scanners=["bandit", "grype"],
        )

        assert _run(path) == 0

    def test_the_comparison_ignores_case_and_separator_spelling(self, tmp_path):
        """A roster written ``detect_secrets`` must not fail a row ``detect-secrets``.

        The roster is taken from config field aliases and the rows from
        ``config.name`` on the instantiated plugin. Those agree today; a gate that
        compared them literally would turn any future divergence into ten false
        failures rather than into the one real one it exists to report.
        """
        path = _write_with_metadata(
            tmp_path,
            {"detect-secrets": _entry("PASSED")},
            expected_scanners=["Detect_Secrets"],
        )

        assert _run(path) == 0

    def test_no_roster_leaves_the_gate_as_it_was(self, tmp_path):
        """Backward compatibility, and it is load-bearing rather than polite.

        ``ash merge`` reads shard results from whatever ASH wrote each one, and the
        reusable workflow runs this script against files produced by released
        versions. A missing roster has to read as "this producer recorded none",
        not as "every scanner is missing".
        """
        path = _write(tmp_path, {"bandit": _entry("PASSED")})

        assert _run(path) == 0

    def test_an_extra_row_not_on_the_roster_is_not_a_failure(self, tmp_path):
        """A third-party scanner the config did not declare still ran.

        Only the roster-minus-rows direction is a finding. The other direction is a
        plugin module an operator loaded without a config entry, which is a
        supported arrangement.
        """
        path = _write_with_metadata(
            tmp_path,
            {"bandit": _entry("PASSED"), "ferret-scan": _entry("PASSED")},
            expected_scanners=["bandit"],
        )

        assert _run(path) == 0


class TestRecordedPluginLoadErrorsFailTheGate:
    """Per-module import isolation is only safe if the loss is loud.

    Isolating each plugin group's import turns a hard startup failure into a
    degraded run. That is the right direction -- one missing optional dependency
    should not cost fifteen reporters -- but only if something fails on the
    degradation. A run that lost a plugin module still produces valid-looking rows
    for every scanner that survived.
    """

    def test_a_recorded_load_error_fails(self, tmp_path, capsys):
        path = _write_with_metadata(
            tmp_path,
            {"bandit": _entry("PASSED")},
            plugin_load_errors={
                "automated_security_helper.plugin_modules.ash_builtin.reporters": (
                    "ImportError: No module named 'boto3'"
                )
            },
        )

        assert _run(path) == 1
        assert "reporters" in capsys.readouterr().out

    def test_an_empty_load_error_map_passes(self, tmp_path):
        path = _write_with_metadata(
            tmp_path, {"bandit": _entry("PASSED")}, plugin_load_errors={}
        )

        assert _run(path) == 0
