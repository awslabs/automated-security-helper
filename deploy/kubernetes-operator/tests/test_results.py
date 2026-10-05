"""Status derivation, and the classification direction that matters."""

from __future__ import annotations

import json

import pytest

from ash_operator.constants import COMPLETE_SCANNER_STATUSES, KNOWN_SCANNER_STATUSES
from ash_operator.results import (
    classify_status,
    derive_phase,
    parse_collector_summary,
    status_from_summary,
)


class TestVocabulary:
    def test_the_status_set_matches_ash_exactly(self):
        """A status added upstream must fail here rather than be tolerated.

        This is the guard behind :func:`classify_status`. Membership of the complete
        set is the right test only while the operator knows the whole vocabulary; a
        sixth status that nobody noticed would land in "Unknown", which is the safe
        answer but also one nobody would investigate.
        """
        enums = pytest.importorskip(
            "automated_security_helper.core.enums",
            reason=(
                "ASH is not importable here, so the vocabularies cannot be compared. "
                "A real coverage gap, not a pass."
            ),
        )
        ash_statuses = {member.value for member in enums.ScannerStatus}
        assert ash_statuses == set(KNOWN_SCANNER_STATUSES), (
            f"ASH's ScannerStatus is {sorted(ash_statuses)} but the operator knows "
            f"{sorted(KNOWN_SCANNER_STATUSES)}. Decide which side of "
            f"COMPLETE_SCANNER_STATUSES the new status belongs on before shipping."
        )
        assert COMPLETE_SCANNER_STATUSES < ash_statuses


class TestClassify:
    @pytest.mark.parametrize("status", ["PASSED", "FAILED", "SKIPPED"])
    def test_complete_statuses(self, status):
        assert classify_status(status) == "Complete"

    @pytest.mark.parametrize("status", ["ERROR", "MISSING"])
    def test_incomplete_statuses(self, status):
        assert classify_status(status) == "Incomplete"

    def test_an_unrecognised_status_is_unknown_not_complete(self):
        # The direction is the whole point. Asking "is it one of the two bad ones"
        # answers no for a status from a newer ASH and reports the shard complete,
        # which reads an unfamiliar status as success.
        assert classify_status("QUARANTINED") == "Unknown"
        assert classify_status(None) == "Unknown"

    def test_skipped_is_complete_because_it_means_not_selected(self):
        assert classify_status("SKIPPED") == "Complete"


def summary_json(**overrides):
    body = {
        "phase": "Succeeded",
        "shardCount": 2,
        "consumedShardIndices": [0, 1],
        "mergeExitCode": 0,
        "mergedShardCount": 2,
        "mergedShardIndices": [0, 1],
        "candidateRosterAgreed": True,
        "findings": {"total": 3, "actionable": 2, "suppressed": 0},
        "scanners": [
            {"n": "bandit", "s": "FAILED", "o": 0, "d": True, "f": 3, "a": 2},
            {"n": "grype", "s": "MISSING", "o": 1, "d": False, "f": 0, "a": 0},
        ],
    }
    body.update(overrides)
    return json.dumps(body)


class TestParse:
    def test_a_full_summary_parses(self):
        summary = parse_collector_summary(summary_json())
        assert summary.phase == "Succeeded"
        assert summary.merge_exit_code == 0
        assert len(summary.scanners) == 2

    def test_a_truncated_message_is_not_read_as_clean(self):
        # The kubelet caps the message at 4 KiB. Truncation yields invalid JSON, and
        # swallowing that would report Succeeded for a run whose outcome the
        # operator never saw.
        summary = parse_collector_summary(summary_json()[:-40])
        assert summary.parse_error is not None
        assert derive_phase(summary, complete_walk=True) == "Refused"

    def test_no_message_at_all_is_not_read_as_clean(self):
        summary = parse_collector_summary(None)
        assert summary.parse_error is not None
        assert derive_phase(summary, complete_walk=True) == "Refused"


class TestStatus:
    def test_a_clean_run_succeeds(self):
        status = status_from_summary(
            parse_collector_summary(
                summary_json(
                    scanners=[{"n": "bandit", "s": "PASSED", "o": 0, "d": True, "f": 0, "a": 0}],
                    findings={"total": 0, "actionable": 0, "suppressed": 0},
                )
            ),
            expected_shard_count=2,
        )
        assert status["phase"] == "Succeeded"
        assert status["incompleteScanners"] == []
        assert status["findings"]["actionable"] == 0

    def test_a_missing_scanner_is_named_but_does_not_itself_fail_the_run(self):
        # fail_on_incomplete_scanners defaults to False in ASH, so a MISSING scanner
        # leaves the phase Succeeded. .status.incompleteScanners is where an adopter
        # finds out which scanner did not run, which is the whole reason it is
        # surfaced unconditionally rather than only when the gate is on.
        status = status_from_summary(
            parse_collector_summary(summary_json(mergeExitCode=0)), expected_shard_count=2
        )
        assert status["incompleteScanners"] == ["grype"]
        assert status["phase"] == "Succeeded"

    def test_a_non_zero_merge_exit_fails_the_run(self):
        status = status_from_summary(
            parse_collector_summary(summary_json(mergeExitCode=2)), expected_shard_count=2
        )
        assert status["phase"] == "Failed"

    def test_a_short_walk_is_refused_even_if_the_merge_exited_zero(self):
        # The single failure mode the whole design is built against: a merge over a
        # subset exits 0 and reports a clean scan.
        status = status_from_summary(
            parse_collector_summary(summary_json(consumedShardIndices=[0], mergeExitCode=0)),
            expected_shard_count=2,
        )
        assert status["phase"] == "Refused"
        assert "clean scan" in status["merge"]["refusalReason"]

    def test_the_collectors_walk_and_the_merges_own_accounting_are_both_reported(self):
        status = status_from_summary(
            parse_collector_summary(summary_json(mergedShardIndices=[0])),
            expected_shard_count=2,
        )
        assert status["merge"]["consumedShardIndices"] == [0, 1]
        assert status["merge"]["mergeReportedShardIndices"] == [0]

    def test_a_refusal_reason_survives_into_status(self):
        status = status_from_summary(
            parse_collector_summary(
                summary_json(phase="Refused", refusal="no verified attempt for shard 1")
            ),
            expected_shard_count=2,
        )
        assert status["phase"] == "Refused"
        assert "shard 1" in status["merge"]["refusalReason"]

    def test_discarded_attempts_are_visible(self):
        status = status_from_summary(
            parse_collector_summary(summary_json(discardedAttempts=[{"i": 0, "a": "job-0-old"}])),
            expected_shard_count=2,
        )
        assert status["merge"]["discardedAttempts"] == [{"i": 0, "a": "job-0-old"}]

    def test_a_roster_nobody_recorded_is_reported_as_such(self):
        status = status_from_summary(
            parse_collector_summary(summary_json(candidateRosterAgreed=False)),
            expected_shard_count=2,
        )
        assert status["merge"]["candidateRosterAgreed"] is False

    def test_a_run_with_no_provenance_is_refused_not_succeeded(self):
        """The gap the old suite could not see.

        Before this, ``derive_phase`` never read ``candidateRosterAgreed``, so a scan
        whose shards recorded no ``candidate_scanners`` at all reported ``Succeeded``
        with ``candidateRosterAgreed: false`` in its own status. ``ash merge`` does not
        refuse that case -- it skips the union check -- so nothing else caught it.
        The e2e asserted the field was ``true``, which proves the provenance was
        present and says nothing about its absence.
        """
        status = status_from_summary(
            parse_collector_summary(summary_json(candidateRosterAgreed=False, mergeExitCode=0)),
            expected_shard_count=2,
        )
        assert status["phase"] == "Refused"
        assert "candidate_scanners" in status["merge"]["refusalReason"]
        assert "coverage hole" in status["merge"]["refusalReason"]

    def test_a_missing_roster_field_is_also_refused(self):
        # None means the summary did not survive, so the operator does not know
        # whether the coverage check was possible. The collector always sets it.
        raw = json.loads(summary_json(mergeExitCode=0))
        del raw["candidateRosterAgreed"]
        status = status_from_summary(
            parse_collector_summary(json.dumps(raw)), expected_shard_count=2
        )
        assert status["phase"] == "Refused"

    def test_the_roster_gate_does_not_refuse_a_healthy_run(self):
        # Positive control. Without it, the two tests above would also pass for a
        # derive_phase that refused everything.
        status = status_from_summary(
            parse_collector_summary(summary_json(candidateRosterAgreed=True, mergeExitCode=0)),
            expected_shard_count=2,
        )
        assert status["phase"] == "Succeeded"
        assert "refusalReason" not in status["merge"]

    def test_the_collector_never_sheds_the_roster_field(self):
        """The shed list must not contain the key derive_phase refuses on.

        Shedding it would turn a detected coverage hole into a Refused with no stated
        reason, or -- if someone then relaxed the refusal to tolerate a missing key --
        back into a silent success.
        """
        from ash_operator.entrypoints import collect

        payload = {
            "phase": "Succeeded",
            "candidateRosterAgreed": True,
            "mergeExitCode": 0,
            "consumedShardIndices": [0, 1],
            "refusal": None,
            "scanners": [{"n": f"scanner-{i}", "s": "PASSED"} for i in range(400)],
            "selectedAttempts": [{"i": i, "a": f"attempt-{i}" * 20} for i in range(60)],
            "discardedAttempts": [{"i": i, "a": f"old-{i}" * 20} for i in range(60)],
        }
        written: dict[str, str] = {}

        class _Path:
            def __init__(self, path):
                self.path = path

            def write_text(self, text):
                written["text"] = text

        original = collect.Path
        collect.Path = _Path
        try:
            collect.write_termination_message("/dev/null", payload)
        finally:
            collect.Path = original

        shed = json.loads(written["text"])
        assert shed["omittedFromStatus"], "the payload was not large enough to shed"
        assert "candidateRosterAgreed" in shed, (
            f"the roster field was shed: {sorted(shed)}. derive_phase refuses on its "
            f"absence, so shedding it turns a detected hole into an unexplained refusal."
        )
        assert len(written["text"].encode()) <= collect.TERMINATION_MESSAGE_BUDGET

    def test_shed_detail_is_flagged(self):
        status = status_from_summary(
            parse_collector_summary(summary_json(omittedFromStatus=["scanners"])),
            expected_shard_count=2,
        )
        assert status["statusTruncated"] == ["scanners"]

    def test_owning_shard_index_is_carried_per_scanner(self):
        status = status_from_summary(
            parse_collector_summary(summary_json()), expected_shard_count=2
        )
        owners = {s["name"]: s["owningShardIndex"] for s in status["scannerCompleteness"]}
        assert owners == {"bandit": 0, "grype": 1}
