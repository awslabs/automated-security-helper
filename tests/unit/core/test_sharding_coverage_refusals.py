# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The missing-index refusal of ``verify_shard_coverage`` is bounded.

Why this file exists
--------------------
The missing-index refusal built ``set(range(shard_count))`` and listed every
missing index. ``shard_count`` is read from a results file and has no upper
bound, so a corrupt or hostile count made ``ash merge`` exhaust memory or print
a refusal megabytes long instead of refusing promptly. The count is now exact and
the listing bounded.

A matrix with ``--python-only`` set on only some jobs is not refused here, and
the module docstring and the candidate-set message no longer say it is: every
executor records its candidates before the selection filters apply, so the
candidate sets agree whatever the flag. The merge's contribution check reads the
flag from the shards' records and warns, naming the scanners the flagged shards
left unrun; ``tests/unit/cli/test_merge.py`` pins that disclosure.
"""

from __future__ import annotations

import threading

import pytest

from automated_security_helper.core.sharding import (
    MISSING_SHARD_INDICES_SHOWN,
    ShardAssignment,
    ShardCoverageError,
    verify_shard_coverage,
)

pytestmark = pytest.mark.unit


def _assignment(index: int, count: int, owned, **extra) -> ShardAssignment:
    return ShardAssignment(
        shard_index=index, shard_count=count, assigned_scanners=list(owned), **extra
    )


def _coverage_outcome_within(seconds: float, assignments):
    """What ``verify_shard_coverage`` raised, or None for a return, within
    *seconds*; a daemon thread, so a call that never returns fails the test
    instead of hanging the run (the thread is left behind in that case)."""
    outcome: list = []

    def run() -> None:
        try:
            verify_shard_coverage(assignments)
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - the outcome under test
            outcome.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    assert outcome, f"verify_shard_coverage did not return within {seconds} s"
    return outcome[0]


class TestMissingIndicesAreCountedNotListed:
    def test_a_hostile_declared_count_is_refused_at_once(self):
        """The memory claim: ``set(range(10**15))`` would exhaust memory, and a
        refusal that listed every index would run to petabytes; a count of a
        million, the earlier value, is tens of megabytes and milliseconds, so an
        implementation that still built the set passed. The bound turns a
        regression into a failure instead of a hung run."""
        count = 10**15
        outcome = _coverage_outcome_within(30.0, [_assignment(0, count, ["bandit"])])
        assert isinstance(outcome, ShardCoverageError), outcome
        message = str(outcome)
        assert "Missing shard results" in message
        assert f"{count - 1} of {count}" in message
        assert " more" in message
        assert len(message) < 2000, len(message)

    def test_the_listing_names_every_index_up_to_the_cap(self):
        count = MISSING_SHARD_INDICES_SHOWN + 1
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage([_assignment(count - 1, count, ["bandit"])])
        message = str(excinfo.value)
        listed = ", ".join(str(i) for i in range(MISSING_SHARD_INDICES_SHOWN))
        assert f"({listed})" in message, message
        assert " more" not in message

    def test_one_past_the_cap_is_counted_not_listed(self):
        count = MISSING_SHARD_INDICES_SHOWN + 2
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage([_assignment(count - 1, count, ["bandit"])])
        message = str(excinfo.value)
        listed = ", ".join(str(i) for i in range(MISSING_SHARD_INDICES_SHOWN))
        assert f"({listed} and 1 more)" in message, message
        assert f"{count - 1} of {count}" in message

    def test_a_short_gap_names_every_missing_index(self):
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage([_assignment(1, 4, ["bandit"])])
        message = str(excinfo.value)
        assert "3 of 4" in message
        assert "(0, 2, 3)" in message
        assert " more" not in message

    @pytest.mark.parametrize(
        "flags",
        [(True, False), (True, True), (None, None), (True, None)],
        ids=["mixed", "all-with", "none-recorded", "with-and-unrecorded"],
    )
    def test_the_python_only_record_is_not_a_coverage_refusal(self, flags):
        # The flag is disclosed by the merge's contribution check, which reads the
        # shards' records and warns; the coverage check sees complete shards here.
        candidates = ["bandit", "checkov", "grype", "semgrep"]
        verify_shard_coverage(
            [
                _assignment(
                    0,
                    2,
                    ["bandit", "grype"],
                    candidate_scanners=candidates,
                    python_only=flags[0],
                ),
                _assignment(
                    1,
                    2,
                    ["checkov", "semgrep"],
                    candidate_scanners=candidates,
                    python_only=flags[1],
                ),
            ]
        )
