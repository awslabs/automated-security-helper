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

import pytest

from automated_security_helper.core.sharding import (
    ShardAssignment,
    ShardCoverageError,
    verify_shard_coverage,
)

pytestmark = pytest.mark.unit


def _assignment(index: int, count: int, owned, **extra) -> ShardAssignment:
    return ShardAssignment(
        shard_index=index, shard_count=count, assigned_scanners=list(owned), **extra
    )


class TestMissingIndicesAreCountedNotListed:
    def test_a_large_declared_count_is_refused_with_a_bounded_message(self):
        count = 1_000_000
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage([_assignment(0, count, ["bandit"])])
        message = str(excinfo.value)
        assert "Missing shard results" in message
        assert f"{count - 1} of {count}" in message
        assert " more" in message
        assert len(message) < 2000, len(message)

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
