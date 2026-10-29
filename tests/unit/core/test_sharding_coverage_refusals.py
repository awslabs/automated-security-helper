# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two refusals of ``verify_shard_coverage``.

Why this file exists
--------------------
The missing-index refusal built ``set(range(shard_count))`` and listed every
missing index. ``shard_count`` is read from a results file and has no upper
bound, so a corrupt or hostile count made ``ash merge`` exhaust memory or print
a refusal megabytes long instead of refusing promptly. The count is now exact and
the listing bounded.

The module docstring counts a matrix with ``--python-only`` set on only some
jobs among the cases a merge refuses, and the candidate-set comparison named the
flag as a cause it catches. It cannot: every executor records its candidates
before the selection filters apply, so the candidate sets agree whatever the
flag, and such a matrix merged with a warning while the non-Python scanners the
flagged shards owned had run nowhere. The flag's own record now decides it.
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


class TestPythonOnlyAgreement:
    CANDIDATES = ["bandit", "checkov", "grype", "semgrep"]

    def _pair(self, first, second):
        return [
            _assignment(
                0,
                2,
                ["bandit", "grype"],
                candidate_scanners=self.CANDIDATES,
                python_only=first,
            ),
            _assignment(
                1,
                2,
                ["checkov", "semgrep"],
                candidate_scanners=self.CANDIDATES,
                python_only=second,
            ),
        ]

    def test_a_matrix_where_only_some_jobs_ran_python_only_is_refused(self):
        with pytest.raises(ShardCoverageError, match=r"disagree on --python-only"):
            verify_shard_coverage(self._pair(True, False))

    @pytest.mark.parametrize(
        "flags",
        [(True, True), (False, False), (None, None), (True, None)],
        ids=["all-with", "all-without", "none-recorded", "with-and-unrecorded"],
    )
    def test_shards_that_agree_or_did_not_record_the_flag_merge(self, flags):
        # A shard that recorded nothing predates the field; that mix is left to
        # the merge's contribution check, which warns from the statuses.
        verify_shard_coverage(self._pair(*flags))
