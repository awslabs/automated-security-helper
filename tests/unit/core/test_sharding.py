# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the scan-sharding partition and coverage checks.

The partition is the load-bearing part: every executor computes it independently
with no coordination, so a rule that is not a pure function of (sorted names,
index, count) would let two executors disagree and silently drop a scanner. The
tests below therefore pin determinism, disjointness and completeness as
properties rather than checking one hand-picked split.
"""

import pytest

from automated_security_helper.core.sharding import (
    ShardAssignment,
    ShardCoverageError,
    ShardSelectionError,
    partition_scanners,
    scanners_to_exclude,
    validate_shard_selection,
    verify_shard_coverage,
)

# A deliberately unsorted list. Passing an already-sorted list would let a
# partition that depends on input order pass by accident.
SCANNERS = [
    "semgrep",
    "bandit",
    "checkov",
    "detect-secrets",
    "cdk-nag",
    "grype",
    "npm-audit",
    "cfn-nag",
    "syft",
    "opengrep",
]


class TestValidateShardSelection:
    def test_both_unset_is_allowed(self):
        # The overwhelmingly common case: no sharding at all.
        validate_shard_selection(None, None)

    @pytest.mark.parametrize(
        "index,count",
        [(0, None), (None, 2)],
    )
    def test_one_without_the_other_is_refused(self, index, count):
        # A lone --shard-index would otherwise scan shard 0 of an unknown total
        # and report a partial scan as a whole one.
        with pytest.raises(ShardSelectionError):
            validate_shard_selection(index, count)

    @pytest.mark.parametrize("count", [0, -1])
    def test_non_positive_count_is_refused(self, count):
        with pytest.raises(ShardSelectionError):
            validate_shard_selection(0, count)

    @pytest.mark.parametrize("index", [-1, 2, 99])
    def test_index_outside_the_count_is_refused(self, index):
        with pytest.raises(ShardSelectionError):
            validate_shard_selection(index, 2)

    def test_single_shard_is_allowed(self):
        # count=1 is degenerate but legitimate: a pipeline that parameterises
        # shard count should not break when someone sets it to 1.
        validate_shard_selection(0, 1)


class TestPartitionScanners:
    @pytest.mark.parametrize("count", [1, 2, 3, 4, 7, 10])
    def test_shards_are_disjoint_and_cover_everything(self, count):
        shards = [partition_scanners(SCANNERS, i, count) for i in range(count)]

        flat = [name for shard in shards for name in shard]
        # Disjoint: no scanner runs twice, which would double-report its findings
        # after the merge, because merging does not dedupe.
        assert len(flat) == len(set(flat))
        # Complete: no scanner is dropped, which would silently narrow coverage.
        assert set(flat) == set(SCANNERS)

    @pytest.mark.parametrize("count", [2, 3, 5])
    def test_partition_is_deterministic_across_input_orderings(self, count):
        # Different executors may enumerate plugins in different orders (dict
        # ordering, plugin module load order). The split must not depend on it.
        shuffled = list(reversed(SCANNERS))
        for i in range(count):
            assert partition_scanners(SCANNERS, i, count) == partition_scanners(
                shuffled, i, count
            )

    def test_repeated_calls_agree(self):
        assert partition_scanners(SCANNERS, 1, 3) == partition_scanners(SCANNERS, 1, 3)

    def test_single_shard_gets_everything(self):
        assert partition_scanners(SCANNERS, 0, 1) == sorted(SCANNERS)

    def test_more_shards_than_scanners_leaves_some_empty(self):
        count = len(SCANNERS) + 3
        shards = [partition_scanners(SCANNERS, i, count) for i in range(count)]
        assert sum(1 for s in shards if not s) == 3
        # Still complete despite the empties.
        assert sorted(n for s in shards for n in s) == sorted(SCANNERS)

    def test_empty_scanner_list_yields_empty_shard(self):
        assert partition_scanners([], 0, 2) == []

    def test_duplicates_in_the_input_are_collapsed(self):
        # plugin_modules() can return the same scanner twice when a module is
        # registered under two names. Keeping both would run it twice in one
        # shard, or once in two shards.
        assert partition_scanners(["bandit", "bandit", "semgrep"], 0, 1) == [
            "bandit",
            "semgrep",
        ]

    def test_sizes_are_balanced_to_within_one(self):
        sizes = [len(partition_scanners(SCANNERS, i, 3)) for i in range(3)]
        assert max(sizes) - min(sizes) <= 1


class TestScannersToExclude:
    def test_excludes_exactly_the_unassigned(self):
        assigned = partition_scanners(SCANNERS, 0, 2)
        excluded = scanners_to_exclude(SCANNERS, assigned)
        assert set(assigned).isdisjoint(excluded)
        assert set(assigned) | set(excluded) == set(SCANNERS)

    def test_operator_exclusions_are_preserved(self):
        # --exclude-scanners must survive sharding; dropping it would run a
        # scanner the operator deliberately turned off.
        assigned = partition_scanners(SCANNERS, 0, 2)
        excluded = scanners_to_exclude(
            SCANNERS, assigned, already_excluded=["semgrep", "SYFT"]
        )
        assert "semgrep" in excluded
        # Case-insensitive: the CLI lowercases scanner names when matching.
        assert "syft" in excluded

    def test_result_is_sorted_and_deduplicated(self):
        excluded = scanners_to_exclude(
            SCANNERS, ["bandit"], already_excluded=["semgrep", "semgrep"]
        )
        assert excluded == sorted(set(excluded))


class TestVerifyShardCoverage:
    def _assignments(self, count, names=SCANNERS, record_candidates=True):
        """Build a complete set of shard assignments.

        ``record_candidates`` defaults to True because that is what a real scan
        now writes. Passing False produces the shape results written before
        ``candidate_scanners`` existed have, which
        ``TestCandidateSetIsVerified`` uses for the backward-compatibility path.
        """
        return [
            ShardAssignment(
                shard_index=i,
                shard_count=count,
                assigned_scanners=partition_scanners(names, i, count),
                candidate_scanners=sorted(set(names)) if record_candidates else None,
            )
            for i in range(count)
        ]

    def test_a_complete_set_passes(self):
        verify_shard_coverage(self._assignments(3))

    def test_a_missing_shard_is_refused(self):
        assignments = self._assignments(3)
        del assignments[1]
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(assignments)
        # The message must name the gap; "merge failed" alone leaves the
        # operator to guess which job did not upload its artifact.
        assert "1" in str(excinfo.value)

    def test_a_duplicate_shard_is_refused(self):
        assignments = self._assignments(3)
        assignments.append(assignments[0])
        with pytest.raises(ShardCoverageError):
            verify_shard_coverage(assignments)

    def test_a_duplicate_empty_shard_is_refused(self):
        # Isolates the duplicate-index check from the scanner-overlap check.
        # Duplicating a *populated* shard trips both, so it does not prove the
        # index check works. Empty shards are not hypothetical: any shard count
        # above the scanner count produces them, and collecting one job's
        # artifact twice has to be refused even when it claims no scanners.
        count = len(SCANNERS) + 2
        assignments = self._assignments(count)
        empties = [a for a in assignments if not a.assigned_scanners]
        assert empties, "expected surplus shards to be empty"
        assignments.append(empties[0])
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(assignments)
        assert "more than once" in str(excinfo.value)

    def test_disagreeing_shard_counts_are_refused(self):
        # Two jobs from different runs, or a pipeline whose shard count changed
        # mid-flight. Merging them would produce a report missing whole scanners
        # while looking structurally fine.
        assignments = self._assignments(3)
        assignments[2] = ShardAssignment(
            shard_index=2, shard_count=4, assigned_scanners=["syft"]
        )
        with pytest.raises(ShardCoverageError):
            verify_shard_coverage(assignments)

    def test_a_scanner_claimed_by_two_shards_is_refused(self):
        assignments = self._assignments(2)
        assignments[1].assigned_scanners.append(assignments[0].assigned_scanners[0])
        with pytest.raises(ShardCoverageError):
            verify_shard_coverage(assignments)

    def test_empty_input_is_refused(self):
        # Nothing to merge is a failure, not a clean empty report: an empty
        # report reads as "no findings".
        with pytest.raises(ShardCoverageError):
            verify_shard_coverage([])


class TestCandidateSetIsVerified:
    """The hole the module docstring claimed was caught here, and was not.

    Every other check in ``verify_shard_coverage`` reads only shard indices and
    assignments. Two executors that resolve *different* scanner sets each produce
    an internally valid partition, so counts agree, indices are complete, there
    are no duplicates and no overlap -- and a scanner only one of them knew about
    was never run. The worked example below is the smallest form of it.

    Why this is not already covered by ``merge._verify_scanner_union``
    ----------------------------------------------------------------
    That check does catch this case in practice, but incidentally: it works from
    the SKIPPED markers each shard writes for scanners it did not own, which is a
    property of how ``ScanPhase`` records exclusions rather than of the coverage
    contract. ``verify_shard_coverage`` is exported in ``sharding.__all__``, so a
    caller using it on its own -- which is exactly what its docstring invites --
    got no hole detection at all.
    """

    def _shard(self, index, count, assigned, candidates):
        return ShardAssignment(
            shard_index=index,
            shard_count=count,
            assigned_scanners=list(assigned),
            candidate_scanners=list(candidates),
        )

    def test_the_reviewers_worked_example_is_refused(self):
        """shard_count=2; executor 1 is missing plugin ``d``.

        Executor 0 resolves {a,b,c,d} and takes [a,c]; executor 1 resolves {a,b,c}
        and takes [b]. Counts agree, indices complete, no duplicates, no overlap.
        Before ``candidate_scanners`` this passed and ``d`` was never scanned.
        """
        assignments = [
            self._shard(0, 2, ["a", "c"], ["a", "b", "c", "d"]),
            self._shard(1, 2, ["b"], ["a", "b", "c"]),
        ]
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(assignments)
        assert "different scanner sets" in str(excinfo.value)

    def test_every_check_except_the_candidate_one_passes_on_that_example(self):
        """Proves the example really is invisible to the other checks.

        Without this, the test above would pass for a set of shards that any check
        would have rejected, and it would not be evidence that the new check is
        what catches the hole.
        """
        assignments = [
            self._shard(0, 2, ["a", "c"], ["a", "b", "c", "d"]),
            self._shard(1, 2, ["b"], ["a", "b", "c"]),
        ]
        stripped = [
            ShardAssignment(
                shard_index=a.shard_index,
                shard_count=a.shard_count,
                assigned_scanners=a.assigned_scanners,
            )
            for a in assignments
        ]
        # No raise: this is the state the function was in before this change.
        verify_shard_coverage(stripped)

    def test_an_agreed_candidate_set_the_partition_does_not_cover_is_refused(self):
        """One executor's own partition missing a scanner it did resolve.

        Distinct from the disagreement case: here both shards agree the candidate
        set includes ``d``, and neither took it. A partition bug rather than an
        environment difference.
        """
        candidates = ["a", "b", "c", "d"]
        assignments = [
            self._shard(0, 2, ["a", "c"], candidates),
            self._shard(1, 2, ["b"], candidates),
        ]
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(assignments)
        assert "assigned to none" in str(excinfo.value)
        assert "d" in str(excinfo.value)

    def test_an_assignment_outside_the_candidate_set_is_refused(self):
        candidates = ["a", "b"]
        assignments = [
            self._shard(0, 2, ["a", "zzz-not-a-candidate"], candidates),
            self._shard(1, 2, ["b"], candidates),
        ]
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(assignments)
        assert "not in the candidate set" in str(excinfo.value)

    def test_a_complete_agreeing_set_passes(self):
        candidates = ["a", "b", "c", "d"]
        verify_shard_coverage(
            [
                self._shard(0, 2, ["a", "c"], candidates),
                self._shard(1, 2, ["b", "d"], candidates),
            ]
        )

    def test_candidate_names_are_compared_case_insensitively(self):
        """The rest of the CLI treats scanner names case insensitively.

        A case-sensitive comparison here would read "Bandit" and "bandit" as two
        scanners and refuse a correct set of shards -- a merge that fails on a
        naming difference is as bad as one that passes on a real gap.
        """
        verify_shard_coverage(
            [
                self._shard(0, 2, ["Bandit"], ["Bandit", "semgrep"]),
                self._shard(1, 2, ["SEMGREP"], ["bandit", "Semgrep"]),
            ]
        )

    def test_a_real_partition_of_the_recorded_candidates_passes(self):
        """The mainline case, over every shard count the partition supports."""
        for count in (1, 2, 3, 5, len(SCANNERS) + 2):
            verify_shard_coverage(
                [
                    ShardAssignment(
                        shard_index=i,
                        shard_count=count,
                        assigned_scanners=partition_scanners(SCANNERS, i, count),
                        candidate_scanners=SCANNERS,
                    )
                    for i in range(count)
                ]
            )


class TestCandidateSetBackwardCompatibility:
    """Results written before ``candidate_scanners`` existed must still merge."""

    def test_no_shard_recording_candidates_skips_the_check(self):
        assignments = [
            ShardAssignment(
                shard_index=i,
                shard_count=2,
                assigned_scanners=partition_scanners(SCANNERS, i, 2),
            )
            for i in range(2)
        ]
        assert all(a.candidate_scanners is None for a in assignments)
        verify_shard_coverage(assignments)

    def test_a_mixed_set_is_refused(self):
        """Some shards carrying the field and some not is not verifiable.

        Checking only the shards that do carry it would report a pass that means
        less than it appears to: the shards predating the field are exactly the
        ones that could be hiding the gap. Refusing names the real problem, which
        is a matrix running two versions of ASH.
        """
        assignments = [
            ShardAssignment(
                shard_index=0,
                shard_count=2,
                assigned_scanners=partition_scanners(SCANNERS, 0, 2),
                candidate_scanners=SCANNERS,
            ),
            ShardAssignment(
                shard_index=1,
                shard_count=2,
                assigned_scanners=partition_scanners(SCANNERS, 1, 2),
            ),
        ]
        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(assignments)
        assert "record no candidate scanner set" in str(excinfo.value)

    def test_the_field_round_trips_through_json(self):
        """``ash merge`` reads these back off disk, so serialization is the contract."""
        original = ShardAssignment(
            shard_index=0,
            shard_count=2,
            assigned_scanners=["bandit"],
            candidate_scanners=["bandit", "semgrep"],
        )
        restored = ShardAssignment.model_validate_json(original.model_dump_json())
        assert restored.candidate_scanners == ["bandit", "semgrep"]

    def test_an_absent_key_validates_to_none(self):
        """A results file written by an older ASH has no such key at all."""
        restored = ShardAssignment.model_validate(
            {"shard_index": 0, "shard_count": 1, "assigned_scanners": ["bandit"]}
        )
        assert restored.candidate_scanners is None
