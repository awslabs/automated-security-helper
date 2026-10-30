# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three shapes the sharding module meets in a mixed-version or defective fan-out.

A results file written by a newer ASH can carry a provenance field this version
does not know; ``ShardAssignment`` refused it, and ``ash merge`` then reported
the shard as having no provenance at all, naming the wrong cause. A caller that
reaches ``partition_scanners`` with no selection at all got a ``TypeError`` from
the modulo instead of the selection error every other bad pair raises. And a
shard that recorded selecting a scanner no shard was assigned passed the
selection check, which only compared against other shards' assignments, so two
such shards would merge with that scanner's findings counted twice.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.sharding import (
    ShardAssignment,
    ShardCoverageError,
    ShardSelectionError,
    partition_scanners,
    verify_shard_coverage,
)

pytestmark = pytest.mark.unit

SCANNERS = ["semgrep", "bandit", "grype", "checkov"]


class TestAnUnknownProvenanceFieldIsDropped:
    def test_a_field_this_version_does_not_know_still_loads(self):
        restored = ShardAssignment.model_validate(
            {
                "shard_index": 0,
                "shard_count": 2,
                "assigned_scanners": ["bandit"],
                "field_from_a_newer_ash": {"anything": True},
            }
        )

        assert restored.shard_index == 0
        assert restored.assigned_scanners == ["bandit"]
        assert not hasattr(restored, "field_from_a_newer_ash")

    def test_the_known_fields_are_still_validated(self):
        """The control: dropping unknown keys must not loosen the known ones."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ShardAssignment.model_validate(
                {"shard_index": "not-an-int", "shard_count": 2}
            )


class TestPartitionWithNoSelection:
    def test_no_index_and_no_count_is_a_selection_error(self):
        with pytest.raises(ShardSelectionError, match="both --shard-index"):
            partition_scanners(SCANNERS, None, None)

    def test_a_real_pair_still_partitions(self):
        """The control, so the refusal above is not an always-raise."""
        assert partition_scanners(SCANNERS, 0, 1) == sorted(SCANNERS)


class TestSelectingAScannerNoShardOwns:
    @staticmethod
    def _shard(index, assigned, selected):
        return ShardAssignment(
            shard_index=index,
            shard_count=2,
            assigned_scanners=list(assigned),
            candidate_scanners=sorted(SCANNERS),
            selected_scanners=list(selected),
        )

    def test_a_selection_outside_every_assignment_is_refused(self):
        shards = [
            self._shard(0, ["bandit", "grype"], ["bandit", "grype", "stray"]),
            self._shard(1, ["checkov", "semgrep"], ["checkov", "semgrep"]),
        ]

        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(shards)
        assert "stray" in str(excinfo.value)
        assert "assigned to no shard" in str(excinfo.value)

    def test_a_selection_within_the_assignment_passes(self):
        """The control, with the same shards and the stray selection removed."""
        shards = [
            self._shard(0, ["bandit", "grype"], ["bandit", "grype"]),
            self._shard(1, ["checkov", "semgrep"], ["checkov"]),
        ]

        verify_shard_coverage(shards)
