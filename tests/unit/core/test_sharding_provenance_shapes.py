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

    def test_a_dropped_field_is_named_at_warning(self):
        """The module fails closed on every other version mismatch, so a dropped
        field is said once, by name, rather than ignored in silence."""
        from unittest.mock import patch

        from automated_security_helper.core import sharding

        with patch.object(sharding.ASH_LOGGER, "warning") as warning:
            ShardAssignment.model_validate(
                {
                    "shard_index": 1,
                    "shard_count": 2,
                    "assigned_scanners": ["bandit"],
                    "field_from_a_newer_ash": {"anything": True},
                }
            )

        assert warning.call_count == 1, warning.call_args_list
        text = warning.call_args.args[0]
        assert "field_from_a_newer_ash" in text
        assert "shard 1" in text

    def test_a_record_with_only_known_fields_logs_nothing(self):
        """The control for the warning."""
        from unittest.mock import patch

        from automated_security_helper.core import sharding

        with patch.object(sharding.ASH_LOGGER, "warning") as warning:
            ShardAssignment.model_validate(
                {"shard_index": 0, "shard_count": 2, "assigned_scanners": ["bandit"]}
            )

        assert warning.call_count == 0, warning.call_args_list

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
        # The header speaks of a scanner that ran on both shards; this case gets
        # its own sentence.
        assert "outside the split" in str(excinfo.value)

    def test_a_selection_of_another_shards_scanner_keeps_the_two_shard_wording(
        self,
    ):
        """The control: the pinned refusal text for the other-shard case is
        unchanged (tests/snapshot/errors pins it)."""
        shards = [
            self._shard(0, ["bandit", "grype"], ["bandit", "grype", "semgrep"]),
            self._shard(1, ["checkov", "semgrep"], ["checkov", "semgrep"]),
        ]

        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(shards)
        assert "assigned to shard 1" in str(excinfo.value)
        assert "outside the split" not in str(excinfo.value)

    def test_a_selection_within_the_assignment_passes(self):
        """The control, with the same shards and the stray selection removed."""
        shards = [
            self._shard(0, ["bandit", "grype"], ["bandit", "grype"]),
            self._shard(1, ["checkov", "semgrep"], ["checkov"]),
        ]

        verify_shard_coverage(shards)
