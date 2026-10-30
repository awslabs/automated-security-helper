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

import logging
from collections.abc import Iterator
from contextlib import contextmanager

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


class _Records(logging.Handler):
    """Keeps every record the logger emits, as the sinks receive it."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@contextmanager
def _recording() -> Iterator[_Records]:
    """ASH's logger at WARNING with a recording handler on it, for the block.

    The logger's own level is set for the duration: a merge that ran earlier in
    the process may have left it higher, and then nothing would reach the
    handler and an empty list would read as "nothing logged".
    """
    from automated_security_helper.core import sharding

    records = _Records()
    saved_level = sharding.ASH_LOGGER.level
    sharding.ASH_LOGGER.addHandler(records)
    sharding.ASH_LOGGER.setLevel(logging.WARNING)
    try:
        yield records
    finally:
        sharding.ASH_LOGGER.removeHandler(records)
        sharding.ASH_LOGGER.setLevel(saved_level)


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

        sharding._WARNED_PROVENANCE_KEYS.clear()
        record = {
            "shard_index": 1,
            "shard_count": 2,
            "assigned_scanners": ["bandit"],
            "field_from_a_newer_ash": {"anything": True},
        }
        with patch.object(sharding.ASH_LOGGER, "warning") as warning:
            # A merge validates one shard's record several times; the warning
            # is said once per record.
            ShardAssignment.model_validate(record)
            ShardAssignment.model_validate(dict(record))
            ShardAssignment.model_validate({**record, "shard_index": 0})

        assert warning.call_count == 2, warning.call_args_list
        text = warning.call_args_list[0].args[0]
        assert "field_from_a_newer_ash" in text
        assert "shard 1" in text

    def test_the_dropped_names_are_shown_once_at_the_sinks(self):
        """A dropped key's text comes from a results file any shard wrote. It was
        shown (ESC as the text ``\\x1b``) before the message was built, and the
        console and ash.log sinks then showed the plain message again, so the
        console read ``\\\\x1b``, two backslashes for one ESC, and a backslash
        that reads as an escape four deep. The values are now put in raw and the
        whole message is shown once, as a ShownText the sinks write as it is. Checked as
        both sinks write the record (console_text, and ash.log's
        TextFileFormatter)."""
        from automated_security_helper.core import sharding
        from automated_security_helper.utils.log import TextFileFormatter, console_text
        from automated_security_helper.utils.terminal_text import ShownText

        sharding._WARNED_PROVENANCE_KEYS.clear()
        with _recording() as records:
            ShardAssignment.model_validate(
                {
                    "shard_index": 1,
                    "shard_count": 2,
                    "assigned_scanners": ["bandit"],
                    "k\x1b[31m": True,
                    "##group[x": True,
                    "C:\\x64": True,
                }
            )

        [record] = [r for r in records.records if "does not know" in r.getMessage()]
        assert isinstance(record.msg, ShownText), type(record.msg)
        assert getattr(record, "markup", True) is False
        for printed in (
            console_text(record, record.getMessage()),
            TextFileFormatter("%(message)s").format(record),
        ):
            # ESC as one escape; the runner command's first "#" as its escape; a
            # backslash that reads as an escape doubled once.
            assert "k\\x1b[31m" in printed, printed
            assert "\\x23#group[x" in printed, printed
            assert "C:\\\\x64" in printed, printed
            assert "\\\\x1b" not in printed and "\\\\x23" not in printed, printed
            assert "\\\\\\\\" not in printed, printed
            assert "\x1b" not in printed and "\n" not in printed, repr(printed)

    def test_a_shard_index_that_is_not_an_int_is_shown_once_too(self):
        """The index is read from the same file as the keys and goes into the
        message the same way; a text index carrying ESC is shown once."""
        from pydantic import ValidationError

        from automated_security_helper.core import sharding
        from automated_security_helper.utils.log import console_text

        sharding._WARNED_PROVENANCE_KEYS.clear()
        with _recording() as records, pytest.raises(ValidationError):
            ShardAssignment.model_validate(
                {
                    "shard_index": "one\x1b[0m",
                    "shard_count": 2,
                    "assigned_scanners": ["bandit"],
                    "field_from_a_newer_ash": True,
                }
            )

        [record] = [r for r in records.records if "does not know" in r.getMessage()]
        printed = console_text(record, record.getMessage())
        assert "shard one\\x1b[0m" in printed, printed
        assert "\\\\x1b" not in printed and "\x1b" not in printed, repr(printed)

    def test_a_record_with_only_known_fields_logs_nothing(self):
        """The control for the warning."""
        from unittest.mock import patch

        from automated_security_helper.core import sharding

        sharding._WARNED_PROVENANCE_KEYS.clear()
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
        # No other shard ran the scanner, so the refusal does not say one did.
        assert "outside the split" in str(excinfo.value)
        assert "in no shard's assignment" in str(excinfo.value)
        assert "assigned to another shard" not in str(excinfo.value)
        assert "ran on both shards" not in str(excinfo.value)

    def test_a_mix_keeps_the_two_shard_header_and_adds_the_no_owner_sentence(self):
        shards = [
            self._shard(
                0, ["bandit", "grype"], ["bandit", "grype", "semgrep", "stray"]
            ),
            self._shard(1, ["checkov", "semgrep"], ["checkov", "semgrep"]),
        ]

        with pytest.raises(ShardCoverageError) as excinfo:
            verify_shard_coverage(shards)
        text = str(excinfo.value)
        assert "assigned to another shard" in text
        assert "assigned to shard 1" in text
        assert "assigned to no shard" in text
        assert "outside the split" in text

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
