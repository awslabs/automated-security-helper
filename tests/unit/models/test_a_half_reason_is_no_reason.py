"""A container holds a whole reason or none, and a whole one replaces half of one.

``record_error_reason`` assigns the code and the sentence together and keeps the
first reason, but it returned early when either field was set, so a container built
from a one-key dict, or given one field by direct assignment, kept half a pair that
the readers treat as no reason and refused every full pair after it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)

pytestmark = pytest.mark.unit

FIRST = ("timed_out", "it timed out and was killed")
LATER = ("no_result", "it returned no result")


def _pair(container: ScanResultsContainer):
    return container.error_reason_code, container.error_reason


class TestAContainerBuiltFromHalfAPair:
    @pytest.mark.parametrize(
        "half",
        [
            {"error_reason_code": FIRST[0]},
            {"error_reason": FIRST[1]},
        ],
        ids=["a-code-only", "a-sentence-only"],
    )
    def test_the_half_is_cleared_when_it_is_built(self, half):
        container = ScanResultsContainer.model_validate(
            {"scanner_name": "example-tool", **half}
        )

        assert _pair(container) == (None, None)

    @pytest.mark.parametrize(
        "half",
        [
            {"error_reason_code": FIRST[0]},
            {"error_reason": FIRST[1]},
        ],
        ids=["a-code-only", "a-sentence-only"],
    )
    def test_a_later_full_pair_wins_over_the_cleared_half(self, half):
        container = ScanResultsContainer.model_validate(
            {"scanner_name": "example-tool", **half}
        )

        container.record_error_reason(*LATER)

        assert _pair(container) == LATER

    def test_the_cleared_fields_are_not_in_the_dump_that_leaves_unset_ones_out(self):
        container = ScanResultsContainer.model_validate(
            {"scanner_name": "example-tool", "error_reason_code": FIRST[0]}
        )

        dumped = container.model_dump(exclude_unset=True)

        assert "error_reason" not in dumped
        assert "error_reason_code" not in dumped

    def test_control_a_whole_pair_is_kept_as_it_was_built(self):
        container = ScanResultsContainer.model_validate(
            {
                "scanner_name": "example-tool",
                "error_reason_code": FIRST[0],
                "error_reason": FIRST[1],
            }
        )

        assert _pair(container) == FIRST
        assert container.model_dump(exclude_unset=True)["error_reason"] == FIRST[1]

    def test_control_a_container_with_neither_has_neither(self):
        container = ScanResultsContainer.model_validate(
            {"scanner_name": "example-tool"}
        )

        assert _pair(container) == (None, None)


class TestAContainerGivenHalfAPairByAssignment:
    """A plain assignment runs no validator, so the recorder has to take a full
    pair over a half one itself."""

    @pytest.mark.parametrize("field", ["error_reason_code", "error_reason"])
    def test_a_full_pair_replaces_the_half(self, field):
        container = ScanResultsContainer(scanner_name="example-tool")
        setattr(container, field, FIRST[0] if field.endswith("code") else FIRST[1])

        container.record_error_reason(*LATER)

        assert _pair(container) == LATER

    def test_control_the_first_whole_pair_is_kept(self):
        container = ScanResultsContainer(scanner_name="example-tool")
        container.record_error_reason(*FIRST)

        container.record_error_reason(*LATER)

        assert _pair(container) == FIRST

    def test_control_a_pair_that_is_not_two_strings_still_records_nothing(self):
        container = ScanResultsContainer(scanner_name="example-tool")

        container.record_error_reason(FIRST[0], "")
        container.record_error_reason("", FIRST[1])

        assert _pair(container) == (None, None)
