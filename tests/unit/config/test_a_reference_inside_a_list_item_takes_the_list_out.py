# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A recorded reference in a fixed-choice field inside a list item takes the list out.

``without_unreadable_references`` cut only trailing list indices off the refused
field's path, so a fixed-choice field INSIDE a list item
(``content_db_staleness_overrides[i].policy``) kept a path through the index,
which the pop cannot walk: the field was reported handled while nothing was
removed, and a results file whose record held such a reference could not be
read at all. The path is now cut at the first index, so the whole list is the
field taken out, as the documented rule says for a reference in a list.

Red at the base: ``kept`` still held the list and the record stayed unreadable.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.recorded_config import (
    without_unreadable_references,
)

pytestmark = pytest.mark.unit


class _Refusal:
    def __init__(self, items: list) -> None:
        self._items = items

    def errors(self) -> list:
        return self._items


def test_the_list_holding_the_item_is_taken_out() -> None:
    data = {
        "fail_on_findings": True,
        "content_db_staleness_overrides": [
            {
                "database": "grype-db",
                "policy": "${ASH_U35_POLICY}",
                "expiration": "2099-01-01",
                "reason": "held",
            }
        ],
    }
    refusal = _Refusal(
        [
            {
                "type": "literal_error",
                "loc": ("content_db_staleness_overrides", 0, "policy"),
                "input": "${ASH_U35_POLICY}",
            }
        ]
    )

    kept, found = without_unreadable_references(data, refusal)

    assert "content_db_staleness_overrides" not in kept
    assert kept["fail_on_findings"] is True
    assert found == [("content_db_staleness_overrides", "${ASH_U35_POLICY}")]
    # The input is left as it was.
    assert "content_db_staleness_overrides" in data


def test_a_reference_at_a_list_index_takes_the_list_out_as_before() -> None:
    """The control: the documented list rule, a reference that IS the item."""
    data = {"output_formats": ["${ASH_U35_FORMAT}"]}
    refusal = _Refusal(
        [
            {
                "type": "value_error",
                "loc": ("output_formats", 0),
                "input": "${ASH_U35_FORMAT}",
            }
        ]
    )

    kept, found = without_unreadable_references(data, refusal)

    assert kept == {}
    assert found == [("output_formats", "${ASH_U35_FORMAT}")]
