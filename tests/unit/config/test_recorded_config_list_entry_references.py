# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""take_own_values carries the operator's references written inside a field.

The operator's value for a field the record cannot hold is copied into the
record whole. A list field written entry by entry has a reference at each
entry's index, and only a reference at the field's own path was carried, so a
record written out again held the operator's entry read from the environment
as text.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.config_validator import EnvironmentRewrite
from automated_security_helper.config.recorded_config import take_own_values

pytestmark = pytest.mark.unit


class _Config(dict):
    """A configuration as take_own_values reads one: its fields as keys, and
    the references its files wrote as an attribute."""


def _rewrite(path) -> EnvironmentRewrite:
    return EnvironmentRewrite(
        "value", path, "html", "${ASH_U35_F}", "html", "${ASH_U35_F}"
    )


def _taken(own: _Config) -> _Config:
    record = _Config({"output_formats": ["sarif"], "project_name": "p"})
    take_own_values(record, own, references=[("output_formats", "${ASH_U35_F}")])
    return record


def test_a_reference_at_a_list_entry_of_the_field_is_carried() -> None:
    """Red at the base: the record carried no reference."""
    own = _Config({"output_formats": ["sarif", "html"], "project_name": "o"})
    own._written_references = [_rewrite(("output_formats", 1))]

    record = _taken(own)

    assert record["output_formats"] == ["sarif", "html"]
    carried = getattr(record, "_written_references", [])
    assert [r.path for r in carried] == [("output_formats", 1)]


def test_a_reference_at_the_field_itself_is_still_carried() -> None:
    """The control: a field the file wrote as one reference."""
    own = _Config({"output_formats": ["html"], "project_name": "o"})
    own._written_references = [_rewrite(("output-formats",))]

    record = _taken(own)

    carried = getattr(record, "_written_references", [])
    assert [r.path for r in carried] == [("output_formats",)]


def test_a_reference_of_another_field_is_not_carried() -> None:
    """The control: the operator's references outside the field stay out."""
    own = _Config({"output_formats": ["sarif"], "project_name": "o"})
    own._written_references = [_rewrite(("project_name",))]

    record = _taken(own)

    assert getattr(record, "_written_references", []) == []
