# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An expected transformation covers the elements of a list-valued field.

``EXPECTED_TRANSFORMATIONS`` names ``properties.tags``, and the matching its
consumer did (exact path, or ``entry.`` as a prefix) left every indexed element
``properties.tags[N]`` uncovered, so each tag of an expected-to-change list was
reported as a missing field. ``is_expected_transformation`` is the one reading of
the list for every consumer.
"""

import pytest

from automated_security_helper.utils.meta_analysis import (
    EXPECTED_TRANSFORMATIONS,
    is_expected_transformation,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("entry", EXPECTED_TRANSFORMATIONS)
def test_every_entry_covers_itself_and_its_dotted_children(entry):
    assert is_expected_transformation(entry)
    assert is_expected_transformation(f"{entry}.child")


def test_an_indexed_element_of_a_list_valued_entry_is_covered():
    assert is_expected_transformation("properties.tags[0]")
    assert is_expected_transformation("properties.tags[3]")
    assert is_expected_transformation("properties.tags[0].name")


def test_a_field_that_only_shares_a_prefix_is_not_covered():
    assert not is_expected_transformation("properties.tagsExtra")
    assert not is_expected_transformation("ruleIndexed")
    assert not is_expected_transformation("ruleId")
    assert not is_expected_transformation("")
