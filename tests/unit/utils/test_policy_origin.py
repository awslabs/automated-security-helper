# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one predicate for a finding a workspace policy scanner produced.

A project's outcome reads ``properties.origin`` alone. These cases pin that the
shared predicate does too, for a mapping and for a property bag, and that a
``workspace-policy`` tag with no origin is not the mark.
"""

import pytest

from automated_security_helper.schemas.sarif_schema_model import PropertyBag
from automated_security_helper.utils.policy_origin import (
    POLICY_ORIGIN,
    is_policy_origin,
)
from automated_security_helper.workspace import aggregation

pytestmark = pytest.mark.unit


def test_a_mapping_with_the_origin_is_policy_origin():
    assert is_policy_origin({"origin": POLICY_ORIGIN})


def test_a_mapping_with_another_or_no_origin_is_not():
    assert not is_policy_origin({"origin": "project"})
    assert not is_policy_origin({})


def test_a_mapping_with_only_the_tag_is_not():
    assert not is_policy_origin({"tags": [POLICY_ORIGIN]})


def test_a_property_bag_with_the_origin_in_its_extras_is_policy_origin():
    assert is_policy_origin(PropertyBag(origin=POLICY_ORIGIN))


def test_a_property_bag_with_only_the_tag_is_not():
    assert not is_policy_origin(PropertyBag(tags=[POLICY_ORIGIN]))


def test_no_properties_is_not_policy_origin():
    assert not is_policy_origin(None)


#: One fixture per shape a property bag takes, with the answer both readers owe.
_BAGS = [
    pytest.param({"origin": POLICY_ORIGIN}, True, id="mapping-with-origin"),
    pytest.param({"origin": "project"}, False, id="mapping-other-origin"),
    pytest.param({}, False, id="empty-mapping"),
    pytest.param({"tags": [POLICY_ORIGIN]}, False, id="mapping-tag-only"),
    pytest.param(PropertyBag(origin=POLICY_ORIGIN), True, id="bag-with-origin"),
    pytest.param(PropertyBag(origin="project"), False, id="bag-other-origin"),
    pytest.param(PropertyBag(tags=[POLICY_ORIGIN]), False, id="bag-tag-only"),
]


class TestTheExecutorsReaderAsksTheSameQuestion:
    """``workspace.aggregation.is_policy_origin`` reads a whole SARIF result.

    It is the filter the project's outcome applies (the executor's
    ``gating_results``), so it must answer as the shared predicate does for the
    same property bag. It kept a copy that read mappings only, and said no to a
    bag held as a model.
    """

    @pytest.mark.parametrize(("properties", "expected"), _BAGS)
    def test_it_agrees_with_the_shared_predicate(self, properties, expected):
        """RED at the base for the two bag fixtures that name the origin: the
        copy answered False for any properties that were not a mapping."""
        assert is_policy_origin(properties) is expected
        assert aggregation.is_policy_origin({"properties": properties}) is expected

    def test_a_result_with_no_properties_is_not_policy_origin(self):
        assert aggregation.is_policy_origin({}) is False
        assert aggregation.is_policy_origin({"properties": None}) is False

    def test_it_spells_the_origin_as_the_shared_constant_does(self):
        assert aggregation.POLICY_ORIGIN == POLICY_ORIGIN
