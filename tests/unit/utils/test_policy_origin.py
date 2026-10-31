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
