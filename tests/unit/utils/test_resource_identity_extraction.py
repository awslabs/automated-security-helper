# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading a finding's resource identity for resource-scoped suppressions.

The contract is two flat property-bag keys, ``ash_resource_id`` and
``ash_resource_type`` (utils/package_identity.py). Results written before the
contract existed carry only cdk-nag's own bag (``cdk_nag_finding`` /
``cfn_resource``), which the extractor falls back to, so resource scoping
works against existing cdk-nag output files. An engine that publishes neither
answers (None, None), and a resource-scoped suppression then never matches its
findings (fail closed).
"""

import pytest

from automated_security_helper.schemas.sarif_schema_model import PropertyBag
from automated_security_helper.utils.package_identity import (
    ASH_RESOURCE_ID_KEY,
    ASH_RESOURCE_TYPE_KEY,
    extract_resource_identity,
)

pytestmark = pytest.mark.unit

CONSTRUCT_PATH = "ObservabilityDemoStack/CollectorTaskRole/DefaultPolicy/Resource"

#: The shape utils/cdk_nag_wrapper.py has shipped in the field: the report
#: line's dict and the one-resource template slice.
LEGACY_CDK_NAG_BAG = {
    "cdk_nag_finding": {
        "rule_id": "AwsSolutions-IAM5[Action::logs:*]",
        "resource_id": CONSTRUCT_PATH,
        "compliance": "Non-Compliant",
    },
    "cfn_resource": {
        "Resources": {"Resource": {"Type": "AWS::IAM::Policy", "Properties": {}}}
    },
}


class TestGenericKeysFirst:
    def test_reads_the_generic_keys(self):
        resource_id, resource_type = extract_resource_identity(
            {
                ASH_RESOURCE_ID_KEY: CONSTRUCT_PATH,
                ASH_RESOURCE_TYPE_KEY: "AWS::IAM::Policy",
            }
        )
        assert resource_id == CONSTRUCT_PATH
        assert resource_type == "AWS::IAM::Policy"

    def test_generic_keys_win_over_the_fallback(self):
        bag = dict(LEGACY_CDK_NAG_BAG)
        bag[ASH_RESOURCE_ID_KEY] = "Another/Path"
        resource_id, _ = extract_resource_identity(bag)
        assert resource_id == "Another/Path"

    def test_reads_a_property_bag_model(self):
        bag = PropertyBag(**{ASH_RESOURCE_ID_KEY: CONSTRUCT_PATH})
        resource_id, resource_type = extract_resource_identity(bag)
        assert resource_id == CONSTRUCT_PATH
        assert resource_type is None


class TestCdkNagFallback:
    def test_reads_the_shipped_cdk_nag_bag(self):
        resource_id, resource_type = extract_resource_identity(LEGACY_CDK_NAG_BAG)
        assert resource_id == CONSTRUCT_PATH
        assert resource_type == "AWS::IAM::Policy"

    def test_two_resources_give_no_type(self):
        bag = {
            "cfn_resource": {
                "Resources": {
                    "A": {"Type": "AWS::IAM::Policy"},
                    "B": {"Type": "AWS::S3::Bucket"},
                }
            }
        }
        assert extract_resource_identity(bag) == (None, None)


class TestFailClosed:
    def test_a_bare_bandit_shaped_result_has_no_identity(self):
        assert extract_resource_identity({"tags": ["security"]}) == (None, None)

    def test_none_and_non_dict_answer_nothing(self):
        assert extract_resource_identity(None) == (None, None)
        assert extract_resource_identity("text") == (None, None)

    def test_non_string_values_are_ignored(self):
        assert extract_resource_identity(
            {ASH_RESOURCE_ID_KEY: 7, ASH_RESOURCE_TYPE_KEY: ["x"]}
        ) == (None, None)
