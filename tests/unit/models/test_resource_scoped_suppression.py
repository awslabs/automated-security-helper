# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Matching a suppression ``scope`` against a finding's resource identity.

The universal keys are evaluated by ``AshSuppression.matches`` for every
engine: literal equality first, then a glob with ``[`` escaped (the cdk-nag
bracket lesson), ``resource_id`` case-sensitive and ``resource_type``
case-insensitive. Everything fails closed: a finding that carries no resource
identity never matches a resource-scoped entry, and an ``engines`` list covers
only the scanners it names.
"""

import pytest

from automated_security_helper.models.core import (
    AshSuppression,
    scope_value_matches,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils import suppression_scope_registry

pytestmark = pytest.mark.unit

CONSTRUCT_PATH = "Stack/CollectorTaskRole/DefaultPolicy/Resource"


def _finding(**overrides):
    values = {
        "id": "f1",
        "title": "t",
        "description": "d",
        "severity": "HIGH",
        "scanner": "cdk-nag",
        "scanner_type": "IAC",
        "rule_id": "AwsSolutions-IAM5",
        "file_path": "cdk.out/stack.template.json",
        "resource_id": CONSTRUCT_PATH,
        "resource_type": "AWS::IAM::Policy",
    }
    values.update(overrides)
    return FlatVulnerability(**values)


def _entry(**scope):
    return AshSuppression.model_validate(
        {
            "rule_id": "AwsSolutions-IAM5",
            "path": "cdk.out/*.template.json",
            "reason": "test",
            "scope": scope,
        }
    )


class TestResourceIdMatching:
    def test_literal_hit(self):
        assert _entry(resource_id=CONSTRUCT_PATH).matches(_finding())

    def test_glob_hit(self):
        assert _entry(resource_id="Stack/CollectorTaskRole/*").matches(_finding())

    def test_miss(self):
        assert not _entry(resource_id="Stack/OtherRole/*").matches(_finding())

    def test_a_bracket_containing_id_is_matched_literally(self):
        bracketed = "Stack/Thing[0]/Resource"
        entry = _entry(resource_id=bracketed)
        assert entry.matches(_finding(resource_id=bracketed))

    def test_resource_id_is_case_sensitive(self):
        assert not _entry(resource_id=CONSTRUCT_PATH.lower()).matches(_finding())

    def test_a_finding_with_no_identity_never_matches(self):
        entry = _entry(resource_id=CONSTRUCT_PATH)
        assert not entry.matches(_finding(resource_id=None, resource_type=None))


class TestResourceTypeMatching:
    def test_resource_type_is_case_insensitive(self):
        assert _entry(resource_type="aws::iam::policy").matches(_finding())

    def test_resource_type_glob(self):
        assert _entry(resource_type="AWS::IAM::*").matches(_finding())

    def test_a_finding_with_no_type_never_matches(self):
        entry = _entry(resource_type="AWS::IAM::Policy")
        assert not entry.matches(_finding(resource_type=None))

    def test_both_universal_keys_are_anded(self):
        entry = _entry(resource_id=CONSTRUCT_PATH, resource_type="AWS::S3::*")
        assert not entry.matches(_finding())


class TestEnginesEnumerate:
    def test_an_unlisted_scanner_does_not_match(self):
        entry = _entry(engines={"cdk-nag": {"resource_path": CONSTRUCT_PATH}})
        assert not entry.matches(_finding(scanner="checkov"))

    def test_a_listed_engine_with_no_registered_plugin_fails_closed(self, monkeypatch):
        # The cdk-nag plugin registers itself at module import, so a prior
        # test importing it leaves the process-global registry populated;
        # the unregistered state this test pins must be explicit.
        monkeypatch.delitem(
            suppression_scope_registry._ENGINE_HOOKS, "cdk-nag", raising=False
        )
        entry = _entry(engines={"cdk-nag": {"resource_path": CONSTRUCT_PATH}})
        assert not entry.matches(_finding())


class TestNoScopeUnchanged:
    def test_an_entry_without_scope_matches_as_before(self):
        entry = AshSuppression.model_validate(
            {
                "rule_id": "AwsSolutions-IAM5",
                "path": "cdk.out/*.template.json",
                "reason": "test",
            }
        )
        assert entry.matches(_finding())
        assert entry.matches(_finding(resource_id=None, resource_type=None))


class TestScopeValueMatches:
    def test_literal_before_glob(self):
        assert scope_value_matches("a[b]", "a[b]", case_sensitive=True)

    def test_glob_with_escaped_bracket(self):
        assert scope_value_matches("a[b]c", "a[b]*", case_sensitive=True)

    def test_case_folding(self):
        assert scope_value_matches("AbC", "abc", case_sensitive=False)
        assert not scope_value_matches("AbC", "abc", case_sensitive=True)
