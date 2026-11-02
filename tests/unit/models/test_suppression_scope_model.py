# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``scope`` envelope on a suppression: universal keys plus engine blocks.

A scope carries the universal keys ASH's own matcher evaluates
(``resource_id``, ``resource_type``) and per-engine blocks under ``engines``,
keyed by scanner name and owned by the named plugin. An empty scope, an empty
``engines`` map and an empty engine block are refused: a suppression is a
security-relevant widening, so match-all must be the absence of the field,
never an empty dict.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.models.core import (
    AshSuppression,
    EMPTY_SCOPE_NOTE,
    SuppressionScope,
)
from automated_security_helper.utils.unknown_keys import (
    TOLERATE_STORED_CONFIG,
    WARN_UNKNOWN_KEYS,
)

pytestmark = pytest.mark.unit


CANONICAL = {
    "rule_id": "AwsSolutions-IAM5",
    "path": "cdk.out/*.template.json",
    "reason": "Wildcard is scoped to the collector's own log group prefix",
    "expiration": "2099-06-30",
    "scope": {
        "resource_id": "Stack/CollectorTaskRole/DefaultPolicy/Resource",
        "resource_type": "AWS::IAM::Policy",
        "engines": {
            "cdk-nag": {
                "applies_to": "Action::logs:*",
                "resource_path": "Stack/CollectorTaskRole/DefaultPolicy/Resource",
            }
        },
    },
}


class TestScopeParses:
    def test_the_canonical_shape_parses(self):
        entry = AshSuppression.model_validate(CANONICAL)
        assert entry.scope is not None
        assert (
            entry.scope.resource_id == "Stack/CollectorTaskRole/DefaultPolicy/Resource"
        )
        assert entry.scope.resource_type == "AWS::IAM::Policy"
        assert set(entry.scope.engines) == {"cdk-nag"}

    def test_an_entry_without_scope_still_parses(self):
        entry = AshSuppression.model_validate(
            {"rule_id": "R", "path": "a.py", "reason": "r"}
        )
        assert entry.scope is None

    def test_a_resource_id_alone_is_a_valid_scope(self):
        scope = SuppressionScope.model_validate({"resource_id": "Stack/Thing"})
        assert not scope.selects_nothing


class TestEmptyShapesRefused:
    def test_an_empty_scope_is_refused(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {"rule_id": "R", "path": "a.py", "reason": "r", "scope": {}}
            )
        assert "selects nothing" in str(excinfo.value)

    def test_empty_engines_is_refused(self):
        with pytest.raises(ValidationError) as excinfo:
            SuppressionScope.model_validate({"engines": {}})
        assert "selects nothing" in str(excinfo.value)

    def test_an_empty_engine_block_is_refused(self):
        with pytest.raises(ValidationError) as excinfo:
            SuppressionScope.model_validate({"engines": {"cdk-nag": {}}})
        message = str(excinfo.value)
        assert "selects nothing" in message
        assert "cdk-nag" in message

    def test_a_blank_resource_id_is_refused(self):
        with pytest.raises(ValidationError) as excinfo:
            SuppressionScope.model_validate({"resource_id": "  "})
        assert "selects nothing" in str(excinfo.value)

    def test_a_tolerated_empty_scope_is_kept_and_selects_nothing(self):
        notes: list = []
        scope = SuppressionScope.model_validate(
            {}, context={TOLERATE_STORED_CONFIG: notes}
        )
        assert EMPTY_SCOPE_NOTE in notes
        assert scope.selects_nothing


class TestScopeUnknownKeys:
    def test_an_unknown_scope_key_is_refused_with_did_you_mean(self):
        with pytest.raises(ValidationError) as excinfo:
            SuppressionScope.model_validate({"resource_idd": "Stack/Thing"})
        message = str(excinfo.value)
        assert "Unknown key 'resource_idd'" in message
        assert "did you mean 'resource_id'?" in message
        assert "a suppression scope" in message

    def test_an_unknown_scope_key_warns_under_warn_mode(self):
        warnings: list = []
        scope = SuppressionScope.model_validate(
            {"resource_idd": "Stack/Thing"},
            context={WARN_UNKNOWN_KEYS: warnings},
        )
        assert len(warnings) == 1
        assert "Unknown key 'resource_idd'" in warnings[0]
        assert scope.has_unknown_keys
