# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The applied suppression records its scope by the WRITTEN form only.

This module records a reason read from the environment by its reference, never
the value; the scope's resource identity follows the same rule. The entry-level
sugar has a written record (SHOWN_SUPPRESSION_FIELDS), so it is recorded,
rewritten to the reference where one applies. A canonical-spelling scope has no
written record, so its value keys are left out of the SARIF rather than risk a
resolved environment value in every report; the engine names stay.
"""

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Message1,
    Result,
)
from automated_security_helper.utils.sarif_utils import _apply_config_suppression

pytestmark = pytest.mark.unit

CONSTRUCT_PATH = "Stack/Role/DefaultPolicy/Resource"


def _finding():
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="MEDIUM",
        scanner="cdk-nag",
        scanner_type="IAC",
        rule_id="AwsSolutions-IAM5",
        file_path="cdk.out/stack.template.json",
        resource_id=CONSTRUCT_PATH,
        resource_type="AWS::IAM::Policy",
    )


def _result():
    return Result(
        ruleId="AwsSolutions-IAM5",
        message=Message(root=Message1(text="t")),
    )


def _apply(entry, recorded_fields=None):
    result = _result()
    applied = _apply_config_suppression(
        result,
        [entry],
        _finding(),
        used_suppressions=set(),
        recorded_fields=recorded_fields,
    )
    assert applied is True
    return result.suppressions[0]


class TestWrittenForm:
    def test_an_env_read_sugar_records_the_reference(self):
        entry = AshSuppression.model_validate(
            {
                "rule_id": "AwsSolutions-IAM5",
                "path": "cdk.out/*.template.json",
                "reason": "r",
                "resource_id": CONSTRUCT_PATH,
            }
        )
        recorded = {id(entry): {"resource_id": "${RESOURCE_PATH}"}}
        suppression = _apply(entry, recorded_fields=recorded)
        assert suppression.properties.scope_resource_id == "${RESOURCE_PATH}"
        assert CONSTRUCT_PATH not in (suppression.properties.scope_resource_id or "")

    def test_a_literal_sugar_records_the_literal(self):
        entry = AshSuppression.model_validate(
            {
                "rule_id": "AwsSolutions-IAM5",
                "path": "cdk.out/*.template.json",
                "reason": "r",
                "resource_id": CONSTRUCT_PATH,
            }
        )
        suppression = _apply(entry, recorded_fields=None)
        assert suppression.properties.scope_resource_id == CONSTRUCT_PATH

    def test_a_canonical_only_scope_records_no_value_keys(self):
        entry = AshSuppression.model_validate(
            {
                "rule_id": "AwsSolutions-IAM5",
                "path": "cdk.out/*.template.json",
                "reason": "r",
                "scope": {
                    "resource_id": CONSTRUCT_PATH,
                    "resource_type": "AWS::IAM::Policy",
                },
            }
        )
        suppression = _apply(entry)
        properties = suppression.properties
        extra = properties.model_extra if properties is not None else {}
        assert "scope_resource_id" not in (extra or {})
        assert "scope_resource_type" not in (extra or {})
