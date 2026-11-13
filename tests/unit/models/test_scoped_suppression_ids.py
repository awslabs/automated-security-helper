# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Scoped suppressions carry their scope in their id.

Without it, the demo shape (one rule, one path, 26 resource_ids) collapsed
into one id: one matched entry marked all 26 as used, so the control entry was
never reported unused, and the config linter's by-id map collapsed them too.
The scope part is canonical over both dict shapes the id is built from (a
model dump and the linter's raw YAML), so the two keep agreeing.
"""

import pytest

from automated_security_helper.models.core import AshSuppression, suppression_id
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    should_suppress_finding,
)

pytestmark = pytest.mark.unit


def _entry(resource_id):
    return AshSuppression.model_validate(
        {
            "rule_id": "AwsSolutions-IAM5",
            "path": "cdk.out/*.template.json",
            "reason": "r",
            "resource_id": resource_id,
        }
    )


def _finding(resource_id="Stack/A/Resource"):
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="MEDIUM",
        scanner="cdk-nag",
        scanner_type="IAC",
        rule_id="AwsSolutions-IAM5",
        file_path="cdk.out/stack.template.json",
        resource_id=resource_id,
    )


class TestScopedIds:
    def test_entries_differing_only_by_resource_id_have_distinct_ids(self):
        assert _entry("Stack/A/Resource").id != _entry("Stack/B/Resource").id

    def test_the_unmatched_entry_reads_as_unused(self):
        matched_entry = _entry("Stack/A/Resource")
        control = _entry("Stack/NoSuchThing/Resource")
        suppressed, matching = should_suppress_finding(
            _finding(), [matched_entry, control]
        )
        assert suppressed and matching is matched_entry
        used_ids = {matching.id}
        unused = [s for s in (matched_entry, control) if s.id not in used_ids]
        assert unused == [control]

    def test_the_linters_raw_dict_agrees_with_the_model(self):
        raw = {
            "rule_id": "AwsSolutions-IAM5",
            "path": "cdk.out/*.template.json",
            "reason": "r",
            "resource_id": "Stack/A/Resource",
        }
        assert suppression_id(raw) == _entry("Stack/A/Resource").id

    def test_engine_names_and_resource_type_take_part(self):
        base = {"rule_id": "R", "path": "a", "reason": "r"}
        with_type = AshSuppression.model_validate(
            {**base, "scope": {"resource_type": "AWS::IAM::Policy"}}
        )
        with_engine = AshSuppression.model_validate(
            {**base, "scope": {"engines": {"cdk-nag": {"applies_to": "X"}}}}
        )
        assert with_type.id != with_engine.id
        assert "scope=" in with_type.id

    def test_an_unscoped_entry_keeps_its_old_id(self):
        entry = AshSuppression.model_validate(
            {"rule_id": "R-1", "path": "a.py", "reason": "r"}
        )
        assert entry.id == "a.py|R-1|*|*"

    def test_non_string_raw_values_are_coerced_not_a_traceback(self):
        """The linter hands this raw YAML: an unquoted ``resource_id: 123`` or
        mixed-type engine keys must produce an id (and so a lint finding),
        never a TypeError out of ``"@".join`` or ``sorted()``."""
        raw = {
            "rule_id": "R",
            "path": "a",
            "reason": "r",
            "scope": {"resource_id": 123, "engines": {1: {}, "cdk-nag": {}}},
        }
        assert suppression_id(raw).endswith("|scope=123@*@1,cdk-nag")

    def test_non_string_flat_raw_values_are_coerced_not_a_traceback(self):
        """An unquoted ``package_version: 1.2`` is a float in raw YAML (the
        common spelling for versions), and path or rule_id can be bare
        numbers; every flat piece is coerced as the scope part already is,
        so the linter gets an id (and so a lint finding), never a TypeError."""
        raw = {
            "rule_id": 1234,
            "path": 2024,
            "reason": "r",
            "package_name": "requests",
            "package_version": 1.2,
        }
        assert suppression_id(raw) == "2024|1234|*|*|requests@1.2@*"
