# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cdk-nag's suppression-scope block: validation, matching, qualifier split.

``scope.engines.cdk-nag`` carries ``applies_to`` (compared exactly against the
granular qualifier cdk-nag appends to a rule id, as cdk-nag's own appliesTo)
and ``resource_path`` (matched against the CDK construct path). The plugin owns
both: ASH's core dispatches the block here and never reads its keys.
"""

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
    CdkNagScopeBlock,
)
from automated_security_helper.utils.suppression_scope_registry import (
    engine_hooks_for,
)

pytestmark = pytest.mark.unit

CONSTRUCT_PATH = "Stack/CollectorTaskRole/DefaultPolicy/Resource"


def _finding(rule_id="AwsSolutions-IAM5[Action::logs:*]", scanner="cdk-nag", **kw):
    values = {
        "id": "f1",
        "title": "t",
        "description": "d",
        "severity": "MEDIUM",
        "scanner": scanner,
        "scanner_type": "IAC",
        "rule_id": rule_id,
        "file_path": "cdk.out/stack.template.json",
        "resource_id": CONSTRUCT_PATH,
        "resource_type": "AWS::IAM::Policy",
    }
    values.update(kw)
    return FlatVulnerability(**values)


def _entry(block, rule_id="AwsSolutions-IAM5"):
    return AshSuppression.model_validate(
        {
            "rule_id": rule_id,
            "path": "cdk.out/*.template.json",
            "reason": "test",
            "scope": {"engines": {"cdk-nag": block}},
        }
    )


class TestRegistration:
    def test_cdk_nag_registers_its_hooks(self):
        assert engine_hooks_for("cdk-nag") is CdkNagScanner


class TestQualifierSplit:
    def test_splits_the_bracketed_tail(self):
        assert CdkNagScanner.split_rule_qualifier("AwsSolutions-IAM5[Resource::*]") == (
            "AwsSolutions-IAM5",
            "Resource::*",
        )

    def test_no_brackets_no_qualifier(self):
        assert CdkNagScanner.split_rule_qualifier("AwsSolutions-IAM5") == (
            "AwsSolutions-IAM5",
            None,
        )


class TestEndToEndMatching:
    def test_plain_rule_id_plus_scope_matches_the_qualified_finding(self):
        # No bracket-escaped glob in the user's YAML: the scoped entry matches
        # the granular finding through the base rule id.
        entry = _entry({"applies_to": "Action::logs:*"})
        assert entry.matches(_finding())

    def test_applies_to_list_form(self):
        entry = _entry({"applies_to": ["Resource::*", "Action::logs:*"]})
        assert entry.matches(_finding())

    def test_applies_to_miss(self):
        entry = _entry({"applies_to": "Action::s3:*"})
        assert not entry.matches(_finding())

    def test_applies_to_never_matches_an_unqualified_finding(self):
        entry = _entry({"applies_to": "Action::logs:*"})
        assert not entry.matches(_finding(rule_id="AwsSolutions-IAM5"))

    def test_resource_path_glob(self):
        entry = _entry({"resource_path": "Stack/CollectorTaskRole/*"})
        assert entry.matches(_finding())

    def test_resource_path_miss(self):
        entry = _entry({"resource_path": "Stack/OtherRole/*"})
        assert not entry.matches(_finding())

    def test_a_block_is_never_consulted_for_another_scanner(self):
        entry = _entry({"resource_path": "Stack/CollectorTaskRole/*"})
        assert not entry.matches(_finding(scanner="checkov"))


class TestAppliesToIsExact:
    """``applies_to`` is exact membership, as cdk-nag's own appliesTo.

    A literal ported from a cdk-nag config often contains ``*`` (IAM action
    and resource wildcards are part of the qualifier's own text); read as a
    glob it would silently widen the suppression to every finding the wildcard
    happens to cover.
    """

    def test_a_star_in_the_value_does_not_widen_to_other_qualifiers(self):
        # Glob reading would make "Resource::*" cover this differently
        # qualified finding; exact membership must not.
        entry = _entry({"applies_to": "Resource::*"})
        assert not entry.matches(
            _finding(rule_id="AwsSolutions-IAM5[Resource::arn:aws:s3:::logs/key]")
        )

    def test_the_identical_literal_still_matches_its_own_finding(self):
        entry = _entry({"applies_to": "Resource::*"})
        assert entry.matches(_finding(rule_id="AwsSolutions-IAM5[Resource::*]"))

    def test_resource_id_scope_keeps_its_documented_glob(self):
        # Pin the shared scope matching the fix must not narrow: a
        # scope.resource_id pattern is still literal-first, then glob.
        entry = AshSuppression.model_validate(
            {
                "rule_id": "AwsSolutions-IAM5",
                "path": "cdk.out/*.template.json",
                "reason": "test",
                "scope": {"resource_id": "Stack/CollectorTaskRole/*"},
            }
        )
        assert entry.matches(_finding())


class TestBlockValidation:
    def test_an_unknown_block_key_gets_the_cdk_nag_scoped_did_you_mean(self):
        problems = CdkNagScanner.validate_suppression_scope({"applies_too": "x"})
        assert len(problems) == 1
        assert "Unknown key 'applies_too'" in problems[0]
        assert "did you mean 'applies_to'?" in problems[0]
        assert "a cdk-nag suppression scope" in problems[0]

    def test_a_block_with_neither_key_is_a_problem(self):
        block = CdkNagScopeBlock.model_validate({"applies_to": None})
        assert block.applies_to is None
        problems = CdkNagScanner.validate_suppression_scope({"applies_to": None})
        assert problems and "selects nothing" in problems[0]

    def test_an_empty_applies_to_list_is_refused_naming_the_field(self):
        # At 0a04458b only None-and-None was checked, so [] validated clean
        # yet could never match: a silently inert entry.
        problems = CdkNagScanner.validate_suppression_scope({"applies_to": []})
        assert problems
        assert "applies_to" in problems[0]
        assert "selects nothing" in problems[0]

    def test_an_empty_applies_to_string_is_refused_naming_the_field(self):
        problems = CdkNagScanner.validate_suppression_scope({"applies_to": ""})
        assert problems
        assert "applies_to" in problems[0]
        assert "selects nothing" in problems[0]

    def test_an_empty_resource_path_is_refused_naming_the_field(self):
        problems = CdkNagScanner.validate_suppression_scope({"resource_path": ""})
        assert problems
        assert "resource_path" in problems[0]
        assert "selects nothing" in problems[0]

    def test_an_empty_valued_block_matches_nothing(self):
        # Match time agrees with validation: the same model refuses the block,
        # so the matcher fails closed.
        for block in ({"applies_to": []}, {"applies_to": ""}, {"resource_path": ""}):
            assert not CdkNagScanner.suppression_scope_matches(block, _finding())

    def test_a_valid_applies_to_list_still_validates_and_matches(self):
        # The control the refusal must not narrow.
        assert (
            CdkNagScanner.validate_suppression_scope({"applies_to": ["Action::logs:*"]})
            == []
        )
        assert CdkNagScanner.suppression_scope_matches(
            {"applies_to": ["Action::logs:*"]}, _finding()
        )

    def test_a_valid_block_reports_nothing(self):
        assert (
            CdkNagScanner.validate_suppression_scope(
                {"applies_to": "Action::logs:*", "resource_path": CONSTRUCT_PATH}
            )
            == []
        )

    def test_an_invalid_block_matches_nothing(self):
        assert not CdkNagScanner.suppression_scope_matches(
            {"applies_too": "x"}, _finding()
        )
