# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The SARIF rule descriptor has to name the plugin that owns the rule.

``validation-report.json`` is CDK's shared policy-validation report. Registering any cdk-nag
pack on an app whose aws-cdk-lib is 2.262.0 or newer also gets the CDK's own
``CloudFormationValidatePlugin``, whose ``PLUGIN_NAME`` is ``"CloudFormation Validate"``, so a
single scan produces rules from two different tools. The wrapper keys them apart; the scanner
flattens them into one result list and then builds one ``ReportingDescriptor`` per rule id.

That descriptor is where a consumer looks up what a rule is and where it is documented, and it
carried neither fact correctly:

* ``helpUri`` was cdk-nag's RULES.md for every rule. Following it for ``F3017`` lands on a page
  that does not mention ``F3017`` and does not describe the mechanism that governs it.
* ``tags`` was built from ``finding_props.get("tags", [])``, and ``finding_props`` is
  ``_NagFinding.as_dict()``, which has no ``tags`` key. The lookup returned its default on
  every finding that has ever been scanned, so the pack the wrapper had been writing onto each
  result never reached the rule.

The tags repair went wrong once before it went right, and that is what
``TestRuleTagsAreRuleScoped`` guards. Forwarding ``result.properties.tags`` wholesale put the
pack on the rule and also put the FIRST matching resource's logical id and ``AWS::*::*`` type
there, because the wrapper builds that list per occurrence while the descriptor is built once per
``ruleId``. Measured on this repository: ``HIPAA.Security-IAMNoInlinePolicy`` fires on 35 results
and its descriptor carried ``ConfigKeyAccessB463082D`` and ``AWS::IAM::Policy``. Which resource
won was an ordering, not a fact, so identical input could produce different bytes. The tags are
now constructed from rule-scoped facts, and the per-occurrence values stay on the results.

These tests drive ``_reporting_descriptor_for`` directly. It was inline in ``scan()`` until this
change, where reaching it meant running a full CDK synthesis -- which is why an always-empty
``tags`` read survived in it.
"""

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Message1,
    PropertyBag,
    Result,
)


def _result(rule_id: str, pack: str, rule_level: str = "Error") -> Result:
    """A Result shaped the way the wrapper emits one.

    ``cdk_nag_finding`` lands in ``model_extra`` because ``PropertyBag`` allows extras and does
    not declare it; ``tags`` is a declared field. The descriptor builder reads both, so the
    fixture has to populate both or it would be testing a shape the wrapper never produces.

    ``tags`` reproduces the wrapper's list verbatim, ``tool_name::``/``tool_type::`` entries
    included. Those two matter: the wrapper already writes them onto every result, so a
    descriptor that forwards the result's tags AND appends its own emits each twice. A fixture
    that omitted them would leave the duplication tests unable to fail.
    """
    return Result(
        ruleId=rule_id,
        message=Message(root=Message1(text=f"{rule_id} description text")),
        properties=PropertyBag(
            cdk_nag_finding={
                "pack": pack,
                "rule_id": rule_id,
                "resource_id": "ProbeResource",
                "compliance": "Non-Compliant",
                "exception_reason": "N/A",
                "rule_level": rule_level,
                "rule_info": f"{rule_id} rule info",
            },
            tags=[
                "aws",
                "cdk",
                "cdk-nag",
                pack,
                rule_id,
                "ProbeResource",
                "tool_name::cdk-nag",
                "tool_type::IAC",
            ],
        ),
    )


class TestRuleDescriptorNamesItsPack:
    def test_the_pack_is_a_labelled_property_on_the_rule(self):
        """A named field, not a positional entry in a nine-element tag list.

        The pack is in ``tags`` as well, and that is not sufficient on its own: beside it sit
        the rule id, the resource logical id and the resource type, and nothing tells a
        consumer which string is which.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        descriptor = _reporting_descriptor_for(
            _result("F3017", "CloudFormation Validate", rule_level="Warning"),
            tool_name="cdk-nag",
            tool_type="IAC",
        )

        assert descriptor.properties.model_extra["pack"] == "CloudFormation Validate"
        assert "pack::CloudFormation Validate" in descriptor.properties.tags

    def test_the_rule_scoped_tags_reach_the_rule(self):
        """The always-empty lookup, stated as the tags that must now be present.

        Asserted as a subset rather than an exact list so that adding a rule-scoped tag later
        does not break this. Every one of these names the rule, the pack or the tool -- none of
        them names a resource, which is the whole distinction
        ``TestRuleTagsAreRuleScoped`` exists to hold.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        descriptor = _reporting_descriptor_for(
            _result("AwsSolutions-S1", "AwsSolutions"),
            tool_name="cdk-nag",
            tool_type="IAC",
        )

        assert {
            "aws",
            "cdk",
            "cdk-nag",
            "AwsSolutions",
            "AwsSolutions-S1",
            "pack::AwsSolutions",
            "tool_name::cdk-nag",
            "tool_type::IAC",
        }.issubset(set(descriptor.properties.tags))

    def test_a_cdk_nag_rule_still_points_at_cdk_nags_rule_documentation(self):
        """The behaviour that was already right, pinned so the fix cannot break it.

        The anchor is derived from the rule level, which is the pre-existing convention. Naming
        the whole URL means a change to either half fails here.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        descriptor = _reporting_descriptor_for(
            _result("AwsSolutions-S1", "AwsSolutions", rule_level="Error"),
            tool_name="cdk-nag",
            tool_type="IAC",
        )

        # str(), because ReportingDescriptor.helpUri is typed as a pydantic AnyUrl and
        # comparing the model object with a string is always False.
        assert (
            str(descriptor.helpUri)
            == "https://github.com/cdklabs/cdk-nag/blob/main/RULES.md#errors"
        )

    def test_a_cloudformation_validate_rule_points_at_the_cdk_validation_guide(self):
        """The destination that documents the plugin AND how to acknowledge its findings.

        Named as an exact URL rather than "not the cdk-nag one", because "not X" is satisfied
        by an empty string, by None, and by any wrong page.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        descriptor = _reporting_descriptor_for(
            _result("F3017", "CloudFormation Validate", rule_level="Warning"),
            tool_name="cdk-nag",
            tool_type="IAC",
        )

        assert (
            str(descriptor.helpUri)
            == "https://docs.aws.amazon.com/cdk/v2/guide/policy-validation-synthesis.html"
        )

    def test_a_finding_with_no_recorded_pack_keeps_its_previous_destination(self):
        """Only findings positively known to be foreign are redirected.

        An absent pack is not evidence of a foreign producer. Inside this scanner's own report
        the likeliest producer is cdk-nag, so treating "no pack recorded" as "not cdk-nag" would
        send genuine cdk-nag rules away from their own documentation -- the same misattribution
        in the opposite direction, introduced by the fix for it.

        The generic ``#rules`` anchor is what a missing ``rule_level`` degrades to, and it
        claims nothing about a specific rule.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        bare = _result("AwsSolutions-S9", pack="")
        bare.properties.model_extra["cdk_nag_finding"].pop("rule_level")

        descriptor = _reporting_descriptor_for(
            bare, tool_name="cdk-nag", tool_type="IAC"
        )

        assert (
            str(descriptor.helpUri)
            == "https://github.com/cdklabs/cdk-nag/blob/main/RULES.md#rules"
        )
        # The pack is reported as unknown rather than invented, so a reader can tell the
        # difference between "cdk-nag" and "we do not know".
        assert descriptor.properties.model_extra["pack"] == ""
        assert "pack::unknown" in descriptor.properties.tags


class TestRuleTagsAreRuleScoped:
    """A rule descriptor describes a rule. It must carry nothing about one occurrence of it.

    ``scan()`` keys a ``rule_map`` by ``ruleId`` and ``continue``s on a repeat, so exactly one
    of a rule's N results becomes its descriptor. Anything per-occurrence that reaches the
    descriptor is therefore both wrong -- it describes one resource as though it described the
    rule -- and unstable, since "the first result" is an ordering.
    """

    def test_a_resource_logical_id_never_reaches_the_rule_descriptor(self):
        """The leak in its narrowest form.

        ``ProbeResource`` is on the result's own tag list, exactly as the wrapper puts a real
        resource's logical id there. It must not appear on the rule. Asserted on the resource id
        specifically rather than on the list length, because a length assertion passes for the
        wrong reason as soon as any tag is added or removed.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        result = _result("AwsSolutions-S1", "AwsSolutions")
        assert "ProbeResource" in result.properties.tags, (
            "the fixture must carry a per-occurrence tag or this test proves nothing"
        )

        descriptor = _reporting_descriptor_for(
            result, tool_name="cdk-nag", tool_type="IAC"
        )

        assert "ProbeResource" not in descriptor.properties.tags, (
            "the resource this rule happened to fire on first was stamped into the rule's "
            "own definition"
        )

    def test_a_resource_type_never_reaches_the_rule_descriptor(self):
        """The second per-occurrence value, asserted separately.

        The wrapper writes ``cfn_resource.Type`` beside the logical id. Both are per-occurrence
        and a filter could plausibly catch one and miss the other, so neither is covered by a
        test of the other.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        result = _result("AwsSolutions-S1", "AwsSolutions")
        result.properties.tags.append("AWS::IAM::Policy")

        descriptor = _reporting_descriptor_for(
            result, tool_name="cdk-nag", tool_type="IAC"
        )

        assert "AWS::IAM::Policy" not in descriptor.properties.tags

    def test_two_results_for_one_rule_yield_byte_identical_descriptors(self):
        """Identical input, identical bytes -- whichever occurrence the aggregation yields first.

        This is the stability half, and it is the one that could not be expressed at all while
        the tags were inherited: the two results below differ ONLY in their per-occurrence tags,
        so under forwarding the two descriptors differed and the emitted SARIF depended on
        result order. Compared as serialized JSON rather than field by field, so a
        per-occurrence value reaching any part of the descriptor fails here, not just one the
        assertion happened to name.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        first = _result("AwsSolutions-IAM5", "AwsSolutions")
        first.properties.tags = [
            "aws",
            "cdk",
            "cdk-nag",
            "AwsSolutions",
            "AwsSolutions-IAM5",
            "ConfigKeyAccessB463082D",
            "AWS::IAM::Policy",
            "tool_name::cdk-nag",
            "tool_type::IAC",
        ]
        second = _result("AwsSolutions-IAM5", "AwsSolutions")
        second.properties.tags = [
            "aws",
            "cdk",
            "cdk-nag",
            "AwsSolutions",
            "AwsSolutions-IAM5",
            "TaskExecutionRole250D2532",
            "AWS::IAM::Role",
            "tool_name::cdk-nag",
            "tool_type::IAC",
        ]

        assert first.properties.tags != second.properties.tags, (
            "the two occurrences must differ or this test cannot detect order dependence"
        )

        one = _reporting_descriptor_for(first, tool_name="cdk-nag", tool_type="IAC")
        two = _reporting_descriptor_for(second, tool_name="cdk-nag", tool_type="IAC")

        assert one.model_dump_json() == two.model_dump_json(), (
            "the rule descriptor depends on which occurrence was seen first, so two runs over "
            "identical input can emit different SARIF"
        )

    def test_the_tool_type_tag_uses_the_enum_value_not_its_repr(self):
        """``ScannerToolType`` is a str mixin, and ``Enum.__str__`` still wins.

        ``scan()`` passes ``self.tool_type``, a ``ScannerToolType`` member, so interpolating it
        renders ``tool_type::ScannerToolType.IAC`` while the wrapper writes the literal
        ``tool_type::IAC`` onto every result. Measured on this repository, forwarding put both
        spellings in one list. The descriptor has to agree with the results.
        """
        from automated_security_helper.core.enums import ScannerToolType
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        assert str(ScannerToolType.IAC) != ScannerToolType.IAC.value, (
            "if the enum ever renders as its value this test is no longer about anything"
        )

        descriptor = _reporting_descriptor_for(
            _result("AwsSolutions-S1", "AwsSolutions"),
            tool_name="cdk-nag",
            tool_type=ScannerToolType.IAC,
        )

        type_tags = [
            tag for tag in descriptor.properties.tags if tag.startswith("tool_type::")
        ]
        assert type_tags == ["tool_type::IAC"], (
            f"expected exactly one tool_type tag spelled as the literal; got {type_tags}"
        )

    def test_the_tool_name_tag_appears_exactly_once(self):
        """Forwarding duplicated it, because the wrapper already writes it onto the result."""
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _reporting_descriptor_for,
        )

        descriptor = _reporting_descriptor_for(
            _result("AwsSolutions-S1", "AwsSolutions"),
            tool_name="cdk-nag",
            tool_type="IAC",
        )

        name_tags = [
            tag for tag in descriptor.properties.tags if tag.startswith("tool_name::")
        ]
        assert name_tags == ["tool_name::cdk-nag"]


class TestPackOwnershipIsDerivedNotListed:
    @pytest.mark.parametrize(
        ("rule_id", "pack", "owned"),
        [
            # cdk-nag mints every rule id as f"{packName}-{ruleSuffix}".
            ("AwsSolutions-S1", "AwsSolutions", True),
            ("AwsSolutions-IAM5[Resource::*]", "AwsSolutions", True),
            ("HIPAASecurity-S1", "HIPAASecurity", True),
            # A pack cdk-nag has not shipped yet must still be recognised, which is the whole
            # reason ownership is derived from the id rather than from a list of names.
            ("SomeFuturePack-XYZ1", "SomeFuturePack", True),
            # The CDK's own plugin does not prefix its rule ids with its plugin name.
            ("F3017", "CloudFormation Validate", False),
            ("W3010", "CloudFormation Validate", False),
            # A pack that is merely a prefix of another pack's name must not claim its rules.
            ("AwsSolutionsExtra-S1", "AwsSolutions", False),
            # No pack recorded at all -- nothing can be claimed.
            ("AwsSolutions-S1", "", False),
        ],
    )
    def test_ownership_follows_cdk_nags_rule_id_construction(
        self, rule_id: str, pack: str, owned: bool
    ):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _rule_is_from_pack,
        )

        assert _rule_is_from_pack(rule_id, pack) is owned
