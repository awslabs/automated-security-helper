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
            tags=["aws", "cdk", "cdk-nag", pack, rule_id, "ProbeResource"],
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

    def test_the_findings_own_tags_are_forwarded_onto_the_rule(self):
        """The always-empty lookup, stated as the tags that must now be present.

        Asserted as a subset rather than an exact list so that adding a tag later does not
        break this, but every tag the result carried is named -- the previous code forwarded
        none of them and no test noticed.
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
            "ProbeResource",
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
