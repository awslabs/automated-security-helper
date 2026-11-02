"""The beta FlowLogs rule reads each FlowLog's ResourceId as cfn-model stores it.

cfn-model keeps a resource's properties in lower camel case instance variables
(``resourceId``) answered through ``method_missing``, so ``flowlog.ResourceId`` named
nothing and every VPC was reported whether or not a FlowLog covered it. The value
is the template's Ref or GetAtt, not the VPC's logical id, so the id has to be read
out of it before the subtraction. Read from the source, since this suite cannot run
Ruby.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR

pytestmark = pytest.mark.unit

RULE = ASH_ASSETS_DIR / "appsec_cfn_rules" / "beta" / "FlowLogsEnabledForVPCsRule.rb"


def test_the_flow_logs_rule_reads_the_lower_camel_case_property():
    source = RULE.read_text(encoding="utf-8")
    assert "flowlog.resourceId" in source
    assert "&:ResourceId" not in source
    assert "vpc_ids - flowlogs.map(&:ResourceId)" not in source


def test_the_flow_logs_rule_reads_the_logical_id_out_of_a_ref_or_get_att():
    source = RULE.read_text(encoding="utf-8")
    assert "def referenced_logical_id(value)" in source
    assert 'return value["Ref"] if value.key?("Ref")' in source
    assert 'attribute = value["Fn::GetAtt"]' in source
    assert "vpc_ids - covered" in source
