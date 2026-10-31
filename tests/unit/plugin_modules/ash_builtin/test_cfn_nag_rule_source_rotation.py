"""The beta rotation rule reads each RotationSchedule's SecretId as cfn-model stores it.

The same defect as the FlowLogs rule: ``schedule.SecretId`` named no instance
variable (cfn-model keeps ``secretId``), so every secret was reported whether or not
a RotationSchedule covered it, and the value is a Ref or GetAtt to the secret, not
its logical id. Read from the source, since this suite cannot run Ruby.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR

pytestmark = pytest.mark.unit

RULE = (
    ASH_ASSETS_DIR
    / "appsec_cfn_rules"
    / "beta"
    / "RotationEnabledForSecretsManagerRule.rb"
)


def test_the_rotation_rule_reads_the_lower_camel_case_property():
    source = RULE.read_text(encoding="utf-8")
    assert "schedule.secretId" in source
    assert "&:SecretId" not in source
    assert "secret_ids - rotation_schedules.map(&:SecretId)" not in source


def test_the_rotation_rule_reads_the_logical_id_out_of_a_ref_or_get_att():
    source = RULE.read_text(encoding="utf-8")
    assert "def referenced_logical_id(value)" in source
    assert 'return value["Ref"] if value.key?("Ref")' in source
    assert "secret_ids - covered" in source
