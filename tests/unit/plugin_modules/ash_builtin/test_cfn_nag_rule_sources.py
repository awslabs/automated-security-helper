"""The shipped cfn_nag rules read cfn-model's values in both shapes it gives them.

cfn-model gives a parameter's type as ``{"value" => ..., "line" => ...}`` when it
keeps line numbers and as the plain string otherwise. ``String#[]("value")`` is nil,
so a rule that indexed the type with ``["value"]`` alone never matched the plain
shape and never reported. The rule is Ruby, which this suite cannot run, so the
source is read: the rule takes the value out of a Hash and compares the string.
"""

from __future__ import annotations

import re

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR

pytestmark = pytest.mark.unit

RULE = ASH_ASSETS_DIR / "appsec_cfn_rules" / "KeyPairAsCFnParameterRule.rb"


def test_the_key_pair_rule_reads_the_type_in_both_shapes():
    source = RULE.read_text(encoding="utf-8")
    assert 'type["value"] if type.is_a?(Hash)' in source, source
    assert re.search(
        r'^\s*type == "AWS::EC2::KeyPair::KeyName"\s*$', source, re.MULTILINE
    )
    assert 'properties.type["value"] ==' not in source
