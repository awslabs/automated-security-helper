"""The two resource-policy rules read an AccessPolicies written as a JSON string.

AccessPolicies is a JSON property, so a template can write it as a string, or as an
Fn::Sub or Fn::Join that cfn-model resolves to one. cfn-model's PolicyDocumentParser
indexes its document with ``[]``, which on a String answers a substring or nil, never
a statement, so such a policy was read as empty and neither rule reported it. Both
rules parse the string first now, and report one they cannot parse as unread.
Read from the sources, since this suite cannot run Ruby.
"""

from __future__ import annotations

import re

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR

pytestmark = pytest.mark.unit

RULES = ASH_ASSETS_DIR / "appsec_cfn_rules"
STAR = RULES / "StarResourceAccessPolicyRule.rb"
VERB = RULES / "ResourcePolicyStarAccessVerbPolicyRule.rb"


@pytest.mark.parametrize("rule", [STAR, VERB], ids=["principal", "verb"])
def test_a_string_policy_is_parsed_before_the_parser_reads_it(rule):
    source = rule.read_text(encoding="utf-8")
    assert "require 'json'" in source
    assert "if document.is_a?(String) then" in source
    assert "document = parse_policy_text(document)" in source
    assert "def parse_policy_text(text)" in source
    assert "JSON.parse(text)" in source
    # The parse comes before the parser is handed the document.
    assert source.index("parse_policy_text(document)") < source.index(
        "PolicyDocumentParser.new().parse(cfn_model, document)"
    )


@pytest.mark.parametrize("rule", [STAR, VERB], ids=["principal", "verb"])
def test_a_string_that_is_not_json_is_reported_as_unread(rule):
    source = rule.read_text(encoding="utf-8")
    assert "unread_policies << resource.logical_resource_id" in source
    # Ruby joins adjacent string literals across a `\`-continued line, so the
    # message is read as Ruby reads it, not line by line: one rule breaks the
    # line between "is a " and "string".
    joined = re.sub(r'"\s*\\\s*\n\s*"', "", source)
    assert "is a string that is not a JSON document" in joined
