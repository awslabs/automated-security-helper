"""The beta password-parameter rule reads the type in both shapes and any yes/no pair.

Two defects in ``beta/PasswordAsCFnParameterRule.rb``, read from its source since
this suite cannot run Ruby:

* ``properties.type["value"] == "String"`` matched only the line-numbered Hash
  shape of a parameter's type, so with a plain ``Type: String`` the rule never
  reported (the key pair rule had the same defect and the same fix);
* the boolean-parameter exemption compared AllowedValues with ``[true, false]``
  and ``['Yes', 'No']`` exactly, so ``['No', 'Yes']``, ``['false', 'true']`` and
  ``['yes', 'no']`` were reported as passwords. The pair is matched in any order,
  case and type now.
"""

from __future__ import annotations

import re

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR

pytestmark = pytest.mark.unit

RULE = ASH_ASSETS_DIR / "appsec_cfn_rules" / "beta" / "PasswordAsCFnParameterRule.rb"


def test_the_password_rule_reads_the_type_in_both_shapes():
    source = RULE.read_text(encoding="utf-8")
    assert 'type["value"] if type.is_a?(Hash)' in source, source
    assert re.search(r'^\s*type == "String" and\s*$', source, re.MULTILINE)
    assert 'properties.type["value"] ==' not in source


def test_the_boolean_exemption_is_order_case_and_type_insensitive():
    source = RULE.read_text(encoding="utf-8")
    assert "BOOLEAN_CHOICES = [%w[true false], %w[yes no]].freeze" in source
    assert "!boolean_choices?(properties.allowedValues)" in source
    assert "value.to_s.strip.downcase" in source
    assert "choice.sort == normalized" in source
    # The exact, ordered comparisons are gone.
    assert "properties.allowedValues != [true, false]" not in source
    assert "properties.allowedValues != ['Yes', 'No']" not in source
