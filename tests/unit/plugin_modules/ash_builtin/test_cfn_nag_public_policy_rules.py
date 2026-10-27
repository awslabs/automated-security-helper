"""What can be checked about the two resource-policy rules without Ruby or cfn-nag.

Why this file exists: ``StarResourceAccessPolicyRule`` and
``ResourcePolicyStarAccessVerbPolicyRule`` decide whether a resource policy is open to
everyone. The behavior is measured by
``tests/integration/scanners/test_cfn_nag_custom_rules.py``, which runs the real
``cfn_nag_scan`` and skips where the gem is not installed. This module is the part that
runs everywhere. It reads the Ruby source and the fixtures and executes neither, so a pass
here is not evidence that a rule works. It stands in two places:

* a few narrow reads of the rule source, each tied to a defect the integration cells
  measure (a Hash method called on a principal that can be a String, and an action test
  that cannot see the bare ``*``), so that a revert shows up on a machine with no Ruby;
* the shape of every fixture resource, so the integration cells cannot go on passing
  after someone edits a fixture into a shape its name no longer describes.

Both defects shipped for the same reason: the rules were written against the policies
people usually write. A principal can be a String, a Hash whose values are Strings or
Arrays, or an Array (cfn-model 0.6.6 ``PolicyDocumentParser`` keeps the template's shape),
and an action list can hold the bare ``*``.
"""

import re
from pathlib import Path

import pytest
import yaml

from automated_security_helper.core.constants import ASH_ASSETS_DIR

RULE_DIR = ASH_ASSETS_DIR.joinpath("appsec_cfn_rules")
FIXTURE_DIR = Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "cfn_nag"

# A method that only a Hash has, called straight on the statement's principal. The
# principal is a String when the template says ``Principal: "*"``, and a String has none
# of these, so the call raises NoMethodError.
HASH_METHOD_ON_PRINCIPAL = re.compile(
    r"statement\.principal\.(?:has_key\?|has_value\?|key\?|value\?|keys|values)"
)

# A whole-string comparison with the bare ``*``, as opposed to ``end_with?(":*")``.
WHOLE_STAR_COMPARISON = re.compile(r"==\s*[\"']\*[\"']")

# A test that a principal Hash has the "AWS" key, as a gate on whether its values are read.
AWS_KEY_GATE = re.compile(r"""(?:has_key\?|key\?|include\?)\(\s*["']AWS["']\s*\)""")

# A type check on a value, and a call that only a String answers. cfn-model 0.6.6 hands the
# rule an action as a Hash when the template writes it as Fn::ImportValue, Fn::GetAtt,
# Fn::Transform or Fn::Cidr, or as a Ref to a parameter (ASH passes no parameter values),
# and a Hash has no downcase. Fn::Sub and Fn::If arrive as a String.
STRING_CHECK = re.compile(r"\.is_a\?\(\s*String\s*\)")
DOWNCASE_CALL = re.compile(r"\.downcase\b")

# (fixture file, logical id, effect, principal, action) as YAML hands them to cfn-model.
# Every resource in these fixtures has exactly one statement.
ARN = "arn:aws:iam::123456789012:root"
ARN_OTHER = "arn:aws:iam::210987654321:root"
SUB_FIXTURE = "opensearch_policy_sub_action.yaml"
IF_FIXTURE = "opensearch_policy_if_forms.yaml"
PRINCIPAL_FIXTURE = "opensearch_policy_principal_parameters.yaml"
SHAPES = [
    (
        "opensearch_policy_principal_forms.yaml",
        "AwsListStar",
        "Allow",
        {"AWS": ["*"]},
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_forms.yaml",
        "AwsListMixedStar",
        "Allow",
        {"AWS": [ARN, "*"]},
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_forms.yaml",
        "AwsAndServiceStar",
        "Allow",
        {"AWS": ARN, "Service": "*"},
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_forms.yaml",
        "ServiceStarOnly",
        "Allow",
        {"Service": "*"},
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_forms.yaml",
        "ScopedAccount",
        "Allow",
        {"AWS": ARN},
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_forms.yaml",
        "ScopedAccountList",
        "Allow",
        {"AWS": [ARN, "arn:aws:iam::123456789012:role/reader"]},
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_forms.yaml",
        "ServicePrincipal",
        "Allow",
        {"Service": "es.amazonaws.com"},
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_forms.yaml",
        "DeniedStar",
        "Deny",
        {"AWS": ["*"]},
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_string_star.yaml",
        "StringStar",
        "Allow",
        "*",
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_string_scoped.yaml",
        "StringScoped",
        "Allow",
        ARN,
        "es:ESHttpGet",
    ),
    (
        "opensearch_policy_principal_array_star.yaml",
        "ArrayStar",
        "Allow",
        ["*"],
        "es:ESHttpGet",
    ),
    ("opensearch_policy_action_forms.yaml", "BareStar", "Allow", {"AWS": ARN}, "*"),
    (
        "opensearch_policy_action_forms.yaml",
        "ListOnlyBareStar",
        "Allow",
        {"AWS": ARN},
        ["*"],
    ),
    (
        "opensearch_policy_action_forms.yaml",
        "ListWithBareStar",
        "Allow",
        {"AWS": ARN},
        ["es:ESHttpGet", "*"],
    ),
    (
        "opensearch_policy_action_forms.yaml",
        "ServiceStar",
        "Allow",
        {"AWS": ARN},
        "es:*",
    ),
    (
        "opensearch_policy_action_forms.yaml",
        "ScopedActions",
        "Allow",
        {"AWS": ARN},
        ["es:ESHttpGet", "es:ESHttpHead"],
    ),
    (
        "opensearch_policy_action_forms.yaml",
        "DeniedBareStar",
        "Deny",
        {"AWS": ARN},
        "*",
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "SubAction",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": "es:ESHttp${Method}"}],
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "IfAction",
        "Allow",
        {"AWS": ARN},
        [{"Fn::If": ["UseHead", "es:ESHttpHead", "es:ESHttpGet"]}],
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "ImportValueAction",
        "Allow",
        {"AWS": ARN},
        [{"Fn::ImportValue": "SharedActionExport"}],
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "ServiceStarAfterIntrinsic",
        "Allow",
        {"AWS": ARN},
        "es:*",
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "BareStarAfterIntrinsic",
        "Allow",
        {"AWS": ARN},
        "*",
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "ListIntrinsicThenBareStar",
        "Allow",
        {"AWS": ARN},
        [{"Fn::ImportValue": "SharedActionExport"}, "*"],
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "ScopedAfterIntrinsic",
        "Allow",
        {"AWS": ARN},
        ["es:ESHttpGet", "es:ESHttpHead"],
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "RefNoDefaultAction",
        "Allow",
        {"AWS": ARN},
        {"Ref": "NoDefaultAction"},
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "RefDefaultStar",
        "Allow",
        {"AWS": ARN},
        {"Ref": "OpenAction"},
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "RefDefaultListStar",
        "Allow",
        {"AWS": ARN},
        {"Ref": "OpenActionList"},
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "RefDefaultScoped",
        "Allow",
        {"AWS": ARN},
        [{"Ref": "ScopedAction"}],
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "RefSsmAction",
        "Allow",
        {"AWS": ARN},
        {"Ref": "SsmAction"},
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "RefEmptyDefault",
        "Allow",
        {"AWS": ARN},
        [{"Ref": "EmptyAction"}, {"Ref": "CommaOnlyAction"}],
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "RefAllowedStar",
        "Allow",
        {"AWS": ARN},
        {"Ref": "ChosenAction"},
    ),
    (
        "opensearch_policy_intrinsic_action.yaml",
        "RefAllowedScoped",
        "Allow",
        {"AWS": ARN},
        {"Ref": "ScopedChoice"},
    ),
    (
        SUB_FIXTURE,
        "SubParameterStar",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": "${OpenAction}"}],
    ),
    (
        SUB_FIXTURE,
        "SubVerbStar",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": "es:${OpenVerb}"}],
    ),
    (
        SUB_FIXTURE,
        "SubAllowedStar",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": "es:${ChosenVerb}"}],
    ),
    (
        SUB_FIXTURE,
        "SubTwoParameters",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": "${Service}:${OpenVerb}"}],
    ),
    (
        SUB_FIXTURE,
        "SubParameterScoped",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": "es:${ScopedVerb}"}],
    ),
    (
        SUB_FIXTURE,
        "SubNoHole",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": "es:ESHttpGet"}],
    ),
    (
        SUB_FIXTURE,
        "SubPseudoParameter",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": "es:${AWS::Region}"}],
    ),
    (
        SUB_FIXTURE,
        "SubNoText",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": "es:${NoDefaultVerb}"}],
    ),
    (
        SUB_FIXTURE,
        "SubLongForm",
        "Allow",
        {"AWS": ARN},
        [{"Fn::Sub": ["es:${Verb}", {"Verb": {"Ref": "OpenVerb"}}]}],
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalRefDefaultStar",
        "Allow",
        {"AWS": {"Ref": "OpenPrincipal"}},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalRefAllowedStar",
        "Allow",
        {"AWS": {"Ref": "ChosenPrincipal"}},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalRefListStar",
        "Allow",
        {"AWS": [{"Ref": "ScopedPrincipal"}, {"Ref": "OpenPrincipal"}]},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalWholeRef",
        "Allow",
        {"Ref": "OpenPrincipal"},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalSubStar",
        "Allow",
        {"AWS": {"Fn::Sub": "${OpenPrincipal}"}},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalRefScoped",
        "Allow",
        {"AWS": {"Ref": "ScopedPrincipal"}},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalSubAccount",
        "Allow",
        {"AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalGetAtt",
        "Allow",
        {"AWS": {"Fn::GetAtt": ["AccessRole", "Arn"]}},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalImportValue",
        "Allow",
        {"AWS": {"Fn::ImportValue": "SharedPrincipalExport"}},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalRefNoDefault",
        "Allow",
        {"AWS": {"Ref": "NoDefaultPrincipal"}},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalRefSsm",
        "Allow",
        {"AWS": {"Ref": "SsmPrincipal"}},
        "es:ESHttpGet",
    ),
    (
        PRINCIPAL_FIXTURE,
        "PrincipalSubUnreadStar",
        "Allow",
        {"AWS": {"Fn::Sub": "${NoDefaultPrincipal}"}},
        "es:ESHttpGet",
    ),
]

# (parameter name, the parameter as YAML hands it to cfn-model) for the parameters of the
# intrinsic-action fixture that the Ref resources above read. The fixture's tests depend on
# the type, the Default and the AllowedValues of each, so a change to one of them has to
# show here rather than change what a resource is testing.
INTRINSIC_FIXTURE = "opensearch_policy_intrinsic_action.yaml"
PARAMETER_SHAPES = [
    ("OpenAction", {"Type": "String", "Default": "*"}),
    ("OpenActionList", {"Type": "CommaDelimitedList", "Default": "es:ESHttpGet,*"}),
    ("ScopedAction", {"Type": "String", "Default": "es:ESHttpGet"}),
    ("NoDefaultAction", {"Type": "String"}),
    (
        "SsmAction",
        {
            "Type": "AWS::SSM::Parameter::Value<String>",
            "Default": "/ash/fixture/action",
        },
    ),
    ("EmptyAction", {"Type": "String", "Default": ""}),
    ("CommaOnlyAction", {"Type": "CommaDelimitedList", "Default": ","}),
    (
        "ChosenAction",
        {
            "Type": "String",
            "Default": "es:ESHttpGet",
            "AllowedValues": ["es:ESHttpGet", "*"],
        },
    ),
    (
        "ScopedChoice",
        {
            "Type": "String",
            "Default": "es:ESHttpGet",
            "AllowedValues": ["es:ESHttpGet", "es:ESHttpHead"],
        },
    ),
]


# (fixture file, logical id, the statement as YAML hands it to cfn-model, without Resource).
# These statements name who or what they exclude, so they carry NotPrincipal or NotAction
# in place of Principal or Action.
NOT_FIXTURE = "opensearch_policy_not_forms.yaml"
NOT_SHAPES = [
    (
        NOT_FIXTURE,
        "AllowNotPrincipal",
        {"Effect": "Allow", "NotPrincipal": {"AWS": ARN}, "Action": "es:ESHttpGet"},
    ),
    (
        NOT_FIXTURE,
        "AllowNotAction",
        {"Effect": "Allow", "Principal": {"AWS": ARN}, "NotAction": "es:ESHttpDelete"},
    ),
    (
        NOT_FIXTURE,
        "DenyNotPrincipal",
        {"Effect": "Deny", "NotPrincipal": {"AWS": ARN}, "Action": "es:ESHttpGet"},
    ),
    (
        NOT_FIXTURE,
        "DenyNotAction",
        {"Effect": "Deny", "Principal": {"AWS": ARN}, "NotAction": "es:ESHttpDelete"},
    ),
]

# A read of the statement's excluded principal or excluded actions.
NOT_PRINCIPAL_READ = re.compile(r"statement\.not_principal\b")
NOT_ACTIONS_READ = re.compile(r"statement\.not_actions\b")

# (fixture file, logical id, the statements as YAML hands them to cfn-model, without
# Resource). These resources match a rule more than once, or are the control for one that
# matches once.
REPEAT_FIXTURE = "opensearch_policy_repeated_matches.yaml"
REPEAT_SHAPES = [
    (
        REPEAT_FIXTURE,
        "TwoMatchingStatements",
        [
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "es:*"},
            {"Effect": "Allow", "Principal": "*", "Action": "*"},
        ],
    ),
    (
        REPEAT_FIXTURE,
        "StarsInOneAction",
        [{"Effect": "Allow", "Principal": {"AWS": ARN}, "Action": ["es:*", "*"]}],
    ),
    (
        REPEAT_FIXTURE,
        "SingleStarStatement",
        [{"Effect": "Allow", "Principal": "*", "Action": "es:ESHttpGet"}],
    ),
]

# A result list that is de-duplicated before it is returned, so a resource that matched
# twice is listed once.
UNIQUE_RESULT = re.compile(r"logical_resource_ids\.uniq\b")

# A read of the Default of a parameter that an action names with Ref, as a method call or
# through the rule's parameter_attribute helper. cfn-model does not apply a Default when
# no parameter values are passed, and ASH passes none.
PARAMETER_DEFAULT_READ = re.compile(
    r"\.default\b|\bparameter_attribute\(\s*\w+\s*,\s*:default\s*\)"
)

# A line written to stderr for an action the rule cannot read.
STDERR_WARNING = re.compile(r"\bwarn\b|\$stderr\.puts|STDERR\.puts")

# The type prefix of a parameter whose Default is the name of an SSM parameter, not a
# value: AWS::SSM::Parameter::Value<String>, <List<String>> and the rest.
SSM_TYPE_PREFIX = re.compile(r"AWS::SSM::Parameter::Value")

# A read of the AllowedValues of a parameter. cfn-model keeps the key with its first letter
# lowered.
ALLOWED_VALUES_READ = re.compile(r"\ballowedValues\b")

# cfn_nag_scan parses the template with line numbers, and that wraps a scalar Type in
# {"value" => ..., "line" => ...}. A parameter's type is a String only after "value" is read.
TYPE_VALUE_READ = re.compile(r"""\[\s*["']value["']\s*\]""")

# respond_to? on a Parameter. cfn-model answers a Parameter's attributes (default,
# allowedValues and the rest) through method_missing and defines no respond_to_missing?,
# so respond_to? is false for each of them.
RESPOND_TO_DEFAULT = re.compile(r"respond_to\?\(\s*:default\s*\)")

# How a rule loads the shared helper: relative to its own file, because cfn-nag requires a
# rule by absolute path and puts no rule directory on the load path.
REQUIRE_HELPER = re.compile(r"""require_relative\s+['"]AccessPolicyReading['"]""")


COMMENT_START = re.compile(r"(^|\s)#(?!\{).*")


def _code(rule_file: str) -> str:
    """A rule's Ruby source with comments removed, so a comment cannot decide a check.

    A comment starts at a ``#`` that begins the line or follows white space and is not
    ``#{``. A ``#`` inside a word is kept, and so is the ``#{`` of string interpolation:
    the verb rule builds an instance variable name with ``"@#{name}"``, and cutting the
    line at that ``#`` left the call half written. A ``#`` after white space inside a
    string would still be read as a comment; no shipped rule has one.
    """
    return _without_comments(RULE_DIR.joinpath(rule_file).read_text(encoding="utf-8"))


def _without_comments(source: str) -> str:
    return "\n".join(COMMENT_START.sub(r"\1", line) for line in source.splitlines())


# The file both rules load for what they read in common. cfn-nag runs every file of the
# rule directory whose name ends in Rule.rb, so this one is named for what it does.
HELPER_FILE = "AccessPolicyReading.rb"


def _code_with_helper(rule_file: str) -> str:
    """A rule's source and the shared helper's, for a check on what the rule can read.

    The reads of a parameter's Default, AllowedValues and type live in the helper that
    both rules load, so a check that the rule reads them looks at both files.
    """
    return _code(rule_file) + "\n" + _code(HELPER_FILE)


def _statements(fixture_name: str, logical_id: str) -> list:
    template = yaml.safe_load(FIXTURE_DIR.joinpath(fixture_name).read_text("utf-8"))
    policy = template["Resources"][logical_id]["Properties"]["AccessPolicies"]
    return policy["Statement"]


def test_the_patterns_match_what_they_exist_to_find():
    """Each read below needs an input it must flag and one it must not.

    Without this a pattern that stopped matching anything would leave the cells below
    green over source that had regressed.
    """
    assert HASH_METHOD_ON_PRINCIPAL.search(
        'if statement.principal.has_key?("AWS") and statement.principal.has_value?("*")'
    )
    assert not HASH_METHOD_ON_PRINCIPAL.search(
        "if public_principal?(statement.principal)"
    )
    assert WHOLE_STAR_COMPARISON.search('if verb == "*" || verb.end_with?(":*")')
    assert WHOLE_STAR_COMPARISON.search("if verb == '*'")
    assert not WHOLE_STAR_COMPARISON.search('if action.downcase.end_with?(":*")')
    assert STRING_CHECK.search("next unless action.is_a?(String)")
    assert not STRING_CHECK.search("verb = action.downcase")
    assert DOWNCASE_CALL.search("verb = action.downcase")
    assert not DOWNCASE_CALL.search("next unless action.is_a?(String)")
    assert AWS_KEY_GATE.search('principal.has_key?("AWS") &&')
    assert not AWS_KEY_GATE.search("principal.values.any? { |value| value == '*' }")
    assert NOT_PRINCIPAL_READ.search("if public_principal?(statement.not_principal)")
    assert not NOT_PRINCIPAL_READ.search("if public_principal?(statement.principal)")
    assert NOT_ACTIONS_READ.search("if statement.not_actions.any?")
    assert not NOT_ACTIONS_READ.search("statement.actions.each do |action|")
    assert UNIQUE_RESULT.search("logical_resource_ids.uniq")
    assert not UNIQUE_RESULT.search("    logical_resource_ids")
    assert PARAMETER_DEFAULT_READ.search("parameter.default.to_s.split(',')")
    assert PARAMETER_DEFAULT_READ.search("parameter_attribute(parameter, :default)")
    assert not PARAMETER_DEFAULT_READ.search("parameter_attribute(parameter, :type)")
    assert not PARAMETER_DEFAULT_READ.search("action['Ref']")
    assert STDERR_WARNING.search('warn "unread action"')
    assert STDERR_WARNING.search("$stderr.puts 'unread action'")
    assert not STDERR_WARNING.search("logical_resource_ids << id")
    assert SSM_TYPE_PREFIX.search('type.to_s.start_with?("AWS::SSM::Parameter::Value")')
    assert not SSM_TYPE_PREFIX.search('type.to_s.start_with?("AWS::EC2::")')
    assert ALLOWED_VALUES_READ.search("instance_variable_get(:@allowedValues)")
    assert ALLOWED_VALUES_READ.search("parameter.allowedValues")
    assert not ALLOWED_VALUES_READ.search("parameter.default")
    assert TYPE_VALUE_READ.search('type = type["value"] if type.is_a?(Hash)')
    assert TYPE_VALUE_READ.search("type['value']")
    assert not TYPE_VALUE_READ.search('action["Ref"]')
    assert RESPOND_TO_DEFAULT.search("!parameter.respond_to?(:default)")
    assert not RESPOND_TO_DEFAULT.search("parameter.respond_to?(:type)")
    assert SUB_HOLE_READ.search(r"SUB_HOLE = /\$\{(?!!)([^}]*)\}/")
    assert not SUB_HOLE_READ.search(r"split = /\d+/")
    assert HELPER_STRING_CHECK.search("if value.is_a?(String)")
    assert not HELPER_STRING_CHECK.search("verb = value.downcase")
    assert HELPER_TEXTS_CALL.search(
        "texts = AccessPolicyReading.texts(cfn_model, action)"
    )
    assert not HELPER_TEXTS_CALL.search("texts = [action]")
    assert IF_BRANCHES_READ.search("""value["Fn::If"][1..2].flat_map""")
    assert IF_BRANCHES_READ.search("expression['Fn::If'][1..2]")
    assert not IF_BRANCHES_READ.search("""value["Fn::If"][1..1]""")
    assert not IF_BRANCHES_READ.search("""value["Fn::If"][1]""")
    assert RAW_MODEL_READ.search("raw = cfn_model.raw_model")
    assert not RAW_MODEL_READ.search("raw = resource.accessPolicies")
    assert POLICY_DOCUMENT_CALL.search(
        "document, limited = AccessPolicyReading.policy_document(cfn_model, resource)"
    )
    assert not POLICY_DOCUMENT_CALL.search("parse(cfn_model, resource.accessPolicies)")
    assert PRINCIPAL_READ_CALL.search(
        "texts, shape = AccessPolicyReading.read_principal(m, e)"
    )
    assert not PRINCIPAL_READ_CALL.search("star_or_list_holding_star?(principal)")
    assert UNREAD_PRINCIPAL_LINE.search('"WARNING: Rule: unread principal in %s (%s)"')
    assert not UNREAD_PRINCIPAL_LINE.search('"WARNING: Rule: unread action in %s (%s)"')
    assert LISTED_METHOD.search("def excluded_principal_listed?(statement)")
    assert LISTED_METHOD.search("  def listed?(excluded)")
    assert not LISTED_METHOD.search(
        "if AccessPolicyReading.listed?(statement.not_actions)"
    )
    assert REQUIRE_HELPER.search("require_relative 'AccessPolicyReading'")
    assert REQUIRE_HELPER.search('require_relative "AccessPolicyReading"')
    assert not REQUIRE_HELPER.search(
        "require 'cfn-model/parser/policy_document_parser'"
    )
    # What _code strips: comments, and nothing else.
    assert _without_comments("# a whole line comment") == ""
    assert _without_comments("x = 1 # a trailing comment").rstrip() == "x = 1"
    assert _without_comments('parameter.instance_variable_get("@#{name}")') == (
        'parameter.instance_variable_get("@#{name}")'
    )
    assert _without_comments("value = a#b") == "value = a#b"


def test_the_star_policy_rule_calls_no_hash_method_on_the_statement_principal():
    """A principal that is a String must reach a type check, not ``has_key?``.

    ``Principal: "*"`` is a String after parsing. Calling a Hash method on it raises, and
    under ``--isolate-custom-rule-exceptions`` that costs the rule's verdict on every
    resource in the template, not only the one with the String. This is a read of the
    source: the integration cells are what show the rule reporting the right resources.
    """
    calls = HASH_METHOD_ON_PRINCIPAL.findall(_code("StarResourceAccessPolicyRule.rb"))

    assert calls == [], (
        "StarResourceAccessPolicyRule.rb calls "
        f"{sorted(set(calls))} directly on statement.principal; the principal is a "
        'String for Principal: "*" and a String has none of them'
    )


def test_the_star_policy_rule_reads_a_star_under_any_principal_key():
    """A ``*`` under any key of a principal Hash is public, with or without an ``AWS`` key.

    The rule used to read a Hash only when it had an ``AWS`` key, so ``{Service: "*"}``
    was not reported while ``{AWS: arn, Service: "*"}`` was. This is a read of the
    source: the integration cells show which resources are reported.
    """
    gates = AWS_KEY_GATE.findall(_code("StarResourceAccessPolicyRule.rb"))

    assert gates == [], (
        "StarResourceAccessPolicyRule.rb tests for an AWS key before it reads a principal "
        "Hash, so a star under another key is reported only beside an AWS key"
    )


def test_the_verb_rule_compares_the_whole_action_with_a_bare_star():
    """``Action: "*"`` ends in no ``:*``, so the suffix test alone never sees it."""
    code = _code("ResourcePolicyStarAccessVerbPolicyRule.rb")

    assert WHOLE_STAR_COMPARISON.search(code), (
        "ResourcePolicyStarAccessVerbPolicyRule.rb never compares an action with the "
        'bare "*", so an Allow statement for every action is not reported'
    )


@pytest.mark.parametrize(
    "rule_file",
    [
        "StarResourceAccessPolicyRule.rb",
        "ResourcePolicyStarAccessVerbPolicyRule.rb",
    ],
)
def test_a_rule_lists_a_resource_once_however_many_times_it_matches(rule_file):
    """A rule adds a resource to its list once per match, so it returns the list de-duplicated.

    This is a read of the source: the integration cells over the repeated-matches fixture
    show each resource listed once.
    """
    assert UNIQUE_RESULT.search(_code(rule_file)), (
        f"{rule_file} returns its list without removing repeats, so a resource that "
        "matches twice is reported twice"
    )


def test_the_verb_rule_reads_the_default_of_a_parameter_an_action_names():
    """``Action: !Ref P`` reaches the rule as a Hash, and cfn-model has not applied ``P``'s Default.

    ASH passes no parameter values, and cfn-model applies a Default only when it is given
    some. A rule that passes the Hash over cannot see a Default of ``*``. This is a read of
    the source: the integration cells show the resources reported.
    """
    assert PARAMETER_DEFAULT_READ.search(
        _code_with_helper("ResourcePolicyStarAccessVerbPolicyRule.rb")
    ), (
        "ResourcePolicyStarAccessVerbPolicyRule.rb never reads a parameter's Default, so "
        "an action that is a Ref to a parameter whose Default is * is not reported"
    )


def test_the_verb_rule_writes_a_line_to_stderr_for_an_action_it_cannot_read():
    """An action that is not text and names no parameter with a Default is not checked.

    The rule says so on stderr instead of passing it over without a trace. This is a read
    of the source: the integration cell shows the line.
    """
    assert STDERR_WARNING.search(_code("ResourcePolicyStarAccessVerbPolicyRule.rb")), (
        "ResourcePolicyStarAccessVerbPolicyRule.rb writes nothing to stderr, so an "
        "action it cannot read is passed over without a trace"
    )


def test_the_verb_rule_does_not_read_an_ssm_parameters_default_as_the_action():
    """The Default of a parameter of an SSM type is the name of an SSM parameter.

    ``Type: AWS::SSM::Parameter::Value<String>`` with ``Default: /app/action`` means the
    action is whatever that SSM parameter holds when the stack is created. Reading the
    Default as the action finds a key name with no star in it, and the rule then says
    nothing about an action that may be ``*``. This is a read of the source: the
    integration test on ``RefSsmAction`` shows the stderr line.
    """
    assert SSM_TYPE_PREFIX.search(
        _code_with_helper("ResourcePolicyStarAccessVerbPolicyRule.rb")
    ), (
        "ResourcePolicyStarAccessVerbPolicyRule.rb never tests for an SSM parameter "
        "type, so the Default of one is read as the action"
    )


def test_the_verb_rule_reads_the_allowed_values_of_a_parameter():
    """A deployer may choose any of a parameter's AllowedValues, whatever its Default is.

    ``Default: es:ESHttpGet`` with ``AllowedValues: [es:ESHttpGet, "*"]`` lets the
    stack's creator pick the star. A rule that reads only the Default passes it. This is a
    read of the source: the integration test on ``RefAllowedStar`` shows the resource
    reported.
    """
    assert ALLOWED_VALUES_READ.search(
        _code_with_helper("ResourcePolicyStarAccessVerbPolicyRule.rb")
    ), (
        "ResourcePolicyStarAccessVerbPolicyRule.rb never reads a parameter's "
        "AllowedValues, so a star among them is not reported"
    )


def test_the_verb_rule_reads_a_parameter_type_out_of_the_line_number_wrapper():
    """cfn_nag_scan parses with line numbers, so a parameter's ``type`` is a Hash.

    cfn-model wraps every scalar ``Type`` in ``{"value" => ..., "line" => ...}`` in that
    mode, and ``parameter.type`` is that Hash. ``to_s`` on it begins with ``{``, so a
    prefix test on the type never matches unless ``value`` is read first. This is a read
    of the source: the integration test on ``RefSsmAction`` shows the stderr line.
    """
    assert TYPE_VALUE_READ.search(
        _code_with_helper("ResourcePolicyStarAccessVerbPolicyRule.rb")
    ), (
        "ResourcePolicyStarAccessVerbPolicyRule.rb never reads the value of a "
        "parameter's type, so a type test would run on the line-number Hash"
    )


def test_the_verb_rule_does_not_ask_a_parameter_whether_it_responds_to_default():
    """A Parameter answers ``default`` through method_missing, and ``respond_to?`` is false.

    The guard made every ``Ref`` to a parameter read as one with no Default, so a Default
    of ``*`` was never reported. This is a read of the source: the integration tests on
    ``RefDefaultStar`` and ``RefDefaultListStar`` show the resources reported.
    """
    assert not RESPOND_TO_DEFAULT.search(
        _code_with_helper("ResourcePolicyStarAccessVerbPolicyRule.rb")
    ), (
        "ResourcePolicyStarAccessVerbPolicyRule.rb asks a parameter whether it "
        "responds to default, which is false for every parameter, so no Default is read"
    )


def test_the_shared_helper_is_not_named_like_a_rule():
    """cfn-nag requires and runs every file of the rule directory whose name ends in Rule.rb.

    The helper holds no rule class, so a name ending that way would make cfn-nag look for
    a class of that name and fail. This is a read of the file name: the integration tests
    show the scan running with the helper in the directory.
    """
    assert RULE_DIR.joinpath(HELPER_FILE).is_file(), HELPER_FILE
    assert not HELPER_FILE.endswith("Rule.rb"), HELPER_FILE


@pytest.mark.parametrize(
    "rule_file",
    [
        "StarResourceAccessPolicyRule.rb",
        "ResourcePolicyStarAccessVerbPolicyRule.rb",
    ],
)
def test_a_rule_loads_the_shared_helper_relative_to_its_own_file(rule_file):
    """cfn-nag requires a rule by absolute path and adds no directory to the load path."""
    assert REQUIRE_HELPER.search(_code(rule_file)), (
        f"{rule_file} does not require_relative the shared helper, so the constant it "
        "reads parameters through is not defined when cfn-nag loads it"
    )


@pytest.mark.parametrize(
    "name,parameter", PARAMETER_SHAPES, ids=[row[0] for row in PARAMETER_SHAPES]
)
def test_the_intrinsic_fixture_parameter_has_the_shape_its_name_describes(
    name, parameter
):
    """The Ref resources are named for the parameter each reads; this pins the parameters."""
    template = yaml.safe_load(
        FIXTURE_DIR.joinpath(INTRINSIC_FIXTURE).read_text("utf-8")
    )

    assert template["Parameters"][name] == parameter


# (fixture file, parameter name, the parameter as YAML hands it to cfn-model) for the
# parameters the substitution, conditional and principal fixtures read. Each fixture
# resource depends on the type, Default and AllowedValues of the parameters it names.
NEW_PARAMETER_SHAPES = [
    (SUB_FIXTURE, "OpenAction", {"Type": "String", "Default": "*"}),
    (SUB_FIXTURE, "OpenVerb", {"Type": "String", "Default": "*"}),
    (SUB_FIXTURE, "ScopedVerb", {"Type": "String", "Default": "ESHttpGet"}),
    (
        SUB_FIXTURE,
        "ChosenVerb",
        {
            "Type": "String",
            "Default": "ESHttpGet",
            "AllowedValues": ["ESHttpGet", "*"],
        },
    ),
    (SUB_FIXTURE, "Service", {"Type": "String", "Default": "es"}),
    (SUB_FIXTURE, "NoDefaultVerb", {"Type": "String"}),
    (IF_FIXTURE, "Stage", {"Type": "String", "Default": "dev"}),
    (PRINCIPAL_FIXTURE, "OpenPrincipal", {"Type": "String", "Default": "*"}),
    (PRINCIPAL_FIXTURE, "ScopedPrincipal", {"Type": "String", "Default": ARN}),
    (
        PRINCIPAL_FIXTURE,
        "ChosenPrincipal",
        {"Type": "String", "Default": ARN, "AllowedValues": [ARN, "*"]},
    ),
    (PRINCIPAL_FIXTURE, "NoDefaultPrincipal", {"Type": "String"}),
    (
        PRINCIPAL_FIXTURE,
        "SsmPrincipal",
        {
            "Type": "AWS::SSM::Parameter::Value<String>",
            "Default": "/ash/fixture/principal",
        },
    ),
]


def _if(first, second):
    """An Fn::If on the fixture's one condition, as YAML hands it to cfn-model."""
    return {"Fn::If": ["IsProd", first, second]}


def _statement(principal, action, effect="Allow"):
    return {
        "Effect": effect,
        "Principal": principal,
        "Action": action,
        "Resource": "*",
    }


def _policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


# (logical id, the AccessPolicies property as YAML hands it to cfn-model) for the
# conditional fixture. The statements differ in where the Fn::If sits, so each row pins
# the whole property.
IF_SHAPES = [
    (
        "IfActionSecondStar",
        _policy(_statement({"AWS": ARN}, [_if("es:ESHttpGet", "*")])),
    ),
    (
        "IfActionFirstStar",
        _policy(_statement({"AWS": ARN}, [_if("*", "es:ESHttpGet")])),
    ),
    (
        "IfActionScoped",
        _policy(_statement({"AWS": ARN}, [_if("es:ESHttpGet", "es:ESHttpHead")])),
    ),
    (
        "IfActionListElement",
        _policy(
            _statement({"AWS": ARN}, ["es:ESHttpGet", _if("es:ESHttpHead", "es:*")])
        ),
    ),
    (
        "IfActionNoValue",
        _policy(
            _statement(
                {"AWS": ARN},
                ["es:ESHttpGet", _if("es:ESHttpHead", {"Ref": "AWS::NoValue"})],
            )
        ),
    ),
    (
        "IfPrincipalSecondStar",
        _policy(_statement(_if({"AWS": ARN}, "*"), "es:ESHttpGet")),
    ),
    (
        "IfPrincipalValueStar",
        _policy(_statement({"AWS": _if(ARN, "*")}, "es:ESHttpGet")),
    ),
    (
        "IfPrincipalScoped",
        _policy(
            _statement(_if({"AWS": ARN}, {"AWS": ARN_OTHER}), "es:ESHttpGet"),
        ),
    ),
    (
        "IfStatementSecondOpen",
        _policy(
            _if(_statement({"AWS": ARN}, "es:ESHttpGet"), _statement("*", "*")),
        ),
    ),
    (
        "IfEffectSecondAllow",
        _policy(_statement("*", "*", effect=_if("Deny", "Allow"))),
    ),
    (
        "IfWholePolicy",
        _if(
            _policy(_statement({"AWS": ARN}, "es:ESHttpGet")),
            _policy(_statement("*", "*")),
        ),
    ),
    (
        "IfTooManyBranches",
        _policy(
            _statement(
                {
                    "AWS": _if(ARN, ARN_OTHER),
                    "Service": _if("es.amazonaws.com", "lambda.amazonaws.com"),
                    "Federated": _if(
                        "cognito-identity.amazonaws.com", "accounts.google.com"
                    ),
                    "CanonicalUser": _if(
                        "79a59df900b949e55d96a1e698fbaced",
                        "79a59df900b949e55d96a1e698fbacee",
                    ),
                },
                _if("es:ESHttpGet", "es:ESHttpHead"),
                effect=_if("Allow", "Allow"),
            )
        ),
    ),
]

# A pattern in the helper that finds the ${Name} holes of an Fn::Sub text, and the check
# that the helper's reading of a value begins with its type.
SUB_HOLE_READ = re.compile(r"/\\\$\\\{")
HELPER_STRING_CHECK = re.compile(r"\bis_a\?\(\s*String\s*\)")
HELPER_TEXTS_CALL = re.compile(r"AccessPolicyReading\.texts\(")

# The helper's read of both branches of an Fn::If (the then and else branches are elements
# 1 and 2 of its three-element list), its read of cfn-model's raw model, and a rule's call
# for the expanded policy document.
IF_BRANCHES_READ = re.compile(r"""\[\s*["']Fn::If["']\s*\]\s*\[\s*1\s*\.\.\s*2\s*\]""")
RAW_MODEL_READ = re.compile(r"\.raw_model\b")
POLICY_DOCUMENT_CALL = re.compile(r"AccessPolicyReading\.policy_document\(")

# The principal rule's read of a principal through the helper, and a method that reports
# whether a statement lists something to exclude. The helper defines the one such method.
PRINCIPAL_READ_CALL = re.compile(r"AccessPolicyReading\.read_principal\(")
UNREAD_PRINCIPAL_LINE = re.compile(r"unread principal in")
LISTED_METHOD = re.compile(r"\bdef\s+(?:self\.)?\w*listed\?")


@pytest.mark.parametrize(
    "fixture_name,name,parameter",
    NEW_PARAMETER_SHAPES,
    ids=[f"{row[0]}:{row[1]}" for row in NEW_PARAMETER_SHAPES],
)
def test_a_new_fixture_parameter_has_the_shape_its_name_describes(
    fixture_name, name, parameter
):
    """The fixture resources are named for the parameters they read; this pins them."""
    template = yaml.safe_load(FIXTURE_DIR.joinpath(fixture_name).read_text("utf-8"))

    assert template["Parameters"][name] == parameter


@pytest.mark.parametrize(
    "logical_id,policy", IF_SHAPES, ids=[row[0] for row in IF_SHAPES]
)
def test_the_conditional_fixture_resource_has_the_shape_its_name_describes(
    logical_id, policy
):
    """Pins the AccessPolicies property of each resource of the Fn::If fixture."""
    template = yaml.safe_load(FIXTURE_DIR.joinpath(IF_FIXTURE).read_text("utf-8"))

    assert template["Resources"][logical_id]["Properties"]["AccessPolicies"] == policy


def test_the_conditional_fixture_has_the_one_condition_its_branches_name():
    template = yaml.safe_load(FIXTURE_DIR.joinpath(IF_FIXTURE).read_text("utf-8"))

    assert template["Conditions"] == {
        "IsProd": {"Fn::Equals": [{"Ref": "Stage"}, "prod"]}
    }


def test_the_helper_reads_both_branches_of_an_fn_if():
    """cfn-model resolves an Fn::If to one branch, so the second is read from the raw policy.

    With every condition true, which is how cfn-model parses a template it is given no
    condition values for, ``Fn::If: [C, "es:ESHttpGet", "*"]`` arrives as the first
    branch. The helper takes both branches from the policy as the template wrote it. This
    is a read of the source: the integration tests on ``IfActionSecondStar`` and its
    siblings show the resources reported.
    """
    code = _code(HELPER_FILE)

    assert IF_BRANCHES_READ.search(code), (
        f"{HELPER_FILE} never reads the second branch of an Fn::If, so a public value "
        "in it is not seen"
    )
    assert RAW_MODEL_READ.search(code), (
        f"{HELPER_FILE} never reads cfn-model's raw model, so it has only the policy "
        "after cfn-model chose a branch of an Fn::If around the whole property"
    )


@pytest.mark.parametrize(
    "rule_file",
    [
        "StarResourceAccessPolicyRule.rb",
        "ResourcePolicyStarAccessVerbPolicyRule.rb",
    ],
)
def test_a_rule_parses_the_policy_the_helper_expands(rule_file):
    """A rule parses the document the helper built from the raw policy, not the property."""
    assert POLICY_DOCUMENT_CALL.search(_code(rule_file)), (
        f"{rule_file} never asks AccessPolicyReading for the policy document, so it "
        "parses the property cfn-model already resolved"
    )


def test_the_star_policy_rule_reads_a_principal_through_the_helper():
    """A Ref to a parameter in a principal is read the way the verb rule reads one in an action.

    ``Principal: {AWS: !Ref P}`` reaches the rule as a Hash, and cfn-model has applied no
    Default. The helper holds the reading of a parameter that both rules share. This is a
    read of the source: the integration tests on ``PrincipalRefDefaultStar`` and its
    siblings show the resources reported.
    """
    assert PRINCIPAL_READ_CALL.search(_code("StarResourceAccessPolicyRule.rb")), (
        "StarResourceAccessPolicyRule.rb never reads a principal through "
        "AccessPolicyReading, so a parameter whose Default is * is not reported"
    )


def test_the_star_policy_rule_writes_a_line_to_stderr_for_a_principal_it_cannot_read():
    """An import, or a Ref to a parameter with no text, is not checked, and the rule says so."""
    code = _code("StarResourceAccessPolicyRule.rb")

    assert STDERR_WARNING.search(code) and UNREAD_PRINCIPAL_LINE.search(code), (
        "StarResourceAccessPolicyRule.rb writes no line to stderr for a principal it "
        "cannot read, so such a principal is passed over without a trace"
    )


def test_the_two_rules_share_one_helper_for_what_a_statement_excludes():
    """NotAction and NotPrincipal are both reported through AccessPolicyReading.listed?."""
    for rule_file in (
        "StarResourceAccessPolicyRule.rb",
        "ResourcePolicyStarAccessVerbPolicyRule.rb",
    ):
        assert not LISTED_METHOD.search(_code(rule_file)), (
            f"{rule_file} defines its own method for what a statement excludes"
        )
    assert LISTED_METHOD.search(_code(HELPER_FILE)), HELPER_FILE


def test_the_helper_reads_the_holes_of_an_fn_sub_text():
    """An action written with Fn::Sub keeps its ``${Name}`` text, and the helper reads each name.

    cfn-model resolves a substitution only for a parameter it was given a value for, and
    ASH gives none. A rule that reads the text as it arrives finds no star in
    ``es:${Verb}`` whatever ``Verb`` holds. This is a read of the source: the integration
    tests on ``SubVerbStar`` and its siblings show the resources reported.
    """
    assert SUB_HOLE_READ.search(_code(HELPER_FILE)), (
        f"{HELPER_FILE} never looks for the ${{Name}} holes of a substitution, so the "
        "text of an Fn::Sub action is read with its holes in it"
    )


def test_the_verb_rule_reads_an_action_through_the_helper_before_it_downcases_it():
    """The helper answers with text, or nil when the value is not text it can read.

    The rule calls it before ``downcase``, and the helper checks the value is a String
    before it treats it as one. This is a read of the source: the integration tests show
    the rule still reporting the other resources of a template with an unreadable action.
    """
    code = _code("ResourcePolicyStarAccessVerbPolicyRule.rb")
    call = HELPER_TEXTS_CALL.search(code)
    lowered = DOWNCASE_CALL.search(code)

    assert call and lowered and call.start() < lowered.start(), (
        "ResourcePolicyStarAccessVerbPolicyRule.rb does not read an action through "
        "AccessPolicyReading.texts before it calls downcase"
    )
    assert HELPER_STRING_CHECK.search(_code(HELPER_FILE)), (
        f"{HELPER_FILE} never checks that a value is a String, so it could call a String "
        "method on a Hash"
    )


def test_the_star_policy_rule_reads_the_statements_excluded_principal():
    """``Allow`` with ``NotPrincipal`` names everyone except the listed principals.

    A rule that reads only ``principal`` sees nil on that statement and passes it over.
    This is a read of the source: the integration cells show the statement reported.
    """
    assert NOT_PRINCIPAL_READ.search(_code("StarResourceAccessPolicyRule.rb")), (
        "StarResourceAccessPolicyRule.rb never reads statement.not_principal, so an "
        "Allow statement with NotPrincipal is not reported"
    )


def test_the_verb_rule_reads_the_statements_excluded_actions():
    """``Allow`` with ``NotAction`` grants every action except the listed ones."""
    assert NOT_ACTIONS_READ.search(
        _code("ResourcePolicyStarAccessVerbPolicyRule.rb")
    ), (
        "ResourcePolicyStarAccessVerbPolicyRule.rb never reads statement.not_actions, so "
        "an Allow statement with NotAction is not reported"
    )


@pytest.mark.parametrize(
    "fixture_name,logical_id,statement",
    NOT_SHAPES,
    ids=[row[1] for row in NOT_SHAPES],
)
def test_the_excluding_fixture_resource_has_the_shape_its_name_describes(
    fixture_name, logical_id, statement
):
    """Pins each resource of the NotPrincipal and NotAction fixture."""
    (actual,) = _statements(fixture_name, logical_id)

    assert {
        key: value for key, value in actual.items() if key != "Resource"
    } == statement


@pytest.mark.parametrize(
    "fixture_name,logical_id,statements",
    REPEAT_SHAPES,
    ids=[row[1] for row in REPEAT_SHAPES],
)
def test_the_repeated_match_fixture_resource_has_the_shape_its_name_describes(
    fixture_name, logical_id, statements
):
    """Pins each resource of the fixture whose resources match a rule more than once."""
    actual = _statements(fixture_name, logical_id)

    assert [
        {key: value for key, value in one.items() if key != "Resource"}
        for one in actual
    ] == statements


@pytest.mark.parametrize(
    "fixture_name,logical_id,effect,principal,action",
    SHAPES,
    ids=[row[1] for row in SHAPES],
)
def test_the_fixture_resource_has_the_shape_its_name_describes(
    fixture_name, logical_id, effect, principal, action
):
    """The integration cells assert findings per resource name; this pins what each is."""
    (statement,) = _statements(fixture_name, logical_id)

    assert statement["Effect"] == effect
    assert statement["Principal"] == principal
    assert statement["Action"] == action


def test_every_resource_of_the_case_fixtures_has_a_row_above():
    """A resource added to a fixture without a row would be asserted on, but not pinned."""
    rows = [(row[0], row[1]) for row in SHAPES + NOT_SHAPES + REPEAT_SHAPES]
    rows += [(IF_FIXTURE, row[0]) for row in IF_SHAPES]
    # The role the principal fixture's Fn::GetAtt points at carries no resource policy.
    rows += [(PRINCIPAL_FIXTURE, "AccessRole")]
    fixtures = sorted({fixture_name for fixture_name, _ in rows})
    in_templates = {
        (fixture_name, logical_id)
        for fixture_name in fixtures
        for logical_id in yaml.safe_load(
            FIXTURE_DIR.joinpath(fixture_name).read_text("utf-8")
        )["Resources"]
    }

    assert in_templates == set(rows)
