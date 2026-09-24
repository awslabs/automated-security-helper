"""The shipped cfn-nag rules must call cfn-model with the arity cfn-model declares.

Why a source-text test rather than a behavior test: exercising these rules for real needs
a Ruby interpreter, the cfn-nag gem and its pinned cfn-model, which is what
``tests/integration/scanners/test_cfn_nag_custom_rules.py`` does. That test is the one
that proves the rules work; this one runs everywhere and fails fast, because the cost of
getting the arity wrong is not a lost rule.

``PolicyDocumentParser#parse`` took one argument in cfn-model 0.4.0 and takes two from
later releases, and cfn-nag 0.8.10 pins ``cfn-model (= 0.6.6)`` exactly, so no reachable
version accepts the one-argument form. Called with one argument Ruby raises
ArgumentError; cfn-nag's CustomRuleLoader re-raises it unless
``--isolate-custom-rule-exceptions`` is passed, CfnNag#audit rescues four exception
classes that do not include it, and the executor has no rescue at all -- so the process
exits before writing any output and every rule's verdict on that template is lost, not
just the broken rule's.
"""

import re
from pathlib import Path

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR

RULE_DIR = ASH_ASSETS_DIR.joinpath("appsec_cfn_rules")

# `PolicyDocumentParser.new.parse(` or `PolicyDocumentParser.new().parse(`, capturing the
# argument list up to the first closing paren. The rules' calls are single-line, and a
# multi-line call would not match -- which is why the count assertion below exists.
PARSE_CALL = re.compile(r"PolicyDocumentParser\.new\(?\)?\.parse\(([^)]*)\)")


def _rule_files():
    return sorted(RULE_DIR.rglob("*.rb"))


def test_the_rule_directory_is_where_the_scanner_looks():
    """Guard against this whole module silently testing an empty directory."""
    assert RULE_DIR.is_dir(), RULE_DIR
    assert _rule_files(), f"no .rb rules found under {RULE_DIR}"


@pytest.mark.parametrize("rule_file", _rule_files(), ids=lambda path: Path(path).name)
def test_policy_document_parser_is_called_with_the_model_first(rule_file: Path):
    """Every parse call passes ``cfn_model`` first, as cfn-model's own callers do.

    ``cfn_model`` is the parameter ``audit_impl`` already receives, so nothing has to be
    plumbed in to satisfy this; the argument was simply missing.
    """
    source = rule_file.read_text(encoding="utf-8")
    for arguments in PARSE_CALL.findall(source):
        first = arguments.split(",")[0].strip()
        assert first == "cfn_model", (
            f"{rule_file.name} calls PolicyDocumentParser#parse with "
            f"({arguments.strip()}); cfn-model 0.6.6 declares "
            "parse(cfn_model, raw_policy_document) and both positionals are required, "
            "so this raises ArgumentError and takes the whole template's scan with it"
        )
        assert len([a for a in arguments.split(",") if a.strip()]) == 2, (
            f"{rule_file.name} passes {arguments.strip()!r}; parse takes exactly two "
            "arguments"
        )


def test_the_two_resource_policy_rules_are_covered_by_the_check_above():
    """The regex must actually match the two call sites the defect lived at.

    Without this, a rename or a reflow that stopped the pattern from matching would
    leave the parametrized test passing over zero call sites.
    """
    matched = {
        rule_file.name
        for rule_file in _rule_files()
        if PARSE_CALL.search(rule_file.read_text(encoding="utf-8"))
    }
    assert {
        "StarResourceAccessPolicyRule.rb",
        "ResourcePolicyStarAccessVerbPolicyRule.rb",
    } <= matched, (
        f"the parse-call pattern matched {sorted(matched)}; the two rules that call "
        "PolicyDocumentParser must be among them or this module checks nothing"
    )
