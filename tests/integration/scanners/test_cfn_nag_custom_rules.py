"""The shipped cfn-nag rules, run by the real cfn_nag_scan against a real template.

Why this file exists: the two resource-policy rules under ``appsec_cfn_rules`` only
execute on a resource whose ``AccessPolicies`` property is set, and no fixture or test in
this repository had one. The single path on which either rule can report a finding was
therefore never run, and a call that raises ``ArgumentError`` on every invocation of it
went undetected. Measured before the fix, with ASH's own argv against the fixture below:
exit 1, zero bytes of stdout, and
``policy_document_parser.rb:9:in 'parse': wrong number of arguments (given 1, expected
2)`` on stderr. The loss was not the two rules' verdicts but every rule's verdict on that
template, because the exception escapes cfn-nag's rescue clauses and the process never
renders.

The fixture is chosen so that these assertions cannot pass vacuously: an
``AWS::OpenSearchService::Domain`` with an open access policy trips no built-in cfn-nag
rule, so on this template the shipped rules are the only possible source of a finding.
``test_without_the_rule_directory_the_fixture_has_no_findings`` pins that, and if a
future cfn-nag release starts reporting on this shape it fails and says so rather than
letting the other tests quietly stop discriminating.

The skip is env-gated for the reason ``test_cdk_nag_real_pack.py`` gives for the same
pattern: a test that silently skips when its dependency is missing protects nothing.
``ASH_REQUIRE_CFN_NAG=1`` turns the skip into a failure. CI provisions Ruby and the gem
for the scan legs (see .github/actions/run-scan-test/action.yml), so it can set it.
"""

import json
import os
import subprocess  # nosec B404 - the tool under test is a separate process
from pathlib import Path

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR
from automated_security_helper.utils.subprocess_utils import find_executable

RULE_DIR = ASH_ASSETS_DIR.joinpath("appsec_cfn_rules")
FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "scanners"
    / "cfn_nag"
    / "opensearch_open_access_policy.yaml"
)

STAR_ACCESS_POLICY = "CFN_NAG_APPSEC-IAM-RestrictPublicAccess-StarAccessPolicy"
STAR_ACCESS_VERB = "CFN_NAG_APPSEC-IAM-LeastPrivilege-ResourcePolicyStarVerb"


def _cfn_nag_scan() -> str:
    """The cfn_nag_scan entrypoint, or skip -- unless the environment forbids skipping."""
    found = find_executable("cfn_nag_scan")
    if found:
        return str(found)
    if os.environ.get("ASH_REQUIRE_CFN_NAG", "").strip() in (
        "1",
        "YES",
        "TRUE",
        "true",
    ):
        pytest.fail(
            "ASH_REQUIRE_CFN_NAG is set but cfn_nag_scan is not on PATH. This test must "
            "RUN where cfn-nag is provisioned: it is the only test that executes the "
            "shipped Ruby rules at all."
        )
    pytest.skip("cfn_nag_scan is not installed on this machine")


def _run(*extra: str) -> subprocess.CompletedProcess:
    """Invoke cfn_nag_scan with *extra* plus the flags the scanner always passes."""
    return subprocess.run(  # nosec B603 - fixed argv, no shell
        [
            _cfn_nag_scan(),
            "--print-suppression",
            *extra,
            "--output-format",
            "sarif",
            "--input-path",
            FIXTURE.as_posix(),
        ],
        capture_output=True,
        text=True,
    )


def _rule_ids(proc: subprocess.CompletedProcess) -> set:
    assert proc.stdout.strip(), (
        "cfn_nag_scan wrote nothing, which means it died before rendering. stderr was:\n"
        f"{proc.stderr}"
    )
    report = json.loads(proc.stdout)
    return {
        result.get("ruleId")
        for run in report["runs"]
        for result in (run.get("results") or [])
    }


def test_the_fixture_declares_an_access_policy():
    """The fixture is the test. If AccessPolicies is gone, nothing below runs a rule."""
    assert FIXTURE.is_file(), FIXTURE
    assert "AccessPolicies:" in FIXTURE.read_text(encoding="utf-8")


@pytest.mark.integration
@pytest.mark.scanner
def test_without_the_rule_directory_the_fixture_has_no_findings():
    """Control for the two tests below: the built-in rules report nothing here.

    This is what makes "the result set is non-empty" a statement about the shipped rules
    rather than about cfn-nag in general. If this ever fails, the assertions below have
    stopped discriminating and need a different fixture, not a looser assertion.
    """
    assert _rule_ids(_run()) == set()


@pytest.mark.integration
@pytest.mark.scanner
def test_the_two_resource_policy_rules_report_the_open_policy():
    """Both shipped rules reach a verdict, rather than merely not raising.

    Passing ``cfn_model`` makes the call legal, but legal is not the same as working:
    ``PolicyDocumentParser#parse`` resolves references through the model, so a rule that
    parsed the document and then read the resulting statement wrongly would still report
    nothing. Asserting the two rule ids separates those two outcomes.
    """
    rule_ids = _rule_ids(
        _run(
            "--isolate-custom-rule-exceptions",
            "--rule-directory",
            RULE_DIR.as_posix(),
        )
    )

    assert {STAR_ACCESS_POLICY, STAR_ACCESS_VERB} <= rule_ids, (
        f"expected both resource-policy rules to fire; got {sorted(rule_ids)}"
    )


@pytest.mark.integration
@pytest.mark.scanner
def test_the_rules_do_not_raise_without_exception_isolation():
    """The arity fix, isolated from the flag that would otherwise mask it.

    ``--isolate-custom-rule-exceptions`` turns a raising rule into a stderr line and a
    skipped rule, which is why it is now passed -- but it would also hide the arity
    defect behind an empty result set. Measured on this fixture at the broken revision:
    with the flag, exit 0 and zero violations plus two "wrong number of arguments (given
    1, expected 2)" lines on stderr; without it, exit 1 and zero bytes of stdout. This
    test drops the flag so that only a rule that genuinely does not raise can satisfy it.
    """
    proc = _run("--rule-directory", RULE_DIR.as_posix())

    assert "wrong number of arguments" not in proc.stderr, proc.stderr
    assert "ArgumentError" not in proc.stderr, proc.stderr
    assert {STAR_ACCESS_POLICY, STAR_ACCESS_VERB} <= _rule_ids(proc)
