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

The fixture above covers one principal shape, ``{AWS: "*"}``, and one action shape,
``es:*``. The cells at the end of this file cover the others, one fixture per question,
and assert the exact list of logical resource ids each rule reports rather than only that
a rule fired. A rule that reports too much, or reports one resource twice, fails them as
surely as one that reports too little. Each fixture runs twice: with the flag ASH passes
and without it, because the flag turns a raising rule into one stderr line and no finding.
"""

import json
import os
import subprocess  # nosec B404 - the tool under test is a separate process
from pathlib import Path

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR
from automated_security_helper.utils.subprocess_utils import find_executable
from tests.utils.helpers import ash_tool_not_found_reason

RULE_DIR = ASH_ASSETS_DIR.joinpath("appsec_cfn_rules")
FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "scanners"
    / "cfn_nag"
    / "opensearch_open_access_policy.yaml"
)

STAR_ACCESS_POLICY = "CFN_NAG_APPSEC-IAM-RestrictPublicAccess-StarAccessPolicy"
STAR_ACCESS_VERB = "CFN_NAG_APPSEC-IAM-LeastPrivilege-ResourcePolicyStarVerb"  # pragma: allowlist secret


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
    pytest.skip(ash_tool_not_found_reason("cfn_nag_scan"))


def _run(*extra: str, fixture: Path = FIXTURE) -> subprocess.CompletedProcess:
    """Invoke cfn_nag_scan with *extra* plus the flags the scanner always passes."""
    return subprocess.run(  # nosec B603 - fixed argv, no shell
        [
            _cfn_nag_scan(),
            "--print-suppression",
            *extra,
            "--output-format",
            "sarif",
            "--input-path",
            fixture.as_posix(),
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


# Fixture file -> for each rule, the logical resource ids it must report on that template,
# no more and no fewer. Every set is the one the fixture's own description names.
SHAPE_CASES = {
    "opensearch_policy_principal_forms.yaml": {
        STAR_ACCESS_POLICY: {
            "AwsListStar",
            "AwsListMixedStar",
            "AwsAndServiceStar",
            "ServiceStarOnly",
        },
        STAR_ACCESS_VERB: set(),
    },
    "opensearch_policy_principal_string_star.yaml": {
        STAR_ACCESS_POLICY: {"StringStar"},
        STAR_ACCESS_VERB: set(),
    },
    "opensearch_policy_principal_string_scoped.yaml": {
        STAR_ACCESS_POLICY: set(),
        STAR_ACCESS_VERB: set(),
    },
    "opensearch_policy_principal_array_star.yaml": {
        STAR_ACCESS_POLICY: {"ArrayStar"},
        STAR_ACCESS_VERB: set(),
    },
    "opensearch_policy_action_forms.yaml": {
        STAR_ACCESS_POLICY: set(),
        STAR_ACCESS_VERB: {
            "BareStar",
            "ListOnlyBareStar",
            "ListWithBareStar",
            "ServiceStar",
        },
    },
    "opensearch_policy_not_forms.yaml": {
        STAR_ACCESS_POLICY: {"AllowNotPrincipal"},
        STAR_ACCESS_VERB: {"AllowNotAction"},
    },
    "opensearch_policy_intrinsic_action.yaml": {
        STAR_ACCESS_POLICY: set(),
        STAR_ACCESS_VERB: {
            "ServiceStarAfterIntrinsic",
            "BareStarAfterIntrinsic",
            "ListIntrinsicThenBareStar",
            "RefDefaultStar",
            "RefDefaultListStar",
            "RefAllowedStar",
        },
    },
    "opensearch_policy_repeated_matches.yaml": {
        STAR_ACCESS_POLICY: {"TwoMatchingStatements", "SingleStarStatement"},
        STAR_ACCESS_VERB: {"TwoMatchingStatements", "StarsInOneAction"},
    },
    "opensearch_policy_if_forms.yaml": {
        STAR_ACCESS_POLICY: {
            "IfPrincipalSecondStar",
            "IfPrincipalValueStar",
            "IfStatementSecondOpen",
            "IfEffectSecondAllow",
            "IfWholePolicy",
        },
        STAR_ACCESS_VERB: {
            "IfActionSecondStar",
            "IfActionFirstStar",
            "IfActionListElement",
            "IfStatementSecondOpen",
            "IfEffectSecondAllow",
            "IfWholePolicy",
        },
    },
    "opensearch_policy_principal_parameters.yaml": {
        STAR_ACCESS_POLICY: {
            "PrincipalRefDefaultStar",
            "PrincipalRefAllowedStar",
            "PrincipalRefListStar",
            "PrincipalWholeRef",
            "PrincipalSubStar",
        },
        STAR_ACCESS_VERB: set(),
    },
    "opensearch_policy_sub_action.yaml": {
        STAR_ACCESS_POLICY: set(),
        STAR_ACCESS_VERB: {
            "SubParameterStar",
            "SubVerbStar",
            "SubAllowedStar",
            "SubTwoParameters",
        },
    },
}


# What a rule that raised leaves on stderr. The two messages cfn-nag printed for the
# arity defect and for a Hash method called on a String come first; the class names cover
# a raise of any other kind.
RAISE_MARKERS = (
    "undefined method",
    "wrong number of arguments",
    "NoMethodError",
    "ArgumentError",
    "TypeError",
    "RuntimeError",
    "NameError",
)


def _custom_findings(proc: subprocess.CompletedProcess) -> dict:
    """The logical resource ids each shipped rule reported, keyed by rule id.

    Each value is a sorted list, not a set, so a resource a rule reports twice shows up.
    """
    assert proc.stdout.strip(), (
        "cfn_nag_scan wrote nothing, which means it died before rendering. stderr was:\n"
        f"{proc.stderr}"
    )
    found = {rule_id: [] for rule_id in (STAR_ACCESS_POLICY, STAR_ACCESS_VERB)}
    for run in json.loads(proc.stdout)["runs"]:
        for result in run.get("results") or []:
            if result.get("ruleId") not in found:
                continue
            for location in result.get("locations") or []:
                for logical in location.get("logicalLocations") or []:
                    found[result["ruleId"]].append(logical["name"])
    return {rule_id: sorted(names) for rule_id, names in found.items()}


def _expected_findings(fixture_name: str) -> dict:
    """SHAPE_CASES for one fixture, as the sorted lists _custom_findings returns."""
    return {
        rule_id: sorted(names) for rule_id, names in SHAPE_CASES[fixture_name].items()
    }


@pytest.mark.integration
@pytest.mark.scanner
@pytest.mark.parametrize("fixture_name", sorted(SHAPE_CASES))
def test_each_rule_reports_exactly_the_open_resources_of_a_fixture(fixture_name):
    """The principal and action shapes the first fixture does not cover.

    Run with ``--isolate-custom-rule-exceptions``, as ASH runs it. That flag turns a rule
    that raises into one stderr line and no finding, so a rule that raised would look
    like a rule with nothing to report. Two checks keep those apart:

    * stderr must not hold the message of a rule that raised. A principal written as a
      plain String used to make StarResourceAccessPolicyRule call a Hash method on a
      String, and the exception also dropped the rule's verdict on every other resource
      in the template, so the exact-list assertion catches it a second time.
    * a template that reports nothing must exit 0. cfn_nag_scan exits non-zero for a
      template it could not model, and that also renders as zero results.

    The assertion is on the exact list of resources per rule, so a rule that starts
    reporting a scoped principal, a Deny statement or a plain ``es:ESHttpGet``, or that
    reports one resource twice, fails as well.
    """
    proc = _run(
        "--isolate-custom-rule-exceptions",
        "--rule-directory",
        RULE_DIR.as_posix(),
        fixture=FIXTURE.parent / fixture_name,
    )

    for marker in RAISE_MARKERS:
        assert marker not in proc.stderr, proc.stderr
    expected = _expected_findings(fixture_name)
    assert _custom_findings(proc) == expected
    if not any(expected.values()):
        assert proc.returncode == 0, (
            f"nothing is expected on {fixture_name} but cfn_nag_scan exited "
            f"{proc.returncode}; stderr was:\n{proc.stderr}"
        )


@pytest.mark.integration
@pytest.mark.scanner
@pytest.mark.parametrize("fixture_name", sorted(SHAPE_CASES))
def test_each_fixture_gives_the_same_findings_without_exception_isolation(
    fixture_name,
):
    """The same cells with the isolation flag off, so a raise cannot hide behind it.

    Without ``--isolate-custom-rule-exceptions`` a rule that raises ends the process
    before it renders, so the run fails on the empty stdout whatever the exception was.
    Whatever the isolated run reports must be what this run reports, as a list.
    """
    proc = _run(
        "--rule-directory",
        RULE_DIR.as_posix(),
        fixture=FIXTURE.parent / fixture_name,
    )

    for marker in RAISE_MARKERS:
        assert marker not in proc.stderr, proc.stderr
    assert _custom_findings(proc) == _expected_findings(fixture_name)


# The verb rule's stderr line for an action it cannot read, up to the resource and shape.
UNREAD_WARNING = "WARNING: ResourcePolicyStarAccessVerbPolicyRule: unread action in "
UNREAD_SUFFIX = "; the rule cannot read it, so the action was not checked"


@pytest.mark.integration
@pytest.mark.scanner
@pytest.mark.parametrize("isolate", [True, False], ids=["isolated", "not-isolated"])
def test_an_action_the_rule_cannot_read_is_reported_as_unread(isolate):
    """An action the rule has no text for gets one stderr line, naming the resource and shape.

    cfn-model 0.6.6 passes ``Fn::ImportValue`` on unresolved, and a ``Ref`` to a parameter
    stays a Hash because ASH passes no parameter values. The rule reads the Default of a
    parameter itself, and its AllowedValues when it lists them. These have no text the
    template knows, so the rule cannot check them and says so, rather than passing them
    with no trace:

    * an import, and a ``Ref`` to a parameter with no Default;
    * a ``Ref`` to a parameter of an SSM type (``RefSsmAction``): its Default is the
      name of an SSM parameter, so reading it as the action would find nothing and say
      nothing;
    * a ``Ref`` to a parameter whose Default is empty or holds only commas
      (``RefEmptyDefault``, one line for each of its two parameters): splitting it at
      commas leaves no entry, and a rule that checked "each entry" would check none.

    The tests above show the other entries of the same action list still being read
    (``ListIntrinsicThenBareStar`` is reported although its first entry is an import).

    A resource with a readable action gets no line: ``SubAction`` and ``IfAction`` arrive
    as text, ``RefDefaultScoped`` names a parameter whose Default is read, and
    ``RefAllowedStar`` and ``RefAllowedScoped`` name parameters whose AllowedValues are.
    """
    proc = _run(
        *(["--isolate-custom-rule-exceptions"] if isolate else []),
        "--rule-directory",
        RULE_DIR.as_posix(),
        fixture=FIXTURE.parent / "opensearch_policy_intrinsic_action.yaml",
    )

    for marker in RAISE_MARKERS:
        assert marker not in proc.stderr, proc.stderr
    lines = [
        line[len(UNREAD_WARNING) :]
        for line in proc.stderr.splitlines()
        if line.startswith(UNREAD_WARNING)
    ]
    assert sorted(lines) == sorted(
        [
            f"ImportValueAction (Fn::ImportValue){UNREAD_SUFFIX}",
            f"ListIntrinsicThenBareStar (Fn::ImportValue){UNREAD_SUFFIX}",
            f"RefNoDefaultAction (Ref NoDefaultAction){UNREAD_SUFFIX}",
            f"RefSsmAction (Ref SsmAction, a parameter Default that is an SSM key){UNREAD_SUFFIX}",
            f"RefEmptyDefault (Ref EmptyAction, an empty Default){UNREAD_SUFFIX}",
            f"RefEmptyDefault (Ref CommaOnlyAction, an empty Default){UNREAD_SUFFIX}",
        ]
    ), proc.stderr


def _warning_lines(proc: subprocess.CompletedProcess, prefix: str) -> list:
    """What follows *prefix* on each stderr line that starts with it, sorted."""
    return sorted(
        line[len(prefix) :]
        for line in proc.stderr.splitlines()
        if line.startswith(prefix)
    )


@pytest.mark.integration
@pytest.mark.scanner
@pytest.mark.parametrize("isolate", [True, False], ids=["isolated", "not-isolated"])
def test_a_substituted_action_the_rule_cannot_read_is_reported_as_unread(isolate):
    """An Fn::Sub that names a parameter is read through the parameter, or reported.

    ASH passes no parameter values, so cfn-model leaves ``${Name}`` in the text of the
    action. The rule fills each ``${Name}`` that is a parameter with text from the
    parameter's Default and AllowedValues. When a name is not such a parameter the rule
    cannot tell what the action is, so it says so on stderr, once per resource:

    * a pseudo parameter (``SubPseudoParameter``);
    * a parameter with no Default (``SubNoText``);
    * a name only a long-form substitution map defines (``SubLongForm``).

    The resources that are read get no line: ``SubVerbStar`` and its siblings are
    reported as findings, ``SubParameterScoped`` names a parameter whose Default is
    scoped, and ``SubNoHole`` has nothing to substitute.
    """
    proc = _run(
        *(["--isolate-custom-rule-exceptions"] if isolate else []),
        "--rule-directory",
        RULE_DIR.as_posix(),
        fixture=FIXTURE.parent / "opensearch_policy_sub_action.yaml",
    )

    for marker in RAISE_MARKERS:
        assert marker not in proc.stderr, proc.stderr
    assert _warning_lines(proc, UNREAD_WARNING) == sorted(
        [
            f"SubPseudoParameter (Fn::Sub, ${{AWS::Region}} has no text to read){UNREAD_SUFFIX}",
            f"SubNoText (Fn::Sub, ${{NoDefaultVerb}} has no text to read){UNREAD_SUFFIX}",
            f"SubLongForm (Fn::Sub, ${{Verb}} has no text to read){UNREAD_SUFFIX}",
        ]
    ), proc.stderr


# The principal rule's stderr line for a principal it cannot read, up to the resource and shape.
PRINCIPAL_UNREAD_WARNING = "WARNING: StarResourceAccessPolicyRule: unread principal in "
PRINCIPAL_UNREAD_SUFFIX = "; the rule cannot read it, so the principal was not checked"


@pytest.mark.integration
@pytest.mark.scanner
@pytest.mark.parametrize("isolate", [True, False], ids=["isolated", "not-isolated"])
def test_a_principal_the_rule_cannot_read_is_reported_as_unread(isolate):
    """A principal the rule has no text for gets one stderr line, naming the resource and shape.

    The rule reads a Ref to a parameter through the parameter, as the verb rule does for an
    action, and fills the names of an Fn::Sub that are parameters. It cannot read:

    * an import (``PrincipalImportValue``);
    * a Ref to a parameter with no Default (``PrincipalRefNoDefault``) or whose Default is
      an SSM key (``PrincipalRefSsm``);
    * an Fn::Sub with a name that is not a parameter with text, when the text around the
      names could make the whole principal ``*`` (``PrincipalSubUnreadStar``).

    It writes nothing for an Fn::GetAtt (``PrincipalGetAtt``), which names something the
    template creates, for an Fn::Sub that holds an account id in an ARN
    (``PrincipalSubAccount``), or for a principal it reads.
    """
    proc = _run(
        *(["--isolate-custom-rule-exceptions"] if isolate else []),
        "--rule-directory",
        RULE_DIR.as_posix(),
        fixture=FIXTURE.parent / "opensearch_policy_principal_parameters.yaml",
    )

    for marker in RAISE_MARKERS:
        assert marker not in proc.stderr, proc.stderr
    assert _warning_lines(proc, PRINCIPAL_UNREAD_WARNING) == sorted(
        [
            f"PrincipalImportValue (Fn::ImportValue){PRINCIPAL_UNREAD_SUFFIX}",
            f"PrincipalRefNoDefault (Ref NoDefaultPrincipal){PRINCIPAL_UNREAD_SUFFIX}",
            (
                "PrincipalRefSsm (Ref SsmPrincipal, a parameter Default that is an SSM "
                f"key){PRINCIPAL_UNREAD_SUFFIX}"
            ),
            (
                "PrincipalSubUnreadStar (Fn::Sub, ${NoDefaultPrincipal} has no text to "
                f"read){PRINCIPAL_UNREAD_SUFFIX}"
            ),
        ]
    ), proc.stderr
    # No other rule or shape writes a warning on this template.
    assert all(
        line.startswith(PRINCIPAL_UNREAD_WARNING)
        for line in proc.stderr.splitlines()
        if line.startswith("WARNING: ")
    ), proc.stderr


# What each rule writes for a statement whose Fn::If branches multiply past what it reads.
LIMIT_WARNING = (
    "WARNING: {rule}: a statement of {resource} has more than 32 combinations of "
    "Fn::If branches; the rule read only the first branch of each Fn::If in it"
)


@pytest.mark.integration
@pytest.mark.scanner
@pytest.mark.parametrize("isolate", [True, False], ids=["isolated", "not-isolated"])
def test_a_statement_with_too_many_fn_if_branches_is_reported_as_partly_read(isolate):
    """A rule reads every combination of Fn::If branches in a statement, up to 32.

    ``IfTooManyBranches`` has two effects, two actions and sixteen principals, which is 64
    combinations, so each rule reads it the way cfn-model parses it (the first branch of
    each Fn::If) and writes one line saying so. Those are the only warning lines on the
    template: the other resources are read in full, ``IfActionNoValue`` included, whose
    second branch is an absent value and not an action that cannot be read.
    """
    proc = _run(
        *(["--isolate-custom-rule-exceptions"] if isolate else []),
        "--rule-directory",
        RULE_DIR.as_posix(),
        fixture=FIXTURE.parent / "opensearch_policy_if_forms.yaml",
    )

    for marker in RAISE_MARKERS:
        assert marker not in proc.stderr, proc.stderr
    assert _warning_lines(proc, "WARNING: ") == sorted(
        line[len("WARNING: ") :]
        for line in (
            LIMIT_WARNING.format(rule=rule, resource="IfTooManyBranches")
            for rule in (
                "ResourcePolicyStarAccessVerbPolicyRule",
                "StarResourceAccessPolicyRule",
            )
        )
    ), proc.stderr
