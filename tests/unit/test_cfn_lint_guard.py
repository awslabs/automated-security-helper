"""Unit tests for deploy/tests/cfn-lint-guard.py that need neither tool installed.

The real tools run in ash-iac-drift.yml's cfn-lint-guard job, self-test first.
These tests cover the logic that decides a verdict from the tools' output, using
small fake executables that print canned output, so each disagreement and
coverage case can be planted exactly:

  * cfn-lint's exit code and its JSON must agree, both ways;
  * cfn-guard's status, exit code and rule lists must agree;
  * a guard rule that matches nothing fails the check unless it is listed as
    expected-unexercised, and a listed rule that starts matching fails too;
  * suppressions in a template fail the check;
  * every guard rule has a mutant, and every mutant really changes its template.
"""

from __future__ import annotations

import importlib.util
import json
import stat
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy" / "tests" / "cfn-lint-guard.py"


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("cfn_lint_guard", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fake_tool(path: Path, stdout: str, rc: int) -> str:
    """An executable that prints `stdout` and exits `rc`, whatever its arguments.

    The behavior is a Python script, so it is the same program on every platform; only
    the launcher differs. On POSIX it is an executable file at `path` that execs this
    interpreter. Windows cannot start a shebang script at all (CreateProcess refuses it
    with WinError 193), so there the launcher is `path` + ".cmd", the shim form npm and
    pip install, which `subprocess.run` with a list starts directly and whose exit
    status is the last command's. Either way the gate's own `run` is what starts it.
    """
    script = path.with_name(f"_fake_{path.name}.py")
    script.write_text(
        f"import sys\nsys.stdout.write({stdout!r})\nsys.exit({rc})\n",
        encoding="utf-8",
    )
    if sys.platform == "win32":
        launcher = path.with_name(f"{path.name}.cmd")
        launcher.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return str(launcher)
    path.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8"
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def guard_report(
    status: str, failed: list[str], passed: list[str], na: list[str]
) -> str:
    return json.dumps(
        {
            "name": "t",
            "metadata": {},
            "status": status,
            "not_compliant": [
                {"Rule": {"name": r, "metadata": {}, "checks": []}} for r in failed
            ],
            "not_applicable": na,
            "compliant": passed,
        }
    )


@pytest.fixture
def scratch(tmp_path: Path) -> Path:
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "AshEksOperator.template.json").write_text(
        json.dumps({"Resources": {"Q": {"Type": "AWS::SQS::Queue"}}}), encoding="utf-8"
    )
    (tmp_path / "rules.guard").write_text(
        "rule ONE when %x !empty { %x.Properties.A == 1 }\nrule EKS_CLUSTER_ENDPOINT_NOT_OPEN { %y !empty }\n",
        encoding="utf-8",
    )
    return tmp_path


# --------------------------------------------------------------------------- #
# The tools' own output must agree with itself
# --------------------------------------------------------------------------- #


def test_cfn_lint_exit_zero_with_matches_is_refused(
    gate: ModuleType, scratch: Path
) -> None:
    lint = fake_tool(scratch / "lint", json.dumps([{"Rule": {"Id": "W3005"}}]), 0)
    with pytest.raises(gate.GateError, match="disagrees"):
        gate.cfn_lint_matches(gate.Tools(lint, "unused"), [scratch / "x.json"])


def test_cfn_lint_nonzero_with_no_matches_is_refused(
    gate: ModuleType, scratch: Path
) -> None:
    lint = fake_tool(scratch / "lint", "[]", 2)
    with pytest.raises(gate.GateError, match="disagrees"):
        gate.cfn_lint_matches(gate.Tools(lint, "unused"), [scratch / "x.json"])


def test_cfn_lint_non_json_is_refused(gate: ModuleType, scratch: Path) -> None:
    lint = fake_tool(scratch / "lint", "Traceback (most recent call last):", 1)
    with pytest.raises(gate.GateError, match="non-JSON"):
        gate.cfn_lint_matches(gate.Tools(lint, "unused"), [scratch / "x.json"])


def test_cfn_lint_warning_is_a_match(gate: ModuleType, scratch: Path) -> None:
    lint = fake_tool(scratch / "lint", json.dumps([{"Rule": {"Id": "W3005"}}]), 4)
    assert [
        m["Rule"]["Id"]
        for m in gate.cfn_lint_matches(gate.Tools(lint, "unused"), [scratch / "x.json"])
    ] == ["W3005"]


def test_missing_tool_is_a_gate_error(gate: ModuleType, scratch: Path) -> None:
    with pytest.raises(gate.GateError, match="cannot run"):
        gate.cfn_lint_matches(
            gate.Tools(str(scratch / "absent"), "unused"), [scratch / "x.json"]
        )


def test_a_tool_the_os_cannot_start_is_a_gate_error(
    gate: ModuleType, scratch: Path
) -> None:
    # A file that exists but cannot be executed: POSIX refuses it with PermissionError
    # (no execute bit), Windows with WinError 193 (not a Win32 program). Both are
    # OSErrors that are not FileNotFoundError, and both must read as "cannot run".
    not_a_program = scratch / "not-a-program"
    not_a_program.write_text("this is not a program\n", encoding="utf-8")
    with pytest.raises(gate.GateError, match="cannot run"):
        gate.cfn_lint_matches(
            gate.Tools(str(not_a_program), "unused"), [scratch / "x.json"]
        )


@pytest.mark.parametrize(
    ("status", "failed", "rc"),
    [("PASS", ["ONE"], 19), ("FAIL", [], 19), ("FAIL", ["ONE"], 0), ("PASS", [], 19)],
    ids=[
        "pass-with-failed-rule",
        "fail-with-no-rule",
        "fail-exit-zero",
        "pass-exit-nonzero",
    ],
)
def test_inconsistent_guard_output_is_refused(
    gate: ModuleType, scratch: Path, status: str, failed: list[str], rc: int
) -> None:
    guard = fake_tool(scratch / "guard", guard_report(status, failed, [], []), rc)
    with pytest.raises(gate.GateError, match="inconsistent"):
        gate.cfn_guard(
            gate.Tools("unused", guard), scratch / "rules.guard", scratch / "t.json"
        )


def test_guard_rule_name_needs_the_measured_shape(gate: ModuleType) -> None:
    assert gate.guard_rule_name({"Rule": {"name": "ONE"}}) == "ONE"
    with pytest.raises(gate.GateError):
        gate.guard_rule_name("ONE")


# --------------------------------------------------------------------------- #
# check(): coverage, suppressions, required templates
# --------------------------------------------------------------------------- #


def run_check(gate: ModuleType, scratch: Path, report: str, rc: int = 0) -> list[str]:
    lint = fake_tool(scratch / "lint", "[]", 0)
    guard = fake_tool(scratch / "guard", report, rc)
    return gate.check(
        gate.Tools(lint, guard), scratch / "templates", scratch / "rules.guard"
    )


def test_check_passes_when_every_rule_is_exercised_or_expected_idle(
    gate: ModuleType, scratch: Path
) -> None:
    assert (
        run_check(
            gate,
            scratch,
            guard_report("PASS", [], ["ONE"], ["EKS_CLUSTER_ENDPOINT_NOT_OPEN"]),
        )
        == []
    )


def test_rule_that_matches_nothing_fails(gate: ModuleType, scratch: Path) -> None:
    problems = run_check(
        gate,
        scratch,
        guard_report("PASS", [], [], ["ONE", "EKS_CLUSTER_ENDPOINT_NOT_OPEN"]),
    )
    assert any("ONE matched no resource" in p for p in problems)


def test_expected_idle_rule_that_starts_matching_fails(
    gate: ModuleType, scratch: Path
) -> None:
    problems = run_check(
        gate,
        scratch,
        guard_report("PASS", [], ["ONE", "EKS_CLUSTER_ENDPOINT_NOT_OPEN"], []),
    )
    assert any("remove it from EXPECTED_UNEXERCISED" in p for p in problems)


def test_failed_rule_fails_the_check(gate: ModuleType, scratch: Path) -> None:
    problems = run_check(
        gate,
        scratch,
        guard_report("FAIL", ["ONE"], [], ["EKS_CLUSTER_ENDPOINT_NOT_OPEN"]),
        rc=19,
    )
    assert problems == ["cfn-guard ONE fails for AshEksOperator.template.json"]


def test_unknown_rule_in_report_is_refused(gate: ModuleType, scratch: Path) -> None:
    with pytest.raises(gate.GateError, match="not in"):
        run_check(
            gate,
            scratch,
            guard_report(
                "PASS", [], ["ONE", "SURPRISE"], ["EKS_CLUSTER_ENDPOINT_NOT_OPEN"]
            ),
        )


def test_cfn_lint_match_fails_the_check(gate: ModuleType, scratch: Path) -> None:
    lint = fake_tool(
        scratch / "lint",
        json.dumps([{"Rule": {"Id": "E3002"}, "Filename": "t.json", "Message": "m"}]),
        2,
    )
    guard = fake_tool(
        scratch / "guard",
        guard_report("PASS", [], ["ONE"], ["EKS_CLUSTER_ENDPOINT_NOT_OPEN"]),
        0,
    )
    problems = gate.check(
        gate.Tools(lint, guard), scratch / "templates", scratch / "rules.guard"
    )
    assert len(problems) == 1 and problems[0].startswith("cfn-lint E3002")


def test_template_suppression_fails_the_check(gate: ModuleType, scratch: Path) -> None:
    (scratch / "templates" / "AshEksOperator.template.json").write_text(
        json.dumps(
            {
                "Resources": {
                    "Q": {
                        "Type": "AWS::SQS::Queue",
                        "Metadata": {
                            "cfn-lint": {"config": {"ignore_checks": ["W3005"]}}
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    problems = run_check(
        gate,
        scratch,
        guard_report("PASS", [], ["ONE"], ["EKS_CLUSTER_ENDPOINT_NOT_OPEN"]),
    )
    assert any("Metadata.cfn-lint suppresses" in p for p in problems)


def test_missing_eks_template_is_refused(gate: ModuleType, scratch: Path) -> None:
    (scratch / "templates" / "AshEksOperator.template.json").rename(
        scratch / "templates" / "Other.template.json"
    )
    with pytest.raises(gate.GateError, match="AshEksOperator"):
        run_check(gate, scratch, guard_report("PASS", [], ["ONE"], []))


def test_empty_template_dir_is_refused(gate: ModuleType, tmp_path: Path) -> None:
    with pytest.raises(gate.GateError, match="nothing would be checked"):
        gate.committed_templates(tmp_path)


def test_suppression_detector_ignores_ordinary_metadata(gate: ModuleType) -> None:
    assert (
        gate.find_suppressions(
            {
                "Resources": {
                    "A": {"Type": "x", "Metadata": {"aws:cdk:path": "p", "guard": {}}}
                }
            }
        )
        == []
    )


@pytest.fixture(scope="module")
def approved(gate: ModuleType) -> list:
    return gate.load_approved(gate.APPROVED_FILE)


def _committed(gate: ModuleType) -> dict:
    return {
        p.name.removesuffix(".template.json"): json.loads(p.read_text(encoding="utf-8"))
        for p in gate.committed_templates(gate.TEMPLATE_DIR)
    }


def _flagged(gate: ModuleType, bodies: dict, approved: list) -> list[str]:
    rules = frozenset(gate.rule_names(gate.RULES_FILE))
    return [
        f"{name}: {where}"
        for name, body in bodies.items()
        for where in gate.find_suppressions(body, name, approved, rules)
    ]


def test_the_approved_list_is_mains_thirteen(approved: list) -> None:
    # #761 approved 13 resources over three registry rules; the jest test pins the
    # same file, so the two gates read one list.
    assert len(approved) == 13
    assert {r for a in approved for r in a.rules} == {
        "LAMBDA_INSIDE_VPC",
        "NO_UNRESTRICTED_ROUTE_TO_IGW",
        "S3_BUCKET_SSL_REQUESTS_ONLY",
    }


def test_the_committed_templates_carry_exactly_the_approved_list(
    gate: ModuleType, approved: list
) -> None:
    bodies = _committed(gate)
    assert _flagged(gate, bodies, approved) == []
    assert gate.stale_approvals(bodies, approved) == []


def test_without_the_list_every_guard_suppression_is_reported(
    gate: ModuleType,
) -> None:
    # Non-vacuity: the committed templates do carry guard metadata, so the test above
    # passing means each entry matched the list.
    assert len(_flagged(gate, _committed(gate), [])) == 13


def test_a_fourteenth_suppression_on_another_resource_fails(
    gate: ModuleType, approved: list
) -> None:
    bodies = _committed(gate)
    first = approved[0]
    approved_keys = {(a.template, a.logical_id) for a in approved}
    victim = next(
        lid
        for lid in bodies[first.template]["Resources"]
        if (first.template, lid) not in approved_keys
    )
    bodies[first.template]["Resources"][victim].setdefault("Metadata", {})["guard"] = {
        "SuppressedRules": list(first.rules),
        "SuppressedRuleReasons": dict(first.reasons),
    }
    assert _flagged(gate, bodies, approved) == [
        f"{first.template}: {victim} Metadata.guard.SuppressedRules"
    ]


def test_the_same_entry_in_another_template_fails(
    gate: ModuleType, approved: list
) -> None:
    bodies = _committed(gate)
    entry = next(a for a in approved if a.template == "AshAgentCore")
    resource = bodies["AshAgentCore"]["Resources"][entry.logical_id]
    bodies["AshEksOperator"]["Resources"][entry.logical_id] = resource
    assert _flagged(gate, bodies, approved) == [
        f"AshEksOperator: {entry.logical_id} Metadata.guard.SuppressedRules"
    ]


@pytest.mark.parametrize(
    "tamper",
    ["reworded", "extra_rule", "gate_rule", "no_reasons", "other_type"],
)
def test_an_approved_resource_changed_in_any_way_fails(
    gate: ModuleType, approved: list, tamper: str
) -> None:
    bodies = _committed(gate)
    first = approved[0]
    resource = bodies[first.template]["Resources"][first.logical_id]
    guard = resource["Metadata"]["guard"]
    rule = first.rules[0]
    if tamper == "reworded":
        guard["SuppressedRuleReasons"][rule] += " (edited)"
    elif tamper == "extra_rule":
        guard["SuppressedRules"].append("INCOMING_SSH_DISABLED")
        guard["SuppressedRuleReasons"]["INCOMING_SSH_DISABLED"] = "why"
    elif tamper == "gate_rule":
        guard["SuppressedRules"].append("S3_BUCKET_ENCRYPTED")
        guard["SuppressedRuleReasons"]["S3_BUCKET_ENCRYPTED"] = "why"
    elif tamper == "no_reasons":
        del guard["SuppressedRuleReasons"]
    else:
        resource["Type"] = "AWS::SQS::Queue"
    assert (
        f"{first.template}: {first.logical_id} Metadata.guard.SuppressedRules"
        in _flagged(gate, bodies, approved)
    )


def test_a_removed_approved_suppression_is_reported_stale(
    gate: ModuleType, approved: list
) -> None:
    bodies = _committed(gate)
    last = approved[-1]
    del bodies[last.template]["Resources"][last.logical_id]["Metadata"]["guard"]
    assert gate.stale_approvals(bodies, approved) == [
        f"{last.template}/{last.logical_id} {list(last.rules)}"
    ]


def test_check_reports_stale_and_unapproved_entries(
    gate: ModuleType, scratch: Path, tmp_path: Path
) -> None:
    # Through check() itself, with an approved list naming a resource the scratch
    # template does not carry, beside an unapproved suppression it does.
    listed = tmp_path / "approved.json"
    listed.write_text(
        json.dumps(
            {
                "approved": [
                    {
                        "template": "AshEksOperator",
                        "logicalId": "Gone",
                        "type": "AWS::Lambda::Function",
                        "rules": ["LAMBDA_INSIDE_VPC"],
                        "reasons": {"LAMBDA_INSIDE_VPC": "why"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (scratch / "templates" / "AshEksOperator.template.json").write_text(
        json.dumps(
            {
                "Resources": {
                    "Q": {
                        "Type": "AWS::SQS::Queue",
                        "Metadata": {
                            "guard": {
                                "SuppressedRules": ["LAMBDA_INSIDE_VPC"],
                                "SuppressedRuleReasons": {"LAMBDA_INSIDE_VPC": "why"},
                            }
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    lint = fake_tool(scratch / "cfn-lint", "[]", 0)
    guard = fake_tool(
        scratch / "cfn-guard",
        guard_report("PASS", [], ["ONE"], ["EKS_CLUSTER_ENDPOINT_NOT_OPEN"]),
        0,
    )
    problems = gate.check(
        gate.Tools(lint, guard),
        scratch / "templates",
        scratch / "rules.guard",
        listed,
    )
    assert any("Q Metadata.guard.SuppressedRules suppresses" in p for p in problems)
    assert any(
        "AshEksOperator/Gone" in p and "no template carries it" in p for p in problems
    )


@pytest.mark.parametrize(
    "entry",
    [
        {"template": "T", "logicalId": "R", "type": "x", "rules": [], "reasons": {}},
        {"template": "T", "logicalId": "R", "type": "x", "rules": ["A"], "reasons": {}},
        {
            "template": "T",
            "logicalId": "R",
            "type": "x",
            "rules": ["A"],
            "reasons": {"A": " "},
        },
        {"template": "T", "logicalId": "R", "rules": ["A"], "reasons": {"A": "why"}},
    ],
)
def test_a_malformed_approved_entry_is_refused(
    gate: ModuleType, tmp_path: Path, entry: dict
) -> None:
    listed = tmp_path / "approved.json"
    listed.write_text(json.dumps({"approved": [entry]}), encoding="utf-8")
    with pytest.raises(gate.GateError):
        gate.load_approved(listed)


# --------------------------------------------------------------------------- #
# The shipped rules, mutants and templates line up
# --------------------------------------------------------------------------- #


def test_every_shipped_rule_has_a_failing_mutant(gate: ModuleType) -> None:
    covered = set().union(*(m.expect_failed for m in gate.guard_mutants()))
    assert set(gate.rule_names(gate.RULES_FILE)) == covered


def test_expected_unexercised_names_real_rules(gate: ModuleType) -> None:
    assert set(gate.EXPECTED_UNEXERCISED) <= set(gate.rule_names(gate.RULES_FILE))


def test_every_mutant_changes_its_committed_template(
    gate: ModuleType, tmp_path: Path
) -> None:
    index = 0
    for _label, source, mutate, _rule in gate.lint_mutants():
        index += 1
        gate.write_mutant(tmp_path, gate.TEMPLATE_DIR, source, mutate, index)
    for mutant in gate.guard_mutants():
        index += 1
        gate.write_mutant(
            tmp_path, gate.TEMPLATE_DIR, mutant.template, mutant.mutate, index
        )
    assert len(list(tmp_path.glob("mutant-*"))) == index


def test_a_mutant_that_changes_nothing_is_refused(
    gate: ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(gate.GateError, match="changed nothing"):
        gate.write_mutant(
            tmp_path,
            gate.TEMPLATE_DIR,
            "AshEksOperator.template.json",
            lambda t: None,
            1,
        )


def test_committed_templates_carry_no_suppression(
    gate: ModuleType, approved: list
) -> None:
    # Nothing beyond the approved guard list: no cfn-lint suppression anywhere and no
    # guard suppression the list does not name.
    rules = frozenset(gate.rule_names(gate.RULES_FILE))
    for path in gate.committed_templates(gate.TEMPLATE_DIR):
        name = path.name.removesuffix(".template.json")
        body = json.loads(path.read_text(encoding="utf-8"))
        assert gate.find_suppressions(body, name, approved, rules) == [], path.name
