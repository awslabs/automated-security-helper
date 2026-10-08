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


def _guard_meta(rules: list[str], reasons: dict[str, str] | None) -> dict:
    guard: dict = {"SuppressedRules": rules}
    if reasons is not None:
        guard["SuppressedRuleReasons"] = reasons
    return {"Resources": {"R": {"Type": "x", "Metadata": {"guard": guard}}}}


def test_a_reasoned_registry_suppression_is_accepted(gate: ModuleType) -> None:
    # The shape main's per-resource cfn-guard suppressions take (#761).
    rule = "LAMBDA_INSIDE_VPC"
    assert gate.find_suppressions(_guard_meta([rule], {rule: "why"})) == []


@pytest.mark.parametrize(
    ("rules", "reasons"),
    [
        # A rule this gate itself enforces is never suppressible.
        (["S3_BUCKET_ENCRYPTED"], {"S3_BUCKET_ENCRYPTED": "why"}),
        # A registry rule nobody approved.
        (["SOME_OTHER_REGISTRY_RULE"], {"SOME_OTHER_REGISTRY_RULE": "why"}),
        # An approved rule with no reason, an empty reason, or no reasons map.
        (["LAMBDA_INSIDE_VPC"], {}),
        (["LAMBDA_INSIDE_VPC"], {"LAMBDA_INSIDE_VPC": "  "}),
        (["LAMBDA_INSIDE_VPC"], None),
        # One unapproved rule riding along with an approved one.
        (
            ["LAMBDA_INSIDE_VPC", "S3_BUCKET_ENCRYPTED"],
            {"LAMBDA_INSIDE_VPC": "why", "S3_BUCKET_ENCRYPTED": "why"},
        ),
        # An empty list asks for nothing and is still not the accepted shape.
        ([], {}),
    ],
)
def test_any_other_guard_suppression_fails(
    gate: ModuleType, rules: list[str], reasons: dict[str, str] | None
) -> None:
    assert gate.find_suppressions(_guard_meta(rules, reasons)) == [
        "R Metadata.guard.SuppressedRules"
    ]


def test_no_accepted_registry_rule_shares_a_name_with_a_gate_rule(
    gate: ModuleType,
) -> None:
    shipped = set(gate.rule_names(gate.RULES_FILE))
    assert shipped, "no rules parsed from the shipped rules file"
    assert set(gate.ACCEPTED_REGISTRY_SUPPRESSIONS).isdisjoint(shipped)


def test_the_committed_templates_do_carry_registry_suppressions(
    gate: ModuleType,
) -> None:
    # Non-vacuity for test_committed_templates_carry_no_suppression: the templates
    # do hold guard metadata, so that test passing means each entry was accepted,
    # not that there was nothing to look at.
    carrying = [
        logical_id
        for path in gate.committed_templates(gate.TEMPLATE_DIR)
        for logical_id, resource in json.loads(path.read_text(encoding="utf-8"))[
            "Resources"
        ].items()
        if "guard" in (resource.get("Metadata") or {})
    ]
    assert carrying


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


def test_committed_templates_carry_no_suppression(gate: ModuleType) -> None:
    for path in gate.committed_templates(gate.TEMPLATE_DIR):
        assert (
            gate.find_suppressions(json.loads(path.read_text(encoding="utf-8"))) == []
        ), path.name
