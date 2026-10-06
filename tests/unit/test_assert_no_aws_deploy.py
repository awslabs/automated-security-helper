"""Unit tests for .github/scripts/assert-no-aws-deploy.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / ".github" / "scripts" / "assert-no-aws-deploy.py"


@pytest.fixture(scope="module")
def guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location("assert_no_aws_deploy", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_self_test_passes(guard: ModuleType) -> None:
    assert guard.self_test() == 0


def test_repository_has_no_deploy_command(guard: ModuleType) -> None:
    hits, scanned = guard.scan_repo(REPO)
    assert scanned > 0
    assert hits == []


def test_planted_deploy_in_a_workflow_fails_main(
    guard: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ok.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - run: npx cdk synth\n", encoding="utf-8"
    )
    assert guard.main(["--root", str(tmp_path)]) == 0
    (workflows / "bad.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - run: |\n          cd deploy/cdk\n          npx cdk deploy --all\n",
        encoding="utf-8",
    )
    assert guard.main(["--root", str(tmp_path)]) == 1
    assert "bad.yml,line=6" in capsys.readouterr().out


def test_planted_deploy_in_a_composite_action_is_found(
    guard: ModuleType, tmp_path: Path
) -> None:
    action = tmp_path / ".github" / "actions" / "x"
    action.mkdir(parents=True)
    (action / "action.yaml").write_text(
        "runs:\n  steps:\n    - run: terraform apply -auto-approve\n", encoding="utf-8"
    )
    hits, scanned = guard.scan_repo(tmp_path)
    assert scanned == 1 and len(hits) == 1


def test_no_files_is_a_failure_not_a_pass(guard: ModuleType, tmp_path: Path) -> None:
    assert guard.main(["--root", str(tmp_path)]) == 1


def test_a_broken_detector_fails_its_self_test(
    guard: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(guard, "deploy_reason", lambda command: None)
    assert guard.self_test() == 1


def test_separators_split_commands(guard: ModuleType) -> None:
    # `deploy` after the separator belongs to a different command than `cdk`.
    assert guard.scan_text("x.yml", "run: npx cdk synth && echo deploy") == []
    assert guard.scan_text("x.yml", "run: echo ok; npx cdk deploy") != []


@pytest.mark.parametrize(
    ("token", "tool"),
    [
        ("cdk", "cdk"),
        ("aws-cdk", "cdk"),
        ("aws-cdk@2.150.0", "cdk"),
        ("cdk@latest", "cdk"),
        ("./node_modules/.bin/cdk", "cdk"),
        ("/usr/local/bin/terraform", "terraform"),
        ("tofu", "terraform"),
        ("aws-cdk-lib@2.150.0", "aws-cdk-lib"),
        ("deploy/cdk-constructs", "cdk-constructs"),
    ],
)
def test_normalize_tool(guard: ModuleType, token: str, tool: str) -> None:
    assert guard.normalize_tool(token) == tool


def test_a_background_job_ends_a_command(guard: ModuleType) -> None:
    assert guard.scan_text("x.yml", "run: cdk deploy&") != []
    assert guard.scan_text("x.yml", "run: npx cdk synth & echo deploy") == []


@pytest.mark.parametrize(
    "line",
    [
        "run: cdk 2>&1 deploy",
        "run: terraform 2>&1 apply -auto-approve",
        "run: cdk >&2 deploy",
        "run: cdk &>out.log deploy",
        # A redirection glued to the verb is not part of the verb.
        "run: cdk deploy&>log",
        "run: cdk deploy&>>log",
        "run: terraform apply&>/dev/null",
        "run: cdk deploy>log",
        "run: cdk deploy>&2",
        "run: cdk deploy<&3",
    ],
)
def test_a_redirection_does_not_end_a_command(guard: ModuleType, line: str) -> None:
    assert guard.scan_text("x.yml", line) != []
