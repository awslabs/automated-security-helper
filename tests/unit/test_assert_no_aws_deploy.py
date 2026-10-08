"""Unit tests for .github/scripts/assert-no-aws-deploy.py."""

from __future__ import annotations

import importlib.util
import json
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


def test_the_real_repository_is_followed_into_its_scripts(guard: ModuleType) -> None:
    # A follower that followed nothing would also report no hits. These are scripts
    # the workflows run today, reached by `./x.sh` after a `cd`, by `bash x.sh`, by
    # `${{ github.action_path }}/x.py`, and by `npm run` through package.json.
    follower, scanned = guard.scan_repo_detailed(REPO)
    assert scanned > 0
    assert follower.hits == []
    for expected in (
        "deploy/cdk/scripts/synth-templates.sh",
        "packaging/build-test-wheels.sh",
        ".github/actions/run-scan-test/count_scanner_errors.py",
        "deploy/cdk-constructs/package.json#scripts.check:buildspec",
    ):
        assert expected in follower.followed


def _write(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


WORKFLOW = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"


def test_a_workflow_calling_a_deploying_script_fails_main(
    guard: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + "      - run: bash scripts/release.sh\n",
            "scripts/release.sh": "#!/bin/sh\necho ok\n",
        },
    )
    assert guard.main(["--root", str(tmp_path)]) == 0
    capsys.readouterr()
    (tmp_path / "scripts/release.sh").write_text(
        "#!/bin/sh\necho ok\nnpx cdk deploy --all\n", encoding="utf-8"
    )
    assert guard.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "file=scripts/release.sh,line=3::" in out
    assert "reached from .github/workflows/w.yml:6" in out


def test_npm_run_deploy_maps_through_package_json(
    guard: ModuleType, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + "      - working-directory: deploy/app\n        run: npm run deploy\n",
            "deploy/app/package.json": json.dumps(
                {"scripts": {"deploy": "cdk deploy"}}
            ),
        },
    )
    hits, _ = guard.scan_repo(tmp_path)
    assert [(h.path, h.reason) for h in hits] == [
        ("deploy/app/package.json#scripts.deploy", "`cdk ... deploy`")
    ]


def test_npm_pre_and_post_hooks_are_followed(guard: ModuleType, tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + "      - run: npm run build\n",
            "package.json": json.dumps(
                {
                    "scripts": {
                        "build": "tsc",
                        "postbuild": "terraform apply -auto-approve",
                    }
                }
            ),
        },
    )
    hits, _ = guard.scan_repo(tmp_path)
    assert [h.path for h in hits] == ["package.json#scripts.postbuild"]


def test_a_script_outside_the_repository_is_not_followed(
    guard: ModuleType, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.sh"
    outside.write_text("cdk deploy\n", encoding="utf-8")
    repo = tmp_path / "repo"
    _write(
        repo,
        {".github/workflows/w.yml": WORKFLOW + "      - run: bash ../outside.sh\n"},
    )
    follower, _ = guard.scan_repo_detailed(repo)
    assert follower.hits == [] and follower.followed == []


def test_each_file_is_followed_once_even_in_a_cycle(
    guard: ModuleType, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + "      - run: bash scripts/a.sh\n",
            "scripts/a.sh": "bash scripts/b.sh\n",
            "scripts/b.sh": "bash scripts/a.sh\n",
        },
    )
    follower, _ = guard.scan_repo_detailed(tmp_path)
    assert follower.followed == ["scripts/a.sh", "scripts/b.sh"]


@pytest.mark.parametrize(
    "source",
    [
        'import subprocess\nsubprocess.run(["npx", "cdk", "deploy"], check=True)\n',
        'import subprocess, sys\nsubprocess.check_call([sys.executable, "-m", "x"]); subprocess.call(("terraform", "apply"))\n',
        'import os\nos.system("cd deploy/cdk && npx cdk destroy --force")\n',
    ],
)
def test_python_commands_find_what_a_script_runs(
    guard: ModuleType, source: str
) -> None:
    commands = guard.python_commands(source)
    assert any(guard.deploy_reason(c.text) for c in commands)


def test_python_prose_and_data_are_not_commands(guard: ModuleType) -> None:
    source = (
        '"""Never run `cdk deploy` here."""\n'
        'PLANTS = ("run: cdk deploy", "run: terraform apply")\n'
        'VERBS = frozenset({"deploy", "destroy"})\n'
        'raise SystemExit("cdk deploy is forbidden")\n'
    )
    assert not any(guard.deploy_reason(c.text) for c in guard.python_commands(source))


def test_a_follower_that_follows_nothing_fails_the_self_test(
    guard: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(guard.Follower, "follow_file", lambda self, path, via: None)
    assert guard.self_test() == 1


def test_an_npm_mapper_that_maps_nothing_fails_the_self_test(
    guard: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(guard.Follower, "npm_scripts", lambda self, tokens: None)
    assert guard.self_test() == 1


@pytest.mark.parametrize(
    ("tokens", "names"),
    [
        (["npm", "run", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (
            ["npm", "--prefix", "deploy/cdk", "run", "synth"],
            ["presynth", "synth", "postsynth"],
        ),
        (
            ["npm", "--prefix", "$EXPR", "test", "--", "--ci"],
            ["pretest", "test", "posttest"],
        ),
        (["npm", "ci"], ["preinstall", "install", "postinstall", "prepare"]),
        (["npm", "install", "aws-cdk-lib@2.150.0"], []),
        (["npm", "run", "$script"], ["$script"]),
        (["yarn", "deploy"], ["deploy"]),
        (["npx", "cdk", "synth"], None),
    ],
)
def test_npm_scripts(
    guard: ModuleType, tmp_path: Path, tokens: list[str], names: list[str] | None
) -> None:
    assert guard.Follower(tmp_path).npm_scripts(tokens) == names


def test_a_package_script_hit_annotates_the_manifest_file(
    guard: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + "      - run: npm run ship\n",
            "package.json": json.dumps({"scripts": {"ship": "npx cdk deploy"}}),
        },
    )
    assert guard.main(["--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "::error file=package.json,line=1::package.json#scripts.ship: " in out
