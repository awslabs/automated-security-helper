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
    # the workflows run today, reached by `./x.sh` from a `working-directory:` or
    # `cd` base, by `bash x.sh`, by `${{ github.action_path }}/x.py`, and by
    # `npm run` through package.json. The `cd` base alone is tested on planted
    # repositories below, because this one also reaches the script without it.
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
        # An element with whitespace is a command line a shell may run.
        'import subprocess\nsubprocess.run(["bash", "-c", "npx cdk deploy --all"])\n',
        'import subprocess\nsubprocess.run(["sh", "-c", "echo hi && terraform apply"])\n',
        # ...and an argument with a space does not hide the rest of the argv.
        'import subprocess\nsubprocess.run(["npx", "cdk", "deploy", "--context", "a b"])\n',
        # A bare argv list run by `-c` later, through a name.
        'import subprocess\nCMD = ("bash", "-lc", "cdk destroy --force")\nsubprocess.check_call(CMD)\n',
        'import subprocess\nsubprocess.run(args=["terraform", "apply"])\n',
        # A bare argv handed to a helper the scan does not know: `-c` marks the
        # command line.
        'import helpers\nhelpers.go(["bash", "-c", "npx cdk deploy"])\n',
        'import os\nos.execlp("npx", "npx", "cdk", "deploy")\n',
        'import os\nos.execv("/bin/sh", ["sh", "-c", "sam deploy"])\n',
        'import asyncio\nasyncio.create_subprocess_exec("npx", "cdk", "deploy")\n',
        'import asyncio\nasyncio.create_subprocess_shell("npx cdk deploy")\n',
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
        'NOTES = ["cdk", "never run cdk deploy here"]\n'
        'raise SystemExit("cdk deploy is forbidden")\n'
    )
    assert not any(guard.deploy_reason(c.text) for c in guard.python_commands(source))


@pytest.mark.parametrize(
    ("source", "command"),
    [
        ('import subprocess\nsubprocess.run(["scripts/d.sh"])\n', "scripts/d.sh"),
        (
            'import subprocess, sys\nsubprocess.run([sys.executable, "scripts/d.py"])\n',
            "scripts/d.py",
        ),
        (
            'import subprocess\nCMD = ["scripts/d.sh"]\nsubprocess.Popen(CMD)\n',
            "scripts/d.sh",
        ),
    ],
)
def test_a_short_python_argv_is_a_command_to_follow(
    guard: ModuleType, source: str, command: str
) -> None:
    # One string word is too short to tell an argv from data, unless a runner gets it.
    assert command in [c.text for c in guard.python_commands(source)]


def test_a_python_argv_hit_is_reported_once(guard: ModuleType) -> None:
    # The list is an argv both on its own and as a runner's argument.
    source = 'import subprocess\nsubprocess.run(\n    ["npx", "cdk", "deploy"]\n)\n'
    hits = [c for c in guard.python_commands(source) if guard.deploy_reason(c.text)]
    assert len(hits) == 1


def test_a_follower_that_follows_nothing_fails_the_self_test(
    guard: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        guard.Follower, "follow_file", lambda self, path, via, mode=None: None
    )
    assert guard.self_test() == 1


def test_an_npm_mapper_that_maps_nothing_fails_the_self_test(
    guard: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(guard.Follower, "npm_invocations", lambda self, tokens: None)
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
        (
            ["npm", "ci"],
            [
                "preinstall",
                "install",
                "postinstall",
                "prepublish",
                "preprepare",
                "prepare",
                "postprepare",
            ],
        ),
        (["npm", "install", "aws-cdk-lib@2.150.0"], []),
        (["npm", "run", "$script"], ["$script"]),
        (["yarn", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (["npx", "cdk", "synth"], None),
        # A flag's value is not the script name: npm reads these as value options.
        (["npm", "run", "-w", "app", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (
            ["npm", "run", "--workspace", "app", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (
            ["npm", "--workspace", "app", "run", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (
            ["npm", "run", "--prefix", "x", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (["npm", "run", "-C", "x", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (
            ["npm", "run", "--loglevel", "warn", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (
            ["npm", "run", "-L", "project", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (["npm", "run", "-gw", "app", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (["npm", "--reg", "u", "run", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        # ...and a boolean takes none.
        (["npm", "run", "--silent", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (["npm", "run", "-s", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (
            ["npm", "run", "--if-present", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (
            ["npm", "run", "--no-workspaces", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (
            ["npm", "run", "--workspace=app", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        # `--` ends the flags; the script name may follow it.
        (["npm", "run", "--", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (
            ["npm", "run", "build", "--", "--prefix", "x"],
            ["prebuild", "build", "postbuild"],
        ),
        # An abbreviation npm may expand to a value option is read both ways.
        (
            ["npm", "run", "--pref", "app", "deploy"],
            ["predeploy", "deploy", "postdeploy", "preapp", "app", "postapp"],
        ),
        # npm's aliases and lifecycles, from cmd-list.js and scripts.md.
        (["npm", "rum", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (["npm", "urn", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (
            ["npm", "clean-install"],
            [
                "preinstall",
                "install",
                "postinstall",
                "prepublish",
                "preprepare",
                "prepare",
                "postprepare",
            ],
        ),
        (
            ["npm", "i"],
            [
                "preinstall",
                "install",
                "postinstall",
                "prepublish",
                "preprepare",
                "prepare",
                "postprepare",
            ],
        ),
        (["npm", "tst"], ["pretest", "test", "posttest"]),
        (["npm", "pack"], ["prepack", "prepare", "postpack"]),
        (["npm", "add", "left-pad"], []),
        # pnpm's -w is --workspace-root, a boolean; --filter and -F take a value.
        (["pnpm", "-w", "run", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (["pnpm", "-w", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (
            ["pnpm", "--filter", "app", "run", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (["pnpm", "-F", "app", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (["pnpm", "-r", "run", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        # yarn: --cwd takes a value, workspace names a workspace, bare yarn installs.
        (["yarn", "--cwd", "app", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (["yarn", "workspace", "app", "deploy"], ["predeploy", "deploy", "postdeploy"]),
        (
            ["yarn", "workspace", "app", "run", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (
            ["yarn", "workspaces", "run", "deploy"],
            ["predeploy", "deploy", "postdeploy"],
        ),
        (
            ["yarn"],
            [
                "preinstall",
                "install",
                "postinstall",
                "prepublish",
                "preprepare",
                "prepare",
                "postprepare",
            ],
        ),
    ],
)
def test_npm_scripts(
    guard: ModuleType, tmp_path: Path, tokens: list[str], names: list[str] | None
) -> None:
    got = guard.Follower(tmp_path).npm_scripts(tokens)
    assert (sorted(got) if got is not None else None) == (
        sorted(names) if names is not None else None
    )


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


def test_a_planted_npm_workspace_deploy_is_caught(
    guard: ModuleType, tmp_path: Path
) -> None:
    # `-w app` before the script name: read as the script, `app` would be followed
    # instead of `deploy`, and the deploy would pass.
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + "      - run: npm run -w app deploy\n",
            "package.json": json.dumps(
                {"workspaces": ["app"], "scripts": {"app": "echo"}}
            ),
            "app/package.json": json.dumps({"scripts": {"deploy": "cdk deploy"}}),
        },
    )
    hits, _ = guard.scan_repo(tmp_path)
    assert [h.path for h in hits] == ["app/package.json#scripts.deploy"]


@pytest.mark.parametrize(
    "script",
    [
        'import subprocess\nsubprocess.run(["scripts/d.sh"])\n',
        'import subprocess\nCMD = ["scripts/d.sh"]\nsubprocess.run(CMD)\n',
        'import subprocess, sys\nsubprocess.run([sys.executable, "scripts/d.py"])\n',
    ],
)
def test_a_python_argv_naming_a_script_is_followed(
    guard: ModuleType, tmp_path: Path, script: str
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + "      - run: python3 scripts/ship.py\n",
            "scripts/ship.py": script,
            "scripts/d.sh": "#!/bin/sh\nnpx cdk deploy\n",
            "scripts/d.py": 'import os\nos.system("npx cdk deploy")\n',
        },
    )
    hits, _ = guard.scan_repo(tmp_path)
    assert [h.path for h in hits] in (["scripts/d.sh"], ["scripts/d.py"])


# -- shebang following --------------------------------------------------------


def test_an_extensionless_script_with_a_shebang_is_followed(
    guard: ModuleType, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + "      - run: ./scripts/release\n",
            "scripts/release": "#!/usr/bin/env bash\nnpx cdk deploy --all\n",
        },
    )
    follower, _ = guard.scan_repo_detailed(tmp_path)
    assert follower.followed == ["scripts/release"]
    assert [(h.path, h.line) for h in follower.hits] == [("scripts/release", 2)]


def test_an_extensionless_file_without_a_shebang_is_not_followed(
    guard: ModuleType, tmp_path: Path
) -> None:
    # A README-like text file the workflow only reads must not be scanned as a
    # script: it names the command in prose.
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + "      - run: cat ./scripts/notes\n",
            "scripts/notes": "Ship by hand with: npx cdk deploy --all\n",
        },
    )
    follower, _ = guard.scan_repo_detailed(tmp_path)
    assert follower.followed == [] and follower.hits == []


def test_a_bare_extensionless_word_is_not_followed_even_with_a_shebang(
    guard: ModuleType, tmp_path: Path
) -> None:
    # `release` with no `/` is a command looked up on PATH, not this file.
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + "      - run: release\n",
            "release": "#!/bin/sh\nnpx cdk deploy\n",
        },
    )
    follower, _ = guard.scan_repo_detailed(tmp_path)
    assert follower.followed == []


# -- cd base directories ------------------------------------------------------


@pytest.mark.parametrize("verb", ["cd", "pushd"])
def test_a_script_named_relative_to_a_cd_target_is_followed(
    guard: ModuleType, tmp_path: Path, verb: str
) -> None:
    # `./ship.sh` resolves against neither the root nor the workflow's directory;
    # only the `cd` target makes it a file.
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + f"      - run: {verb} tools && ./ship.sh\n",
            "tools/ship.sh": "#!/bin/sh\nterraform apply -auto-approve\n",
        },
    )
    follower, _ = guard.scan_repo_detailed(tmp_path)
    assert follower.followed == ["tools/ship.sh"]
    assert [h.path for h in follower.hits] == ["tools/ship.sh"]


def test_a_cd_inside_a_script_is_a_base_for_that_script(
    guard: ModuleType, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + "      - run: bash scripts/a.sh\n",
            "scripts/a.sh": "#!/bin/sh\ncd ../tools\n./ship.sh\n",
            "tools/ship.sh": "#!/bin/sh\nsam deploy\n",
        },
    )
    follower, _ = guard.scan_repo_detailed(tmp_path)
    assert [h.path for h in follower.hits] == ["tools/ship.sh"]


def test_a_cd_target_does_not_reach_a_same_named_script_elsewhere(
    guard: ModuleType, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + "      - run: cd tools && ./ship.sh\n",
            "tools/ship.sh": "#!/bin/sh\nnpx cdk synth\n",
            "elsewhere/ship.sh": "#!/bin/sh\nnpx cdk deploy\n",
        },
    )
    follower, _ = guard.scan_repo_detailed(tmp_path)
    assert follower.followed == ["tools/ship.sh"] and follower.hits == []


# -- other followed shapes ----------------------------------------------------


def test_node_modules_package_scripts_are_not_followed(
    guard: ModuleType, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + "      - run: npm run deploy\n",
            "package.json": json.dumps({"scripts": {"deploy": "tsc"}}),
            "node_modules/dep/package.json": json.dumps(
                {"scripts": {"deploy": "cdk deploy"}}
            ),
        },
    )
    follower, _ = guard.scan_repo_detailed(tmp_path)
    assert follower.followed == ["package.json#scripts.deploy"] and follower.hits == []


def test_javascript_comments_are_not_commands(guard: ModuleType) -> None:
    text = (
        "// npx cdk deploy\n/*\n * terraform apply\n */\nexecSync('npx cdk synth');\n"
    )
    commands = guard.shell_commands(text, js=True)
    assert not any(guard.deploy_reason(c.text) for c in commands)
    assert any("synth" in c.text for c in commands)


def test_a_multi_line_javascript_argv_is_one_command(guard: ModuleType) -> None:
    text = (
        "const x = 1;\nspawnSync('npx', [\n  'cdk',\n  'deploy',\n]);\nconst y = [1];\n"
    )
    commands = guard.shell_commands(text, js=True)
    hits = [c for c in commands if guard.deploy_reason(c.text)]
    assert [c.line for c in hits] == [2]
    # Lines after the joined array keep their numbers.
    assert any(c.line == 6 and "y" in c.text for c in commands)


def test_an_unclosed_javascript_bracket_joins_and_is_reported(
    guard: ModuleType,
) -> None:
    # Joining only adds words to a command, so an unmatched `[` joins the rest of
    # the file and can only add a hit; the file is also reported as misread.
    text = "const re = [\nconst cdk = 1\n" + "x()\n" * 60 + "deploy()\n"
    commands = guard.shell_commands(text, js=True)
    assert any(guard.deploy_reason(c.text) for c in commands)
    assert guard.js_misread(text)
    assert not guard.js_misread("const a = [\n 1,\n];\nconst q = /[\"']/;\n")


def test_typescript_and_python_modules_are_followed(
    guard: ModuleType, tmp_path: Path
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + "      - run: npx tsx scripts/a.ts && python -m tools.b && python -m tools.c\n",
            "scripts/a.ts": "execSync('npx cdk deploy');\n",
            "tools/b.py": 'import os\nos.system("terraform apply")\n',
            "tools/c/__main__.py": 'import os\nos.system("sam deploy")\n',
        },
    )
    hits, _ = guard.scan_repo(tmp_path)
    assert sorted(h.path for h in hits) == [
        "scripts/a.ts",
        "tools/b.py",
        "tools/c/__main__.py",
    ]


def test_an_echoed_npm_command_is_not_noted_as_unfollowed(
    guard: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + '      - run: echo "regenerate with npm run $script"\n'
        },
    )
    assert guard.main(["--root", str(tmp_path)]) == 0
    assert "named by a variable" not in capsys.readouterr().out
    _write(
        tmp_path,
        {".github/workflows/w.yml": WORKFLOW + '      - run: npm run "$script"\n'},
    )
    assert guard.main(["--root", str(tmp_path)]) == 0
    assert "w.yml:6 runs an npm script named by a variable" in capsys.readouterr().out


# -- round 2: complete flag readings, pass-through words, Python runner inputs --


def test_flag_readings_are_complete_for_many_ambiguous_flags(guard: ModuleType) -> None:
    # Each unknown pnpm flag may or may not take the word after it; with 12 of them
    # there are 4096 ways to read the words, and the one with every flag a boolean
    # (so `ship` is the subcommand after twelve positional values) must be among them.
    words = [w for i in range(12) for w in (f"--u{i}", f"v{i}")] + ["ship"]
    readings = guard.flag_readings(words, guard.PNPM_SYNTAX)
    assert ("ship",) in [r.words for r in readings]
    assert any(r.words[:1] == ("v0",) for r in readings)


def test_too_many_flag_readings_fail_closed(
    guard: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(guard, "MAX_FLAG_STATES", 3)
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + "      - run: pnpm --a x --b y --c z ship\n",
            "package.json": json.dumps({"scripts": {"ship": "tsc"}}),
        },
    )
    assert guard.main(["--root", str(tmp_path)]) == 1
    assert guard.UNREADABLE in capsys.readouterr().out


def test_a_subcommand_chain_past_the_reading_depth_fails_closed(
    guard: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    chain = " ".join(f"workspace w{i}" for i in range(5))
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + f"      - run: yarn {chain} ship\n",
            "package.json": json.dumps({"scripts": {"ship": "tsc"}}),
        },
    )
    assert guard.main(["--root", str(tmp_path)]) == 1
    assert guard.UNREADABLE in capsys.readouterr().out


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (["npm", "run", "tool", "--", "deploy", "--all"], ("tool", "-- deploy --all")),
        (["npm", "run", "-w", "app", "tool", "deploy"], ("tool", "deploy")),
        (["yarn", "tool", "deploy"], ("tool", "deploy")),
        (["yarn", "workspace", "app", "tool", "deploy"], ("tool", "deploy")),
        (["pnpm", "--filter", "app", "run", "tool", "deploy"], ("tool", "deploy")),
        (["npm", "test", "--", "--ci"], ("test", "-- --ci")),
        (["npm", "ci"], ("install", "")),
    ],
)
def test_npm_invocations_carry_the_pass_through_words(
    guard: ModuleType, tmp_path: Path, tokens: list[str], expected: tuple[str, str]
) -> None:
    assert expected in guard.Follower(tmp_path).npm_invocations(tokens)


@pytest.mark.parametrize(
    "source",
    [
        'import os\nCMD = "npx cdk deploy --all"\nos.system(CMD)\n',
        'import os\nCMD: str = "npx cdk deploy --all"\nos.popen(CMD)\n',
        'import subprocess, shlex\nsubprocess.run(shlex.split("npx cdk deploy --all"))\n',
        'import subprocess\nsubprocess.run("npx cdk deploy --all".split())\n',
        'import subprocess\nsubprocess.run(["npx", "cdk"] + ["deploy"])\n',
        'import subprocess\nCMD = shlex.split("terraform apply")\nsubprocess.run(CMD)\n',
        'import os\nx = 1\nos.system(f"npx cdk --profile {x} deploy")\n',
        'from subprocess import check_call as cc\ncc(["terraform", "apply"])\n',
        'from os import system as sh\nsh("sam deploy")\n',
        'import subprocess\nsubprocess.run(["ssh", "host", "npx cdk deploy"])\n',
    ],
)
def test_python_runner_inputs_in_every_shape(guard: ModuleType, source: str) -> None:
    assert any(guard.deploy_reason(c.text) for c in guard.python_commands(source))


@pytest.mark.parametrize(
    "source",
    [
        'import subprocess\nA = B = ["scripts/d.sh"]\nsubprocess.run(A)\n',
        'import subprocess\nA: list[str] = ["scripts/d.sh"]\nsubprocess.run(A)\n',
    ],
)
def test_python_bound_argv_shapes_name_the_script(
    guard: ModuleType, source: str
) -> None:
    assert "scripts/d.sh" in [c.text for c in guard.python_commands(source)]


def test_javascript_comment_stripping_keeps_code_after_a_comment(
    guard: ModuleType,
) -> None:
    text = "/* x */ execSync('npx cdk deploy');\nconst u = 'http://a'; // cdk deploy\n"
    stripped = guard.strip_js_comments(text)
    assert "execSync('npx cdk deploy')" in stripped
    assert "http://a" in stripped and "// cdk" not in stripped
    assert stripped.count("\n") == text.count("\n")


def test_a_regex_literal_does_not_open_a_string(guard: ModuleType) -> None:
    text = "const q = /^(['\"])(.*)\\1$/;\nspawnSync('npx', [\n  'cdk',\n  'deploy',\n]);\n"
    assert not guard.js_misread(text)
    assert any(guard.deploy_reason(c.text) for c in guard.shell_commands(text, js=True))
    # Division is not a regex.
    assert not guard.js_misread("const a = b / c / d;\n")


def test_matrix_items_are_runnable_and_paths_items_are_not(guard: ModuleType) -> None:
    text = (
        "on:\n  push:\n    paths:\n      - a.sh\njobs:\n  j:\n    strategy:\n"
        "      matrix:\n        s:\n          - b.sh\n    steps:\n      - run: x\n"
    )
    assert guard.matrix_item_lines(text) == {10}


@pytest.mark.parametrize(
    ("tool", "words"),
    [
        # A boolean before a word that is not a flag: read as a value, the word
        # would vanish.
        ("pnpm", ["--silent", "a", "--no-bail", "b", "--stream", "c", "-w", "ship"]),
        ("yarn", ["--silent", "a", "--frozen-lockfile", "b", "-s", "ship"]),
        ("npm", ["--silent", "--if-present", "-s", "run", "ship"]),
    ],
)
def test_known_boolean_flags_are_read_one_way(
    guard: ModuleType, tool: str, words: list[str]
) -> None:
    readings = guard.flag_readings(words, guard.NPM_FLAG_SYNTAX[tool])
    assert [r.words for r in readings] == [
        tuple(w for w in words if not w.startswith("-"))
    ]


# -- round 3: the JavaScript walker, Python string building and wrappers,
# more script runners, and bounds that fail closed ---------------------------


@pytest.mark.parametrize(
    "text",
    [
        'const s = `${"`"}${"//"}`; execSync("npx cdk deploy --all");\n',
        "if (1) /'/.test('x'); const u = '//'; execSync('npx cdk deploy');\n",
        "const s = `${'a'.replace(/`/g, '')}//`; execSync('npx cdk deploy');\n",
        "const s = 'a\\\n// '; execSync('npx cdk deploy');\n",
        "const t = `a${`b`}//`; execSync('npx cdk deploy');\n",
    ],
)
def test_the_javascript_walker_does_not_blank_real_code(
    guard: ModuleType, text: str
) -> None:
    commands = guard.shell_commands(text, js=True)
    assert any(guard.deploy_reason(c.text) for c in commands)


@pytest.mark.parametrize(
    "text",
    [
        "const a = `${[1, 2].map((v) => `(${v}`)}`;\n",
        "if (s) /\\(/.test(s);\n",
        "while (x) /[)]/.exec(y);\n",
        "const q = `${a}`; const r = (b) / 2;\n",
    ],
)
def test_legitimate_javascript_is_not_a_misread(guard: ModuleType, text: str) -> None:
    assert not guard.js_misread(text)


def test_a_suspect_javascript_line_is_also_read_with_its_comment(
    guard: ModuleType,
) -> None:
    # A comment that starts after a string or regex on its line may be one the
    # walker misplaced, so the whole line is read too.
    text = "const u = 'x'; // execSync('npx cdk deploy')\n"
    assert guard._js_walk(text).suspect == frozenset({1})
    assert any(guard.deploy_reason(c.text) for c in guard.shell_commands(text, js=True))
    # A comment line on its own is not suspect, and is not read.
    assert not any(
        guard.deploy_reason(c.text)
        for c in guard.shell_commands("// npx cdk deploy\n", js=True)
    )


def test_the_misread_finding_tells_the_reader_what_to_change(guard: ModuleType) -> None:
    assert "Restructure the JavaScript" in guard.JS_MISREAD
    assert "instead of changing this check" in guard.JS_MISREAD


@pytest.mark.parametrize(
    "source",
    [
        'import os\nos.system("npx cdk " + "deploy --all")\n',
        'import subprocess\nsubprocess.run("npx cdk " + "deploy", shell=True)\n',
        'import os\nC = "npx cdk " + "deploy"\nos.system(C)\n',
        'import os\nos.system("npx cdk %s" % "deploy")\n',
        'import os\nos.system("npx cdk {}".format("deploy"))\n',
        'import os\nA = "npx cdk"\nos.system(A + " deploy")\n',
        'import subprocess\ndef sh(c):\n    subprocess.run(c, shell=True)\nsh("npx cdk deploy")\n',
        'import subprocess\ndef sh(*a):\n    subprocess.run(a)\nsh("npx", "cdk", "deploy")\n',
        'import subprocess\nclass R:\n    def go(self, c):\n        subprocess.run(c, shell=True)\nR().go("npx cdk deploy")\n',
        'import subprocess\ndef a(c):\n    b(c)\ndef b(c):\n    subprocess.call(shlex.split(c))\na("terraform apply")\n',
        'import subprocess\nsh = subprocess.check_call\nsh("npx cdk deploy", shell=True)\n',
        'import subprocess\ngetattr(subprocess, "run")("npx cdk deploy", shell=True)\n',
        'import subprocess\nC = {"go": "npx cdk deploy"}\nsubprocess.run(C["go"], shell=True)\n',
        'import sh\nsh.npx("cdk", "deploy")\n',
    ],
)
def test_python_string_building_and_wrappers(guard: ModuleType, source: str) -> None:
    assert any(guard.deploy_reason(c.text) for c in guard.python_commands(source))


def test_python_wrappers_reach_a_fixpoint(guard: ModuleType) -> None:
    source = (
        "import subprocess\n"
        "def a(x, y):\n    return b(y)\n"
        "def b(z):\n    return c(z)\n"
        "def c(w):\n    subprocess.run(w)\n"
    )
    wrappers = guard.python_wrappers(source)
    assert {p.position for p in wrappers["a"]} == {1}
    assert {p.position for p in wrappers["b"]} == {0}


def test_a_wrapper_defined_in_another_followed_file_is_used(
    guard: ModuleType, tmp_path: Path
) -> None:
    # The caller is read before the module that defines the wrapper; the rescan
    # reads it again once the wrapper is known.
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW
            + "      - run: python3 scripts/a.py && python3 scripts/b.py\n",
            "scripts/a.py": 'from helpers import run_command\nrun_command("npx cdk deploy")\n',
            "scripts/b.py": "import helpers\n",
            "scripts/helpers.py": "import subprocess\ndef run_command(args):\n    subprocess.run(args, shell=True)\n",
        },
    )
    hits, _ = guard.scan_repo(tmp_path)
    assert [h.path for h in hits] == ["scripts/a.py"]


@pytest.mark.parametrize(
    ("tokens", "name"),
    [
        (["bun", "run", "ship"], "ship"),
        (["bun", "ship"], "ship"),
        (["npx", "lerna", "run", "ship", "--stream"], "ship"),
        (["deno", "task", "ship"], "ship"),
        (["npm", "explore", "app", "--", "npm", "run", "ship"], "ship"),
    ],
)
def test_more_tools_that_run_scripts(
    guard: ModuleType, tmp_path: Path, tokens: list[str], name: str
) -> None:
    assert name in guard.Follower(tmp_path).npm_scripts(tokens)


def test_task_runners_read_npm_prefixed_names(guard: ModuleType) -> None:
    names = guard.task_runner_names(["npx", "concurrently", "npm:ship", "yarn:lint:*"])
    assert "ship" in names and "lint:*" in names


def test_parser_states_are_deduplicated(guard: ModuleType) -> None:
    # Each unknown flag here may take the next flag as its value or not, so the
    # paths number in the billions; deduplicated, the states are about 80.
    words = [f"--u{i}" for i in range(40)] + ["ship"]
    readings = guard.flag_readings(words, guard.PNPM_SYNTAX)
    assert ("ship",) in [r.words for r in readings]


def test_a_long_tail_after_the_reading_depth_is_not_walked(
    guard: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(guard, "MAX_FLAG_STATES", 200)
    words = ["--u0", "v0", "--u1", "v1", *[f"w{i}" for i in range(8)]]
    words += ["--t", "x"] * 2000
    readings = guard.flag_readings(words, guard.PNPM_SYNTAX)
    assert all(r.more for r in readings if len(r.words) == guard.READING_DEPTH)


def test_too_many_argument_lists_for_one_script_fail_closed(
    guard: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Each script passes an ambiguous flag to the next, doubling the argument
    # lists the next is followed with.
    levels = 14
    scripts = {f"s{i}": f"pnpm --u s{i + 1} s{i + 1} x{i}" for i in range(levels)}
    scripts[f"s{levels}"] = "echo"
    _write(
        tmp_path,
        {
            ".github/workflows/w.yml": WORKFLOW + "      - run: pnpm s0\n",
            "package.json": json.dumps({"scripts": scripts}),
        },
    )
    assert guard.main(["--root", str(tmp_path)]) == 1
    assert "different argument lists" in capsys.readouterr().out


def test_yaml_block_scalars(guard: ModuleType) -> None:
    folded = "steps:\n  - run: >\n      npx cdk\n      deploy\n  - run: echo\n"
    assert "npx cdk deploy" in guard.yaml_block_scalars(folded).split("\n")[2]
    literal = "steps:\n  - run: |\n      npx cdk\n      deploy\n"
    # A literal block is lines of shell; they stay apart.
    assert guard.yaml_block_scalars(literal) == literal


@pytest.mark.parametrize(
    "script",
    [
        '#!/bin/bash\nc() { npx cdk "$@"; }\nc deploy\n',
        '#!/bin/bash\nfunction c {\n  npx cdk "$@"\n}\nc deploy\n',
        "#!/bin/bash\nalias c='npx cdk'\nc deploy\n",
        "#!/bin/bash\necho deploy | xargs npx cdk\n",
    ],
)
def test_shell_functions_aliases_and_xargs(guard: ModuleType, script: str) -> None:
    assert any(guard.deploy_reason(c.text) for c in guard.shell_commands(script))


def test_a_comment_after_code_is_read_with_its_line(guard: ModuleType) -> None:
    # No string or regex precedes the comment, yet a walker that misjudged a `/`
    # earlier in the file could still have placed it wrongly, so it is read.
    text = "go(); // execSync('npx cdk deploy')\n"
    assert guard._js_walk(text).suspect == frozenset({1})
    assert any(guard.deploy_reason(c.text) for c in guard.shell_commands(text, js=True))
