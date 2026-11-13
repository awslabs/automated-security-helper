# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A pre-commit hook must not rebuild the contributor's project environment.

``sync-cdk-extra-fallback`` ran ``uv run --python 3.13 python ...``. Inside the project,
``uv run`` syncs the project environment, and asked for an interpreter the existing
``.venv`` does not have, it removes the ``.venv`` and creates a new one on 3.13 with the
default dependencies only. So every ``pre-commit run --all-files`` (and every commit that
touched pyproject.toml) replaced a contributor's 3.14 environment with a 3.13 one without
the ``cdk`` and ``symbols`` extras. The script needs nothing from the project, so the
hook runs it with ``--no-project``.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SYNC_SCRIPT = REPO_ROOT / "scripts" / "sync_cdk_extra_fallback.py"
TRAILER_SCRIPT = REPO_ROOT / "scripts" / "check_snapshot_trailer.py"
CI_TRAILER_SCRIPT = REPO_ROOT / ".github" / "scripts" / "check-snapshot-trailers.py"
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"


def _local_hooks() -> list[dict]:
    config = yaml.safe_load(
        (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    return [
        hook
        for repo in config["repos"]
        if repo["repo"] == "local"
        for hook in repo["hooks"]
    ]


def _hook(hook_id: str) -> dict:
    (hook,) = [h for h in _local_hooks() if h["id"] == hook_id]
    return hook


def _ci_run_lines() -> list[str]:
    workflow = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
    return [
        line.strip()
        for job in workflow["jobs"].values()
        for step in job.get("steps") or []
        for line in str(step.get("run", "")).splitlines()
        if line.strip()
    ]


def test_the_header_names_only_hooks_that_exist():
    """The header says which hooks mean another stage; each name it gives is real."""
    text = (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")

    assert any(hook["id"] == "ash" for hook in _local_hooks()), "no ash hook"
    assert "spawn" + "-audit" not in text


def _picks_an_interpreter(argv: list[str]) -> bool:
    return any(a == "--python" or a.startswith("--python=") for a in argv)


def test_no_hook_runs_the_project_on_an_interpreter_of_its_own():
    uv_hooks = {
        hook["id"]: shlex.split(hook["entry"])
        for hook in _local_hooks()
        if shlex.split(hook["entry"])[:2] == ["uv", "run"]
    }
    assert "sync-cdk-extra-fallback" in uv_hooks, f"read the wrong hooks: {uv_hooks}"
    offenders = [
        hook_id
        for hook_id, argv in uv_hooks.items()
        if _picks_an_interpreter(argv) and "--no-project" not in argv
    ]
    assert not offenders, (
        f"{offenders} run `uv run --python ...` inside the project, which recreates the "
        "contributor's .venv on that interpreter and drops its extras. Add --no-project, "
        "or drop --python."
    )


def test_hooks_that_run_the_project_use_the_lock_as_written():
    """A `uv run` hook inside the project must not rewrite uv.lock on the committer's uv.

    Without ``--frozen`` (or ``--locked``), ``uv run`` re-resolves when the committer's
    uv disagrees with the lock and rewrites uv.lock as part of the commit; one such
    commit moved two pins down and added an ``[options]`` table nobody asked for.
    ``--frozen`` reads the lock as committed and fails instead. A ``--no-project`` hook
    installs nothing and writes no lock, so it is exempt.
    """
    uv_hooks = {
        hook["id"]: shlex.split(hook["entry"])
        for hook in _local_hooks()
        if shlex.split(hook["entry"])[:2] == ["uv", "run"]
    }
    assert "generate-schemas" in uv_hooks, f"read the wrong hooks: {uv_hooks}"
    # The must-not-flag control: a hook that runs outside the project needs no flag.
    assert "--no-project" in uv_hooks["sync-cdk-extra-fallback"], uv_hooks
    offenders = [
        hook_id
        for hook_id, argv in uv_hooks.items()
        if "--no-project" not in argv and not {"--frozen", "--locked"} & set(argv)
    ]
    assert not offenders, (
        f"{offenders} run `uv run` inside the project without --frozen or --locked, so "
        "a committer's uv can rewrite uv.lock in the commit. Add --frozen."
    )


def test_the_sync_hook_runs_its_script_on_python_3_13_with_fix():
    (hook,) = [h for h in _local_hooks() if h["id"] == "sync-cdk-extra-fallback"]
    argv = shlex.split(hook["entry"])
    assert argv[:3] == ["uv", "run", "--no-project"], argv
    assert argv[argv.index("--python") + 1] == "3.13", argv
    assert "scripts/sync_cdk_extra_fallback.py" in argv and argv[-1] == "--fix", argv


def test_the_ruff_hooks_judge_the_whole_tree_without_mutating_it():
    """The local ruff pair is the lint gate's command, not another --fix hook.

    The ruff-pre-commit hooks repair the staged files; this pair exists to fail a
    commit CI's check-only gate would fail, so it must stay check-only (`--fix`
    would repair and exit 0 over its own edits, the defect the config's ruff-check
    comment measures) and whole-tree (the gate lints `.`, not the staged set).
    """
    expected = {
        "ruff-check-project": [
            *("uv", "run", "--frozen", "--group", "dev"),
            *("ruff", "check", "."),
        ],
        "ruff-format-check-project": [
            *("uv", "run", "--frozen", "--group", "dev"),
            *("ruff", "format", "--check", "."),
        ],
    }
    for hook_id, argv_expected in expected.items():
        hook = _hook(hook_id)
        assert shlex.split(hook["entry"]) == argv_expected, hook["entry"]
        assert hook["language"] == "system", hook
        assert hook["pass_filenames"] is False, (
            f"{hook_id} must lint the whole tree; with filenames passed, ruff would "
            "also receive non-Python staged files and skip everything unstaged"
        )
        assert "--fix" not in argv_expected


def test_the_ruff_hooks_run_what_the_ci_lint_gate_runs():
    """Drift gate: each hook's command, minus --frozen, is a line of the CI gate.

    `--frozen` is the one deliberate difference (CI's uv and uv.lock cannot
    disagree in a fresh checkout; a committer's can). Anything else differing --
    the group, the subcommand, the scope -- recreates the version-skew defect the
    ruff-pre-commit comment in .pre-commit-config.yaml documents, where the hook
    enforced a fraction of what CI enforced while looking like it enforced all of it.
    """
    ci_lines = set(_ci_run_lines())
    assert "uv run --group dev ruff check ." in ci_lines, (
        "read the wrong workflow, or the lint gate moved; update this test with it"
    )
    for hook_id in ("ruff-check-project", "ruff-format-check-project"):
        hook = _hook(hook_id)
        argv = shlex.split(hook["entry"])
        assert "--frozen" in argv, argv
        gate_command = " ".join(a for a in argv if a != "--frozen")
        assert gate_command in ci_lines, (
            f"{hook_id} runs {hook['entry']!r}, but no CI run line reads "
            f"{gate_command!r}; the hook and the lint gate must run the same command"
        )


def _catches_an_import_failure(handler: ast.ExceptHandler) -> bool:
    guards = ("ImportError", "ModuleNotFoundError")
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name):
        return handler.type.id in guards
    if isinstance(handler.type, ast.Tuple):
        return any(
            isinstance(name, ast.Name) and name.id in guards
            for name in handler.type.elts
        )
    return False


def test_the_sync_script_needs_only_the_standard_library():
    """What makes --no-project safe: outside the project nothing else is importable.

    ``sys.stdlib_module_names`` belongs to the interpreter running the tests, so
    each unit leg checks the floor it runs on, and the 3.10 leg is the one that
    catches a module that entered the standard library later -- which is how this
    test caught the script's unconditional ``import tomllib`` (stdlib since 3.11).

    An import inside a ``try`` whose handler catches ImportError makes a different
    promise: the script runs without it. Whether it keeps that promise is not
    readable from the import list, so the guarded set is pinned exactly instead --
    tomllib and nothing else, whose fallback test_cdk_extra_fallback_sync_gate.py
    proves (the 3.10 leg runs the whole gate through it, and the 3.11+ legs hold it
    equal to tomllib). A new guarded import is a new unproven fallback: prove it
    there, then extend the pin here.
    """
    tree = ast.parse(SYNC_SCRIPT.read_text(encoding="utf-8"))
    guarded_nodes = {
        id(node)
        for outer in ast.walk(tree)
        if isinstance(outer, ast.Try)
        and any(_catches_an_import_failure(handler) for handler in outer.handlers)
        for statement in outer.body
        for node in ast.walk(statement)
    }
    unconditional: set[str] = set()
    guarded: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = {node.module.split(".")[0]}
        else:
            continue
        (guarded if id(node) in guarded_nodes else unconditional).update(names)
    assert guarded == {"tomllib"}, f"parsed the wrong script: {guarded}"
    outside = sorted(unconditional - set(sys.stdlib_module_names) - {"__future__"})
    assert not outside, (
        f"{SYNC_SCRIPT.name} imports {outside} unconditionally, which "
        "`uv run --no-project` cannot see"
    )


def test_the_commands_the_sync_script_prints_keep_the_project_environment():
    """It tells a contributor what to run; that must not rebuild their .venv either."""
    tree = ast.parse(SYNC_SCRIPT.read_text(encoding="utf-8"))
    advice = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "uv run" in node.value
    ]
    assert advice, "the script no longer prints a uv command; update this test"
    unsafe = [text for text in advice if "--no-project" not in text]
    assert not unsafe, unsafe


DRIFT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-cdk-extra-drift.yml"


def _drift_steps() -> list[dict]:
    workflow = yaml.safe_load(DRIFT_WORKFLOW.read_text(encoding="utf-8"))
    return [step for job in workflow["jobs"].values() for step in job["steps"]]


def test_the_drift_workflow_runs_the_check_outside_the_project_environment():
    """The CI half of the same command: check-only, on 3.13, without the project."""
    runs = [
        shlex.split(step["run"])
        for step in _drift_steps()
        if "sync_cdk_extra_fallback.py" in str(step.get("run", ""))
    ]
    assert len(runs) == 1, runs
    (argv,) = runs
    assert argv[:3] == ["uv", "run", "--no-project"], argv
    assert argv[argv.index("--python") + 1] == "3.13", argv
    assert "--fix" not in argv, "CI must report drift, not repair it"


def test_the_drift_workflow_caches_nothing_it_does_not_use():
    """With --no-project the job installs no packages.

    A run leaves about 16 KB of interpreter metadata in ~/.cache/uv, and the 3.13
    interpreter uv may download goes to ~/.local/share/uv/python, outside that path,
    so a uv cache there restores and saves nothing worth a step.
    """
    uses = [str(step.get("uses", "")) for step in _drift_steps()]
    assert any(u.startswith("astral-sh/setup-uv@") for u in uses), uses
    cached = [u for u in uses if u.startswith("actions/cache")]
    assert not cached, cached


# ---------------------------------------------------------------------------
# The two CI gate scripts and the Snapshot-Update trailer hook (the local ruff
# pair is pinned next to the sync-hook tests above). Each gets the same
# treatment -- the exact command is pinned, and what makes it safe (--frozen,
# --no-project, check-only, the stage, the file scope) is asserted rather than
# described in a comment.
# ---------------------------------------------------------------------------


def _tail_from(argv: "list[str]", script: str) -> "list[str]":
    assert script in argv, argv
    return argv[argv.index(script) :]


def test_the_gate_hooks_run_the_ci_gate_scripts_with_the_ci_arguments():
    """Same script, same arguments, as the CI job that owns each gate.

    The prefixes legitimately differ (one CI job invokes bare `python` after its
    own setup, the hooks go through `uv run --frozen` so the committer's
    environment matches the lock), so the pinned equality runs from the script
    path to the end of the command -- which is where a drifted --timeout or
    --workers would hide.

    Only the lines naming each gate script are shell-split: splitting every CI
    run line made an apostrophe in an unrelated shell comment an error here.
    """
    for hook_id, script in (
        (
            "verify-multi-project-attribution",
            "scripts/verify_multi_project_attribution.py",
        ),
        ("verify-moto-server-suite", "scripts/verify_moto_server_suite.py"),
    ):
        hook = _hook(hook_id)
        argv = shlex.split(hook["entry"])
        assert argv[:4] == ["uv", "run", "--frozen", "python"], argv
        assert hook["pass_filenames"] is False, hook
        assert hook["verbose"] is True, hook
        assert hook["language"] == "system", hook
        script_lines = [line for line in _ci_run_lines() if script in line]
        assert script_lines, f"no CI run line invokes {script}; is the gate gone?"
        matching = []
        for line in script_lines:
            try:
                matching.append(shlex.split(line))
            except ValueError as err:
                raise AssertionError(
                    f"the CI run line invoking {script} does not split as a "
                    f"shell command: {line!r} ({err})"
                ) from err
        for ci_argv in matching:
            assert _tail_from(argv, script) == _tail_from(ci_argv, script), (
                f"{hook_id} passes {_tail_from(argv, script)} but CI passes "
                f"{_tail_from(ci_argv, script)}"
            )


def test_the_gate_hooks_fire_only_on_what_each_gate_proves():
    """The slow gates are scoped by `files:`, and the scope must be real paths.

    Each regex is compiled the way pre-commit compiles it; every path meant to be
    in scope must exist in the tree, because a rename would otherwise quietly
    unscope the hook while the pattern kept compiling; and a path outside the
    machinery must stay out, or the attribution gate's minutes land on every
    commit.
    """
    cases = {
        "verify-multi-project-attribution": (
            [
                "scripts/verify_multi_project_attribution.py",
                "automated_security_helper/workspace/aggregation.py",
                "automated_security_helper/models/workspace.py",
                "automated_security_helper/config/ash_workspace_config.py",
                "automated_security_helper/utils/sarif_utils.py",
                "automated_security_helper/utils/workspace_paths.py",
            ],
            ["automated_security_helper/cli/main.py", "README.md"],
        ),
        "verify-moto-server-suite": (
            [
                "scripts/verify_moto_server_suite.py",
                "tests/unit/deploy/test_deploy_s3_sync_moto_server.py",
                "tests/unit/deploy/codepipeline_stub.py",
                "deploy/terraform/modules/codepipeline-executor/files/ash_s3_sync.py",
                "deploy/cdk/lib/ash-container-scripts.ts",
            ],
            [
                "tests/unit/test_pre_commit_hook_commands.py",
                "automated_security_helper/cli/main.py",
            ],
        ),
    }
    for hook_id, (in_scope, out_of_scope) in cases.items():
        pattern = re.compile(_hook(hook_id)["files"])
        for path in in_scope:
            assert (REPO_ROOT / path).is_file(), f"{path} is gone; rescope {hook_id}"
            assert pattern.search(path), f"{hook_id} would not fire on {path}"
        for path in out_of_scope:
            assert not pattern.search(path), f"{hook_id} would fire on {path}"


def test_the_trailer_hook_reads_the_message_at_commit_msg_time():
    hook = _hook("check-snapshot-trailer")
    argv = shlex.split(hook["entry"])
    assert argv == [
        "uv",
        "run",
        "--no-project",
        "python",
        "scripts/check_snapshot_trailer.py",
    ], argv
    assert hook["stages"] == ["commit-msg"], hook
    assert hook.get("pass_filenames", True) is True, (
        "at the commit-msg stage the filename pre-commit passes IS the message "
        "file the script reads as argv[1]; pass_filenames: false would starve it"
    )


def test_the_trailer_script_needs_only_the_standard_library():
    """What makes --no-project safe for it, as for the sync script above."""
    tree = ast.parse(TRAILER_SCRIPT.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    assert imported, "parsed the wrong script"
    outside = sorted(imported - set(sys.stdlib_module_names) - {"__future__"})
    assert not outside, (
        f"{TRAILER_SCRIPT.name} imports {outside} unconditionally, which "
        "`uv run --no-project` cannot see"
    )


def _assigned_trailer_key(path: Path) -> str:
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "TRAILER_KEY" for t in node.targets
        ):
            assert isinstance(node.value, ast.Constant), ast.dump(node.value)
            return node.value.value
    raise AssertionError(f"{path} assigns no TRAILER_KEY")


def test_the_trailer_hook_and_the_ci_gate_require_the_same_trailer():
    """One convention, two enforcement points; the key must not drift apart."""
    assert (
        _assigned_trailer_key(TRAILER_SCRIPT)
        == _assigned_trailer_key(CI_TRAILER_SCRIPT)
        == "Snapshot-Update"
    )


# ---------------------------------------------------------------------------
# Behavior of scripts/check_snapshot_trailer.py itself, in throwaway git
# repositories: the verdicts the hook gives, not just the command that runs it.
# ---------------------------------------------------------------------------


SNAPSHOT_RELPATH = "tests/__snapshots__/test_example.ambr"


@pytest.fixture(scope="module")
def trailer_mod():
    spec = importlib.util.spec_from_file_location(
        "check_snapshot_trailer", TRAILER_SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repo_git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, encoding="utf-8"
    )
    assert proc.returncode == 0, f"git {' '.join(args)} failed: {proc.stderr}"
    return proc.stdout


@pytest.fixture()
def snapshot_repo(tmp_path: Path) -> Path:
    """A repository with one committed snapshot file and one prose file."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _repo_git(repo, "init", "-q", "-b", "main")
    _repo_git(repo, "config", "user.name", "ash-test")
    _repo_git(repo, "config", "user.email", "ash-test@example.invalid")
    _repo_git(repo, "config", "commit.gpgsign", "false")
    snapshot = repo / SNAPSHOT_RELPATH
    snapshot.parent.mkdir(parents=True)
    snapshot.write_text("# base snapshot\n", encoding="utf-8")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _repo_git(repo, "add", "-A")
    _repo_git(repo, "commit", "-q", "-m", "chore: base")
    return repo


def _run_hook(repo: Path, message: str) -> "subprocess.CompletedProcess[str]":
    """The hook as pre-commit runs it: the message file path as argv[1]."""
    message_file = repo / ".git" / "COMMIT_EDITMSG_TEST"
    message_file.write_text(message, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-I", str(TRAILER_SCRIPT), str(message_file)],
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_a_staged_snapshot_needs_a_trailer_and_the_failure_names_the_path(
    snapshot_repo,
):
    (snapshot_repo / SNAPSHOT_RELPATH).write_text("# regenerated\n", encoding="utf-8")
    _repo_git(snapshot_repo, "add", SNAPSHOT_RELPATH)
    refused = _run_hook(snapshot_repo, "test: regenerate the snapshot\n")
    assert refused.returncode == 1, (refused.stdout, refused.stderr)
    assert SNAPSHOT_RELPATH in refused.stdout
    passed = _run_hook(
        snapshot_repo,
        "test: regenerate the snapshot\n\nSnapshot-Update: the output gained a key\n",
    )
    assert passed.returncode == 0, (passed.stdout, passed.stderr)


def test_an_ambr_file_outside_a_snapshots_directory_is_not_counted(snapshot_repo):
    """CI's GOLDEN set has no bare *.ambr pattern; the subset promise holds."""
    (snapshot_repo / "stray.ambr").write_text("# stray\n", encoding="utf-8")
    _repo_git(snapshot_repo, "add", "stray.ambr")
    proc = _run_hook(snapshot_repo, "chore: add a stray file\n")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)


def _diverge_with_other_side_snapshot(repo: Path) -> None:
    """A branch regenerates the snapshot (with its trailer); main moves on."""
    _repo_git(repo, "checkout", "-q", "-b", "other")
    (repo / SNAPSHOT_RELPATH).write_text("# other side regenerated\n", encoding="utf-8")
    _repo_git(
        repo,
        "commit",
        "-q",
        "-am",
        "test: regenerate\n\nSnapshot-Update: upstream regeneration",
    )
    _repo_git(repo, "checkout", "-q", "main")
    (repo / "README.md").write_text("main moved on\n", encoding="utf-8")
    _repo_git(repo, "commit", "-q", "-am", "docs: unrelated change on main")
    _repo_git(repo, "merge", "--no-commit", "--no-ff", "other")
    assert (repo / ".git" / "MERGE_HEAD").is_file(), "the merge left no MERGE_HEAD"


def test_a_merge_bringing_only_the_other_sides_snapshot_needs_no_trailer(
    snapshot_repo,
):
    """git merge of a branch whose snapshot change carried its own trailer passes.

    Against HEAD alone the staged list holds the snapshot, so the pre-fix hook
    failed this merge; counted against both parents, as CI's combined diff counts
    a merge commit, the snapshot equals MERGE_HEAD's side and does not count.
    """
    _diverge_with_other_side_snapshot(snapshot_repo)
    proc = _run_hook(snapshot_repo, "Merge branch 'other'\n")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)


def test_a_merge_whose_snapshot_differs_from_both_parents_needs_a_trailer(
    snapshot_repo,
):
    _diverge_with_other_side_snapshot(snapshot_repo)
    (snapshot_repo / SNAPSHOT_RELPATH).write_text(
        "# content neither parent has\n", encoding="utf-8"
    )
    _repo_git(snapshot_repo, "add", SNAPSHOT_RELPATH)
    refused = _run_hook(snapshot_repo, "Merge branch 'other'\n")
    assert refused.returncode == 1, (refused.stdout, refused.stderr)
    assert SNAPSHOT_RELPATH in refused.stdout
    passed = _run_hook(
        snapshot_repo,
        "Merge branch 'other'\n\nSnapshot-Update: resolved the merge by regenerating\n",
    )
    assert passed.returncode == 0, (passed.stdout, passed.stderr)


def test_has_reason_follows_git_trailer_semantics(trailer_mod):
    assert trailer_mod.has_reason(
        "feat: change\n\nSnapshot-Update: the CLI gained --foo\n"
    )
    assert trailer_mod.has_reason(
        "feat: change\n\nSNAPSHOT-UPDATE: trailer keys compare case-insensitively\n"
    ), "git trailers compare keys case-insensitively; so must the hook"
    assert not trailer_mod.has_reason(
        "feat: change\n\nSnapshot-Update: <why the output changed>\n"
    ), "the documentation's unedited placeholder is not a reason"
    assert not trailer_mod.has_reason("feat: change\n\nbody prose, no trailer\n")


def test_visible_message_strips_comments_and_the_scissors_section(trailer_mod):
    raw = (
        "feat: change\n"
        "# a comment line git strips\n"
        "# ------------------------ >8 ------------------------\n"
        "diff --git a/f b/f\n"
        "+verbose diff payload below the scissors\n"
    )
    assert trailer_mod.visible_message(raw) == "feat: change"
