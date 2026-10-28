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
import shlex
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SYNC_SCRIPT = REPO_ROOT / "scripts" / "sync_cdk_extra_fallback.py"


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
