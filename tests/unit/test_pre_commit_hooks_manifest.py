# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every hook in .pre-commit-hooks.yaml must be runnable the way pre-commit runs it.

Why this file exists
--------------------
`pre-commit validate-manifest` checks the YAML against pre-commit's schema and
nothing else, and a hook can pass it and still not run:

* A `language: script` hook's entry is a path inside the hook repository, so an
  entry such as `ashv3 --mode=container --simple`, with no file named `ashv3` in
  the repository, ends every run with "Executable `.../ashv3` not found".
* `ash` and `ash-simple-scan` run `--mode precommit`, which always selects
  cdk-nag. pre-commit builds a python hook's environment with `pip install .`, so
  without the `cdk` extra cdk-nag is MISSING, and the completeness gate exits 1 on
  every run, on a clean repository as much as on one with findings.

The checks below ask the questions pre-commit and ASH ask at run time, without
building a hook environment: does the entry's first word name something that
will exist, does the CLI accept the rest of the command line, and does the
environment install what the hook's own scanner preset needs.
`.github/actions/validate-install` runs the hooks for real in CI.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

import pytest
import typer
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / ".pre-commit-hooks.yaml"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# The ids the README, the docs site and the migration guide tell users to put in
# their .pre-commit-config.yaml. Removing one breaks every configuration that
# names it ("hook id not found"), so a removal has to be a decision, not an edit.
DOCUMENTED_HOOK_IDS = {"ash", "ash-simple-scan", "ash-full-scan"}

# `.` or `.[extra,extra]`: the hook repository itself, as pre-commit's
# `pip install . <additional_dependencies>` sees it.
_SELF_WITH_EXTRAS = re.compile(r"^\.\[(?P<extras>[^\]]*)\]$")

# The extra each scanner needs before it can run, for scanners whose Python
# dependencies are not in [project] dependencies. A scanner missing from this
# table needs no extra: it is vendored (detect-secrets), installed at scan time
# with `uv tool` (bandit, checkov), or a host tool (npm-audit's npm).
SCANNER_EXTRAS = {"cdk-nag": "cdk"}


def _hooks() -> list[dict[str, Any]]:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


def _pyproject() -> dict[str, Any]:
    with PYPROJECT_PATH.open("rb") as handle:
        return tomllib.load(handle)


def _argv(hook: dict[str, Any]) -> list[str]:
    """What pre-commit executes: the entry, split, then the hook's args."""
    return shlex.split(hook["entry"]) + list(hook.get("args") or [])


def _installed_extras(hook: dict[str, Any]) -> set[str]:
    extras: set[str] = set()
    for requirement in hook.get("additional_dependencies") or []:
        match = _SELF_WITH_EXTRAS.match(requirement.strip())
        if match:
            extras.update(
                name.strip() for name in match["extras"].split(",") if name.strip()
            )
    return extras


def _runs_precommit_mode(hook: dict[str, Any]) -> bool:
    args = _argv(hook)[1:]
    for index, arg in enumerate(args):
        if arg == "--mode=precommit":
            return True
        if arg == "--mode" and index + 1 < len(args) and args[index + 1] == "precommit":
            return True
    return False


HOOKS = _hooks()
HOOK_IDS = [hook["id"] for hook in HOOKS]


def test_the_documented_hook_ids_all_exist():
    assert DOCUMENTED_HOOK_IDS <= set(HOOK_IDS), (
        f"{sorted(DOCUMENTED_HOOK_IDS - set(HOOK_IDS))} documented but not in "
        f"{MANIFEST_PATH.name}; configurations naming them stop working."
    )


def test_ash_simple_scan_is_the_same_hook_as_ash():
    """CI runs `ash` for real and not `ash-simple-scan`, on the strength of this.

    `ash-simple-scan` is the id the README has always documented, kept so those
    configurations keep working; only its id and description may differ.
    """
    by_id = {hook["id"]: hook for hook in HOOKS}
    ignored = {"id", "description"}
    ash = {k: v for k, v in by_id["ash"].items() if k not in ignored}
    simple = {k: v for k, v in by_id["ash-simple-scan"].items() if k not in ignored}
    assert simple == ash


def test_some_hook_runs_precommit_mode():
    """Positive control: the extras test below must have something to check."""
    assert any(_runs_precommit_mode(hook) for hook in HOOKS)


@pytest.mark.parametrize("hook", HOOKS, ids=HOOK_IDS)
def test_the_entry_names_an_executable_the_hook_environment_has(hook):
    command = _argv(hook)[0]
    language = hook["language"]
    if language == "python":
        scripts = _pyproject()["project"]["scripts"]
        assert command in scripts, (
            f"hook {hook['id']!r} runs {command!r}, which is not one of ASH's "
            f"console scripts {sorted(scripts)}; pip would not install it into "
            "the hook environment."
        )
    elif language == "script":
        # pre-commit resolves a script entry against the hook repository's root.
        path = REPO_ROOT / command
        assert path.is_file() and os.access(path, os.X_OK), (
            f"hook {hook['id']!r} is `language: script` with entry {command!r}, "
            f"so pre-commit runs {path}, which is not an executable file in this "
            "repository."
        )
    else:
        pytest.fail(
            f"hook {hook['id']!r} uses language {language!r}; this test only "
            "knows how pre-commit resolves python and script entries."
        )


@pytest.mark.parametrize("hook", HOOKS, ids=HOOK_IDS)
def test_the_cli_accepts_the_hook_command_line(hook):
    """Parses the entry and args with ASH's own CLI, without running a scan.

    The root command rejects options it does not know (`ash scan` would ignore
    them), and the hooks call the root command, so a misspelled option or a
    --mode value that does not exist fails here as it would in the hook.
    """
    from automated_security_helper.cli.main import app

    command = typer.main.get_command(app)
    argv = _argv(hook)
    try:
        command.make_context(argv[0], argv[1:])
    # Typer vendors its own copy of click, so its usage errors are not
    # click.ClickException; catch broadly and report what the CLI said.
    except Exception as exc:
        format_message = getattr(exc, "format_message", None)
        reason = format_message() if callable(format_message) else repr(exc)
        pytest.fail(
            f"hook {hook['id']!r} runs `{shlex.join(argv)}`, which ASH refuses: "
            f"{reason}"
        )


@pytest.mark.parametrize(
    "hook",
    [hook for hook in HOOKS if _runs_precommit_mode(hook)],
    ids=[hook["id"] for hook in HOOKS if _runs_precommit_mode(hook)],
)
def test_a_precommit_hook_installs_the_extras_its_scanners_need(hook):
    from automated_security_helper.interactions.run_ash_scan import (
        PRECOMMIT_MODE_SCANNERS,
    )

    declared = set(_pyproject()["project"]["optional-dependencies"])
    needed = {
        SCANNER_EXTRAS[scanner]
        for scanner in PRECOMMIT_MODE_SCANNERS
        if scanner in SCANNER_EXTRAS
    }
    assert needed <= declared, (
        f"SCANNER_EXTRAS names extras {sorted(needed - declared)} that "
        "pyproject.toml does not declare; update the table."
    )
    missing = needed - _installed_extras(hook)
    assert not missing, (
        f"hook {hook['id']!r} runs --mode precommit, which always selects "
        f"{', '.join(PRECOMMIT_MODE_SCANNERS)}, but its environment is "
        f"`pip install . {' '.join(hook.get('additional_dependencies') or [])}`"
        f", which lacks the {sorted(missing)} extra(s). The scanner that needs it "
        "is MISSING on every run and the scan exits 1. Add "
        f"'.[{','.join(sorted(needed))}]' to additional_dependencies."
    )


# ---------------------------------------------------------------------------
# Where CI runs the hooks for real
# ---------------------------------------------------------------------------
#
TUTORIAL_PAGES = [
    REPO_ROOT / "docs" / "content" / "how-to" / name
    for name in (
        "pre-commit.md",
        "pre-commit.md.template",
    )
]


@pytest.mark.parametrize("page", TUTORIAL_PAGES, ids=lambda page: page.name)
def test_the_tutorial_ignores_the_output_and_not_the_suppressions(page):
    """It said "Add `.ash/` to your `.gitignore`".

    That also ignores `.ash/.ash.yaml`, where the same page tells readers to
    suppress the rule a frozen `rev:` trips, so the suppression would never be
    committed and the hook would fail for everyone else.

    The page moved from docs/content/tutorials/ to docs/content/how-to/pre-commit.md
    in the docs restructure, and it now shows the line to add as a fenced block
    after "add the line yourself:" instead of naming it inline.
    """
    text = page.read_text(encoding="utf-8")
    [ignored] = re.findall(r"add the line yourself:\n\n```text\n([^\n]+)\n```", text)

    assert ".ash/.ash.yaml" in text
    assert not ".ash/.ash.yaml".startswith(ignored)
    assert ".ash/ash_output/".startswith(ignored)


# validate-install runs the manifest check on every pre-commit cell and the real
# hook runs (minutes each, with network for every scanner install) on one cell
# per OS. Both install surfaces pass the choice in the same expression, and the
# cells it names have to exist on both matrices: an OS dropped from an axis, or
# a Python version renamed, would otherwise turn the real runs off silently.

ACTION_PATH = REPO_ROOT / ".github" / "actions" / "validate-install" / "action.yml"
RUN_HOOKS_INPUT = "pre-commit-run-hooks"
REAL_HOOK_CELLS = {
    ("ubuntu-latest", "3.12"),
    ("macos-latest", "3.12"),
    ("windows-latest", "3.12"),
}
# (workflow, job, the matrix.method value whose legs run the pre-commit step)
SURFACES = [
    (
        REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml",
        "install-validation",
        "bundle",
    ),
    (
        REPO_ROOT / ".github" / "workflows" / "ash-install-methods.yml",
        "validate",
        "pre-commit",
    ),
]
_EXPRESSION = re.compile(
    r"^\$\{\{ matrix\.python-version == '(?P<python>[0-9.]+)' && "
    r"contains\(fromJSON\('(?P<oses>\[[^']*\])'\), matrix\.os\) \}\}$"
)


def _effective_cells(job: dict[str, Any], method: str) -> set[tuple[str, str]]:
    matrix = job["strategy"]["matrix"]
    excludes = matrix.get("exclude") or []
    cells = set()
    for os_name in matrix["os"]:
        for python in matrix["python-version"]:
            cell = {"os": os_name, "python-version": python, "method": method}
            if not any(all(cell.get(k) == v for k, v in ex.items()) for ex in excludes):
                cells.add((os_name, python))
    return cells


def _run_hooks_values(job: dict[str, Any]) -> list[str]:
    values = []
    for step in job["steps"]:
        if step.get("uses") == "./.github/actions/validate-install":
            with_ = step.get("with") or {}
            if with_.get("method") in ("pre-commit", "${{ matrix.method }}"):
                values.append(with_.get(RUN_HOOKS_INPUT))
    return values


def test_the_action_runs_hooks_only_when_asked():
    action = yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))
    assert action["inputs"][RUN_HOOKS_INPUT]["default"] == "false"
    steps = {step.get("name"): step for step in action["runs"]["steps"]}
    manifest = steps["pre-commit: validate manifest"]
    assert manifest["if"] == "inputs.method == 'pre-commit'"
    hooks = steps["pre-commit: run the hooks"]
    assert hooks["if"] == (
        f"inputs.method == 'pre-commit' && inputs.{RUN_HOOKS_INPUT} == 'true'"
    )


@pytest.mark.parametrize(
    "workflow, job_name, method", SURFACES, ids=lambda v: getattr(v, "name", v)
)
def test_each_surface_runs_the_hooks_on_one_cell_per_os(workflow, job_name, method):
    job = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"][job_name]
    values = _run_hooks_values(job)
    assert len(values) == 1, (
        f"{workflow.name}: expected one validate-install pre-commit step passing "
        f"{RUN_HOOKS_INPUT}, found {values}"
    )
    match = _EXPRESSION.match(str(values[0]))
    assert match, f"{workflow.name}: {RUN_HOOKS_INPUT} is {values[0]!r}"
    named = {(os_name, match["python"]) for os_name in json.loads(match["oses"])}
    assert named == REAL_HOOK_CELLS
    missing = named - _effective_cells(job, method)
    assert not missing, (
        f"{workflow.name}: {RUN_HOOKS_INPUT} names cells {sorted(missing)} that the "
        f"{job_name} matrix does not run for {method}, so the hooks would run nowhere"
    )
