# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No composite action writes GITHUB_PATH, and none writes GITHUB_ENV from a variable.

Why this file exists
--------------------
zizmor's ``github-env`` audit reported two GITHUB_PATH writes, one in
``.github/actions/setup-ash`` and one in ``.github/actions/run-scan-test``. A line
appended to GITHUB_PATH or GITHUB_ENV in a composite action reaches every later step
of whichever job uses the action, including steps the action's author never sees.
An attacker who can influence the value can shadow an executable that a later step
runs by name, or set something like ``LD_PRELOAD``
(https://docs.zizmor.sh/audits/#github-env). zizmor cannot see a composite action's
triggers, so it reports any such write there, literal or not.

Both writes were removed rather than suppressed. The setup-ash one added a directory
that never held ``ash.exe``. The run-scan-test one handed ``bash`` back to Git Bash
after setup-ruby, and the later bash step now launches Git Bash by absolute path.
This file keeps either kind of write from coming back.

What it checks
--------------
* Composite actions under ``.github/actions`` and ``ash-agent-plugins/.github``: no
  GITHUB_PATH reference on any command line of any ``run:`` body or github-script
  ``script:``, and no ``core.addPath``. Helper scripts committed next to an
  ``action.yml`` must not expand or look up GITHUB_PATH either.
* The same actions: a GITHUB_ENV write is allowed only in the one shape that cannot
  carry a variable, ``echo "NAME=literal" >> "$GITHUB_ENV"``, with no ``$``, backtick
  or quote in the value. validate-container's ``OCI_RUNNER_WRAPPER=sudo`` is the one
  site today, and zizmor does not report it.
* Workflows triggered by ``pull_request_target`` or ``workflow_run``, the triggers
  zizmor treats as attacker-reachable: no GITHUB_PATH or GITHUB_ENV write at all.

What it does not cover
----------------------
Workflows on other triggers still write GITHUB_PATH (``run-ash-security-scan.yml``
and the actionlint job in ``ash-unified-ci.yml``). zizmor does not report those,
because only that workflow's own trigger can reach them, so this file does not
refuse them either. The checks are text matches over command lines, not shell
parsing. A write spelled through a variable that holds the string
``GITHUB_PATH``, or a helper script outside the action's own directory, gets past
them. zizmor in CI is the backstop for those.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_DIRS = (REPO_ROOT / ".github", REPO_ROOT / "ash-agent-plugins" / ".github")

# The triggers zizmor's github-env audit treats as attacker-reachable in a workflow.
DANGEROUS_TRIGGERS = {"pull_request_target", "workflow_run"}

HELPER_SUFFIXES = {".sh", ".bash", ".ps1", ".py", ".js", ".mjs", ".cjs"}

# The only GITHUB_ENV write accepted in a composite action. A case arm prefix
# (`finch | nerdctl) `) and a trailing `;;` are allowed; the value must not be able
# to expand anything.
LITERAL_ENV_WRITE = re.compile(
    r"""^(?:[^()]*\)\s*)?echo\s+"[A-Za-z_][A-Za-z0-9_]*=[^"$`'\\]*"\s*>>\s*"\$GITHUB_ENV"\s*(?:;;)?$"""
)


def _command_lines(text: str) -> list[str]:
    """Non-blank lines that are not whole-line comments, in bash or pwsh.

    The actions explain at length why they no longer write GITHUB_PATH, so matching
    raw text would report the prose.
    """
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


# How a helper script reaches the file: a shell or pwsh expansion, or an environment
# lookup in Python or JavaScript. Helpers are matched on these rather than on the bare
# name because a Python docstring is not a `#` comment, and setup-ash's helper
# explains in its docstring why the GITHUB_PATH write went away.
ENV_FILE_REFERENCE = (
    r"(?:\$\{?|\$env:|process\.env\.|environ(?:\.get)?\(?\[?\s*[\"']|getenv\(\s*[\"'])"
)
HELPER_PATH_WRITE = re.compile(ENV_FILE_REFERENCE + r"GITHUB_PATH|core\.addPath")
HELPER_ENV_WRITE = re.compile(ENV_FILE_REFERENCE + r"GITHUB_ENV|core\.exportVariable")


def _path_write_lines(text: str) -> list[str]:
    """Any mention on a command line of a `run:` body: the strict form."""
    return [
        line
        for line in _command_lines(text)
        if "GITHUB_PATH" in line or "core.addPath" in line
    ]


def _helper_path_write_lines(text: str) -> list[str]:
    return [line for line in _command_lines(text) if HELPER_PATH_WRITE.search(line)]


def _helper_env_write_lines(text: str) -> list[str]:
    return [
        line
        for line in _command_lines(text)
        if HELPER_ENV_WRITE.search(line) and not LITERAL_ENV_WRITE.match(line)
    ]


def _non_literal_env_write_lines(text: str) -> list[str]:
    return [
        line
        for line in _command_lines(text)
        if ("GITHUB_ENV" in line or "core.exportVariable" in line)
        and not LITERAL_ENV_WRITE.match(line)
    ]


def _action_files() -> list[Path]:
    found: list[Path] = []
    for root in GITHUB_DIRS:
        if root.is_dir():
            found += sorted(root.rglob("action.yml")) + sorted(
                root.rglob("action.yaml")
            )
    return found


def _workflow_files() -> list[Path]:
    found: list[Path] = []
    for root in GITHUB_DIRS:
        wf = root / "workflows"
        if wf.is_dir():
            found += sorted(wf.glob("*.yml")) + sorted(wf.glob("*.yaml"))
    return found


def _step_bodies(steps: list[dict[str, Any]]) -> Iterator[tuple[str, str]]:
    """(step name, text) for every run body and github-script script."""
    for step in steps or []:
        name = str(step.get("name") or step.get("id") or step.get("uses") or "?")
        if "run" in step:
            yield name, str(step["run"])
        script = (step.get("with") or {}).get("script")
        if script and "github-script" in str(step.get("uses", "")):
            yield name, str(script)


def _triggers(data: dict[Any, Any]) -> set[str]:
    # PyYAML reads the bare key `on` as the boolean True.
    on = data.get("on", data.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(t) for t in on}
    return set()


def _composite_offenders(check, helper_check) -> list[str]:
    offenders = []
    for path in _action_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in _step_bodies((data.get("runs") or {}).get("steps")):
            offenders += [f"{rel}: {name!r}: {line}" for line in check(body)]
        for helper in sorted(path.parent.iterdir()):
            if helper.suffix in HELPER_SUFFIXES and helper.is_file():
                offenders += [
                    f"{helper.relative_to(REPO_ROOT).as_posix()}: {line}"
                    for line in helper_check(helper.read_text(encoding="utf-8"))
                ]
    return offenders


def test_the_scan_sees_the_actions_it_is_meant_to_guard():
    """Control: the two actions that had the findings must be in the scanned set."""
    rels = {p.relative_to(REPO_ROOT).as_posix() for p in _action_files()}
    for expected in (
        ".github/actions/setup-ash/action.yml",
        ".github/actions/run-scan-test/action.yml",
    ):
        assert expected in rels, f"{expected} is not scanned; found {sorted(rels)}"
    bodies = [
        body
        for p in _action_files()
        for _, body in _step_bodies(
            (
                (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("runs") or {}
            ).get("steps")
        )
    ]
    assert len(bodies) >= 50, f"only {len(bodies)} run bodies found across actions"


@pytest.mark.parametrize(
    "line",
    [
        # The two lines zizmor reported, as they were on main at 8445a2c0.
        'echo "$env:APPDATA\\Python\\Scripts" >> $env:GITHUB_PATH',
        "Add-Content -Path $env:GITHUB_PATH -Value 'C:\\Program Files\\Git\\bin'",
        'echo "${bin}" >> "$GITHUB_PATH"',
        "core.addPath(dir)",
    ],
)
def test_the_detector_flags_the_writes_that_were_reported(line):
    """Control: both matchers find the exact shapes that were removed."""
    assert _path_write_lines(line) == [line]
    assert _helper_path_write_lines(line) == [line]


@pytest.mark.parametrize(
    "line",
    [
        'with open(os.environ["GITHUB_PATH"], "a") as f:',
        "path = os.environ.get('GITHUB_PATH')",
        'os.getenv("GITHUB_PATH")',
        "fs.appendFileSync(process.env.GITHUB_PATH, dir)",
        'printf "%s\\n" "$dir" >> "${GITHUB_PATH}"',
    ],
)
def test_the_helper_detector_flags_other_spellings(line):
    assert _helper_path_write_lines(line) == [line]


def test_the_helper_detector_ignores_prose():
    assert not _helper_path_write_lines("used to be a GITHUB_PATH write, which zizmor")


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ('finch | nerdctl) echo "OCI_RUNNER_WRAPPER=sudo" >> "$GITHUB_ENV" ;;', False),
        ('echo "MODE=fast" >> "$GITHUB_ENV"', False),
        ('echo "WRAPPER=${WRAPPER}" >> "$GITHUB_ENV"', True),
        ("echo $UNQUOTED >> $GITHUB_ENV", True),
        ('echo "X=$(cat f)" >> "$GITHUB_ENV"', True),
        ('"X=$env:Y" | Out-File -FilePath $env:GITHUB_ENV -Append', True),
        ("core.exportVariable('X', value)", True),
    ],
)
def test_the_env_detector_accepts_only_a_literal(line, flagged):
    assert bool(_non_literal_env_write_lines(line)) is flagged


def test_no_composite_action_writes_github_path():
    offenders = _composite_offenders(_path_write_lines, _helper_path_write_lines)
    assert not offenders, (
        "these composite-action lines write GITHUB_PATH. The entry reaches every later "
        "step of the caller's job and zizmor's github-env audit reports it. Hand the "
        "directory over as a step or action output and prepend it inside the steps "
        "that need it:\n  " + "\n  ".join(offenders)
    )


def test_no_composite_action_writes_github_env_from_a_variable():
    offenders = _composite_offenders(
        _non_literal_env_write_lines, _helper_env_write_lines
    )
    assert not offenders, (
        "these composite-action lines write GITHUB_ENV with a value that can expand, "
        "or in a shape this check cannot prove literal. Pass the value as an output "
        "and map it into `env:` where it is used:\n  " + "\n  ".join(offenders)
    )


def test_no_attacker_triggered_workflow_writes_github_path_or_env():
    files = _workflow_files()
    assert len(files) >= 10, f"only {len(files)} workflows found under {GITHUB_DIRS}"
    offenders = []
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not (_triggers(data) & DANGEROUS_TRIGGERS):
            continue
        for job in (data.get("jobs") or {}).values():
            for name, body in _step_bodies((job or {}).get("steps")):
                for line in _command_lines(body):
                    if re.search(
                        r"GITHUB_(PATH|ENV)|core\.(addPath|exportVariable)", line
                    ):
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT).as_posix()}: {name!r}: {line}"
                        )
    assert not offenders, (
        "a workflow on pull_request_target or workflow_run writes GITHUB_PATH or "
        "GITHUB_ENV:\n  " + "\n  ".join(offenders)
    )


def test_trigger_parsing_reads_the_bare_on_key():
    """Control for the test above: `on:` parses as True, and that must be read."""
    data = yaml.safe_load("on:\n  workflow_run:\n    workflows: [x]\n")
    assert _triggers(data) == {"workflow_run"}
    assert _triggers(yaml.safe_load("on: [push, pull_request_target]\n")) == {
        "push",
        "pull_request_target",
    }


# The GITHUB_PATH and GITHUB_ENV writes main still has in workflows on ordinary
# triggers, which the docstring's "What it does not cover" names, by file, job and
# step, with how many command lines in that step write. v4's own workflow writes
# (cfn-lint-guard's two tool paths, the kind/kubectl directory, the VS Code
# real-ASH directory) became step outputs mapped into the env of the steps that use
# them, so on v4 every other workflow is held to none. The list may only shrink.
MAIN_WORKFLOW_WRITES = {
    (
        ".github/workflows/ash-unified-ci.yml",
        "actionlint",
        "Install actionlint and shellcheck, verified against their pinned digests",
    ): 1,
    # A fixture: the workflow text actionlint's self-test is fed, not a write.
    (
        ".github/workflows/ash-unified-ci.yml",
        "actionlint",
        "Self-test -- an unquoted expansion must be reported",
    ): 1,
    (".github/workflows/run-ash-security-scan.yml", "ash", "Install Grype"): 1,
    (".github/workflows/run-ash-security-scan.yml", "ash", "Install Syft"): 1,
    (".github/workflows/run-ash-security-scan.yml", "ash", "Install OpenGrep"): 1,
    (".github/workflows/run-ash-security-scan.yml", "ash", "Install cfn-nag"): 1,
}


def _workflow_write_counts(
    files: list[Path], root: Path = REPO_ROOT
) -> dict[tuple[str, str, str], int]:
    counts: dict[tuple[str, str, str], int] = {}
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rel = path.relative_to(root).as_posix()
        for job_name, job in (data.get("jobs") or {}).items():
            for name, body in _step_bodies((job or {}).get("steps")):
                n = sum(
                    1
                    for line in _command_lines(body)
                    if re.search(
                        r"GITHUB_(PATH|ENV)|core\.(addPath|exportVariable)", line
                    )
                )
                if n:
                    key = (rel, str(job_name), name)
                    counts[key] = counts.get(key, 0) + n
    return counts


def test_no_workflow_writes_github_path_or_env_beyond_mains_sites():
    counts = _workflow_write_counts(_workflow_files())
    extra = {k: v for k, v in counts.items() if MAIN_WORKFLOW_WRITES.get(k) != v}
    assert not extra, (
        "these workflow steps write GITHUB_PATH or GITHUB_ENV. Hand the value over as "
        "a step output and map it into the `env:` of the steps that use it:\n  "
        + "\n  ".join(f"{k}: {v}" for k, v in sorted(extra.items()))
    )
    stale = sorted(set(MAIN_WORKFLOW_WRITES) - set(counts))
    assert not stale, f"remove these from MAIN_WORKFLOW_WRITES: {stale}"


def test_the_workflow_count_sees_a_planted_write(tmp_path):
    """Control: a write in an ordinary push workflow is counted."""
    planted = tmp_path / "planted.yml"
    planted.write_text(
        "on: push\njobs:\n  j:\n    steps:\n      - name: s\n"
        '        run: echo "X=$Y" >> "$GITHUB_ENV"\n',
        encoding="utf-8",
    )
    assert _workflow_write_counts([planted], tmp_path) == {("planted.yml", "j", "s"): 1}
