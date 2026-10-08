# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every e2e upgrade leg derives its N-1 from history, and none names a branch.

The upgrade legs (the wheel, container and Homebrew jobs in ash-e2e.yml, the JetBrains
headless-real job and the Chocolatey job) used to build N-1 from one development
branch, fetched by name. That fetch fails once the branch is merged and deleted, and
while the branch still exists after v4 lands on main, the legs would compare against a
tree that is no longer the one before HEAD. So each leg sets E2E_PREV_REF=auto, which
scripts/e2e/prev_tree.py resolves to the newest release tag reachable from HEAD, else
the newest ancestor, that differs from HEAD's tree and carries every path the leg
requires (the leg's own driver script and the channel's packaging). The shell legs reach
it through scripts/e2e/n1-ref.sh; the Chocolatey script calls prev_tree.py itself.

This file holds three things to that:

1. A static scan of every workflow and every shell and PowerShell script for an N-1
   ref that is a literal other than `auto` (an E2E_PREV_REF value or default, a
   --prev-ref argument, a PREV_REF assignment, or a refs/heads fetch in an N-1 job),
   shown failing on planted copies.
2. The workflow side of each leg: E2E_PREV_REF=auto, a full-history checkout (the
   tags and older ancestors are what auto chooses from), no fetch step, and in a
   `container:` job a chown to the unprivileged user before git runs.
3. The derivation on every shape of history a leg will meet, through each leg's own
   --require list and, for the shell legs, through n1-ref.sh in a real bash: a push to
   the development branch, a pull request's merge commit whose base predates the
   channel (the development branch deleted), a commit after the first release, a
   squash landing that leaves no earlier package, and a shallow clone. Then the shapes
   where a reachable commit has HEAD's tree and must never be N-1: an up-to-date
   `merge --no-ff`, GitHub's merge ref of an up-to-date pull request, a merge of a
   branch that reverts itself, and an empty commit on a release tag.

The shell legs are also held, line by line, to setting PREV_REF only on their default
line and the commit only through n1_resolve, and to naming no branch at all, so an N-1
cannot come back through a variable or a git argument the value patterns do not see.

None of the legs runs git itself. scripts/e2e/n1-ref.sh holds every git call they need
(n1_head_sha, n1_export, n1_tarball, n1_unchanged), each refusing at run time any
revision but HEAD and the chosen N-1, and its git lines are pinned below. So the rule
for a leg script, and for verify-on-windows.ps1, is the simplest one that can hold: the
word git appears only in comments. Messages and heredoc text are not exempt. Earlier
versions tried to tell a message from code, and each round of that parsing let a real
call through or refused an ordinary line.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.utils.posix_bash import bash_path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PREV_TREE = REPO_ROOT / "scripts" / "e2e" / "prev_tree.py"
N1_HELPER = REPO_ROOT / "scripts" / "e2e" / "n1-ref.sh"
OLD_FETCH_STEP = "Fetch the N-1 ref"

# Every leg that builds an N-1, the script its E2E_PREV_REF step runs, and the paths that
# script requires N-1 to carry. Discovery below finds legs by E2E_PREV_REF, so a new leg
# that is not listed here, or a listed one that disappears, fails
# test_every_n_minus_1_leg_is_listed.
LEGS = {
    ("ash-e2e.yml", "wheel"): ("scripts/e2e/wheel.sh", ("pyproject.toml",)),
    ("ash-e2e.yml", "container"): (
        "scripts/e2e/container.sh",
        ("Dockerfile", "automated_security_helper/__init__.py", "pyproject.toml"),
    ),
    ("ash-e2e.yml", "homebrew"): (
        "scripts/e2e/homebrew.sh",
        ("Formula/ash.rb", "pyproject.toml"),
    ),
    ("ash-jetbrains-ci.yml", "headless-real"): (
        "editors/jetbrains/e2e-ide-cycle.sh",
        (
            "editors/jetbrains/e2e-ide-cycle.sh",
            "editors/jetbrains/build.gradle.kts",
        ),
    ),
    ("ash-package.yml", "chocolatey"): (
        "packaging/chocolatey/verify-on-windows.ps1",
        ("packaging/chocolatey/ash.nuspec", "packaging/chocolatey/build.ps1"),
    ),
}
# The N-1 mode each leg runs in. latest-release is the latest published GitHub
# release, for the channels it shipped (the wheel, the container image built by its
# own CLI, its own Homebrew formula). The JetBrains plugin and Chocolatey never shipped
# in a release yet, so they take auto: the newest release that carries the channel,
# which today is a development commit and becomes a release once one ships it.
LEG_MODES = {
    ("ash-e2e.yml", "wheel"): "latest-release",
    ("ash-e2e.yml", "container"): "latest-release",
    ("ash-e2e.yml", "homebrew"): "latest-release",
    ("ash-jetbrains-ci.yml", "headless-real"): "auto",
    ("ash-package.yml", "chocolatey"): "auto",
}
SHELL_LEGS = {k: v for k, v in LEGS.items() if v[0].endswith(".sh")}


def _load_prev_tree():
    spec = importlib.util.spec_from_file_location("ash_e2e_prev_tree_n1", PREV_TREE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pt = _load_prev_tree()


# -- 1. no literal N-1 ref anywhere --------------------------------------------

# The one value an N-1 ref may hold as a literal. A variable ($PrevRef, "$PREV_REF") is
# not a literal and is not matched.
ALLOWED = {"auto", "latest-release"}

# (name, pattern). Each pattern's `v` group is the literal.
_LITERAL = r"""['"]?(?P<v>[^\s'"$}{)(,#][^\s'"}{)(,#]*)"""
PATTERNS = [
    # env: E2E_PREV_REF: origin/main   /   E2E_PREV_REF=origin/main
    (
        "E2E_PREV_REF value",
        re.compile(r"\bE2E_PREV_REF\s*(?::(?![-=])|=)\s*" + _LITERAL),
    ),
    # "${E2E_PREV_REF:-origin/main}", and the assigning forms "${E2E_PREV_REF:=...}"
    ("E2E_PREV_REF default", re.compile(r"\$\{E2E_PREV_REF:?[-=]" + _LITERAL)),
    # if ($env:E2E_PREV_REF) { $env:E2E_PREV_REF } else { 'origin/main' }
    (
        "E2E_PREV_REF fallback",
        re.compile(r"E2E_PREV_REF\b[^\n]*\belse\s*\{\s*" + _LITERAL),
    ),
    # prev_tree.py --prev-ref origin/main   /   '--prev-ref', 'origin/main'
    (
        "--prev-ref argument",
        re.compile(r"""--prev-ref['"]?(?:\s*,\s*|\s+|=)""" + _LITERAL),
    ),
    # PREV_REF="origin/main" in a shell script
    ("PREV_REF assignment", re.compile(r"(?<![\w$-])PREV_REF=" + _LITERAL)),
    # $PrevRef = 'origin/main' in PowerShell; quoted, so `$PrevRef = if (...)` is not one
    (
        "PREV_REF assignment",
        re.compile(r"""(?i)\$PrevRef\s*=\s*['"](?P<v>[^'"$][^'"]*)['"]"""),
    ),
]


def _scanned_files() -> list:
    """Every workflow, and every shell and PowerShell script the legs could run."""
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    for root in ("scripts", "editors", "packaging", ".github/scripts"):
        for suffix in ("*.sh", "*.ps1", "*.psm1"):
            files += sorted(
                p
                for p in (REPO_ROOT / root).rglob(suffix)
                if "node_modules" not in p.parts and "build" not in p.parts
            )
    return files


def literal_n1_refs(text: str) -> list:
    """[(pattern name, line number, literal)] for every literal N-1 ref but `auto`."""
    hits = []
    for name, pattern in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group("v")
            if value not in ALLOWED:
                line = text.count("\n", 0, match.start()) + 1
                hits.append((name, line, value))
    return hits


def n1_jobs_fetching_a_branch(workflow_text: str) -> list:
    """Jobs that read E2E_PREV_REF or run an N-1 helper and fetch refs/heads/<name>."""
    jobs = yaml.safe_load(workflow_text).get("jobs") or {}
    hits = []
    for name, job in jobs.items():
        dumped = yaml.safe_dump(job)
        n1 = (
            "E2E_PREV_REF" in dumped
            or "prev_tree.py" in dumped
            or "n1-ref.sh" in dumped
        )
        if n1 and re.search(r"refs/heads/[^\s:*]+", dumped):
            hits.append(name)
    return hits


def test_the_scan_covers_every_leg_script_and_workflow():
    scanned = {p.relative_to(REPO_ROOT).as_posix() for p in _scanned_files()}
    for (workflow, _), (script, _) in LEGS.items():
        assert f".github/workflows/{workflow}" in scanned
        assert script in scanned
    assert "scripts/e2e/n1-ref.sh" in scanned


def test_no_workflow_or_script_names_an_n_minus_1_ref():
    hits = {}
    for path in _scanned_files():
        text = path.read_text(encoding="utf-8")
        found = literal_n1_refs(text)
        if path.parent == WORKFLOWS:
            found += [
                ("refs/heads fetch", 0, j) for j in n1_jobs_fetching_a_branch(text)
            ]
        if found:
            hits[path.relative_to(REPO_ROOT).as_posix()] = found
    assert hits == {}, (
        "N-1 is derived from history (E2E_PREV_REF=auto, scripts/e2e/prev_tree.py), "
        f"never named: {hits}"
    )


def test_the_patterns_match_the_real_syntax_they_guard():
    # A pattern that matched nothing in the repository would pass the scan above for
    # the wrong reason. Each one has to see the `auto` it allows, in the files that
    # really use that syntax.
    seen = {name: 0 for name, _ in PATTERNS}
    for path in _scanned_files():
        text = path.read_text(encoding="utf-8")
        for name, pattern in PATTERNS:
            seen[name] += sum(
                1 for m in pattern.finditer(text) if m.group("v") in ALLOWED
            )
    assert seen["E2E_PREV_REF value"] >= len(LEGS)
    assert seen["E2E_PREV_REF default"] >= len(SHELL_LEGS)
    assert seen["E2E_PREV_REF fallback"] >= 1


@pytest.mark.parametrize(
    ("planted", "name", "value"),
    [
        (
            "        env:\n          E2E_PREV_REF: origin/main\n",
            "E2E_PREV_REF value",
            "origin/main",
        ),
        (
            "E2E_PREV_REF=origin/v4-capabilities bash x.sh\n",
            "E2E_PREV_REF value",
            "origin/v4-capabilities",
        ),
        (
            'PREV_REF="${E2E_PREV_REF:-origin/main}"\n',
            "E2E_PREV_REF default",
            "origin/main",
        ),
        ('X="${E2E_PREV_REF-release/4.x}"\n', "E2E_PREV_REF default", "release/4.x"),
        (': "${E2E_PREV_REF:=origin/main}"\n', "E2E_PREV_REF default", "origin/main"),
        ('X="${E2E_PREV_REF=origin/main}"\n', "E2E_PREV_REF default", "origin/main"),
        (
            "if (-not $PrevRef) { $PrevRef = if ($env:E2E_PREV_REF) { $env:E2E_PREV_REF } else { 'origin/main' } }\n",
            "E2E_PREV_REF fallback",
            "origin/main",
        ),
        (
            "python3 scripts/e2e/prev_tree.py --repo . --prev-ref main --out o\n",
            "--prev-ref argument",
            "main",
        ),
        (
            "@('prev_tree.py', '--prev-ref', 'origin/develop', '--out', $w)\n",
            "--prev-ref argument",
            "origin/develop",
        ),
        ("  --prev-ref=v4-capabilities\n", "--prev-ref argument", "v4-capabilities"),
        ('PREV_REF="origin/main"\n', "PREV_REF assignment", "origin/main"),
        ("$PrevRef = 'origin/main'\n", "PREV_REF assignment", "origin/main"),
    ],
)
def test_a_planted_literal_n_minus_1_ref_is_caught(planted, name, value):
    hits = literal_n1_refs(planted)
    assert (name, value) in {(n, v) for n, _, v in hits}, hits


@pytest.mark.parametrize(
    "allowed",
    [
        "          E2E_PREV_REF: auto\n",
        'PREV_REF="${E2E_PREV_REF:-latest-release}"\n',
        "@('prev_tree.py', '--prev-ref', $PrevRef, '--out', $w)\n",
        'line="$(harness prev_tree.py --prev-ref "$PREV_REF" --resolve-only)"\n',
        'PREV_REF="${line#* }"\n',
    ],
)
def test_auto_and_variables_are_not_flagged(allowed):
    assert literal_n1_refs(allowed) == []


@pytest.mark.parametrize("key", sorted(LEGS), ids=lambda k: ":".join(k))
def test_a_planted_branch_in_a_real_leg_is_caught(key):
    # The scan run over a copy of the leg's own workflow with its value replaced, so
    # the plant is in exactly the YAML the real scan reads.
    workflow, _ = key
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    sanctioned = f"E2E_PREV_REF: {LEG_MODES[key]}"
    assert sanctioned in text
    planted = text.replace(sanctioned, "E2E_PREV_REF: origin/main", 1)
    assert ("E2E_PREV_REF value", "origin/main") in {
        (n, v) for n, _, v in literal_n1_refs(planted)
    }


def test_a_planted_branch_fetch_in_an_n_minus_1_job_is_caught():
    text = (WORKFLOWS / "ash-e2e.yml").read_text(encoding="utf-8")
    jobs = yaml.safe_load(text)["jobs"]
    jobs["wheel"]["steps"].insert(
        1,
        {
            "name": "fetch",
            "run": "git fetch --depth=2 origin +refs/heads/main:refs/remotes/origin/main",
        },
    )
    assert n1_jobs_fetching_a_branch(yaml.safe_dump({"jobs": jobs})) == ["wheel"]
    assert n1_jobs_fetching_a_branch(text) == []


# -- 2. the workflow side of each leg -------------------------------------------


def _n1_legs() -> dict:
    legs = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        jobs = yaml.safe_load(path.read_text(encoding="utf-8")).get("jobs") or {}
        for name, job in jobs.items():
            for step in job.get("steps") or []:
                if "E2E_PREV_REF" in (step.get("env") or {}):
                    legs[(path.name, name)] = job
    return legs


N1 = _n1_legs()
IDS = [":".join(k) for k in sorted(LEGS)]
AUTO_LEGS = sorted(k for k in LEGS if LEG_MODES[k] == "auto")
RELEASE_LEGS = sorted(k for k in LEGS if LEG_MODES[k] == "latest-release")


def _checkout(steps: list) -> tuple:
    for index, step in enumerate(steps):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            return index, step
    raise AssertionError("no actions/checkout step")


def _prev_ref_steps(steps: list) -> list:
    return [
        (index, step)
        for index, step in enumerate(steps)
        if "E2E_PREV_REF" in (step.get("env") or {})
    ]


def test_every_n_minus_1_leg_is_listed():
    assert set(N1) == set(LEGS)


@pytest.mark.parametrize("key", sorted(LEGS), ids=IDS)
def test_a_leg_derives_n_minus_1_and_runs_its_script(key):
    script, _ = LEGS[key]
    users = _prev_ref_steps(N1[key]["steps"])
    assert users, key
    for _, step in users:
        assert script.rsplit("/", 1)[-1] in str(step.get("run", "")), (key, script)
        assert step["env"]["E2E_PREV_REF"] == LEG_MODES[key], (key, step["env"])
    workflow = yaml.safe_load((WORKFLOWS / key[0]).read_text(encoding="utf-8"))
    assert workflow_leg_problems(workflow, key[1], LEG_OVERRIDES.get(key, ())) == [], (
        key
    )


# What each leg's script also takes the N-1 from, besides E2E_PREV_REF: the Chocolatey
# script's -PrevRef parameter wins over the environment.
LEG_OVERRIDES = {("ash-package.yml", "chocolatey"): ("PrevRef",)}


# PowerShell's common switch parameters, which take no value.
_PS_SWITCHES = {"verbose", "debug", "whatif", "confirm"}


def _ps1_argument_problems(run: str, overrides) -> list:
    """For a leg whose script takes overrides as parameters: every argument named.

    PowerShell binds an unambiguous prefix (-Prev for -PrevRef) and binds bare words
    by position, so a parameter that is a prefix of an override, and any positional
    argument, are refused.
    """
    problems = []
    if not overrides:
        return problems
    for line in run.splitlines():
        match = re.search(r"\S+\.ps1\b(.*)$", line)
        if not match:
            continue
        try:
            words = shlex.split(match.group(1), posix=False)
        except ValueError:
            problems.append(f"cannot read the script arguments: {line.strip()}")
            continue
        expect_value = False
        for word in words:
            if expect_value and not word.startswith("-"):
                expect_value = False
                continue
            expect_value = False
            if word.startswith("-"):
                param = word[1:].split(":", 1)[0]
                for name in overrides:
                    if len(param) > 1 and name.lower().startswith(param.lower()):
                        problems.append(f"passes {word}, which binds -{name}")
                # A switch (-Verbose, -WhatIf, ...) takes no value, so the word after
                # it would bind by position.
                expect_value = ":" not in word and param.lower() not in _PS_SWITCHES
                continue
            problems.append(f"passes {word} by position")
    return problems


def workflow_leg_problems(workflow: dict, job_name: str, overrides=None) -> list:
    """How an N-1 job could hand its script an N-1 other than `auto`.

    Every env that can reach a step (the workflow's, the job's, each step's) may set
    E2E_PREV_REF only to `auto`, and no step's run: text may mention it, or any of the
    leg's OVERRIDES (a script parameter such as -PrevRef), at all: a command-prefix
    assignment (`E2E_PREV_REF=x bash leg.sh`), a parameter, or a write to $GITHUB_ENV
    overrides the pinned env without touching it. Case-insensitive, as PowerShell
    parameters and Windows environment names are.
    """
    problems = []
    job = workflow["jobs"][job_name]
    scopes = [("workflow env", workflow.get("env")), ("job env", job.get("env"))]
    scopes += [
        (f"step {step.get('name', index)!r} env", step.get("env"))
        for index, step in enumerate(job.get("steps") or [])
    ]
    for where, env in scopes:
        for name, value in (env or {}).items():
            if str(name).upper() == "E2E_PREV_REF" and value not in ALLOWED:
                problems.append(f"{where} sets E2E_PREV_REF to {value!r}")
    if overrides is None:
        overrides = next(
            (names for (_, job), names in LEG_OVERRIDES.items() if job == job_name), ()
        )
    names = ("E2E_PREV_REF", *overrides)
    for index, step in enumerate(job.get("steps") or []):
        problems += _ps1_argument_problems(str(step.get("run", "")), overrides)
        # With quotes removed too, so a name split by quoting ("E2E_PREV""_REF") is seen.
        raw = str(step.get("run", ""))
        run = raw + "\n" + re.sub(r"[\"'`]", "", raw)
        for name in names:
            if re.search(rf"(?i)(?<![\w]){re.escape(name)}(?![\w])", run):
                problems.append(
                    f"step {step.get('name', index)!r} run: mentions {name}"
                )
    if not _prev_ref_steps(job.get("steps") or []):
        problems.append("no step sets E2E_PREV_REF")
    return problems


@pytest.mark.parametrize(
    ("label", "mutate", "expect"),
    [
        (
            "a command-prefix assignment in run: (mB)",
            lambda wf: wf["jobs"]["wheel"]["steps"][-1].update(
                run=wf["jobs"]["wheel"]["steps"][-1]["run"].replace(
                    'bash scripts/e2e/wheel.sh "$work"',
                    'E2E_PREV_REF="${{ vars.N1_REF }}" bash scripts/e2e/wheel.sh "$work"',
                )
            ),
            "run: mentions E2E_PREV_REF",
        ),
        (
            "a write to GITHUB_ENV in an earlier step",
            lambda wf: wf["jobs"]["wheel"]["steps"].insert(
                1, {"name": "pick", "run": 'echo "E2E_PREV_REF=$X" >> "$GITHUB_ENV"'}
            ),
            "run: mentions E2E_PREV_REF",
        ),
        (
            "a name split by quoting, into GITHUB_ENV",
            lambda wf: wf["jobs"]["wheel"]["steps"].insert(
                1, {"name": "pick", "run": 'echo "E2E_PREV""_REF=$X" >> "$GITHUB_ENV"'}
            ),
            "run: mentions E2E_PREV_REF",
        ),
        (
            "a name split by quoting, through env",
            lambda wf: wf["jobs"]["wheel"]["steps"][-1].update(
                run=wf["jobs"]["wheel"]["steps"][-1]["run"].replace(
                    "bash scripts/e2e/wheel.sh",
                    'env "E2E_PREV_""REF=$X" bash scripts/e2e/wheel.sh',
                )
            ),
            "run: mentions E2E_PREV_REF",
        ),
        (
            "a job env value",
            lambda wf: wf["jobs"]["wheel"].update(
                env={"E2E_PREV_REF": "${{ vars.R }}"}
            ),
            "job env sets E2E_PREV_REF",
        ),
        (
            "a workflow env value",
            lambda wf: wf.setdefault("env", {}).update(E2E_PREV_REF="origin/main"),
            "workflow env sets E2E_PREV_REF",
        ),
        (
            "a step env expression",
            lambda wf: wf["jobs"]["wheel"]["steps"][-1]["env"].update(
                E2E_PREV_REF="${{ vars.N1_REF }}"
            ),
            "env sets E2E_PREV_REF",
        ),
    ],
)
def test_a_planted_bypass_in_a_real_workflow_leg_is_caught(label, mutate, expect):
    workflow = yaml.safe_load((WORKFLOWS / "ash-e2e.yml").read_text(encoding="utf-8"))
    assert workflow_leg_problems(workflow, "wheel") == []
    assert (
        'bash scripts/e2e/wheel.sh "$work"'
        in workflow["jobs"]["wheel"]["steps"][-1]["run"]
    )
    mutate(workflow)
    problems = workflow_leg_problems(workflow, "wheel")
    assert any(expect in problem for problem in problems), (label, problems)


@pytest.mark.parametrize("key", sorted(LEGS), ids=IDS)
def test_a_leg_checks_out_full_history_and_fetches_no_branch(key):
    job = N1[key]
    checkout_at, checkout = _checkout(job["steps"])
    assert int((checkout.get("with") or {}).get("fetch-depth", 1)) == 0, (
        f"{key}: the release tags and older ancestors auto chooses from need fetch-depth 0"
    )
    assert checkout_at < min(i for i, _ in _prev_ref_steps(job["steps"]))
    assert not any(step.get("name") == OLD_FETCH_STEP for step in job["steps"])
    assert not re.search(r"\bgit fetch\b", yaml.safe_dump(job)), key


@pytest.mark.parametrize(
    "key", sorted(k for k in LEGS if "container" in N1[k]), ids=lambda k: ":".join(k)
)
def test_a_container_leg_hands_the_checkout_to_its_user_before_git_runs(key):
    # In a `container:` job git runs as root over a checkout the runner's user owns, and
    # refuses it ("detected dubious ownership"); the leg's script re-executes as the
    # checkout's new owner, so the chown has to come first.
    steps = N1[key]["steps"]
    chowns = [
        index
        for index, step in enumerate(steps)
        if re.search(r'chown -R \S+ "\$GITHUB_WORKSPACE"', str(step.get("run", "")))
    ]
    users = [i for i, _ in _prev_ref_steps(steps)]
    assert chowns and min(chowns) < min(users), key
    script, _ = LEGS[key]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    assert 'exec bash "$HERE/run-unprivileged.sh"' in text
    # The re-exec has to come before git runs at all.
    assert text.index("run-unprivileged.sh") < text.index("n1_resolve ")


# What no leg script, n1-ref.sh or N-1 job may contain at all: a branch named as an N-1
# can be spelled through a variable or a git argument, which no value pattern sees.
BRANCH_SPELLINGS = re.compile(r"v4-capabilities|origin/|refs/heads/")


def default_line(mode: str) -> str:
    return f'PREV_REF="${{E2E_PREV_REF:-{mode}}}"'


DEFAULT_LINES = {default_line(mode) for mode in ("auto", "latest-release")}
# The wheel leg's, the one the planted cases below are written into.
DEFAULT_LINE = default_line("latest-release")
# The one sanctioned copy of the commit n1_resolve sets (homebrew.sh's leg function).
SANCTIONED_SHA = 'prev_sha="$PREV_SHA"'
# The word git, as a word: a leg script may carry it only in a comment.
GIT_WORD = re.compile(r"(?<![A-Za-z0-9_])git(?![A-Za-z0-9_])")
# The n1-ref.sh helpers that run git, and the only revisions a caller may hand them.
N1_GIT_HELPERS = ("n1_export", "n1_tarball")
ALLOWED_REVISIONS = {"HEAD", "$PREV_SHA", "$prev_sha"}


def writes_to(name: str, text: str) -> list:
    """Code lines that write the shell variable NAME, by any form bash offers cheaply.

    A plain or appending assignment (also after declare, local, export or readonly),
    ${NAME:=...}, read/mapfile/readarray/printf -v into NAME (its name quoted or not),
    and a nameref (declare/local/typeset -n) bound to NAME. Comment lines are skipped.
    Not covered, and banned outright by shell_leg_problems instead: eval.
    """
    q = r"""["']?"""
    # An assignment is one only where a command starts (a message that says
    # "prev_sha=..." is not one), after any declare/local/export/readonly/typeset.
    declarers = r"(?:(?:declare|local|export|readonly|typeset)(?:\s+-\w+)*\s+)?"
    forms = [
        _COMMAND_START + declarers + rf"{q}{name}{q}\s*\+?=",
        rf"\$\{{{name}:?=",
        rf"\b(?:read|mapfile|readarray)\b[^\n;|&]*\s{q}{name}{q}(?![\w])",
        rf"\bprintf\s+(?:-\S+\s+)*-v\s*{q}{name}{q}(?![\w])",
        rf"\b(?:declare|local|typeset)\s+(?:-\w+\s+)*-\w*n\w*\s+\w+={q}{name}{q}(?![\w])",
    ]
    pattern = re.compile("|".join(forms), re.IGNORECASE)
    # Matched with quotes removed too, so a name split by quoting (PREV_"SHA") is seen.
    return [
        line.strip()
        for line in text.splitlines()
        if not line.lstrip().startswith("#")
        and (pattern.search(line) or pattern.search(re.sub(r"[\"']", "", line)))
    ]


# Options of the variable-writing builtins that take the next word as their value.
_WRITER_VALUE_OPTIONS = {
    "read": {"-d", "-i", "-n", "-N", "-p", "-t", "-u"},
    "mapfile": {"-d", "-n", "-O", "-s", "-u", "-C", "-c"},
    "readarray": {"-d", "-n", "-O", "-s", "-u", "-C", "-c"},
}


def dynamic_write_problems(text: str) -> list:
    """Writes whose target NAME is itself an expansion, so the name cannot be read.

    read "$n", mapfile "$n", printf -v "$n", export "$n=...", declare -n r="$n". Only the
    builtin in command position counts, and only its NAME operands: `say "cannot read
    $f"` is a message, and in `read -r A B <<< "$x"` only the here-string is expanded.
    """
    problems = []
    builtins = r"(read|mapfile|readarray|printf|export|declare|local|typeset|readonly)"
    pattern = re.compile(_COMMAND_START + builtins + r"\b([^|;&)\n]*)")
    for number, line in _code_lines(text):
        mask = _code_mask(line)
        for match in pattern.finditer(line):
            if not mask[match.start(1)]:
                continue
            builtin, rest = match.group(1), match.group(2)
            try:
                words = shlex.split(rest)
            except ValueError:
                words = rest.split()
            names, skip = [], False
            for index, word in enumerate(words):
                if skip:
                    skip = False
                    continue
                if _REDIRECT.match(word) or word.startswith("<("):
                    break
                if builtin == "printf":
                    if word == "-v" and index + 1 < len(words):
                        names.append(words[index + 1])
                    elif word.startswith("-v") and len(word) > 2:
                        names.append(word[2:])
                    continue
                if word.startswith("-") and len(word) > 1:
                    if builtin in _WRITER_VALUE_OPTIONS and word == "-a":
                        continue  # read -a NAME: the next word is still a name
                    skip = word in _WRITER_VALUE_OPTIONS.get(builtin, set())
                    continue
                if builtin in ("read", "mapfile", "readarray"):
                    names.append(word)
                else:
                    name, _, value = word.partition("=")
                    names.append(name)
                    if re.search(r"(?:^|\s)-\w*n", rest) and "$" in value:
                        names.append(value)  # declare -n r="$n": the target is $n
            dynamic = [name for name in names if "$" in name]
            if dynamic:
                problems.append(
                    f"line {number}: {builtin} writes a variable named by "
                    f"an expansion: {', '.join(dynamic)}"
                )
    return problems


def _code_lines(text: str) -> list:
    """(first line number, code): comment lines dropped, backslash-continued lines joined.

    Heredoc bodies are read as code like every other line. That is deliberate: deciding
    which bodies are data is how earlier versions of these checks went wrong.
    """
    lines, pending, first = [], "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending and line.lstrip().startswith("#"):
            continue
        if not pending:
            first = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        lines.append((first, pending + line))
        pending = ""
    if pending:
        lines.append((first, pending))
    return lines


# A command word: at the start of a command (after ;, |, ||, &, &&, (, {, $(, `, a
# keyword or !), past any VAR=value prefixes and any wrapper that runs its argument as a
# command (command, env VAR=x, nice -n N, timeout N, xargs ...), never a word inside a
# message.
_ASSIGNMENTS = r"""(?:\w+=(?:"[^"]*"|'[^']*'|[^\s;|&])*\s+)*"""
_WRAPPERS = (
    r"(?:(?:command|builtin|exec|xargs|env|time|nice|nohup|timeout|stdbuf|sudo|ionice)"
    r"(?:\s+(?:-\S+|\w+=\S*|\d[\w.]*))*\s+)*"
)
_COMMAND_START = (
    r"(?:^|\$\(|`|\|\|?|&&?|;|(?<!\$)\(|(?<!\$)\{"
    r"|\b(?:if|then|elif|else|do|while|until)\b|!)\s*" + _ASSIGNMENTS + _WRAPPERS
)
# A redirection: >x, 2>x, &>x, <x, 2>&1, or the bare operator with its target next.
_REDIRECT = re.compile(r"^(?:\d*|&)[<>]{1,2}&?")


def _code_mask(line: str) -> list:
    """For each character of LINE, whether bash reads it as code: outside quotes, or
    inside a $(...) or `...` within double quotes. Text inside quotes is a message."""
    mask, stack, index = [False] * len(line), ["code"], 0
    while index < len(line):
        here, char = stack[-1], line[index]
        mask[index] = here in ("code", "sub", "tick")
        if here == "sq":
            if char == "'":
                stack.pop()
        elif char == "\\":
            if index + 1 < len(line):
                mask[index + 1] = mask[index]
            index += 1
        elif here == "dq":
            if char == '"':
                stack.pop()
            elif line.startswith("$(", index):
                stack.append("sub")
                index += 1
            elif char == "`":
                stack.append("tick")
        else:  # code, sub or tick
            if char == "'":
                stack.append("sq")
            elif char == '"':
                stack.append("dq")
            elif line.startswith("$(", index):
                stack.append("sub")
                mask[index + 1] = True
                index += 1
            elif char == ")" and here == "sub":
                stack.pop()
            elif char == "`":
                if here == "tick":
                    stack.pop()
                else:
                    stack.append("tick")
            elif char == "#" and (index == 0 or line[index - 1] in " \t;"):
                for rest in range(index, len(line)):
                    mask[rest] = False
                break
        index += 1
    return mask


def git_word_problems(text: str) -> list:
    """Every line of a leg script that mentions git outside a comment.

    The legs run git only through the n1-ref.sh helpers, so the rule needs no parsing:
    the word git, anywhere but a comment line, fails. That includes messages and
    heredoc text, by design; telling a message from code is what the earlier, cleverer
    versions of this check kept getting wrong in both directions. The line is also read
    with quotes and backslashes removed, so "g"it, g''it and a backslashed git are the word too.
    """
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        if GIT_WORD.search(line) or GIT_WORD.search(re.sub(r"[\"'\\]", "", line)):
            problems.append(
                f"line {number} mentions git outside a comment (use the n1-ref.sh "
                f"helpers): {line.strip()!r}"
            )
    return problems


def helper_call_problems(text: str) -> list:
    """Calls of the n1-ref.sh git helpers whose revision is not HEAD or the chosen N-1.

    The helpers refuse such a revision at run time too (n1_revision); this reports it
    without running the leg.
    """
    problems = []
    for number, line in _code_lines(text):
        for match in re.finditer(
            r"\b(" + "|".join(N1_GIT_HELPERS) + r")\b([^;|&)\n]*)", line
        ):
            try:
                words = shlex.split(match.group(2))
            except ValueError:
                problems.append(f"line {number}: cannot read {match.group(0)!r}")
                continue
            if not words or words[0] not in ALLOWED_REVISIONS:
                rev = words[0] if words else ""
                problems.append(f"line {number}: {match.group(1)} is given {rev!r}")
    return problems


# The only files a leg script may source. Anything else is code this scan never reads.
KNOWN_HELPERS = {'"$REPO/packaging/cli-name.sh"', '"$REPO/scripts/e2e/n1-ref.sh"'}
# Ways to point git at another repository, or to swap what a commit id resolves to.
REPOSITORY_REDIRECTS = re.compile(
    r"\bGIT_DIR\b|\bGIT_WORK_TREE\b|\bGIT_OBJECT_DIRECTORY\b|\bGIT_ALTERNATE_OBJECT_DIRECTORIES\b"
    r"|--git-dir\b|--work-tree\b|refs/replace\b"
)


def sourcing_problems(text: str) -> list:
    problems = []
    for number, line in _code_lines(text):
        for match in re.finditer(
            r"(?:^|[;&|]|\bthen\b|\bdo\b)\s*(?:\.|source)\s+(\S+)", line
        ):
            if match.group(1) not in KNOWN_HELPERS:
                problems.append(f"line {number}: sources {match.group(1)}")
    return problems


def shell_leg_problems(text: str, require) -> list:
    """Every way a shell leg's text could pick an N-1 other than through n1_resolve."""
    problems = []
    code = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    # E2E_PREV_REF is only ever read, once, on the default line.
    reads = [line.strip() for line in code if "E2E_PREV_REF" in line]
    if len(reads) != 1 or reads[0] not in DEFAULT_LINES:
        problems.append(f"E2E_PREV_REF is used other than by the default line: {reads}")
    assigns = writes_to("PREV_REF", text)
    if len(assigns) != 1 or assigns[0] not in DEFAULT_LINES:
        problems.append(
            f"PREV_REF is assigned other than by the default line: {assigns}"
        )
    shas = writes_to("PREV_SHA", text)
    if any(line != SANCTIONED_SHA for line in shas):
        problems.append(f"the N-1 commit is set outside n1_resolve: {shas}")
    problems += dynamic_write_problems(text)
    if any(re.search(r"\beval\b", line) for line in code):
        problems.append("uses eval, which can write any variable unseen")
    for line in code:
        redefined = re.search(r"\b(n1_\w+)\s*\(\s*\)", line)
        if redefined:
            problems.append(f"redefines {redefined.group(1)}")
    if len([line for line in code if re.match(r"\s*harness\s*\(\)", line)]) != 1:
        problems.append("defines harness other than exactly once")
    for match in BRANCH_SPELLINGS.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        problems.append(f"line {line} names a branch: {match.group(0)}")
    problems += git_word_problems(text)
    problems += helper_call_problems(text)
    problems += sourcing_problems(text)
    for number, line in _code_lines(text):
        found = REPOSITORY_REDIRECTS.search(line)
        if found:
            problems.append(f"line {number}: redirects git with {found.group(0)}")
    if '. "$REPO/scripts/e2e/n1-ref.sh"' not in text:
        problems.append("does not source scripts/e2e/n1-ref.sh")
    calls = re.findall(r"^\s*n1_resolve (.+)$", text, re.MULTILINE)
    if [tuple(call.split()) for call in calls] != [tuple(require)]:
        problems.append(
            f"n1_resolve is called as {calls}, expected once with {require}"
        )
    # The derivation lives in prev_tree.py now, not in a copy per script.
    if "HEAD^1^{commit}" in text:
        problems.append("re-derives HEAD^ itself")
    return problems


@pytest.mark.parametrize("key", sorted(SHELL_LEGS), ids=lambda k: ":".join(k))
def test_a_shell_leg_defaults_to_its_mode_and_requires_its_paths(key):
    script, require = LEGS[key]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    assert shell_leg_problems(text, require) == []
    assert default_line(LEG_MODES[key]) in text, (key, LEG_MODES[key])


def test_n1_ref_sh_and_the_chocolatey_script_name_no_branch():
    for path in (N1_HELPER, REPO_ROOT / LEGS[("ash-package.yml", "chocolatey")][0]):
        text = path.read_text(encoding="utf-8")
        assert BRANCH_SPELLINGS.findall(text) == [], path


@pytest.mark.parametrize("key", sorted(LEGS), ids=IDS)
def test_an_n_minus_1_job_body_names_no_branch(key):
    # The job body only: a workflow's `on:` may still list a branch to run on.
    dumped = yaml.safe_dump(N1[key])
    assert BRANCH_SPELLINGS.findall(dumped) == [], key


WHEEL = ("ash-e2e.yml", "wheel")
_REAL_DEFAULT = DEFAULT_LINE + "\n"
_REAL_CALL = "n1_resolve pyproject.toml\n"


@pytest.mark.parametrize(
    ("label", "old", "new"),
    [
        (
            "an archive of some paths",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'n1_export "$PREV_SHA" "$WORK/src-prev" pyproject.toml src',
        ),
        (
            "a message that shows prev_sha=",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nsay "N-1: prev_sha=$PREV_SHA"\n',
        ),
        (
            "a message that says cannot read (mJ)",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nsay "cannot read $WORK/list"\n',
        ),
        (
            "read into fixed names from a here-string (mK)",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nread -r A B <<< "$WORK x"\n',
        ),
        (
            "a read loop over a file",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nwhile IFS= read -r line; do say "$line"; done < "$WORK/list"\n',
        ),
        (
            "git in a comment",
            "n1_resolve pyproject.toml\n",
            "n1_resolve pyproject.toml\n# git archive HEAD~1 is what this replaced\n",
        ),
        (
            "a continued helper call",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'n1_export "$PREV_SHA" \\\n  "$WORK/src-prev"',
        ),
        (
            "a message about the export",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nsay "N-1 comes from the export of $PREV_SHA (HEAD~1 is not it)"\n',
        ),
        (
            "the HEAD commit through the helper",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nTOP="$(n1_head_sha)"\n',
        ),
        (
            "a changed-paths check through the helper",
            "n1_resolve pyproject.toml\n",
            "n1_resolve pyproject.toml\nif n1_unchanged pyproject.toml; then say same; fi\n",
        ),
        (
            "an unquoted heredoc using the helpers",
            "n1_resolve pyproject.toml\n",
            "n1_resolve pyproject.toml\ncat <<EOF\nN-1 is $(n1_head_sha) and $PREV_SHA\nEOF\n",
        ),
        (
            "a case arm on a tool name",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ncase "$TOOL" in\n  uv) say uv ;;\nesac\n',
        ),
        (
            "echo inside a message that says then read",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\necho "then read $WORK/n"\n',
        ),
    ],
)
def test_an_ordinary_edit_to_a_shell_leg_passes(label, old, new):
    # The checks fail closed; these are edits a maintainer makes for other reasons, and a
    # check that refused them would be one a maintainer learns to loosen.
    script, require = LEGS[WHEEL]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    assert text.count(old) == 1, label
    assert shell_leg_problems(text.replace(old, new), require) == [], label


@pytest.mark.parametrize(
    ("label", "old", "new", "expect"),
    [
        (
            "a branch through a variable",
            'PREV_REF="${E2E_PREV_REF:-latest-release}"\n',
            'PREV_REF="${E2E_PREV_REF:-latest-release}"\nN1_BRANCH=main-line\n[ "$PREV_REF" != auto ] || PREV_REF=$N1_BRANCH\n',
            "PREV_REF is assigned",
        ),
        (
            "the resolved commit overridden",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nPREV_SHA="$(git -C "$REPO" rev-parse "$N1_BRANCH")"\n',
            "mentions git outside a comment",
        ),
        (
            "a remote-tracking ref as a git argument",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" archive origin/release | tar -x\n',
            "mentions git outside a comment",
        ),
        (
            "the development branch by name",
            "n1_resolve pyproject.toml\n",
            "n1_resolve pyproject.toml\nBASE=v4-capabilities\n",
            "names a branch: v4-capabilities",
        ),
        (
            "a heads ref",
            "n1_resolve pyproject.toml\n",
            "n1_resolve pyproject.toml\ngit fetch origin refs/heads/main\n",
            "mentions git outside a comment",
        ),
        (
            "an assigning default",
            'PREV_REF="${E2E_PREV_REF:-latest-release}"\n',
            'PREV_REF="${E2E_PREV_REF:-latest-release}"\n: "${PREV_REF:=main}"\n',
            "PREV_REF is assigned",
        ),
        (
            "the commit read from elsewhere",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nread -r PREV_SHA < "$WORK/n1"\n',
            "set outside n1_resolve",
        ),
        (
            "the commit written with printf -v",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nprintf -v PREV_SHA %s "$other"\n',
            "set outside n1_resolve",
        ),
        (
            "E2E_PREV_REF through a variable (mA)",
            'PREV_REF="${E2E_PREV_REF:-latest-release}"\n',
            'N1_BRANCH=main-line\nE2E_PREV_REF=$N1_BRANCH\nPREV_REF="${E2E_PREV_REF:-latest-release}"\n',
            "E2E_PREV_REF is used other than by the default line",
        ),
        (
            "E2E_PREV_REF exported with a default",
            'PREV_REF="${E2E_PREV_REF:-latest-release}"\n',
            ': "${E2E_PREV_REF:=$N1}"\nPREV_REF="${E2E_PREV_REF:-latest-release}"\n',
            "E2E_PREV_REF is used other than by the default line",
        ),
        (
            "a hard-coded N-1 revision in the export (mC)",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "a split branch name in the export",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'git -C "$REPO" archive "$R""/main" | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "another remote's ref",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'git -C "$REPO" archive refs/remotes/upstream/main | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "a commit taken from rev-parse",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nOTHER="$(git -C "$REPO" rev-parse HEAD~1)"\n',
            "mentions git outside a comment",
        ),
        (
            "a tree read some other way",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" worktree add "$WORK/old" v3.7.0\n',
            "mentions git outside a comment",
        ),
        (
            "a nameref to the commit",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ndeclare -n _r=PREV_SHA\n_r="$other"\n',
            "set outside n1_resolve",
        ),
        (
            "printf -v with the name quoted",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nprintf -v "PREV_SHA" %s "$other"\n',
            "set outside n1_resolve",
        ),
        (
            "read with the name quoted",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nread -r "PREV_SHA" <<<"$other"\n',
            "set outside n1_resolve",
        ),
        (
            "mapfile",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nmapfile -t PREV_SHA < "$WORK/n1"\n',
            "set outside n1_resolve",
        ),
        (
            "readarray",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nreadarray -t PREV_SHA < "$WORK/n1"\n',
            "set outside n1_resolve",
        ),
        (
            "an append after unset",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nunset PREV_SHA; PREV_SHA+="$other"\n',
            "set outside n1_resolve",
        ),
        (
            "declare -g",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ndeclare -g PREV_SHA="$other"\n',
            "set outside n1_resolve",
        ),
        (
            "a nameref to PREV_REF",
            'PREV_REF="${E2E_PREV_REF:-latest-release}"\n',
            'PREV_REF="${E2E_PREV_REF:-latest-release}"\ndeclare -n _p=PREV_REF; _p=main\n',
            "PREV_REF is assigned",
        ),
        (
            "eval",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\neval "PREV_""SHA=$other"\n',
            "uses eval",
        ),
        (
            "n1_resolve redefined",
            "n1_resolve pyproject.toml\n",
            'n1_resolve() { PREV_SHA="$other"; }\nn1_resolve pyproject.toml\n',
            "redefines n1_resolve",
        ),
        (
            "harness redefined before the call",
            "n1_resolve pyproject.toml\n",
            'harness() { echo "$other x"; }\nn1_resolve pyproject.toml\n',
            "defines harness other than exactly once",
        ),
        (
            "another file sourced",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\n. "$WORK/overrides.sh"\n',
            "sources",
        ),
        (
            "another file sourced with source",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nsource "$REPO/packaging/verify-lib.sh"\n',
            "sources",
        ),
        (
            "git pointed at another repository",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nexport GIT_DIR="$WORK/other.git"\n',
            "mentions git outside a comment",
        ),
        (
            "a replaced commit",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ncp "$WORK/x" "$REPO/.git/refs/replace/$PREV_SHA"\n',
            "mentions git outside a comment",
        ),
        (
            "a git call on a continued line",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'git -C "$REPO" \\\n  archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "a git call after a redirection",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'git -C "$REPO" archive 2>/dev/null HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git quoted",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            '"git" -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git by absolute path",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            '/usr/bin/git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git through a variable",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'GIT=git; $GIT -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git behind a wrapper",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'command git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git replaced by a function",
            "n1_resolve pyproject.toml\n",
            'git() { command git "${@/$PREV_SHA/HEAD~1}"; }\nn1_resolve pyproject.toml\n',
            "mentions git outside a comment",
        ),
        (
            "a write to a name held in a variable",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nn=PREV_SHA; printf -v "$n" %s "$other"\n',
            "named by an expansion",
        ),
        (
            "a name split by quoting",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ndeclare PREV_"SHA"="$other"\n',
            "set outside n1_resolve",
        ),
        (
            "an env prefix before git, on an extra line (mG2)",
            'n1_export "$PREV_SHA" "$WORK/src-prev"\n',
            'n1_export "$PREV_SHA" "$WORK/src-prev"\nLC_ALL=C git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"\n',
            "mentions git outside a comment",
        ),
        (
            "git in a subshell, on an extra line (mH3)",
            'n1_export "$PREV_SHA" "$WORK/src-prev"\n',
            'n1_export "$PREV_SHA" "$WORK/src-prev"\n(git -C "$REPO" archive HEAD~1) | tar -x -C "$WORK/src-prev"\n',
            "mentions git outside a comment",
        ),
        (
            "an env prefix with a value",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'TZ=UTC git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git in a brace group",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            '{ git -C "$REPO" archive HEAD~1; } | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git after ||",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'false || git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git behind env VAR=x",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'env GIT_PAGER=cat git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git behind nice -n N",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'nice -n 10 git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git behind timeout N",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'timeout 60 git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git behind a wrapper this cannot read",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'sudo -u builder git -C "$REPO" archive HEAD~1 | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "a range that leaves the chosen commit",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" log --oneline "HEAD~3..HEAD"\n',
            "mentions git outside a comment",
        ),
        (
            "a rev:path of another commit",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" show "HEAD~1:pyproject.toml"\n',
            "mentions git outside a comment",
        ),
        (
            "a substitution in an unquoted heredoc",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ncat <<EOF2\nN-1: $(git -C "$REPO" archive HEAD~1 | wc -c)\nEOF2\n',
            "mentions git outside a comment",
        ),
        (
            "git describe of another commit",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" describe --tags HEAD~1\n',
            "mentions git outside a comment",
        ),
        (
            "the helper not called",
            "n1_resolve pyproject.toml\n",
            "",
            "n1_resolve is called",
        ),
        (
            "rev-parse with only options",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nTOP="$(git -C "$REPO" rev-parse --show-toplevel)"\n',
            "mentions git outside a comment",
        ),
        (
            "a redirection after HEAD",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" rev-parse HEAD 2>/dev/null >"$WORK/head"\n',
            "mentions git outside a comment",
        ),
        (
            "a redirection operator with its target apart",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" rev-parse HEAD 2> /dev/null\n',
            "mentions git outside a comment",
        ),
        (
            "a continued git call",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'git -C "$REPO" \\\n  archive "$PREV_SHA" | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "git named in a message",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nsay "N-1 comes from git archive of $X (HEAD~1 is not it)"\n',
            "mentions git outside a comment",
        ),
        (
            "git --version",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nsay "git: $(git --version)"\n',
            "mentions git outside a comment",
        ),
        (
            "the commit in braces, peeled",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'git -C "$REPO" rev-parse --verify --quiet "${PREV_SHA}^{commit}" >/dev/null\ngit -C "$REPO" archive "${PREV_SHA}" | tar -x -C "$WORK/src-prev"',
            "mentions git outside a comment",
        ),
        (
            "a log of the chosen commit",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nsay "$(git -C "$REPO" log -1 --oneline "$PREV_SHA")"\n',
            "mentions git outside a comment",
        ),
        (
            "git after ( inside a message",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\necho "N-1 (git archive of the chosen commit) unpacked"\n',
            "mentions git outside a comment",
        ),
        (
            "git after ; inside a message",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\necho "step 2; git archive"\n',
            "mentions git outside a comment",
        ),
        (
            "git after && inside a message",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\necho "done && git is clean"\n',
            "mentions git outside a comment",
        ),
        (
            "an unquoted heredoc that mentions git",
            "n1_resolve pyproject.toml\n",
            "n1_resolve pyproject.toml\ncat <<EOF2\nnote: git archive HEAD~1 is not how N-1 is built\nEOF2\n",
            "mentions git outside a comment",
        ),
        (
            "a quoted heredoc that mentions git",
            "n1_resolve pyproject.toml\n",
            "n1_resolve pyproject.toml\ncat <<'EOF2'\nnote: git archive HEAD~1 is not how N-1 is built\nEOF2\n",
            "mentions git outside a comment",
        ),
        (
            "a check that git is installed",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ncommand -v git >/dev/null || { echo "git missing"; exit 1; }\n',
            "mentions git outside a comment",
        ),
        (
            "git describe of HEAD",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" describe --tags --always\n',
            "mentions git outside a comment",
        ),
        (
            "a range from the chosen commit to HEAD",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" log --oneline "$PREV_SHA..HEAD"\n',
            "mentions git outside a comment",
        ),
        (
            "a file of the chosen commit",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\ngit -C "$REPO" show "$PREV_SHA:pyproject.toml" >/dev/null\n',
            "mentions git outside a comment",
        ),
        (
            "an env prefix on an allowed call",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nLC_ALL=C git -C "$REPO" log -1 --oneline "$PREV_SHA"\n',
            "mentions git outside a comment",
        ),
        (
            "a helper given another revision",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'n1_export HEAD~1 "$WORK/src-prev"',
            "n1_export is given 'HEAD~1'",
        ),
        (
            "a helper given a variable",
            'n1_export "$PREV_SHA" "$WORK/src-prev"',
            'n1_export "$OTHER" "$WORK/src-prev"',
            "n1_export is given '$OTHER'",
        ),
        (
            "a helper redefined",
            '. "$REPO/scripts/e2e/n1-ref.sh"\n',
            '. "$REPO/scripts/e2e/n1-ref.sh"\nn1_revision() { :; }\n',
            "redefines n1_revision",
        ),
        (
            "a heredoc fed to a shell",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nbash <<EOF\ngit -C "$REPO" archive HEAD~1 | tar -x\nEOF\n',
            "mentions git outside a comment",
        ),
        (
            "a heredoc after an arithmetic shift",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\nn=$(( a << b ))\ngit -C "$REPO" archive HEAD~1 | tar -x\n',
            "mentions git outside a comment",
        ),
        (
            "a quoted heredoc opener in a message",
            "n1_resolve pyproject.toml\n",
            'n1_resolve pyproject.toml\necho "feed it with <<EOF"\ngit -C "$REPO" archive HEAD~1 | tar -x\n',
            "mentions git outside a comment",
        ),
        (
            "bash -c with git",
            "n1_resolve pyproject.toml\n",
            "n1_resolve pyproject.toml\nbash -c 'git -C \"$REPO\" archive HEAD~1'\n",
            "mentions git outside a comment",
        ),
        (
            "a trap string with git",
            "n1_resolve pyproject.toml\n",
            "n1_resolve pyproject.toml\ntrap 'git -C \"$REPO\" archive HEAD~1 >/dev/null' EXIT\n",
            "mentions git outside a comment",
        ),
    ],
)
def test_a_planted_bypass_in_a_real_shell_leg_is_caught(label, old, new, expect):
    script, require = LEGS[WHEEL]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    assert text.count(old) == 1, label
    problems = shell_leg_problems(text.replace(old, new), require)
    assert problems, label
    assert any(expect in problem for problem in problems), (label, problems)


def ps1_leg_problems(text: str, require) -> list:
    """Every way verify-on-windows.ps1 could pick an N-1 other than through auto.

    $PrevRef may be assigned only on its default line (the parameter, else
    $env:E2E_PREV_REF, else 'auto'); E2E_PREV_REF may appear nowhere else; and
    prev_tree.py's --prev-ref may be handed only $PrevRef. PowerShell names are
    case-insensitive, so every match is. Comments, including <# ... #> help, are skipped.
    """
    code = re.sub(
        r"<#.*?#>", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL
    )
    lines = [
        line.strip()
        for line in code.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    problems = []
    writes = [
        line
        for line in lines
        if re.search(
            r"(?i)\$(?:script:|global:|local:|private:|using:)?\{?PrevRef\}?\s*(?:[-+*/]?=)(?!=)"
            r"|Set-Variable\b.*\bPrevRef\b|New-Variable\b.*\bPrevRef\b"
            r"|\[ref\]\s*\$\{?PrevRef",
            line,
        )
    ]
    if writes != [PS1_DEFAULT_LINE]:
        problems.append(
            f"$PrevRef is assigned other than by the default line: {writes}"
        )
    reads = [line for line in lines if re.search(r"(?i)E2E_PREV_REF", line)]
    if reads != [PS1_DEFAULT_LINE]:
        problems.append(f"E2E_PREV_REF is used other than by the default line: {reads}")
    # prev_tree.py's --prev-ref appears exactly once, in exactly the form
    # '--prev-ref', $PrevRef: neither another value nor a one-word --prev-ref=... .
    body = "\n".join(lines)
    uses = re.findall(r"(?i)--prev-ref", body)
    sanctioned = re.findall(r"'--prev-ref',\s*\$PrevRef(?![\w:])", body)
    if len(uses) != 1 or len(sanctioned) != 1:
        others = [line for line in lines if re.search(r"(?i)--prev-ref", line)]
        problems.append(
            "--prev-ref is passed other than exactly once as '--prev-ref', $PrevRef: "
            f"{others}"
        )
    # The script runs no git itself; prev_tree.py does, and is what these tests hold.
    # The script runs no git; prev_tree.py does, and is what these tests hold. So the
    # word git may appear only in a comment, whatever the line around it is: a string,
    # a $(...) inside one, $x = git, Invoke-Expression, Start-Process or a call operator.
    for line in lines:
        if GIT_WORD.search(line) or GIT_WORD.search(re.sub(r"[\"'`]", "", line)):
            problems.append(f"mentions git outside a comment: {line}")
    for path in require:
        if f"'--require', '{path}'" not in code:
            problems.append(f"does not require {path}")
    for match in BRANCH_SPELLINGS.finditer(code):
        problems.append(f"names a branch: {match.group(0)}")
    return problems


PS1_DEFAULT_LINE = (
    "if (-not $PrevRef) { $PrevRef = if ($env:E2E_PREV_REF) "
    "{ $env:E2E_PREV_REF } else { 'auto' } }"
)
CHOCO = ("ash-package.yml", "chocolatey")


def test_the_chocolatey_script_takes_its_n_minus_1_only_from_auto():
    script, require = LEGS[CHOCO]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    assert ps1_leg_problems(text, require) == []


_PS1_CALL = "'--prev-ref', $PrevRef,"


@pytest.mark.parametrize(
    "line",
    [
        'Write-Host "N-1 source (prev_tree.py export of $PrevRef) ready"',
        'Write-Verbose "step 3; the export happens in prev_tree.py"',
        "if ($PrevRef -eq 'auto') { Write-Host auto }",
        "# git runs only inside prev_tree.py",
    ],
)
def test_an_ordinary_line_in_the_chocolatey_script_passes(line):
    script, require = LEGS[CHOCO]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    anchor = PS1_DEFAULT_LINE + "\n"
    assert ps1_leg_problems(text.replace(anchor, anchor + line + "\n"), require) == []


@pytest.mark.parametrize(
    "line",
    [
        '$sha = "$(git -C $Repo rev-parse HEAD~1)"',
        'Write-Host "sha: $(git -C $Repo rev-parse HEAD~1)"',
        "$null = git -C $Repo archive HEAD~1 -o x.tar",
        'Invoke-Expression "git -C $Repo archive HEAD~1 -o x.tar"',
        "Start-Process git -ArgumentList 'archive', 'HEAD~1'",
        '& "git" archive HEAD~1',
        "$g = 'git'; & $g archive HEAD~1",
        'Write-Host "N-1 source (git archive of $PrevRef) ready"',
    ],
)
def test_git_anywhere_in_the_chocolatey_script_is_refused(line):
    script, require = LEGS[CHOCO]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    anchor = PS1_DEFAULT_LINE + "\n"
    problems = ps1_leg_problems(text.replace(anchor, anchor + line + "\n"), require)
    assert any("mentions git outside a comment" in p for p in problems), problems


@pytest.mark.parametrize(
    ("label", "old", "new", "expect"),
    [
        (
            "an override after the default (mE)",
            PS1_DEFAULT_LINE + "\n",
            PS1_DEFAULT_LINE
            + "\nif ($PrevRef -eq 'auto') { $PrevRef = $env:N1_FALLBACK }\n",
            "$PrevRef is assigned",
        ),
        (
            "a parameter default",
            "[string] $PrevRef",
            "[string] $PrevRef = 'release'",
            "$PrevRef is assigned",
        ),
        (
            "a differently cased write",
            PS1_DEFAULT_LINE + "\n",
            PS1_DEFAULT_LINE + "\n$prevref = $Other\n",
            "$PrevRef is assigned",
        ),
        (
            "Set-Variable",
            PS1_DEFAULT_LINE + "\n",
            PS1_DEFAULT_LINE + "\nSet-Variable -Name PrevRef -Value $Other\n",
            "$PrevRef is assigned",
        ),
        (
            "the environment written",
            PS1_DEFAULT_LINE + "\n",
            "$env:E2E_PREV_REF = $Other\n" + PS1_DEFAULT_LINE + "\n",
            "E2E_PREV_REF is used",
        ),
        (
            "--prev-ref=value in one word (mI2)",
            _PS1_CALL,
            '"--prev-ref=$env:N1_REF",',
            "--prev-ref is passed other than exactly once",
        ),
        (
            "--prev-ref=literal in one word",
            _PS1_CALL,
            "'--prev-ref=HEAD~1',",
            "--prev-ref is passed other than exactly once",
        ),
        (
            "a script-scoped write",
            PS1_DEFAULT_LINE + "\n",
            PS1_DEFAULT_LINE + "\n$script:PrevRef = $Other\n",
            "$PrevRef is assigned",
        ),
        (
            "a braced write",
            PS1_DEFAULT_LINE + "\n",
            PS1_DEFAULT_LINE + "\n${PrevRef} = $Other\n",
            "$PrevRef is assigned",
        ),
        (
            "git run by the script",
            PS1_DEFAULT_LINE + "\n",
            PS1_DEFAULT_LINE + "\n& git -C $Repo archive HEAD~1 -o x.tar\n",
            "mentions git outside a comment",
        ),
        (
            "another value for --prev-ref",
            _PS1_CALL,
            "'--prev-ref', $Other,",
            "--prev-ref is passed other than exactly once",
        ),
        (
            "a literal for --prev-ref",
            _PS1_CALL,
            "'--prev-ref', 'HEAD~1',",
            "--prev-ref is passed other than exactly once",
        ),
    ],
)
def test_a_planted_bypass_in_the_chocolatey_script_is_caught(label, old, new, expect):
    script, require = LEGS[CHOCO]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    assert text.count(old) == 1, label
    problems = ps1_leg_problems(text.replace(old, new), require)
    assert any(expect in problem for problem in problems), (label, problems)


@pytest.mark.parametrize(
    ("planted", "expect"),
    [
        (' -PrevRef "${{ vars.N1_REF }}"', "mentions PrevRef"),
        (" -prevref $ref", "mentions PrevRef"),
        (" -Prev $ref", "binds -PrevRef"),
        (" -Pr:$ref", "binds -PrevRef"),
        (' "$ref"', "by position"),
        (' -Verbose "$ref"', "by position"),
    ],
)
def test_an_override_of_the_chocolatey_step_is_caught(planted, expect):
    workflow = yaml.safe_load((WORKFLOWS / CHOCO[0]).read_text(encoding="utf-8"))
    assert workflow_leg_problems(workflow, CHOCO[1]) == []
    step = _prev_ref_steps(workflow["jobs"][CHOCO[1]]["steps"])[0][1]
    step["run"] = step["run"].rstrip() + planted
    problems = workflow_leg_problems(workflow, CHOCO[1])
    assert any(expect in problem for problem in problems), problems


def test_a_common_switch_in_the_chocolatey_step_passes():
    workflow = yaml.safe_load((WORKFLOWS / CHOCO[0]).read_text(encoding="utf-8"))
    step = _prev_ref_steps(workflow["jobs"][CHOCO[1]]["steps"])[0][1]
    step["run"] = step["run"].rstrip() + " -Verbose"
    assert workflow_leg_problems(workflow, CHOCO[1]) == []


def test_a_prevref_parameter_in_the_chocolatey_step_is_caught():
    # mD: the edit a maintainer debugging a red Chocolatey leg would make.
    workflow = yaml.safe_load((WORKFLOWS / CHOCO[0]).read_text(encoding="utf-8"))
    overrides = LEG_OVERRIDES[CHOCO]
    assert workflow_leg_problems(workflow, CHOCO[1], overrides) == []
    step = _prev_ref_steps(workflow["jobs"][CHOCO[1]]["steps"])[0][1]
    for planted in (' -PrevRef "${{ vars.N1_REF }}"', " -prevref $ref"):
        step_run = step["run"]
        step["run"] = step_run + planted
        problems = workflow_leg_problems(workflow, CHOCO[1], overrides)
        assert any("mentions PrevRef" in problem for problem in problems), problems
        step["run"] = step_run


# -- 3. the derivation on every shape of history ------------------------------


_CLOCK = [1_700_000_000]


def _git(repo: Path, *args: str) -> str:
    # Every call moves the clock a minute, so commit dates, and with them --date-order,
    # follow the order the fixtures create commits in rather than tying on one second.
    _CLOCK[0] += 60
    stamp = f"{_CLOCK[0]} +0000"
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        env={**os.environ, "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp},
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _commit(work: Path, files: dict, message: str) -> str:
    for name, content in files.items():
        target = work / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(work, "add", "-A")
    _git(
        work,
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.invalid",
        "commit",
        "-q",
        "-m",
        message,
    )
    return _git(work, "rev-parse", "HEAD")


def _pyproject(version: str) -> str:
    return f'[project]\nname = "automated-security-helper"\nversion = "{version}"\n'


def _same_tree_commit(work: Path, tree_of: str, parent: str, message: str) -> str:
    return _git(
        work,
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.invalid",
        "commit-tree",
        f"{tree_of}^{{tree}}",
        "-p",
        parent,
        "-m",
        message,
    )


def _bare(work: Path, dest: Path) -> Path:
    subprocess.run(
        ["git", "clone", "-q", "--bare", str(work), str(dest)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return dest


@pytest.fixture(params=AUTO_LEGS, ids=lambda k: ":".join(k))
def history(request, tmp_path: Path) -> dict:
    """main predates the leg's channel; a development branch adds it.

    main:   m1 (tag v3.9.0) - m2 - M (merge of dev) - L
    dev:    m1 - d1 (adds every path the leg requires) - d2
    squash: m2 - S (dev's tree, one commit, no dev history)
    M also takes a change from m2, so its tree differs from d2's. v4.0.0 tags M.

    m1 already has a pyproject.toml, as v3 did, so a leg whose only requirement were
    pyproject.toml would take v3.9.0; every leg also requires a path v3 never had.
    """
    key = request.param
    require = LEGS[key][1]
    work = tmp_path / "author"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    m1 = _commit(work, {"pyproject.toml": _pyproject("3.9.0"), "a.py": "1\n"}, "m1")
    _git(work, "tag", "v3.9.0", m1)
    _git(work, "checkout", "-q", "-b", "dev", m1)
    channel = {path: f"{path}\n" for path in require if path != "pyproject.toml"}
    d1 = _commit(
        work, {"pyproject.toml": _pyproject("4.0.0"), **channel}, "d1: the channel"
    )
    d2 = _commit(work, {"a.py": "dev\n"}, "d2")
    _git(work, "checkout", "-q", "main")
    m2 = _commit(work, {"b.py": "main\n"}, "m2")
    _git(
        work,
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.invalid",
        "merge",
        "-q",
        "--no-ff",
        "-m",
        "M: land dev",
        "dev",
    )
    merge = _git(work, "rev-parse", "HEAD")
    _git(work, "tag", "v4.0.0", merge)
    later = _commit(work, {"c.py": "later\n"}, "L")
    squash = _same_tree_commit(work, merge, m2, "S: dev squashed onto main")
    _git(work, "branch", "squash", squash)
    full = _bare(work, tmp_path / "origin.git")
    # The same history once dev was merged and deleted, and before v4.0.0 existed.
    landed = _bare(work, tmp_path / "landed.git")
    _git(landed, "branch", "-D", "dev")
    _git(landed, "tag", "-d", "v4.0.0")
    return {
        "key": key,
        "require": require,
        "full": full.as_uri(),
        "landed": landed.as_uri(),
        "sha": {"d1": d1, "d2": d2, "m2": m2, "M": merge, "L": later, "S": squash},
    }


def _full_clone(url: str, head: str, dest: Path) -> Path:
    """What actions/checkout leaves with fetch-depth 0: every branch and tag, HEAD detached."""
    subprocess.run(
        ["git", "clone", "-q", "--no-checkout", url, str(dest)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _git(dest, "checkout", "-q", "--detach", head)
    return dest


def _shallow_clone(url: str, branch: str, dest: Path) -> Path:
    """The default actions/checkout clone: one commit of one branch, no tags."""
    subprocess.run(
        ["git", "clone", "-q", "--no-tags", "--single-branch", "--depth=1"]
        + ["--branch", branch, url, str(dest)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return dest


SHAPES = [
    # dev's parent carries the channel; v3.9.0 predates it and is passed over.
    ("a push to the development branch", "full", "d2", "d1"),
    # M^1 is main without the channel; the walk finds dev's side.
    ("the landing merge commit, dev deleted", "landed", "M", "d2"),
    # After a release, N-1 is that release.
    ("a commit after the first release", "full", "L", "M"),
]


@pytest.mark.parametrize(("label", "origin_key", "head", "want"), SHAPES)
def test_auto_picks_a_commit_that_carries_the_channel(
    history, tmp_path, label, origin_key, head, want
):
    sha = history["sha"]
    clone = _full_clone(history[origin_key], sha[head], tmp_path / "ws")
    used_ref, prev_sha = pt.resolve(clone, "auto", history["require"])
    assert prev_sha == sha[want], (history["key"], label, used_ref)
    if head == "L":
        assert used_ref.startswith("v4.0.0"), used_ref


def test_auto_refuses_a_squash_landing_with_no_earlier_package(history, tmp_path):
    clone = _full_clone(history["full"], history["sha"]["S"], tmp_path / "ws")
    with pytest.raises(pt.DerivationError, match="introduces the channel"):
        pt.resolve(clone, "auto", history["require"])


def test_auto_in_a_shallow_clone_says_to_fetch_history(history, tmp_path):
    clone = _shallow_clone(history["full"], "squash", tmp_path / "ws")
    with pytest.raises(pt.DerivationError, match="fetch-depth: 0"):
        pt.resolve(clone, "auto", history["require"])


def test_auto_without_a_required_path_is_refused(tmp_path):
    work = tmp_path / "r"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    _commit(work, {"pyproject.toml": _pyproject("1.0.0")}, "one")
    _commit(work, {"a.py": "2\n"}, "two")
    with pytest.raises(pt.DerivationError, match="--require"):
        pt.resolve(work, "auto", [])


# -- the shell legs, through scripts/e2e/n1-ref.sh in a real bash ---------------


def _bash() -> str:
    """A bash that runs scripts: on Windows, Git's, not the WSL stub on PATH."""
    if os.name != "nt":
        found = shutil.which("bash")
        assert found, "no bash on PATH"
        return found
    git = shutil.which("git")
    assert git, "no git on PATH"
    for parent in Path(git).resolve().parents:
        candidate = parent / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    raise AssertionError(f"no Git for Windows bash.exe above {git}")


DRIVER = r"""
set -euo pipefail
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
harness() { "$E2E_TEST_PYTHON" "$@"; }
. "$E2E_TEST_HELPER"
PREV_REF="${E2E_PREV_REF:-auto}"
n1_resolve "$@"
printf 'sha=%s\nref=%s\nrelease=%s\n' "$PREV_SHA" "$PREV_REF" "$N1_IS_RELEASE"
"""


def _n1_ref_sh(clone: Path, require, prev_ref=None) -> subprocess.CompletedProcess:
    # The helper runs $REPO/scripts/e2e/prev_tree.py against $REPO, so the clone gets
    # this checkout's prev_tree.py as an untracked file: HEAD's tree is unchanged.
    (clone / "scripts" / "e2e").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PREV_TREE, clone / "scripts" / "e2e" / "prev_tree.py")
    env = {
        **os.environ,
        "REPO": str(clone),
        "E2E_TEST_PYTHON": sys.executable,
        "E2E_TEST_HELPER": bash_path(N1_HELPER),
    }
    env.pop("E2E_PREV_REF", None)
    if prev_ref is not None:
        env["E2E_PREV_REF"] = prev_ref
    return subprocess.run(
        [_bash(), "-c", DRIVER, "n1-ref-test", *require],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(("label", "origin_key", "head", "want"), SHAPES)
def test_n1_ref_sh_sets_the_commit_auto_picks(
    history, tmp_path, label, origin_key, head, want
):
    sha = history["sha"]
    clone = _full_clone(history[origin_key], sha[head], tmp_path / "ws")
    result = _n1_ref_sh(clone, history["require"])
    assert result.returncode == 0, (label, result.stderr)
    lines = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert lines["sha"] == sha[want], (history["key"], label, result.stdout)
    assert lines["ref"] == pt.resolve(clone, "auto", history["require"])[0]
    assert "\r" not in result.stdout


def test_n1_ref_sh_fails_on_a_squash_landing(history, tmp_path):
    clone = _full_clone(history["full"], history["sha"]["S"], tmp_path / "ws")
    result = _n1_ref_sh(clone, history["require"])
    assert result.returncode == 1, result.stdout
    assert "introduces the channel" in result.stderr
    assert "FAIL: cannot derive N-1 from E2E_PREV_REF=auto" in result.stderr


def test_n1_ref_sh_keeps_a_named_ref_and_its_heads_parent_fallback(tmp_path):
    # A ref given by hand still works: with HEAD's tree it falls back to HEAD^.
    require = SHELL_LEGS[("ash-e2e.yml", "wheel")][1]
    work = tmp_path / "r"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    files = {"pyproject.toml": _pyproject("4.0.0"), "scripts/e2e/wheel.sh": "1\n"}
    parent = _commit(work, files, "one")
    _commit(work, {"scripts/e2e/wheel.sh": "2\n"}, "two")
    _git(work, "branch", "named")
    result = _n1_ref_sh(work, require, prev_ref="named")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [f"sha={parent}", "ref=HEAD^", "release=no"]


# -- candidates with HEAD's tree ------------------------------------------------


@pytest.fixture(params=AUTO_LEGS, ids=lambda k: ":".join(k))
def same_tree(request, tmp_path: Path) -> dict:
    """HEADs where some commit auto could reach has HEAD's tree, and must be passed over.

    main:    m0 (no channel) - c1 (adds the channel) - B
    noff:    B - X, an up-to-date `merge --no-ff` of feature (B - f1): X^2 = f1 has X's tree
    pr:      P, GitHub's merge ref of an up-to-date pull request (B - p1 - p2): its first
             parent is B, its second p2, with p2's tree
    revert:  R, a `merge --no-ff` of a branch that reverts itself (B - r1 - r2, r2 = B's
             tree): R, its first parent B and its second r2 all share one tree
    release: B - t1 (tag v4.0.0) - E, an empty commit: the tag has HEAD's tree
    """
    key = request.param
    require = LEGS[key][1]
    work = tmp_path / "author"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    ident = ["-c", "user.name=e2e", "-c", "user.email=e2e@example.invalid"]
    _commit(work, {"pyproject.toml": _pyproject("3.9.0"), "a.py": "0\n"}, "m0")
    channel = {path: f"{path}\n" for path in require if path != "pyproject.toml"}
    c1 = _commit(work, {"pyproject.toml": _pyproject("4.0.0"), **channel}, "c1")
    base = _commit(work, {"a.py": "base\n"}, "B")

    _git(work, "checkout", "-q", "-b", "feature", base)
    f1 = _commit(work, {"f.py": "1\n"}, "f1")
    _git(work, "checkout", "-q", "-b", "noff", base)
    _git(work, *ident, "merge", "-q", "--no-ff", "-m", "X", "feature")
    noff = _git(work, "rev-parse", "HEAD")

    _git(work, "checkout", "-q", "-b", "pr-head", base)
    _commit(work, {"p.py": "1\n"}, "p1")
    p2 = _commit(work, {"p.py": "2\n"}, "p2")
    pr = _git(
        work, *ident, "commit-tree", f"{p2}^{{tree}}", "-p", base, "-p", p2, "-m", "P"
    )
    _git(work, "branch", "pr-merge", pr)  # refs/pull/N/merge, as a branch to clone

    _git(work, "checkout", "-q", "-b", "self-revert", base)
    r1 = _commit(work, {"a.py": "changed\n"}, "r1")
    _commit(work, {"a.py": "base\n"}, "r2: revert r1")
    _git(work, "checkout", "-q", "-b", "revert", base)
    _git(work, *ident, "merge", "-q", "--no-ff", "-m", "R", "self-revert")
    revert = _git(work, "rev-parse", "HEAD")

    _git(work, "checkout", "-q", "-b", "release", base)
    t1 = _commit(work, {"a.py": "4.0.0\n"}, "t1")
    _git(work, "tag", "v4.0.0", t1)
    _git(work, *ident, "commit", "-q", "--allow-empty", "-m", "E: empty")
    empty = _git(work, "rev-parse", "HEAD")

    origin = _bare(work, tmp_path / "origin.git")
    return {
        "key": key,
        "require": require,
        "url": origin.as_uri(),
        "head": {"noff": noff, "pr": pr, "revert": revert, "release": empty},
        "want": {"noff": base, "pr": base, "revert": r1, "release": base},
        "same": {"noff": [f1], "pr": [p2], "revert": [base], "release": [t1]},
        "c1": c1,
    }


SAME_TREE_SHAPES = ["noff", "pr", "revert", "release"]


def _tree(repo: Path, rev: str) -> str:
    return _git(repo, "rev-parse", f"{rev}^{{tree}}")


@pytest.mark.parametrize("shape", SAME_TREE_SHAPES)
def test_auto_never_picks_a_commit_with_heads_tree(same_tree, tmp_path, shape):
    clone = _full_clone(same_tree["url"], same_tree["head"][shape], tmp_path / "ws")
    # The shape is what it claims: some candidate really has HEAD's tree.
    for sha in same_tree["same"][shape]:
        assert _tree(clone, sha) == _tree(clone, "HEAD"), shape
    label, prev_sha = pt.resolve(clone, "auto", same_tree["require"])
    assert _tree(clone, prev_sha) != _tree(clone, "HEAD"), (shape, label)
    assert prev_sha == same_tree["want"][shape], (same_tree["key"], shape, label)


@pytest.mark.parametrize("shape", SAME_TREE_SHAPES)
def test_n1_ref_sh_never_picks_a_commit_with_heads_tree(same_tree, tmp_path, shape):
    clone = _full_clone(same_tree["url"], same_tree["head"][shape], tmp_path / "ws")
    result = _n1_ref_sh(clone, same_tree["require"])
    assert result.returncode == 0, (shape, result.stderr)
    lines = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert _tree(clone, lines["sha"]) != _tree(clone, "HEAD"), (shape, result.stdout)
    assert lines["sha"] == same_tree["want"][shape], (same_tree["key"], shape)
    if shape in ("revert", "release"):
        # Here the commit with HEAD's tree comes first, and is seen and passed over.
        assert "HEAD's tree" in result.stderr, result.stderr


@pytest.mark.parametrize("shape", ["noff", "pr"])
def test_auto_on_a_merge_takes_the_base_before_the_merged_tip(
    same_tree, tmp_path, shape
):
    # The base is what a pull request is upgraded from; the tip, newer by date, is
    # passed over for having HEAD's tree, and the first parent is tried before the walk.
    clone = _full_clone(same_tree["url"], same_tree["head"][shape], tmp_path / "ws")
    label, prev_sha = pt.resolve(clone, "auto", same_tree["require"])
    assert prev_sha == _git(clone, "rev-parse", "HEAD^1")
    assert "(first parent)" in label, label


def test_a_passed_over_commit_is_reported_once_with_each_path_once(tmp_path, capsys):
    # The release tag is also an ancestor; it was queried, and reported, twice.
    work = tmp_path / "r"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    _commit(work, {"pyproject.toml": _pyproject("3.9.0")}, "v3")
    _git(work, "tag", "v3.9.0")
    channel = _commit(work, {"pkg/build.sh": "1\n"}, "channel")
    _commit(work, {"pkg/build.sh": "2\n"}, "head")
    capsys.readouterr()
    label, prev_sha = pt.resolve(work, "auto", ["pkg/build.sh"])
    assert prev_sha == channel
    err = capsys.readouterr().err
    tagged = [line for line in err.splitlines() if "v3.9.0" in line]
    assert tagged == ["passed over v3.9.0 (newest release tag): no pkg/build.sh"], err


# -- n1-ref.sh: the only place a leg runs git ----------------------------------

# Every git line in n1-ref.sh. A new one, or a changed one, fails here until it is
# reviewed and listed: the legs' own rule (no git outside a comment) leans on this.
N1_GIT_LINES = [
    'git -C "$REPO" rev-parse HEAD',
    'git -C "$REPO" archive "$rev" "$@" | (cd "$dir" && tar -x)',
    'git -C "$REPO" archive --format=tar.gz --prefix="$prefix" -o "$out" "$rev"',
    'git -C "$REPO" diff --quiet "$PREV_SHA" HEAD -- "$@"',
]


def _shell_function(text: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n(.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group(1)


def test_n1_ref_sh_runs_git_only_in_its_helpers_and_checks_each_revision():
    text = N1_HELPER.read_text(encoding="utf-8")
    lines = [
        line.strip()
        for line in text.splitlines()
        if not line.lstrip().startswith("#") and GIT_WORD.search(line)
    ]
    assert lines == N1_GIT_LINES
    # Each helper that takes a revision checks it before git sees it.
    for name, rev in (
        ("n1_export", '"$rev"'),
        ("n1_tarball", '"$rev"'),
        ("n1_unchanged", '"${PREV_SHA:-}"'),
    ):
        body = _shell_function(text, name)
        assert body.index(f"n1_revision {rev}") < body.index("git "), name
    revision = _shell_function(text, "n1_revision")
    assert "HEAD) ;;" in revision and '[ "$1" = "$PREV_SHA" ]' in revision


HELPER_DRIVER = r"""
set -euo pipefail
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
harness() { "$E2E_TEST_PYTHON" "$@"; }
if [ -n "${E2E_TEST_PATH_PREPEND:-}" ]; then PATH="$E2E_TEST_PATH_PREPEND:$PATH"; fi
. "$E2E_TEST_HELPER"
PREV_SHA="$E2E_TEST_PREV"
"$@"
"""


def _helper(
    repo: Path, prev: str, *argv: str, extra_env: dict | None = None
) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "REPO": str(repo),
        "E2E_TEST_PYTHON": sys.executable,
        "E2E_TEST_HELPER": bash_path(N1_HELPER),
        "E2E_TEST_PREV": prev,
        **(extra_env or {}),
    }
    return subprocess.run(
        [_bash(), "-c", HELPER_DRIVER, "n1-helper-test", *argv],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


@pytest.fixture
def two_commits(tmp_path: Path) -> dict:
    work = tmp_path / "r"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    first = _commit(work, {"a.txt": "1\n", "same.txt": "s\n"}, "one")
    _commit(work, {"a.txt": "2\n"}, "two")
    older = _commit(work, {"a.txt": "3\n"}, "three")
    head = _commit(work, {"a.txt": "4\n"}, "four")
    return {"repo": work, "prev": older, "first": first, "head": head}


def test_the_helpers_export_head_and_the_chosen_commit(two_commits, tmp_path):
    repo, prev = two_commits["repo"], two_commits["prev"]
    for rev, want in (("HEAD", "4\n"), (prev, "3\n")):
        out = tmp_path / f"out-{rev[:4]}"
        out.mkdir()
        result = _helper(repo, prev, "n1_export", rev, bash_path(out))
        assert result.returncode == 0, result.stderr
        assert (out / "a.txt").read_text(encoding="utf-8") == want
    paths = tmp_path / "paths"
    paths.mkdir()
    result = _helper(repo, prev, "n1_export", prev, bash_path(paths), "same.txt")
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in paths.iterdir()) == ["same.txt"]
    result = _helper(repo, prev, "n1_head_sha")
    assert result.stdout.strip() == two_commits["head"]
    tarball = tmp_path / "t.tar.gz"
    result = _helper(repo, prev, "n1_tarball", "HEAD", "pkg-1/", bash_path(tarball))
    assert result.returncode == 0, result.stderr
    assert tarball.stat().st_size > 0
    assert _helper(repo, prev, "n1_unchanged", "same.txt").returncode == 0
    assert _helper(repo, prev, "n1_unchanged", "a.txt").returncode == 1


# A tar that refuses -C, standing in for the MSYS tar on a Windows runner, which reads a
# native C:\\... directory as a remote host:path and cannot open it. n1_export must not
# hand its directory to tar at all; bash's own cd resolves both path forms.
TAR_REFUSING_DIR = """#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in -C | -C* | --directory*) echo "tar shim: refused $arg" >&2; exit 2 ;; esac
done
exec "$E2E_REAL_TAR" "$@"
"""


def test_n1_export_does_not_pass_its_directory_to_tar(two_commits, tmp_path):
    real_tar = shutil.which("tar")
    assert real_tar, "no tar on PATH"
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "tar").write_bytes(TAR_REFUSING_DIR.encode("utf-8"))
    (shim / "tar").chmod(0o755)
    out = tmp_path / "out"
    out.mkdir()
    result = _helper(
        two_commits["repo"],
        two_commits["prev"],
        "n1_export",
        "HEAD",
        bash_path(out),
        extra_env={
            "E2E_TEST_PATH_PREPEND": bash_path(shim),
            "E2E_REAL_TAR": real_tar,
        },
    )
    assert result.returncode == 0, result.stderr
    assert (out / "a.txt").read_text(encoding="utf-8") == "4\n"


@pytest.mark.parametrize(
    "argv",
    [
        ("n1_export", "HEAD~1", "{out}"),
        ("n1_export", "{first}", "{out}"),
        ("n1_tarball", "HEAD~1", "pkg/", "{out}/t.tar.gz"),
        ("n1_export", "", "{out}"),
    ],
)
def test_the_helpers_refuse_any_other_revision(two_commits, tmp_path, argv):
    out = tmp_path / "out"
    out.mkdir()
    argv = [a.format(out=bash_path(out), first=two_commits["first"]) for a in argv]
    result = _helper(two_commits["repo"], two_commits["prev"], *argv)
    assert result.returncode == 1, result.stdout
    assert "is neither HEAD nor the N-1 n1_resolve chose" in result.stderr
    assert list(out.iterdir()) == []


def test_n1_unchanged_refuses_to_run_before_n1_resolve(two_commits):
    result = _helper(two_commits["repo"], "", "n1_unchanged", "a.txt")
    assert result.returncode == 1
    assert "is neither HEAD nor the N-1 n1_resolve chose" in result.stderr


# -- latest-release, through n1-ref.sh -------------------------------------------


def _release(tag: str, draft: bool = False, prerelease: bool = False) -> dict:
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease}


@pytest.fixture(params=RELEASE_LEGS, ids=lambda k: ":".join(k))
def released(request, tmp_path: Path, monkeypatch) -> dict:
    """old (tag v3.6.1) - rel (tag v3.7.1, Latest) - dev (tag v3.8.0, a draft) - HEAD.

    The listing is GitHub's shape on 2026-10-08 plus a prerelease and a draft that
    sort above the latest published release, and the published one is not the newest
    commit, so a resolver that took the newest tag or ignored the flags is caught.
    """
    key = request.param
    require = LEGS[key][1]
    work = tmp_path / "author"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    files = {path: f"{path}\n" for path in require if path != "pyproject.toml"}
    old = _commit(work, {"pyproject.toml": _pyproject("3.6.1"), **files}, "old")
    _git(work, "tag", "v3.6.1", old)
    rel = _commit(work, {"pyproject.toml": _pyproject("3.7.1"), "a.py": "1\n"}, "rel")
    _git(work, "tag", "v3.7.1", rel)
    dev = _commit(work, {"a.py": "2\n"}, "dev")
    _git(work, "tag", "v3.8.0", dev)
    _commit(work, {"pyproject.toml": _pyproject("4.0.0")}, "head")
    listing = tmp_path / "releases.json"
    listing.write_text(
        json.dumps(
            [
                _release("v4.0.0-rc1", prerelease=True),
                _release("v3.9.0", prerelease=True),
                _release("v3.8.0", draft=True),
                _release("v3.7.1"),
                _release("v3.6.1"),
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv(pt.RELEASES_URL_ENV, listing.as_uri())
    return {
        "key": key,
        "require": require,
        "url": _bare(work, tmp_path / "o.git").as_uri(),
        "rel": rel,
    }


def test_n1_ref_sh_resolves_the_latest_published_release(released, tmp_path):
    clone = tmp_path / "ws"
    # Without tags, the way a single-branch checkout of another line has them: the
    # resolver has to fetch the release tag itself.
    subprocess.run(
        ["git", "clone", "-q", "--no-tags", released["url"], str(clone)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert "v3.7.1" not in _git(clone, "tag").split()
    result = _n1_ref_sh(clone, released["require"], prev_ref="latest-release")
    assert result.returncode == 0, result.stderr
    lines = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert lines["sha"] == released["rel"], (released["key"], result.stdout)
    assert lines["ref"] == "v3.7.1 (latest published release)"
    assert lines["release"] == "yes"


def test_n1_ref_sh_fails_loudly_when_the_releases_cannot_be_listed(
    released, tmp_path, monkeypatch
):
    clone = _full_clone(released["url"], "HEAD", tmp_path / "ws")
    monkeypatch.setenv(pt.RELEASES_URL_ENV, "https://127.0.0.1:9/releases")
    result = _n1_ref_sh(clone, released["require"], prev_ref="latest-release")
    assert result.returncode == 1, result.stdout
    assert "cannot list the releases at" in result.stderr
    assert "FAIL: cannot derive N-1 from E2E_PREV_REF=latest-release" in result.stderr
