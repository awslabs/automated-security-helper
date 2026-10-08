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
"""

from __future__ import annotations

import importlib.util
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

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
    ("ash-e2e.yml", "wheel"): (
        "scripts/e2e/wheel.sh",
        ("scripts/e2e/wheel.sh", "pyproject.toml"),
    ),
    ("ash-e2e.yml", "container"): (
        "scripts/e2e/container.sh",
        (
            "scripts/e2e/container.sh",
            "Dockerfile",
            "automated_security_helper/__init__.py",
        ),
    ),
    ("ash-e2e.yml", "homebrew"): (
        "scripts/e2e/homebrew.sh",
        ("scripts/e2e/homebrew.sh", "Formula/ash.rb", "pyproject.toml"),
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
ALLOWED = {"auto"}

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
                1 for m in pattern.finditer(text) if m.group("v") == "auto"
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
        'PREV_REF="${E2E_PREV_REF:-auto}"\n',
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
    assert "E2E_PREV_REF: auto" in text
    planted = text.replace("E2E_PREV_REF: auto", "E2E_PREV_REF: origin/main", 1)
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
    workflow = yaml.safe_load((WORKFLOWS / key[0]).read_text(encoding="utf-8"))
    assert workflow_leg_problems(workflow, key[1]) == [], key


def workflow_leg_problems(workflow: dict, job_name: str) -> list:
    """How an N-1 job could hand its script an E2E_PREV_REF other than `auto`.

    Every env that can reach a step (the workflow's, the job's, each step's) may set it
    only to `auto`, and no step's run: text may mention it at all: a command-prefix
    assignment (`E2E_PREV_REF=x bash leg.sh`) or a write to $GITHUB_ENV overrides the
    pinned env without touching it.
    """
    problems = []
    job = workflow["jobs"][job_name]
    scopes = [("workflow env", workflow.get("env")), ("job env", job.get("env"))]
    scopes += [
        (f"step {step.get('name', index)!r} env", step.get("env"))
        for index, step in enumerate(job.get("steps") or [])
    ]
    for where, env in scopes:
        if env and "E2E_PREV_REF" in env and env["E2E_PREV_REF"] != "auto":
            problems.append(f"{where} sets E2E_PREV_REF to {env['E2E_PREV_REF']!r}")
    for index, step in enumerate(job.get("steps") or []):
        if "E2E_PREV_REF" in str(step.get("run", "")):
            problems.append(
                f"step {step.get('name', index)!r} run: mentions E2E_PREV_REF"
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
DEFAULT_LINE = 'PREV_REF="${E2E_PREV_REF:-auto}"'
# The one sanctioned copy of the commit n1_resolve sets (homebrew.sh's leg function).
SANCTIONED_SHA = 'prev_sha="$PREV_SHA"'
# The only revisions a leg script may hand git: N, and the N-1 n1_resolve chose.
ALLOWED_REVISIONS = {"HEAD", "$PREV_SHA", "$prev_sha"}
# The git subcommands the legs use. Anything else (show, checkout, worktree, ...) could
# read another tree and is refused rather than parsed.
GIT_SUBCOMMANDS = {"archive", "diff", "rev-parse"}
# Options of those subcommands that take the next word as their value.
_GIT_VALUE_OPTIONS = {"-o", "--output", "--format", "--prefix", "--remote", "--exec"}


def writes_to(name: str, text: str) -> list:
    """Code lines that write the shell variable NAME, by any form bash offers cheaply.

    A plain or appending assignment (also after declare, local, export or readonly),
    ${NAME:=...}, read/mapfile/readarray/printf -v into NAME (its name quoted or not),
    and a nameref (declare/local/typeset -n) bound to NAME. Comment lines are skipped.
    Not covered, and banned outright by shell_leg_problems instead: eval.
    """
    q = r"""["']?"""
    forms = [
        rf"(?<![\w$]){q}{name}{q}\s*\+?=",
        rf"\$\{{{name}:?=",
        rf"\b(?:read|mapfile|readarray)\b[^\n;|&]*\s{q}{name}{q}(?![\w])",
        rf"\bprintf\s+(?:-\S+\s+)*-v\s*{q}{name}{q}(?![\w])",
        rf"\b(?:declare|local|typeset)\s+(?:-\w+\s+)*-\w*n\w*\s+\w+={q}{name}{q}(?![\w])",
    ]
    pattern = re.compile("|".join(forms), re.IGNORECASE)
    return [
        line.strip()
        for line in text.splitlines()
        if not line.lstrip().startswith("#") and pattern.search(line)
    ]


def git_revision_problems(text: str) -> list:
    """Every git call in a leg script whose revisions are not HEAD or the chosen N-1.

    A deny-list of branch spellings cannot enumerate split strings, other remotes,
    tags or SHAs; checking what each git call is given catches all of them.
    """
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for match in re.finditer(r"(?<![\w./-])git\s+[^|;&)\n]*", line):
            call = match.group(0)
            try:
                argv = shlex.split(call)
            except ValueError:
                problems.append(f"line {number}: cannot read the git call {call!r}")
                continue
            # Quoted words come back unquoted; compare the variable names as written.
            index = 1
            while index < len(argv) and argv[index] in ("-C", "-c"):
                index += 2
            if index >= len(argv):
                problems.append(f"line {number}: git call with no subcommand {call!r}")
                continue
            sub, args = argv[index], argv[index + 1 :]
            if sub not in GIT_SUBCOMMANDS:
                problems.append(f"line {number}: git {sub} is not one the legs use")
                continue
            revisions, skip = [], False
            for arg in args:
                if skip:
                    skip = False
                    continue
                if arg == "--":
                    break
                if arg in _GIT_VALUE_OPTIONS:
                    skip = True
                    continue
                if arg.startswith("-"):
                    continue
                revisions.append(arg)
            if sub == "archive":
                # git archive <tree-ish> [<path>...]: only the first word is a revision.
                revisions = revisions[:1]
            if not revisions and sub != "diff":
                problems.append(f"line {number}: git {sub} with no revision {call!r}")
            for rev in revisions:
                if rev not in ALLOWED_REVISIONS:
                    problems.append(f"line {number}: git {sub} is given {rev!r}")
    return problems


def shell_leg_problems(text: str, require) -> list:
    """Every way a shell leg's text could pick an N-1 other than through n1_resolve."""
    problems = []
    code = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    # E2E_PREV_REF is only ever read, once, on the default line.
    reads = [line.strip() for line in code if "E2E_PREV_REF" in line]
    if reads != [DEFAULT_LINE]:
        problems.append(f"E2E_PREV_REF is used other than by the default line: {reads}")
    assigns = writes_to("PREV_REF", text)
    if assigns != [DEFAULT_LINE]:
        problems.append(
            f"PREV_REF is assigned other than by the default line: {assigns}"
        )
    shas = writes_to("PREV_SHA", text)
    if any(line != SANCTIONED_SHA for line in shas):
        problems.append(f"the N-1 commit is set outside n1_resolve: {shas}")
    if any(re.search(r"\beval\b", line) for line in code):
        problems.append("uses eval, which can write any variable unseen")
    if any(re.search(r"\bn1_resolve\s*\(\)", line) for line in code):
        problems.append("redefines n1_resolve")
    if len([line for line in code if re.match(r"\s*harness\s*\(\)", line)]) != 1:
        problems.append("defines harness other than exactly once")
    for match in BRANCH_SPELLINGS.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        problems.append(f"line {line} names a branch: {match.group(0)}")
    problems += git_revision_problems(text)
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
def test_a_shell_leg_defaults_to_auto_and_requires_its_paths(key):
    script, require = LEGS[key]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    assert shell_leg_problems(text, require) == []


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
_REAL_CALL = "n1_resolve scripts/e2e/wheel.sh pyproject.toml\n"


@pytest.mark.parametrize(
    ("label", "old", "new", "expect"),
    [
        (
            "a branch through a variable",
            _REAL_DEFAULT,
            _REAL_DEFAULT
            + "N1_BRANCH=main-line\n"
            + '[ "$PREV_REF" != auto ] || PREV_REF=$N1_BRANCH\n',
            "PREV_REF is assigned",
        ),
        (
            "the resolved commit overridden",
            _REAL_CALL,
            _REAL_CALL + 'PREV_SHA="$(git -C "$REPO" rev-parse "$N1_BRANCH")"\n',
            "set outside n1_resolve",
        ),
        (
            "a remote-tracking ref as a git argument",
            _REAL_CALL,
            _REAL_CALL + 'git -C "$REPO" archive origin/release | tar -x\n',
            "names a branch: origin/",
        ),
        (
            "the development branch by name",
            _REAL_CALL,
            _REAL_CALL + "BASE=v4-capabilities\n",
            "names a branch: v4-capabilities",
        ),
        (
            "a heads ref",
            _REAL_CALL,
            _REAL_CALL + "git fetch origin refs/heads/main\n",
            "names a branch: refs/heads/",
        ),
        (
            "an assigning default",
            _REAL_DEFAULT,
            _REAL_DEFAULT + ': "${PREV_REF:=main}"\n',
            "PREV_REF is assigned",
        ),
        (
            "the commit read from elsewhere",
            _REAL_CALL,
            _REAL_CALL + 'read -r PREV_SHA < "$WORK/n1"\n',
            "set outside n1_resolve",
        ),
        (
            "the commit written with printf -v",
            _REAL_CALL,
            _REAL_CALL + 'printf -v PREV_SHA %s "$other"\n',
            "set outside n1_resolve",
        ),
        (
            "E2E_PREV_REF through a variable (mA)",
            _REAL_DEFAULT,
            "N1_BRANCH=main-line\nE2E_PREV_REF=$N1_BRANCH\n" + _REAL_DEFAULT,
            "E2E_PREV_REF is used other than by the default line",
        ),
        (
            "E2E_PREV_REF exported with a default",
            _REAL_DEFAULT,
            ': "${E2E_PREV_REF:=$N1}"\n' + _REAL_DEFAULT,
            "E2E_PREV_REF is used other than by the default line",
        ),
        (
            "a hard-coded N-1 revision in the export (mC)",
            'git -C "$REPO" archive "$PREV_SHA"',
            'git -C "$REPO" archive HEAD~1',
            "git archive is given 'HEAD~1'",
        ),
        (
            "a split branch name in the export",
            'git -C "$REPO" archive "$PREV_SHA"',
            'git -C "$REPO" archive "$R""/main"',
            "git archive is given '$R/main'",
        ),
        (
            "another remote's ref",
            'git -C "$REPO" archive "$PREV_SHA"',
            'git -C "$REPO" archive refs/remotes/upstream/main',
            "git archive is given 'refs/remotes/upstream/main'",
        ),
        (
            "a commit taken from rev-parse",
            _REAL_CALL,
            _REAL_CALL + 'OTHER="$(git -C "$REPO" rev-parse HEAD~1)"\n',
            "git rev-parse is given 'HEAD~1'",
        ),
        (
            "a tree read some other way",
            _REAL_CALL,
            _REAL_CALL + 'git -C "$REPO" worktree add "$WORK/old" v3.7.0\n',
            "git worktree is not one the legs use",
        ),
        (
            "a nameref to the commit",
            _REAL_CALL,
            _REAL_CALL + 'declare -n _r=PREV_SHA\n_r="$other"\n',
            "set outside n1_resolve",
        ),
        (
            "printf -v with the name quoted",
            _REAL_CALL,
            _REAL_CALL + 'printf -v "PREV_SHA" %s "$other"\n',
            "set outside n1_resolve",
        ),
        (
            "read with the name quoted",
            _REAL_CALL,
            _REAL_CALL + 'read -r "PREV_SHA" <<<"$other"\n',
            "set outside n1_resolve",
        ),
        (
            "mapfile",
            _REAL_CALL,
            _REAL_CALL + 'mapfile -t PREV_SHA < "$WORK/n1"\n',
            "set outside n1_resolve",
        ),
        (
            "readarray",
            _REAL_CALL,
            _REAL_CALL + 'readarray -t PREV_SHA < "$WORK/n1"\n',
            "set outside n1_resolve",
        ),
        (
            "an append after unset",
            _REAL_CALL,
            _REAL_CALL + 'unset PREV_SHA; PREV_SHA+="$other"\n',
            "set outside n1_resolve",
        ),
        (
            "declare -g",
            _REAL_CALL,
            _REAL_CALL + 'declare -g PREV_SHA="$other"\n',
            "set outside n1_resolve",
        ),
        (
            "a nameref to PREV_REF",
            _REAL_DEFAULT,
            _REAL_DEFAULT + "declare -n _p=PREV_REF; _p=main\n",
            "PREV_REF is assigned",
        ),
        (
            "eval",
            _REAL_CALL,
            _REAL_CALL + 'eval "PREV_""SHA=$other"\n',
            "uses eval",
        ),
        (
            "n1_resolve redefined",
            _REAL_CALL,
            'n1_resolve() { PREV_SHA="$other"; }\n' + _REAL_CALL,
            "redefines n1_resolve",
        ),
        (
            "harness redefined before the call",
            _REAL_CALL,
            'harness() { echo "$other x"; }\n' + _REAL_CALL,
            "defines harness other than exactly once",
        ),
        (
            "the helper not called",
            _REAL_CALL,
            "",
            "n1_resolve is called",
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


def test_the_chocolatey_script_requires_its_own_channel():
    script, require = LEGS[("ash-package.yml", "chocolatey")]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    for path in require:
        assert f"'--require', '{path}'" in text
    assert "else { 'auto' }" in text


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


@pytest.fixture(params=sorted(LEGS), ids=IDS)
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
printf 'sha=%s\nref=%s\n' "$PREV_SHA" "$PREV_REF"
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
        "E2E_TEST_HELPER": str(N1_HELPER),
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
    assert result.stdout.splitlines() == [f"sha={parent}", "ref=HEAD^"]


# -- candidates with HEAD's tree ------------------------------------------------


@pytest.fixture(params=sorted(LEGS), ids=IDS)
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
