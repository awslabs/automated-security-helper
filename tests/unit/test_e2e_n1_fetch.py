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
   squash landing that leaves no earlier package, and a shallow clone.
"""

from __future__ import annotations

import importlib.util
import os
import re
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
        re.compile(r"\bE2E_PREV_REF\s*(?::(?!-)|=)\s*" + _LITERAL),
    ),
    # "${E2E_PREV_REF:-origin/main}"
    ("E2E_PREV_REF default", re.compile(r"\$\{E2E_PREV_REF:?-" + _LITERAL)),
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
        assert step["env"]["E2E_PREV_REF"] == "auto", (key, step["env"])
        assert script.rsplit("/", 1)[-1] in str(step.get("run", "")), (key, script)


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


@pytest.mark.parametrize("key", sorted(SHELL_LEGS), ids=lambda k: ":".join(k))
def test_a_shell_leg_defaults_to_auto_and_requires_its_paths(key):
    script, require = LEGS[key]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    assert 'PREV_REF="${E2E_PREV_REF:-auto}"' in text
    assert '. "$REPO/scripts/e2e/n1-ref.sh"' in text
    calls = re.findall(r"^\s*n1_resolve (.+)$", text, re.MULTILINE)
    assert [tuple(call.split()) for call in calls] == [require]
    # The derivation lives in prev_tree.py now, not in a copy per script.
    assert "HEAD^1^{commit}" not in text


def test_the_chocolatey_script_requires_its_own_channel():
    script, require = LEGS[("ash-package.yml", "chocolatey")]
    text = (REPO_ROOT / script).read_text(encoding="utf-8")
    for path in require:
        assert f"'--require', '{path}'" in text
    assert "else { 'auto' }" in text


# -- 3. the derivation on every shape of history ------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
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
