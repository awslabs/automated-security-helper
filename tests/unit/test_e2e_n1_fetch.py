# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The "Fetch the N-1 ref" step of every e2e upgrade leg, held to the clone it runs in.

Each upgrade leg builds N-1 from origin/v4-capabilities, or from HEAD's first parent
when that ref has HEAD's tree (scripts/e2e/prev_tree.py, and the same derivation in
wheel.sh, container.sh, homebrew.sh and editors/jetbrains/e2e-ide-cycle.sh). Two
things have to be true of the workflow for that to work on any branch:

1. The clone holds every commit the derivation can pick. The fetch brings in
   v4-capabilities and its parent; HEAD's parent comes from the checkout, which by
   default fetches one commit. A HEAD that is a different commit from v4-capabilities
   but has its tree (a branch whose content landed on v4-capabilities through another
   commit, or a pull request's merge commit with no net change) then takes the
   fallback to HEAD^ and finds nothing there. The behavioral test below rebuilds that
   clone from each leg's own checkout depth and fetch command.

2. In a `container:` job, git runs as the checkout's owner. The runner checks out as
   its host user and the container runs as root, so a root git refuses the repository
   ("detected dubious ownership"); actions/checkout's safe.directory entry lives in a
   temporary HOME and does not outlast the checkout step. That is what failed the
   JetBrains headless-real job.

A leg can instead derive N-1 from the history with E2E_PREV_REF=auto, which names no
branch and so survives the branch being merged and deleted (the Chocolatey leg does).
Those legs are held to a full-history checkout and to the derivation picking a commit
that carries the channel, on every shape of history the leg will meet: a push to the
development branch, a pull request's merge commit whose base predates the channel, the
landing commit in a clone where the development branch no longer exists, a release
after the first one, and a squash landing that leaves no earlier package at all.
"""

from __future__ import annotations

import importlib.util
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PREV_TREE = REPO_ROOT / "scripts" / "e2e" / "prev_tree.py"
FETCH_STEP = "Fetch the N-1 ref"
BASE = "v4-capabilities"

# Every leg that fetches N-1, so that losing one (a rename, a deleted step) is noticed
# rather than shrinking what this file checks.
EXPECTED_LEGS = {
    ("ash-e2e.yml", "wheel"),
    ("ash-e2e.yml", "container"),
    ("ash-e2e.yml", "homebrew"),
    ("ash-jetbrains-ci.yml", "headless-real"),
}

# Legs that set E2E_PREV_REF=auto, with the paths each passes to prev_tree.py --require.
AUTO_LEGS = {
    ("ash-package.yml", "chocolatey"): (
        "packaging/chocolatey/ash.nuspec",
        "packaging/chocolatey/build.ps1",
    ),
}


def _load_prev_tree():
    spec = importlib.util.spec_from_file_location("ash_e2e_prev_tree_n1", PREV_TREE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pt = _load_prev_tree()


def _legs() -> dict:
    legs = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        jobs = yaml.safe_load(path.read_text(encoding="utf-8")).get("jobs") or {}
        for name, job in jobs.items():
            steps = job.get("steps") or []
            if any(step.get("name") == FETCH_STEP for step in steps):
                legs[(path.name, name)] = job
    return legs


LEGS = _legs()
LEG_IDS = [f"{wf}:{job}" for wf, job in sorted(LEGS)]


def _checkout(steps: list) -> tuple[int, dict]:
    for index, step in enumerate(steps):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            return index, step
    raise AssertionError("no actions/checkout step")


def _fetch(steps: list) -> tuple[int, dict]:
    for index, step in enumerate(steps):
        if step.get("name") == FETCH_STEP:
            return index, step
    raise AssertionError(f"no {FETCH_STEP!r} step")


def _git_fetch_argv(run: str) -> list:
    """The `git fetch ...` the step runs, without any wrapper in front of it."""
    lines = [line for line in run.splitlines() if re.search(r"\bgit fetch\b", line)]
    assert len(lines) == 1, f"expected one git fetch line, found {lines!r}"
    argv = shlex.split(lines[0])
    return argv[argv.index("git") :]


def test_every_n_minus_1_leg_is_checked():
    assert set(LEGS) == EXPECTED_LEGS


@pytest.mark.parametrize("key", sorted(LEGS), ids=LEG_IDS)
def test_the_checkout_holds_heads_parent(key):
    steps = LEGS[key]["steps"]
    _, checkout = _checkout(steps)
    depth = (checkout.get("with") or {}).get("fetch-depth", 1)
    # 0 is full history, which also has HEAD^.
    assert int(depth) == 0 or int(depth) >= 2, (
        f"{key}: the checkout fetches {depth} commit(s), so HEAD^ is missing when "
        f"origin/{BASE} has HEAD's tree but is not HEAD"
    )


@pytest.mark.parametrize("key", sorted(LEGS), ids=LEG_IDS)
def test_the_fetch_runs_before_the_ref_is_used(key):
    steps = LEGS[key]["steps"]
    checkout_at, _ = _checkout(steps)
    fetch_at, _ = _fetch(steps)
    users = [
        index
        for index, step in enumerate(steps)
        if "E2E_PREV_REF" in (step.get("env") or {})
    ]
    assert users, f"{key}: no step reads E2E_PREV_REF"
    assert checkout_at < fetch_at < min(users)


@pytest.mark.parametrize(
    "key", sorted(k for k in LEGS if "container" in LEGS[k]), ids=lambda k: ":".join(k)
)
def test_a_container_job_fetches_as_the_checkouts_owner(key):
    steps = LEGS[key]["steps"]
    fetch_at, fetch = _fetch(steps)
    run = fetch["run"]
    assert "run-unprivileged.sh git fetch" in run, (
        f"{key}: the fetch runs as the container's root, which git refuses in a "
        f"checkout the runner's user owns"
    )
    chowns = [
        index
        for index, step in enumerate(steps)
        if re.search(r'chown -R \S+ "\$GITHUB_WORKSPACE"', str(step.get("run", "")))
    ]
    assert chowns and min(chowns) < fetch_at, (
        f"{key}: the checkout is not handed to an unprivileged owner before the fetch"
    )


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
        (work / name).write_text(content, encoding="utf-8")
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


@pytest.fixture
def origin(tmp_path: Path) -> dict:
    """An origin with v4-capabilities and three kinds of branch HEAD.

    base:       v4-capabilities itself, as on a push to it.
    ahead:      a branch one commit ahead of v4-capabilities.
    same-tree:  a branch whose HEAD is not v4-capabilities but has its tree, its
                parent an older commit (the content landed on v4-capabilities through
                a different commit).
    """
    work = tmp_path / "author"
    work.mkdir()
    _git(work, "init", "-q", "-b", "trunk")
    old = _commit(work, {"pyproject.toml": _pyproject("3.7.0"), "a.py": "1\n"}, "old")
    side = _commit(work, {"a.py": "2\n"}, "side")
    _git(work, "checkout", "-q", "-b", BASE, old)
    base = _commit(work, {"a.py": "3\n"}, "base parent")
    base = _commit(work, {"a.py": "4\n"}, "base")
    _git(work, "branch", "ahead", base)
    _git(work, "checkout", "-q", "ahead")
    ahead = _commit(work, {"a.py": "5\n"}, "ahead")
    same = _same_tree_commit(work, base, side, "same tree as base")
    _git(work, "branch", "same-tree", same)
    bare = tmp_path / "origin.git"
    subprocess.run(
        ["git", "clone", "-q", "--bare", str(work), str(bare)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {
        "url": bare.as_uri(),
        "heads": {"base": base, "ahead": ahead, "same-tree": same},
        "expect": {
            "base": ("HEAD^", _git(work, "rev-parse", f"{base}^")),
            "ahead": (f"origin/{BASE}", base),
            "same-tree": ("HEAD^", side),
        },
        "branch": {"base": BASE, "ahead": "ahead", "same-tree": "same-tree"},
    }


def _ci_clone(origin: dict, shape: str, depth, dest: Path) -> Path:
    """What actions/checkout leaves: a clone of one branch at the job's fetch-depth."""
    argv = ["git", "clone", "-q", "--no-tags", "--single-branch"]
    argv += ["--branch", origin["branch"][shape]]
    if int(depth) != 0:
        argv += [f"--depth={int(depth)}"]
    subprocess.run(
        argv + [origin["url"], str(dest)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return dest


@pytest.mark.parametrize("shape", ["base", "ahead", "same-tree"])
@pytest.mark.parametrize("key", sorted(LEGS), ids=LEG_IDS)
def test_the_leg_derives_n_minus_1_on_any_branch(key, shape, origin, tmp_path):
    steps = LEGS[key]["steps"]
    _, checkout = _checkout(steps)
    depth = (checkout.get("with") or {}).get("fetch-depth", 1)
    _, fetch = _fetch(steps)
    clone = _ci_clone(origin, shape, depth, tmp_path / "ws")
    assert _git(clone, "rev-parse", "HEAD") == origin["heads"][shape]

    subprocess.run(
        _git_fetch_argv(fetch["run"]),
        cwd=clone,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    used_ref, prev_sha = pt.resolve_prev(clone, f"origin/{BASE}")
    assert (used_ref, prev_sha) == origin["expect"][shape]
    # The commit has to be readable, not merely named: every leg archives it.
    assert _git(clone, "cat-file", "-t", f"{prev_sha}^{{tree}}") == "tree"


# -- legs that derive N-1 with E2E_PREV_REF=auto -------------------------------


def _auto_legs() -> dict:
    legs = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        jobs = yaml.safe_load(path.read_text(encoding="utf-8")).get("jobs") or {}
        for name, job in jobs.items():
            for step in job.get("steps") or []:
                if (step.get("env") or {}).get("E2E_PREV_REF") == "auto":
                    legs[(path.name, name)] = job
    return legs


AUTO = _auto_legs()


def test_every_auto_leg_is_checked():
    assert set(AUTO) == set(AUTO_LEGS)


@pytest.mark.parametrize("key", sorted(AUTO), ids=lambda k: ":".join(k))
def test_an_auto_leg_checks_out_full_history_and_names_no_branch(key):
    job = AUTO[key]
    _, checkout = _checkout(job["steps"])
    assert int((checkout.get("with") or {}).get("fetch-depth", 1)) == 0, (
        f"{key}: the release tags and older ancestors auto chooses from need fetch-depth 0"
    )
    assert not any(step.get("name") == FETCH_STEP for step in job["steps"])
    assert f"refs/heads/{BASE}" not in yaml.safe_dump(job)


def test_the_chocolatey_script_requires_its_own_channel():
    script = (REPO_ROOT / "packaging/chocolatey/verify-on-windows.ps1").read_text(
        encoding="utf-8"
    )
    for path in AUTO_LEGS[("ash-package.yml", "chocolatey")]:
        assert f"'--require', '{path}'" in script
    assert "else { 'auto' }" in script
    assert "origin/v4-capabilities" not in script


CHANNEL = "packaging/chocolatey/build.ps1"


@pytest.fixture
def history(tmp_path: Path) -> dict:
    """main predates the channel; a development branch adds it.

    main:   m1 (tag v3.9.0) - m2 - M (merge of dev) - L
    dev:    m1 - d1 (adds the channel) - d2
    squash: m2 - S (dev's tree, one commit, no dev history)
    M also takes a change from m2, so its tree differs from d2's. v4.0.0 tags M.
    """
    work = tmp_path / "author"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    m1 = _commit(work, {"pyproject.toml": _pyproject("3.9.0"), "a.py": "1\n"}, "m1")
    _git(work, "tag", "v3.9.0", m1)
    _git(work, "checkout", "-q", "-b", "dev", m1)
    (work / "packaging" / "chocolatey").mkdir(parents=True)
    (work / CHANNEL).write_text("build\n", encoding="utf-8")
    d1 = _commit(work, {"pyproject.toml": _pyproject("4.0.0")}, "d1: add the channel")
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
    full = tmp_path / "origin.git"
    subprocess.run(
        ["git", "clone", "-q", "--bare", str(work), str(full)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # The same history once dev was merged and deleted, and before v4.0.0 existed.
    landed = tmp_path / "landed.git"
    subprocess.run(
        ["git", "clone", "-q", "--bare", str(work), str(landed)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _git(landed, "branch", "-D", "dev")
    _git(landed, "tag", "-d", "v4.0.0")
    return {
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


@pytest.mark.parametrize(
    ("label", "origin_key", "head", "want"),
    [
        # dev's parent carries the channel; v3.9.0 predates it and is passed over.
        ("a push to the development branch", "full", "d2", "d1"),
        # M^1 is main without the channel; the walk finds dev's side.
        ("the landing merge commit, dev deleted", "landed", "M", "d2"),
        # After a release, N-1 is that release.
        ("a commit after the first release", "full", "L", "M"),
    ],
)
def test_auto_picks_a_commit_that_carries_the_channel(
    history, tmp_path, label, origin_key, head, want
):
    sha = history["sha"]
    clone = _full_clone(history[origin_key], sha[head], tmp_path / "ws")
    used_ref, prev_sha = pt.resolve_auto(clone, [CHANNEL])
    assert prev_sha == sha[want], (label, used_ref)
    if head == "L":
        assert used_ref.startswith("v4.0.0"), used_ref


def test_auto_refuses_a_squash_landing_with_no_earlier_package(history, tmp_path):
    clone = _full_clone(history["full"], history["sha"]["S"], tmp_path / "ws")
    with pytest.raises(pt.DerivationError, match="introduces the channel"):
        pt.resolve_auto(clone, [CHANNEL])


def test_auto_in_a_shallow_clone_says_to_fetch_history(history, tmp_path):
    # The default actions/checkout clone: one commit of one branch, no tags.
    clone = _ci_clone(
        {"url": history["full"], "branch": {"squash": "squash"}},
        "squash",
        1,
        tmp_path / "ws",
    )
    with pytest.raises(pt.DerivationError, match="fetch-depth: 0"):
        pt.resolve_auto(clone, [CHANNEL])


def test_auto_without_a_required_path_is_refused(history, tmp_path):
    clone = _full_clone(history["full"], history["sha"]["d2"], tmp_path / "ws")
    with pytest.raises(pt.DerivationError, match="--require"):
        pt.resolve_auto(clone, [])
