#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CodeCommit gate must not scan with the environment its image gives it.

WHY THIS FILE EXISTS
--------------------
Lambda runs a container image with a read-only root filesystem -- only /tmp is
writable -- and replaces PATH with its own. Every path the ASH image points a
scanner at is therefore unwritable at scan time: the three data caches the base
image sets (``GRYPE_DB_CACHE_DIR``, ``SEMGREP_RULES_CACHE_DIR`` and
``OPENGREP_RULES_CACHE_DIR``, all under ``/deps``), ``HOME``, and uv's cache and
tool directory. A measured run in that state reported bandit, checkov and semgrep
MISSING, opengrep ERROR, and grype PASSED with zero findings; the CDK flavor of
this gate carries that measurement next to its own fix.

The Terraform flavor had no equivalent. Its ``_run`` never passed ``env=``, so the
child inherited exactly the environment described above.

REDIRECTING IS ONLY HALF OF IT, AND THE OTHER HALF IS THE SILENT ONE
-------------------------------------------------------------------
Pointing those variables at fresh ``/tmp`` directories makes them writable and, on
its own, makes them EMPTY. The uv tools, the vulnerability database and the
semgrep/opengrep rulesets are all on the read-only layer the redirect just left
behind. An image built with offline mode carries a database the Dockerfile asserts
is non-empty at build time, and the redirect put it out of reach at scan time --
so the build-time assertion was defeated by the runtime, and grype with no
database reports PASSED with zero findings.

So the assertions here are about the OUTCOME: after ``_scan_env`` runs, is each
redirected path actually reachable. That mirrors the Dockerfile's own offline
assertion, which deliberately checks the artifacts rather than re-testing the
OFFLINE flag, because a check that re-tests the input is silenced by whatever
silenced the thing it is checking.

BOTH FLAVORS, ONE TEST BODY
---------------------------
There are two copies of this function: a real Python module for the Terraform
target, and a Python string inside a TypeScript template literal for the CDK one.
Two copies of a fix drift, and the drift is invisible because only one of them is
importable. So every behavioral test below is parametrized over both, with the CDK
copy sliced out of the TypeScript and executed. The slice is asserted to have
produced callables, because an extraction that silently found nothing would make
the CDK half of every test vacuous.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
from types import ModuleType, SimpleNamespace
from typing import Any, Callable, Dict, List

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
GATE_PATH = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "codecommit-gate"
    / "files"
    / "ash_pr_gate.py"
)
WRAPPER_DOCKERFILE = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "ash-image-pipeline"
    / "files"
    / "wrapper.Dockerfile"
)
CDK_SCRIPTS = REPO_ROOT / "deploy" / "cdk" / "lib" / "ash-container-scripts.ts"
CDK_IMAGE_BUILD = REPO_ROOT / "deploy" / "cdk" / "lib" / "ash-image-build.ts"

#: The variables the image records and the handler reads. Named once here so the
#: contract test below and the behavioral tests cannot disagree about the set.
BAKED_VARS = (
    "ASH_IMAGE_PATH",
    "ASH_BAKED_UV_TOOL_DIR",
    "ASH_BAKED_GRYPE_DB_DIR",
    "ASH_BAKED_SEMGREP_RULES_DIR",
    "ASH_BAKED_OPENGREP_RULES_DIR",
)

#: Where each baked directory has to end up readable from, once redirected.
REDIRECTED_CACHES = (
    ("ASH_BAKED_GRYPE_DB_DIR", "GRYPE_DB_CACHE_DIR"),
    ("ASH_BAKED_SEMGREP_RULES_DIR", "SEMGREP_RULES_CACHE_DIR"),
    ("ASH_BAKED_OPENGREP_RULES_DIR", "OPENGREP_RULES_CACHE_DIR"),
)


def _load_gate() -> ModuleType:
    """Load the Terraform gate by path; it is packaged into a Lambda, not imported."""
    assert GATE_PATH.is_file(), f"gate not found at {GATE_PATH}"
    spec = importlib.util.spec_from_file_location("_ash_pr_gate_scan_env", GATE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_cdk_scan_env() -> SimpleNamespace:
    """Slice the CDK gate's `_scan_env` out of the TypeScript and execute it.

    The region sliced -- from the BAKED_SCANNER_DATA constant to the start of
    `_scan_summary` -- contains no backslash escapes, no backticks and no `${`,
    so the bytes in the template literal are already the Python they represent.
    Regions of that handler which DO carry escapes (the markdown bodies) are
    deliberately outside the slice.

    Executed rather than string-matched because `toContain` on a TypeScript
    literal cannot tell a working implementation from a broken one: the strings
    are present either way. That is the same reasoning the CDK's own entrypoint
    probe tests are built on.

    Anchored on CODE, not on a comment. The first version anchored on the comment
    above BAKED_SCANNER_DATA, and rewording that comment -- which happened in the
    same change, to buy back CloudFormation template budget -- made the slice
    raise. That was the positive control below doing its job, and the lesson is
    that a comment is not an anchor: it is the part of a file people rewrite.
    """
    source = CDK_SCRIPTS.read_text(encoding="utf-8")
    start = source.index("BAKED_SCANNER_DATA = (")
    end = source.index("def _scan_summary(")
    snippet = source[start:end]

    # Positive control on the extraction itself. Without it, a rename in the
    # TypeScript would leave the CDK half of every test below exercising nothing
    # while still reporting green.
    assert "def _scan_env(" in snippet, "the CDK _scan_env was not in the slice"
    assert "def _seed_from_baked(" in snippet, "the CDK seeding helper was not sliced"

    namespace: Dict[str, Any] = {
        "os": os,
        "shutil": shutil,
        "subprocess": subprocess,
        "__name__": "_cdk_gate_scan_env",
    }
    exec(compile(snippet, str(CDK_SCRIPTS), "exec"), namespace)  # noqa: S102
    module = SimpleNamespace(**namespace)
    assert callable(module._scan_env)
    assert callable(module._seed_from_baked)
    return module


@pytest.fixture
def gate() -> ModuleType:
    return _load_gate()


@pytest.fixture(autouse=True)
def _no_ambient_image_variables(monkeypatch) -> None:
    """Nothing the developer's shell happens to export may decide a verdict here.

    An earlier test in this directory passed locally and failed on every CI leg
    because it inherited AWS_REGION. These variables are the image's, so a shell
    that has one would make a test measure the shell.
    """
    for name in (*BAKED_VARS, "ASH_OFFLINE", "ASH_SCAN_EXTRA_ARGS"):
        monkeypatch.delenv(name, raising=False)


class _Flavor:
    """One implementation of `_scan_env`, callable with no arguments.

    Carries no expected paths. Every test below reads the paths out of the returned
    environment rather than reconstructing them here, so an implementation that
    quietly moved one is caught instead of being compared against a copy of its own
    layout.
    """

    def __init__(self, name: str, scan_env: Callable[[], Dict[str, str]]):
        self.name = name
        self.scan_env = scan_env


@pytest.fixture(params=["terraform", "cdk"])
def flavor(request, gate, monkeypatch, tmp_path) -> _Flavor:
    """The two copies, adapted to one signature.

    The Terraform copy takes its root from the module-level WORK_ROOT, which is
    what a Lambda gives it; the CDK copy takes a workdir argument. Only that
    difference is normalized -- both then do their own thing.
    """
    if request.param == "terraform":
        monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
        return _Flavor("terraform", gate._scan_env)

    cdk = _load_cdk_scan_env()
    workdir = tmp_path / "cdk-work"
    workdir.mkdir()
    return _Flavor("cdk", lambda: cdk._scan_env(str(workdir)))


def _bake(monkeypatch, tmp_path, *, grype=True, semgrep=True, opengrep=True) -> None:
    """Stand in for an offline image: three baked caches with content in them.

    grype's database is a versioned SUBDIRECTORY, which is why that fixture is a
    directory and the rule caches are files -- the two shapes are seeded
    differently on purpose.
    """
    baked = tmp_path / "deps"
    if grype:
        db = baked / ".grype" / "5"
        db.mkdir(parents=True)
        (db / "vulnerability.db").write_bytes(b"sqlite\n")
        monkeypatch.setenv("ASH_BAKED_GRYPE_DB_DIR", str(baked / ".grype"))
    if semgrep:
        rules = baked / ".semgrep"
        rules.mkdir(parents=True)
        (rules / "ci.yml").write_text("rules: []\n", encoding="utf-8")
        monkeypatch.setenv("ASH_BAKED_SEMGREP_RULES_DIR", str(rules))
    if opengrep:
        rules = baked / ".opengrep"
        rules.mkdir(parents=True)
        (rules / "ci.yml").write_text("rules: []\n", encoding="utf-8")
        monkeypatch.setenv("ASH_BAKED_OPENGREP_RULES_DIR", str(rules))


# ---------------------------------------------------------------------------
# 1. The scan has to run under the rewritten environment at all
# ---------------------------------------------------------------------------


def test_run_scan_passes_the_redirected_environment(gate, monkeypatch, tmp_path):
    """The defect: `_run` was called with no `env=`, so the child inherited Lambda's.

    Asserted on the RESOLVED values rather than on the presence of a keyword. A
    handler that passed `env=dict(os.environ)` would satisfy "an env was passed"
    while changing nothing, which is the shape of defect this whole effort exists
    to remove.
    """
    captured: List[Dict[str, Any]] = []

    def _fake_run(argv, cwd=None, env=None):
        captured.append({"argv": list(argv), "cwd": cwd, "env": env})
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gate, "_run", _fake_run)
    work_root = tmp_path / "ash-gate"
    monkeypatch.setattr(gate, "WORK_ROOT", work_root)

    gate.run_scan(tmp_path / "src", "low", True)

    assert captured, "run_scan did not invoke the scanner"
    env = captured[0]["env"]
    assert env is not None, (
        "the scan inherited the process environment, so every scanner cache still "
        "points at the read-only root filesystem the image set up"
    )
    for name in (
        "GRYPE_DB_CACHE_DIR",
        "SEMGREP_RULES_CACHE_DIR",
        "OPENGREP_RULES_CACHE_DIR",
        "UV_CACHE_DIR",
        "UV_TOOL_DIR",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "HOME",
    ):
        resolved = pathlib.Path(env[name])
        assert resolved.is_relative_to(work_root), (
            f"{name} resolves to {resolved}, outside the only writable path this "
            "function has"
        )


def test_the_git_calls_keep_the_inherited_environment(gate, monkeypatch, tmp_path):
    """Only the scan is redirected. git-remote-codecommit needs Lambda's own
    credential variables, and a rewritten HOME would move its config."""
    calls: List[Dict[str, Any]] = []

    def _fake_run(argv, cwd=None, env=None):
        calls.append({"argv": list(argv), "env": env})
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gate, "_run", _fake_run)
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")

    gate.clone_source("repo", "feature", "a" * 40, "us-east-1")

    assert calls, "clone_source ran no subprocess"
    assert all(call["env"] is None for call in calls), (
        f"a git call was given a rewritten environment: {calls}"
    )


# ---------------------------------------------------------------------------
# 2. What the rewritten environment has to contain, in both flavors
# ---------------------------------------------------------------------------


def test_every_redirected_path_is_writable_and_created(flavor):
    env = flavor.scan_env()
    for name in (
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "UV_TOOL_DIR",
        *[c for _, c in REDIRECTED_CACHES],
    ):
        path = pathlib.Path(env[name])
        assert path.is_dir(), f"{flavor.name}: {name} -> {path} was not created"
        probe = path / ".writable-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()


def test_the_image_path_is_restored_when_the_image_recorded_one(flavor, monkeypatch):
    monkeypatch.setenv("ASH_IMAGE_PATH", "/baked/bin:/usr/local/bin")
    env = flavor.scan_env()
    assert env["PATH"] == "/baked/bin:/usr/local/bin", flavor.name


def test_the_path_is_left_alone_when_the_image_recorded_none(flavor, monkeypatch):
    """So a locally-run handler behaves normally rather than losing its PATH."""
    monkeypatch.setenv("PATH", "/only/this")
    env = flavor.scan_env()
    assert env["PATH"] == "/only/this", flavor.name


# ---------------------------------------------------------------------------
# 3. The uv tool directory: directories linked, files deliberately skipped
# ---------------------------------------------------------------------------


def test_the_uv_tool_dir_is_seeded_by_symlink(flavor, monkeypatch, tmp_path):
    """Linked rather than copied: the tools are already in the image.

    Pointing UV_TOOL_DIR at an empty directory makes uv reinstall all of them from
    PyPI, which works only where the function has egress and fails outright in an
    offline image. Copying costs hundreds of megabytes of the same ephemeral
    storage the clone and ASH's output draw on.
    """
    baked = tmp_path / "baked-tools"
    (baked / "bandit").mkdir(parents=True)
    (baked / "bandit" / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    monkeypatch.setenv("ASH_BAKED_UV_TOOL_DIR", str(baked))

    env = flavor.scan_env()
    link = pathlib.Path(env["UV_TOOL_DIR"]) / "bandit"
    assert link.is_symlink(), f"{flavor.name}: the baked tool dir was not linked"
    assert link.resolve() == (baked / "bandit").resolve()


def test_a_file_in_the_baked_tool_dir_is_not_seeded(flavor, monkeypatch, tmp_path):
    """The `isdir` check, and it is load-bearing.

    uv's baked tree also holds uv's own `.lock`. uv must CREATE that lock inside
    UV_TOOL_DIR; a symlink to the baked one aims that write at the read-only
    filesystem while looking correctly seeded, and a copy of it is a stale lock
    rather than an absent one. The first version of the CDK fix linked it and three
    scanners still ERRORed.
    """
    baked = tmp_path / "baked-tools"
    (baked / "checkov").mkdir(parents=True)
    (baked / ".lock").write_text("", encoding="utf-8")
    (baked / ".gitignore").write_text("*\n", encoding="utf-8")
    monkeypatch.setenv("ASH_BAKED_UV_TOOL_DIR", str(baked))

    tool_dir = pathlib.Path(flavor.scan_env()["UV_TOOL_DIR"])
    assert (tool_dir / "checkov").is_symlink(), flavor.name
    for skipped in (".lock", ".gitignore"):
        assert not (tool_dir / skipped).exists(), (
            f"{flavor.name}: {skipped} was seeded; uv's lock must be uv's to create"
        )


# ---------------------------------------------------------------------------
# 4. The three data caches: the half that was missing entirely
# ---------------------------------------------------------------------------


def test_the_baked_scanner_data_is_reachable_after_redirection(
    flavor, monkeypatch, tmp_path
):
    """The assertion the build has and the runtime did not.

    The Dockerfile asserts these three directories are non-empty when the image is
    built offline. Nothing asserted they were still reachable after the redirect,
    and they were not: grype scanned an empty database and reported no findings.
    """
    _bake(monkeypatch, tmp_path)
    env = flavor.scan_env()

    for baked_var, cache_var in REDIRECTED_CACHES:
        writable = pathlib.Path(env[cache_var])
        entries = sorted(p.name for p in writable.iterdir())
        assert entries, (
            f"{flavor.name}: {cache_var} -> {writable} is empty, so the content "
            f"{baked_var} names is unreachable from the scan"
        )


def test_a_baked_directory_is_linked_and_a_baked_file_is_copied(
    flavor, monkeypatch, tmp_path
):
    """The shapes are seeded differently, and the difference is the point.

    A directory is read-only content in bulk -- grype's database is a versioned
    subdirectory -- so a link costs nothing. A FILE is what a scanner rewrites in
    place, and a link to one aims that write at the read-only layer: it would look
    seeded and fail at scan time. The copied ruleset must be writable.
    """
    _bake(monkeypatch, tmp_path)
    env = flavor.scan_env()

    grype = pathlib.Path(env["GRYPE_DB_CACHE_DIR"]) / "5"
    assert grype.is_symlink(), (
        f"{flavor.name}: the grype database was copied, not linked"
    )

    for cache_var in ("SEMGREP_RULES_CACHE_DIR", "OPENGREP_RULES_CACHE_DIR"):
        ruleset = pathlib.Path(env[cache_var]) / "ci.yml"
        assert ruleset.is_file(), f"{flavor.name}: {cache_var} has no ruleset"
        assert not ruleset.is_symlink(), (
            f"{flavor.name}: {cache_var}/ci.yml is a link onto the read-only layer, "
            "so a scanner rewriting its own rules file fails"
        )
        ruleset.write_text("rules: [changed]\n", encoding="utf-8")


def test_seeding_is_idempotent(flavor, monkeypatch, tmp_path):
    """A warm invocation re-uses what a cold one seeded rather than raising."""
    _bake(monkeypatch, tmp_path)
    first = flavor.scan_env()
    second = flavor.scan_env()
    for _, cache_var in REDIRECTED_CACHES:
        assert sorted(
            p.name for p in pathlib.Path(first[cache_var]).iterdir()
        ) == sorted(p.name for p in pathlib.Path(second[cache_var]).iterdir()), (
            flavor.name
        )


# ---------------------------------------------------------------------------
# 5. Offline: an unreachable cache must refuse rather than report no findings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("offline_value", ["YES", "yes", "true", "TRUE", "1"])
def test_an_offline_scan_refuses_when_a_baked_cache_is_empty(
    flavor, monkeypatch, tmp_path, offline_value
):
    """Every spelling ASH's own `is_offline_mode()` accepts, so the two agree.

    The refusal is the correct direction even though it converts a currently-green
    deployment into a failing one: an offline gate whose database never arrived was
    reporting zero findings from an empty database, and a clean report over an
    unexamined tree is the worst outcome this gate has.
    """
    _bake(monkeypatch, tmp_path, grype=False)
    monkeypatch.setenv("ASH_OFFLINE", offline_value)

    with pytest.raises(RuntimeError, match="GRYPE_DB_CACHE_DIR"):
        flavor.scan_env()


def test_an_offline_scan_with_every_cache_seeded_does_not_refuse(
    flavor, monkeypatch, tmp_path
):
    """The acceptance control. A guard that refuses a correct offline image is no use."""
    _bake(monkeypatch, tmp_path)
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    env = flavor.scan_env()
    assert pathlib.Path(env["GRYPE_DB_CACHE_DIR"]).is_dir(), flavor.name


def test_an_online_scan_still_runs_when_a_baked_cache_is_empty(
    flavor, monkeypatch, tmp_path
):
    """Scoped deliberately: online, grype can fetch a database, so the scan is slow
    rather than blind. Refusing here would break every non-offline deployment."""
    monkeypatch.setenv("ASH_OFFLINE", "NO")
    env = flavor.scan_env()
    assert pathlib.Path(env["GRYPE_DB_CACHE_DIR"]).is_dir(), flavor.name


def test_an_unset_offline_variable_is_not_offline(flavor, monkeypatch, tmp_path):
    """ASH's default is NO, so an image that never set it must not start refusing."""
    env = flavor.scan_env()
    assert pathlib.Path(env["SEMGREP_RULES_CACHE_DIR"]).is_dir(), flavor.name


# ---------------------------------------------------------------------------
# 6. The refusal has to be fail-closed end to end, not just a raise
# ---------------------------------------------------------------------------


class _FakeCodeCommit:
    def __init__(self) -> None:
        self.approval_calls: List[Dict[str, Any]] = []
        self.comments: List[Dict[str, Any]] = []

    def post_comment_for_pull_request(self, **kwargs):
        self.comments.append(kwargs)
        return {}

    def update_pull_request_approval_state(self, **kwargs):
        self.approval_calls.append(kwargs)
        return {}


def test_an_offline_refusal_reaches_the_pull_request_and_revokes(
    gate, monkeypatch, tmp_path
):
    """Otherwise the refusal is invisible where the decision is read.

    An approval standing from an earlier, cleaner commit must not survive a gate
    that declined to scan: nothing was examined, so nothing supports it.
    """
    client = _FakeCodeCommit()
    monkeypatch.setattr(
        gate.boto3,
        "client",
        lambda service, *a, **k: (
            client
            if service == "codecommit"
            else pytest.fail(f"unexpected boto3 client requested: {service}")
        ),
    )
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    monkeypatch.setattr(gate, "clone_source", lambda *a, **k: tmp_path / "src")
    monkeypatch.setattr(
        gate,
        "_run",
        lambda argv, cwd=None, env=None: pytest.fail(
            f"the scan ran with an unreachable offline database: {argv}"
        ),
    )
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("ASH_MANAGE_APPROVAL_STATE", "true")
    monkeypatch.setenv("ASH_OFFLINE", "YES")

    result = gate.handler(
        {
            "detail": {
                "pullRequestId": "7",
                "repositoryNames": ["repo"],
                "sourceCommit": "a" * 40,
                "destinationCommit": "b" * 40,
                "sourceReference": "refs/heads/feature",
                "revisionId": "rev-1",
            }
        },
        object(),
    )

    assert result["outcome"] == "error", (
        f"a gate that refused to scan reported a verdict: {result}"
    )
    assert [call["approvalState"] for call in client.approval_calls] == ["REVOKE"]
    assert client.comments, "the refusal left no comment on the pull request"
    assert "not been assessed" in client.comments[0]["content"]


# ---------------------------------------------------------------------------
# 7. The cross-file contract: what the handler reads, the image must bake
# ---------------------------------------------------------------------------


def _baked_by(text: str) -> set[str]:
    """Names assigned by an `ENV <NAME>=` line, in a Dockerfile or in a TS literal."""
    return set(re.findall(r"ENV (ASH_IMAGE_PATH|ASH_BAKED_[A-Z_]+)=", text))


def _read_by(text: str) -> set[str]:
    """Names fetched from the environment by a handler."""
    return set(re.findall(r"\"(ASH_IMAGE_PATH|ASH_BAKED_[A-Z_]+)\"", text))


@pytest.mark.parametrize(
    ("flavor_name", "image_file", "handler_file"),
    [
        ("terraform", WRAPPER_DOCKERFILE, GATE_PATH),
        ("cdk", CDK_IMAGE_BUILD, CDK_SCRIPTS),
    ],
)
def test_every_variable_the_handler_reads_is_baked_by_its_image(
    flavor_name, image_file, handler_file
):
    """The inert-half defect, made impossible to land.

    A handler that reads variables nothing bakes looks finished and does nothing:
    every lookup returns None, the seeding is skipped, and the scan runs against
    empty caches -- exactly the state this phase started from. The two halves live
    in different files and different languages, so nothing but this compares them.
    """
    baked = _baked_by(image_file.read_text(encoding="utf-8"))
    read = _read_by(handler_file.read_text(encoding="utf-8"))

    assert set(BAKED_VARS) <= read, (
        f"{flavor_name}: the handler reads {sorted(read)}, missing "
        f"{sorted(set(BAKED_VARS) - read)}"
    )
    assert read <= baked, (
        f"{flavor_name}: {sorted(read - baked)} is read by the handler and baked by "
        f"nothing in {image_file.name}, so it always resolves to None and the "
        "seeding it controls silently does nothing"
    )


def test_the_wrapper_dockerfile_reads_the_paths_off_the_stage(monkeypatch):
    """Not hardcoded, because ash_image_target decides which ASH stage is wrapped.

    Only the non-root stage declares `ENV HOME`, and the three cache variables are
    set by the base stage. A literal path would be correct for one target and
    silently wrong for another, and silently wrong here means an unseeded cache.
    """
    text = WRAPPER_DOCKERFILE.read_text(encoding="utf-8")
    assert 'ENV ASH_IMAGE_PATH="${PATH}"' in text
    assert 'ENV ASH_BAKED_GRYPE_DB_DIR="${GRYPE_DB_CACHE_DIR}"' in text
    assert 'ENV ASH_BAKED_SEMGREP_RULES_DIR="${SEMGREP_RULES_CACHE_DIR}"' in text
    assert 'ENV ASH_BAKED_OPENGREP_RULES_DIR="${OPENGREP_RULES_CACHE_DIR}"' in text
    # The default covers the root-running stages, which set no ENV HOME, so a bare
    # ${HOME} would expand to nothing and record "/.local/share/uv/tools".
    assert 'ENV ASH_BAKED_UV_TOOL_DIR="${HOME:-/root}/.local/share/uv/tools"' in text


def test_both_flavors_refuse_an_offline_scan_with_an_empty_cache():
    """Parity as a structural claim, next to the behavioral parity above.

    The behavioral tests already run both copies, but they load the CDK one by
    slicing TypeScript. This asserts the refusal exists in the committed text of
    both, so a slice that stopped finding it cannot be mistaken for a fix.
    """
    terraform = GATE_PATH.read_text(encoding="utf-8")
    cdk = CDK_SCRIPTS.read_text(encoding="utf-8")
    for label, text in (("terraform", terraform), ("cdk", cdk)):
        assert "ASH_OFFLINE" in text, f"{label} no longer consults offline mode"
        assert "Refusing to scan rather than reporting no findings" in text, (
            f"{label} no longer refuses an offline scan with an empty cache"
        )
