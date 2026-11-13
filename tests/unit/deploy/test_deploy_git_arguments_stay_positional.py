#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Values the deploy targets hand to git as arguments are never read as git options.

Why this file exists
--------------------
Every image build fetches ASH with a ref and a repository URL the operator chooses
(``AshVersion`` / ``ash_version`` and ``ash_repository_clone_url``), and both
CodeCommit gates clone a pull request and check out commit ids from its event. git
parses options anywhere on its command line, before or after the positional
arguments, so a value that starts with ``-`` is read as an option unless ``--`` has
ended option parsing first. ``--upload-pack=<command>`` is the value these tests
use: as an option, it names a program git runs to serve the fetch.

What the deploy targets do now:

* the image builds pass ``--`` before the repository, so the URL is always the
  repository and the ref is always a refspec;
* the cdk-constructs buildspecs install ASH with ``pip install
  "git+<repository>@$ASH_VERSION"``. pip hands the ref to ``git checkout -q <ref>`` as
  an argument of its own, where ``--`` would make it a path, so the install phase
  first checks that ``ASH_VERSION`` is a plain git ref and stops the build otherwise;
* the gates pass ``--`` before the repository they clone, and check that both commit
  ids in the event are full hex object ids before any git call. ``git checkout``
  reads whatever follows ``--`` as paths, and git before 2.44 keeps
  ``--end-of-options`` in checkout's arguments rather than consuming it, so neither
  terminator can carry a commit there.

The fetch tests run the committed commands: the Terraform buildspec, rendered as
``templatefile`` renders it, the image build of every committed CDK template, and the
install phase of every committed cdk-constructs buildspec. They run against a local
repository with two values that start with ``-``:

* ``--upload-pack=<script>``, where the script creates a marker file and then serves
  the fetch, so the marker shows whether git ran it;
* ``-f``, which ``git checkout`` takes as ``--force``: before the install-phase check,
  pip's checkout succeeded with it and the default branch was built.

The install phase's ``pip`` is a stand-in that makes the git calls pip makes for a
``git+`` requirement (measured with pip 25.0.1 and 21.3.1): a clone, then
``git checkout -q <ref>``. pip itself is not a dependency of the test environment.
Each command also fetches a tag, a branch with a slash and a commit, so a command that
no longer fetches the ref it names cannot pass.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
import yaml

from tests.unit.deploy.buildspec_extraction import (
    CDK_TEMPLATE_DIR,
    GATE_HANDLER_MARKER,
    REPO_ROOT,
    heredoc_body,
    load_template,
    phase_commands,
    posix_shell,
    sole_command_containing,
)
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="executes POSIX buildspec commands destined for a Linux build container",
)

IMAGE_PIPELINE = REPO_ROOT / "deploy" / "terraform" / "modules" / "ash-image-pipeline"
TERRAFORM_GATE = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "codecommit-gate"
    / "files"
    / "ash_pr_gate.py"
)

#: What identifies the fetch command in each image build.
TERRAFORM_FETCH_MARKER = "git fetch"
CDK_FETCH_MARKER = "git init -q ash-src"

CONSTRUCTS = REPO_ROOT / "deploy" / "cdk-constructs"
#: The repository the cdk-constructs buildspecs install ASH from.
CONSTRUCTS_REPOSITORY = "https://github.com/awslabs/automated-security-helper.git"

#: Stands in for `python3 -m pip install ... "git+<repository>@<ref>"` in the
#: cdk-constructs install phase. It makes the git calls pip makes for that
#: requirement, as measured with pip 25.0.1 and 21.3.1: a clone, then
#: `git checkout -q <ref>` with the ref as an argument of its own. It clones the
#: local stand-in remote named by ASH_TEST_UPSTREAM, and refuses any repository
#: other than the one the buildspecs name.
PIP_STAND_IN = f"""#!/bin/sh
for requirement in "$@"; do :; done
spec="${{requirement#git+}}"
repository="${{spec%@*}}"
ref="${{spec##*@}}"
if [ "$repository" != "{CONSTRUCTS_REPOSITORY}" ]; then
  echo "unexpected repository: $repository" >&2
  exit 2
fi
git clone -q "$ASH_TEST_UPSTREAM" ash-src || exit 1
cd ash-src && exec git checkout -q "$ref"
"""

#: How the CDK image build writes the gate handler into the image.
CDK_GATE_HEREDOC = "ASH_CDK_EOF"

SOURCE_COMMIT = "a" * 40
DESTINATION_COMMIT = "b" * 40

#: Values a commit id field may not hold. The first four start with "-"; the last
#: three are not full hex object ids.
NOT_COMMIT_IDS = [
    "--upload-pack=touch marker",
    "-f",
    "--orphan=x",
    "-" + "a" * 39,
    "HEAD",
    "a" * 12,
    "g" * 40,
]


# ---------------------------------------------------------------------------
# A local repository standing in for the ASH remote
# ---------------------------------------------------------------------------


def _git_env(home: pathlib.Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "ash-test",
        "GIT_AUTHOR_EMAIL": "ash-test@example.invalid",
        "GIT_COMMITTER_NAME": "ash-test",
        "GIT_COMMITTER_EMAIL": "ash-test@example.invalid",
    }


def _git(cwd: pathlib.Path, home: pathlib.Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=_git_env(home),
        capture_output=True,
        text=True,
        check=False,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    assert result.returncode == 0, f"git {' '.join(args)} failed: {result.stderr}"
    return result.stdout.strip()


@pytest.fixture(scope="module")
def upstream(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """A bare repository: an untagged older commit, a tagged one on main (the
    default branch), and a branch with a slash in its name on a commit of its own."""
    root = tmp_path_factory.mktemp("ash-upstream")
    work = root / "work"
    work.mkdir()
    _git(work, root, "init", "-q", "-b", "main")
    (work / "marker.txt").write_text("one\n", encoding="utf-8")
    _git(work, root, "add", "marker.txt")
    _git(work, root, "commit", "-q", "-m", "one")
    older = _git(work, root, "rev-parse", "HEAD")
    (work / "marker.txt").write_text("two\n", encoding="utf-8")
    _git(work, root, "commit", "-q", "-am", "two")
    _git(work, root, "tag", "v9.9.9")
    tagged = _git(work, root, "rev-parse", "HEAD")
    _git(work, root, "checkout", "-q", "-b", "release/v3.8")
    (work / "marker.txt").write_text("three\n", encoding="utf-8")
    _git(work, root, "commit", "-q", "-am", "three")
    branch_tip = _git(work, root, "rev-parse", "HEAD")
    _git(work, root, "checkout", "-q", "main")
    remote = root / "ash.git"
    _git(root, root, "clone", "-q", "--bare", str(work), str(remote))
    # A hosted remote serves a fetch by commit id; a bare local one does not unless
    # told to, so this makes the stand-in behave like the real remote.
    _git(remote, root, "config", "uploadpack.allowAnySHA1InWant", "true")
    return SimpleNamespace(
        url=f"file://{remote}", tagged=tagged, older=older, branch_tip=branch_tip
    )


@pytest.fixture
def upload_pack_probe(tmp_path: pathlib.Path) -> SimpleNamespace:
    """``--upload-pack=<script>``, where the script leaves a marker and then serves.

    Serving the fetch after leaving the marker means that, read as an option, the
    value both runs and lets the fetch succeed: the marker is the only difference.
    """
    marker = tmp_path / "upload-pack-ran"
    script = tmp_path / "upload-pack.sh"
    script.write_text(
        f'#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexec git upload-pack "$@"\n',
        encoding="utf-8",
    )
    script.chmod(0o755)
    return SimpleNamespace(value=f"--upload-pack={script}", marker=marker)


# ---------------------------------------------------------------------------
# The fetch commands, out of the committed templates
# ---------------------------------------------------------------------------


def _terraform_image_buildspec() -> dict:
    """Render buildspec.yml.tftpl as the module's `templatefile` call renders it."""
    text = (IMAGE_PIPELINE / "buildspec.yml.tftpl").read_text(encoding="utf-8")
    for name, relative in (
        ("wrapper_dockerfile_b64", "files/wrapper.Dockerfile"),
        ("init_script_b64", "files/ash-container-init"),
        ("serve_script_b64", "files/ash-mcp-serve"),
    ):
        placeholder = "${" + name + "}"
        assert placeholder in text, f"buildspec.yml.tftpl no longer embeds {name}"
        encoded = base64.b64encode((IMAGE_PIPELINE / relative).read_bytes()).decode()
        text = text.replace(placeholder, encoded)
    assert re.search(r"(?<!\$)\$\{", text) is None, (
        "buildspec.yml.tftpl has a template variable this does not fill"
    )
    # templatefile renders the escape $${ as a literal ${.
    return yaml.safe_load(text.replace("$${", "${"))


def _joined_buildspecs(template: dict) -> dict[str, dict]:
    """Every `Fn::Join` CodeBuild buildspec in a template, decoded, by logical id."""
    found: dict[str, dict] = {}
    for logical_id, resource in template.get("Resources", {}).items():
        if resource.get("Type") != "AWS::CodeBuild::Project":
            continue
        spec = resource.get("Properties", {}).get("Source", {}).get("BuildSpec")
        if not isinstance(spec, dict) or "Fn::Join" not in spec:
            continue
        delimiter, parts = spec["Fn::Join"]
        found[logical_id] = json.loads(
            delimiter.join(
                part if isinstance(part, str) else "CFN_SUBSTITUTION_PLACEHOLDER"
                for part in parts
            )
        )
    return found


def _cdk_image_builds() -> dict[str, dict]:
    """Every CDK image build, keyed ``<template>:<logical id>``."""
    builds: dict[str, dict] = {}
    for path in sorted(CDK_TEMPLATE_DIR.glob("*.template.json")):
        stack = path.name.replace(".template.json", "")
        for logical_id, spec in _joined_buildspecs(load_template(path)).items():
            if any(CDK_FETCH_MARKER in c for c in phase_commands(spec, "pre_build")):
                builds[f"{stack}:{logical_id}"] = spec
    return builds


CDK_IMAGE_BUILDS = _cdk_image_builds()


def _fetch_commands() -> dict[str, str]:
    """The fetch command of every image build the deploy targets define."""
    commands = {
        "terraform:ash-image-pipeline": sole_command_containing(
            _terraform_image_buildspec(), "build", TERRAFORM_FETCH_MARKER
        )
    }
    for name, spec in CDK_IMAGE_BUILDS.items():
        commands[f"cdk:{name}"] = sole_command_containing(
            spec, "pre_build", CDK_FETCH_MARKER
        )
    commands.update(_constructs_install_phases())
    return commands


def _constructs_install_phases() -> dict[str, str]:
    """Each committed cdk-constructs install phase, as one script.

    The script stops at the first failing command, as CodeBuild stops a phase.
    """
    phases: dict[str, str] = {}
    for path in sorted(CONSTRUCTS.glob("buildspec*.yml")):
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        commands = phase_commands(spec, "install")
        assert any(
            f"git+{CONSTRUCTS_REPOSITORY}@$ASH_VERSION" in c for c in commands
        ), f"{path.name} no longer installs ASH from {CONSTRUCTS_REPOSITORY}"
        phases[f"constructs:{path.name}"] = "\n".join(
            f'{command}\nash_rc=$?; [ "$ash_rc" -eq 0 ] || exit "$ash_rc"'
            for command in commands
        )
    return phases


FETCH_COMMANDS = _fetch_commands()

#: Targets whose fetch is git on the shell command line; the rest go through pip.
SHELL_GIT_TARGETS = sorted(t for t in FETCH_COMMANDS if not t.startswith("constructs:"))


def _run_fetch(
    target: str, workdir: pathlib.Path, ref: str, url: str
) -> subprocess.CompletedProcess:
    """Run one target's fetch the way CodeBuild runs it."""
    env = _git_env(workdir)
    # Each target names the two variables its own way; setting both names lets
    # one runner serve every target.
    env.update(
        {
            "ASH_VERSION": ref,
            "ASH_REPO_CLONE_URL": url,
            "ASH_REPOSITORY_URL": url,
        }
    )
    if target.startswith("constructs:"):
        # The cdk-constructs buildspecs name their repository; the pip stand-in
        # clones the local remote in its place.
        bin_dir = workdir.parent / "installer-bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        stand_in = bin_dir / "python3"
        stand_in.write_text(PIP_STAND_IN, encoding="utf-8")
        stand_in.chmod(0o755)
        env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
        env["ASH_TEST_UPSTREAM"] = url
    workdir.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [posix_shell(env), "-c", FETCH_COMMANDS[target]],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=CHILD_TIMEOUT_SECONDS,
    )


def _head(workdir: pathlib.Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(workdir / "ash-src"), "rev-parse", "HEAD"],
        env=_git_env(workdir),
        capture_output=True,
        text=True,
        check=False,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _git_segments(command: str) -> list[list[str]]:
    """Each shell-level git invocation in a command, as words."""
    segments: list[list[str]] = []
    for line in command.splitlines():
        for segment in re.split(r"&&|\|\||;|\|", line):
            stripped = segment.strip().lstrip("(").strip()
            if stripped.startswith("git "):
                segments.append(shlex.split(stripped))
    return segments


# ---------------------------------------------------------------------------
# The image builds
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_every_image_build_fetch_was_found():
    # One Terraform image pipeline; AgentCore, Fargate, the gate and the pipeline
    # each build once in CDK, and AshImagePipeline builds both architectures.
    stacks = sorted(
        name.split(":")[1] for name in FETCH_COMMANDS if name.startswith("cdk:")
    )
    assert stacks == sorted(
        [
            "AshAgentCore",
            "AshCodeCommitGate",
            "AshDistributedPipeline",
            "AshFargate",
            "AshImagePipeline",
            "AshImagePipeline",
        ]
    )
    assert "terraform:ash-image-pipeline" in FETCH_COMMANDS
    assert sorted(t for t in FETCH_COMMANDS if t.startswith("constructs:")) == [
        "constructs:buildspec-merge.yml",
        "constructs:buildspec-shard.yml",
        "constructs:buildspec.yml",
    ]


@pytest.mark.parametrize("target", SHELL_GIT_TARGETS)
@pytest.mark.unit
def test_git_options_end_before_every_variable_argument(target):
    """Every git call in the fetch has `--` before its first `$VARIABLE` argument."""
    checked = 0
    for words in _git_segments(FETCH_COMMANDS[target]):
        variable_at = [i for i, word in enumerate(words) if "$" in word]
        if not variable_at:
            continue
        checked += 1
        assert "--" in words[: variable_at[0]], (
            f"{target}: {' '.join(words)!r} passes a variable without `--` before it, "
            "so a value starting with '-' is read as a git option"
        )
    assert checked, f"{target}: found no git call that passes a variable"


@pytest.mark.parametrize("target", sorted(FETCH_COMMANDS))
@pytest.mark.parametrize("which", ["tag", "branch", "commit"])
@pytest.mark.integration
def test_control_the_fetch_checks_out_the_ref_it_names(
    target, which, upstream, tmp_path
):
    ref, expected = {
        "tag": ("v9.9.9", upstream.tagged),
        "branch": ("release/v3.8", upstream.branch_tip),
        "commit": (upstream.older, upstream.older),
    }[which]
    result = _run_fetch(target, tmp_path / "build", ref, upstream.url)
    assert result.returncode == 0, f"{target}: {result.stderr[-2000:]}"
    assert _head(tmp_path / "build") == expected


@pytest.mark.parametrize("target", sorted(FETCH_COMMANDS))
@pytest.mark.parametrize("value", ["upload-pack", "force"])
@pytest.mark.integration
def test_a_ref_starting_with_a_dash_never_reaches_git_as_an_option(
    target, value, upstream, upload_pack_probe, tmp_path
):
    """Fetched as a ref, or refused before the installer: never an option.

    `-f` is the value that shows the difference for an installer that checks out
    the ref: `git checkout -q -f` succeeds and leaves the default branch checked out.
    """
    ref = upload_pack_probe.value if value == "upload-pack" else "-f"
    result = _run_fetch(target, tmp_path / "build", ref, upstream.url)
    assert not upload_pack_probe.marker.exists(), (
        f"{target}: git read the ref {ref!r} as an option and ran the program it names"
    )
    assert result.returncode != 0, (
        f"{target}: the ref {ref!r} names no ref, and the fetch succeeded with "
        f"{_head(tmp_path / 'build')} checked out"
    )
    assert ref in result.stderr, (
        f"{target}: the failure does not name the value: {result.stderr[-2000:]}"
    )


@pytest.mark.integration
def test_a_repository_url_starting_with_a_dash_is_the_terraform_remote_url(
    upload_pack_probe, tmp_path
):
    """The Terraform build adds the URL as a remote, so it reaches `git remote add`."""
    target = "terraform:ash-image-pipeline"
    workdir = tmp_path / "build"
    result = _run_fetch(target, workdir, "v9.9.9", upload_pack_probe.value)
    assert not upload_pack_probe.marker.exists()
    assert result.returncode != 0, (
        f"{target}: fetched from a URL that names no repository"
    )
    url = subprocess.run(
        ["git", "-C", str(workdir / "ash-src"), "config", "--get", "remote.origin.url"],
        env=_git_env(workdir),
        capture_output=True,
        text=True,
        check=False,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    assert url.stdout.strip() == upload_pack_probe.value, (
        f"{target}: `git remote add` did not take the value as the URL: "
        f"{result.stderr[-2000:]}"
    )


@pytest.mark.parametrize(
    "target", sorted(t for t in FETCH_COMMANDS if t.startswith("cdk:"))
)
@pytest.mark.integration
def test_a_repository_url_starting_with_a_dash_is_the_cdk_fetch_repository(
    target, upload_pack_probe, tmp_path
):
    result = _run_fetch(target, tmp_path / "build", "v9.9.9", upload_pack_probe.value)
    assert not upload_pack_probe.marker.exists()
    assert result.returncode != 0, (
        f"{target}: fetched from a URL that names no repository"
    )


# ---------------------------------------------------------------------------
# The Terraform CodeCommit gate
# ---------------------------------------------------------------------------


def _load_terraform_gate() -> ModuleType:
    """Load the gate by path; it is packaged into a Lambda, not imported."""
    spec = importlib.util.spec_from_file_location(
        "_ash_pr_gate_git_args", TERRAFORM_GATE
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _event(source: Any = SOURCE_COMMIT, destination: Any = DESTINATION_COMMIT) -> dict:
    return {
        "detail": {
            "event": "pullRequestCreated",
            "repositoryNames": ["repo"],
            "pullRequestId": "7",
            "sourceCommit": source,
            "destinationCommit": destination,
            "sourceReference": "refs/heads/feature",
            "revisionId": "rev-1",
        }
    }


class _Recorder:
    """Stands in for a gate's `_run`: records argv and answers with one exit code."""

    def __init__(self, returncode: int = 0):
        self.calls: list[list[str]] = []
        self.returncode = returncode

    def __call__(self, argv, *args, **kwargs):
        self.calls.append(list(argv))
        return SimpleNamespace(returncode=self.returncode, stdout="", stderr="")


@pytest.mark.parametrize("field", ["source", "destination"])
@pytest.mark.parametrize("value", NOT_COMMIT_IDS)
@pytest.mark.unit
def test_the_terraform_gate_refuses_an_event_commit_that_is_not_a_commit_id(
    field, value, monkeypatch, tmp_path
):
    gate = _load_terraform_gate()
    recorder = _Recorder()
    monkeypatch.setattr(gate, "_run", recorder)
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")
    monkeypatch.setattr(
        gate.boto3, "client", lambda *a, **k: pytest.fail("the gate called AWS")
    )
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    event = _event(**{field: value})

    with pytest.raises(ValueError, match="commit id"):
        gate.parse_event(event)
    with pytest.raises(ValueError, match="commit id"):
        gate.handler(event, None)
    assert recorder.calls == [], f"git ran with an event commit of {value!r}"


@pytest.mark.unit
def test_the_terraform_gate_accepts_full_commit_ids():
    gate = _load_terraform_gate()
    parsed = gate.parse_event(_event())
    assert (parsed["source_commit"], parsed["destination_commit"]) == (
        SOURCE_COMMIT,
        DESTINATION_COMMIT,
    )
    # A SHA-256 repository's ids are 64 hex digits.
    parsed = gate.parse_event(_event("c" * 64, "D" * 40))
    assert parsed["source_commit"] == "c" * 64


@pytest.mark.unit
def test_the_terraform_gate_clone_ends_options_before_the_repository(
    monkeypatch, tmp_path
):
    gate = _load_terraform_gate()
    recorder = _Recorder()
    monkeypatch.setattr(gate, "_run", recorder)
    monkeypatch.setattr(gate, "WORK_ROOT", tmp_path / "ash-gate")

    gate.clone_source("repo", "feature", SOURCE_COMMIT, "us-east-1")

    clones = [argv for argv in recorder.calls if argv[:2] == ["git", "clone"]]
    assert len(clones) == 1, recorder.calls
    clone = clones[0]
    remote = "codecommit::us-east-1://repo"
    assert "--" in clone and clone.index("--") < clone.index(remote), clone
    checkouts = [argv for argv in recorder.calls if "checkout" in argv]
    assert checkouts and checkouts[0][-1] == SOURCE_COMMIT, recorder.calls


# ---------------------------------------------------------------------------
# The CDK CodeCommit gate, out of the committed templates
# ---------------------------------------------------------------------------


def _cdk_gate_sources() -> dict[str, str]:
    """The gate handler each committed CDK build writes into its image."""
    sources: dict[str, str] = {}
    for path in sorted(CDK_TEMPLATE_DIR.glob("*.template.json")):
        stack = path.name.replace(".template.json", "")
        for logical_id, spec in _joined_buildspecs(load_template(path)).items():
            for phase in spec.get("phases", {}):
                for command in phase_commands(spec, phase):
                    if f"cat > ash-src/{GATE_HANDLER_MARKER} <<" in command:
                        sources[f"{stack}:{logical_id}"] = heredoc_body(
                            command, delimiter=CDK_GATE_HEREDOC
                        )
    return sources


CDK_GATE_SOURCES = _cdk_gate_sources()


@pytest.mark.unit
def test_every_cdk_gate_handler_was_found():
    assert sorted(name.split(":")[0] for name in CDK_GATE_SOURCES) == [
        "AshCodeCommitGate",
        "AshImagePipeline",
    ]


class _CodeCommit:
    """Records the CodeCommit calls a gate makes."""

    def __init__(self):
        self.calls: list[str] = []
        self.exceptions = SimpleNamespace(
            PullRequestCannotBeApprovedByAuthorException=type(
                "PullRequestCannotBeApprovedByAuthorException", (Exception,), {}
            )
        )

    def post_comment_for_pull_request(self, **kwargs):
        self.calls.append("post_comment_for_pull_request")

    def update_pull_request_approval_state(self, **kwargs):
        self.calls.append("update_pull_request_approval_state")


def _load_cdk_gate(
    name: str, tmp_path: pathlib.Path, monkeypatch, recorder: _Recorder
) -> tuple[ModuleType, _CodeCommit]:
    """Import one committed CDK gate handler with its side effects stubbed."""
    source = tmp_path / "ash_gate_handler.py"
    source.write_text(CDK_GATE_SOURCES[name], encoding="utf-8")
    spec = importlib.util.spec_from_file_location("_ash_cdk_gate_git_args", source)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    codecommit = _CodeCommit()
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.setattr(module, "_run", recorder)
    monkeypatch.setattr(module, "_scan_env", lambda work: {})
    monkeypatch.setattr(module, "_check_completeness_flag", lambda env: None)
    monkeypatch.setattr(module, "_scan_config", lambda work: str(work) + "/c.yaml")
    monkeypatch.setattr(module.boto3, "client", lambda *a, **k: codecommit)
    monkeypatch.setattr(module.tempfile, "mkdtemp", lambda **k: str(workdir))
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("ASH_APPROVAL_GATE", raising=False)
    monkeypatch.delenv("ASH_CHANGED_FILES_ONLY", raising=False)
    return module, codecommit


@pytest.mark.parametrize("name", sorted(CDK_GATE_SOURCES))
@pytest.mark.parametrize("field", ["source", "destination"])
@pytest.mark.parametrize("value", NOT_COMMIT_IDS)
@pytest.mark.unit
def test_the_cdk_gate_refuses_an_event_commit_that_is_not_a_commit_id(
    name, field, value, monkeypatch, tmp_path
):
    recorder = _Recorder()
    gate, codecommit = _load_cdk_gate(name, tmp_path, monkeypatch, recorder)

    with pytest.raises(RuntimeError, match="commit id"):
        gate.handler(_event(**{field: value}), None)
    assert recorder.calls == [], f"{name}: a command ran with a commit of {value!r}"
    assert codecommit.calls == [], f"{name}: called CodeCommit for that event"


@pytest.mark.parametrize("name", sorted(CDK_GATE_SOURCES))
@pytest.mark.unit
def test_the_cdk_gate_clone_ends_options_before_the_repository(
    name, monkeypatch, tmp_path
):
    recorder = _Recorder()
    gate, _ = _load_cdk_gate(name, tmp_path, monkeypatch, recorder)

    gate.handler(_event(), None)

    clones = [argv for argv in recorder.calls if argv[:2] == ["git", "clone"]]
    assert len(clones) == 1, recorder.calls
    clone = clones[0]
    remote = "codecommit::us-east-1://repo"
    assert "--" in clone and clone.index("--") < clone.index(remote), clone
    checkouts = [argv for argv in recorder.calls if "checkout" in argv]
    assert checkouts and checkouts[0][-1] == SOURCE_COMMIT, recorder.calls
