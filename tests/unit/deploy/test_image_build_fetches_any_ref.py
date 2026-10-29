# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CDK image build must build ASH at the ref AshVersion names: tag, branch or commit.

Why this file exists
--------------------
deploy/README.md tells anyone deploying from `main` between releases to set
`AshVersion` to the full commit SHA they checked out, and the parameter itself is
described as "ASH git ref (tag, branch, or commit)". The CDK image build checked ASH
out with `git clone --depth 1 --branch "${ASH_VERSION}"`, and git refuses a commit
there: "fatal: Remote branch <sha> not found in upstream origin", exit 128, so the
build failed before it started. It then built with
`INSTALL_ASH_REVISION=${ASH_VERSION}`, which makes the Dockerfile clone again with
`git clone --branch`; for a SHA that clone fails too, and the Dockerfile prints
"Skipping clone of repo for LOCAL revision" and builds the context anyway.

The Terraform image pipeline already did this right (buildspec.yml.tftpl): fetch
the ref into an empty repository, check out FETCH_HEAD, and build with
`INSTALL_ASH_REVISION=LOCAL` so the Dockerfile builds exactly that tree.

What is asserted
----------------
For every committed template whose image build checks ASH out, the template's own
checkout commands are run against a local repository with `ASH_VERSION` set to a
tag, a branch, and the full SHA of a commit no branch or tag points at; each time
`ash-src` must end up at that commit. And every `docker build` of `ash-src` passes
`INSTALL_ASH_REVISION=LOCAL`. Nothing here reaches a network or a container runner:
the repository is a local path and no docker command is run.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.unit.deploy.buildspec_extraction import (
    _joined_buildspec_texts,
    all_template_paths,
    load_template,
)

posix_only = pytest.mark.skipif(
    os.name == "nt", reason="runs the buildspec's shell, which CodeBuild runs on Linux"
)


def _image_builds() -> dict[str, list[str]]:
    """`<template> #<n>` -> the commands of each image-build buildspec that checks out ASH.

    One entry per buildspec: a template can hold more than one image build, and each
    runs in a fresh CodeBuild workspace.
    """
    found: dict[str, list[str]] = {}
    for path in all_template_paths():
        for index, text in enumerate(_joined_buildspec_texts(load_template(path))):
            phases = json.loads(text).get("phases", {})
            commands = [
                command
                for body in phases.values()
                for command in body.get("commands", [])
            ]
            if any("ASH_REPOSITORY_URL" in command for command in commands):
                found[f"{path.name} #{index}"] = commands
    return found


@pytest.mark.unit
def test_the_reader_finds_the_image_builds():
    """Positive control: every committed stack builds its image from the ASH repository."""
    templates = {name.split(" #")[0] for name in _image_builds()}
    assert templates == {path.name for path in all_template_paths()}, sorted(templates)


#: The fixture's git reads no user or system config, so a developer's own settings
#: (commit signing, hooks, init templates) cannot break or change it.
_GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        env=_GIT_ENV,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path) -> tuple[Path, dict[str, str]]:
    """main: base <- tagged <- unnamed <- tip, and a branch with a slash in its name."""
    if shutil.which("git") is None:
        pytest.fail("git is required")
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git("init", "-q", "-b", "main", cwd=repo)
    commits = {}
    for name in ("base", "tagged", "unnamed", "tip"):
        (repo / f"{name}.txt").write_text(name, encoding="utf-8")
        _git("add", "-A", cwd=repo)
        _git("commit", "-q", "-m", name, cwd=repo)
        commits[name] = _git("rev-parse", "HEAD", cwd=repo)
        if name == "tagged":
            _git("tag", "v9.9.9", cwd=repo)
    _git("branch", "feat/fixture", commits["base"], cwd=repo)
    return repo, commits


def _checkout_commands(commands: list[str]) -> list[str]:
    checkout = [c for c in commands if "ash-src" in c and "docker" not in c]
    assert checkout, "no command checks ASH out into ash-src"
    return checkout


@posix_only
@pytest.mark.parametrize("template", sorted(_image_builds()))
@pytest.mark.parametrize(
    "ref, expected",
    [("v9.9.9", "tagged"), ("feat/fixture", "base"), ("<sha of unnamed>", "unnamed")],
)
@pytest.mark.integration
def test_the_image_build_checks_out_any_ref(
    template, ref, expected, upstream, tmp_path
):
    repo, commits = upstream
    ash_version = commits["unnamed"] if ref.startswith("<sha") else ref
    workdir = tmp_path / "build"
    workdir.mkdir()

    for command in _checkout_commands(_image_builds()[template]):
        result = subprocess.run(
            [shutil.which("bash") or "bash", "-e", "-o", "pipefail", "-c", command],
            cwd=workdir,
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(tmp_path),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "ASH_VERSION": ash_version,
                "ASH_REPOSITORY_URL": f"file://{repo}",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, (
            f"{template}: `{command}` failed for ASH_VERSION={ash_version}:\n"
            f"{result.stderr.strip()}"
        )

    assert _git("rev-parse", "HEAD", cwd=workdir / "ash-src") == commits[expected]


@pytest.mark.parametrize("template", sorted(_image_builds()))
@pytest.mark.unit
def test_docker_builds_the_tree_that_was_checked_out(template):
    """Every build of ASH's own Dockerfile, the one at the root of ash-src.

    The flavor images (`-f ash-src/Dockerfile.mcp` and the like) are layered on the
    result and take no ASH revision, so they are not what this is about.
    """
    builds = [
        command
        for command in _image_builds()[template]
        if "docker build" in command
        and command.rstrip().endswith("ash-src")
        and " -f " not in command
    ]
    assert builds, f"{template}: no docker build of ash-src's Dockerfile"
    for command in builds:
        words = shlex.split(command)
        build_args = [
            words[index + 1]
            for index, word in enumerate(words[:-1])
            if word == "--build-arg"
        ]
        assert "INSTALL_ASH_REVISION=LOCAL" in build_args, (
            f"{template}: {command!r} lets the Dockerfile clone ASH again with "
            "`git clone --branch`, which cannot check out a commit"
        )


@posix_only
@pytest.mark.parametrize("template", sorted(_image_builds()))
@pytest.mark.integration
def test_an_ash_version_starting_with_a_dash_is_not_a_git_option(
    template, upstream, tmp_path
):
    """AshVersion is a stack parameter, so a value starting with "-" must reach
    git as a refspec, never as an option.

    `--upload-pack=<command>` runs that command on the build host, which is what the
    marker detects. With `--` before the repository, git reads the value as a refspec
    and refuses it.
    """
    repo, _ = upstream
    marker = tmp_path / "upload-pack-ran"
    workdir = tmp_path / "build"
    workdir.mkdir()
    ash_version = f"--upload-pack=touch {marker}; git-upload-pack"

    results = []
    for command in _checkout_commands(_image_builds()[template]):
        result = subprocess.run(
            [shutil.which("bash") or "bash", "-e", "-o", "pipefail", "-c", command],
            cwd=workdir,
            env={
                "PATH": os.environ.get("PATH", ""),
                "HOME": str(tmp_path),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "ASH_VERSION": ash_version,
                "ASH_REPOSITORY_URL": f"file://{repo}",
            },
            capture_output=True,
            text=True,
            check=False,
        )
        results.append(result.returncode)
        if result.returncode != 0:
            break

    assert not marker.exists(), f"{template}: AshVersion ran as --upload-pack"
    assert any(code != 0 for code in results), (
        f"{template}: a dash-leading AshVersion was checked out"
    )
