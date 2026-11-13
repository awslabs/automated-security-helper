#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every image the deploy targets build installs its Ruby gems frozen, from the lockfile.

Why this file exists
--------------------
cfn-nag is a Ruby gem, and the ASH Dockerfile installs it with ``bundle install``. Every
deploy target builds that Dockerfile: the Terraform image pipeline and each CDK image
build fetch ASH at the pinned ref and run ``docker build`` over the fetched tree, with no
``-f``. The Dockerfile copied only the Gemfile, so each build resolved cfn-nag's
dependency closure again, and ``automated_security_helper/assets/Gemfile.lock`` was not
read.

The Dockerfile now copies Gemfile.lock beside the Gemfile and runs Bundler with
``BUNDLE_FROZEN=true``. Frozen, Bundler installs exactly what the lockfile lists, and
refuses to run when the lockfile is missing or disagrees with the Gemfile.

These tests read every Dockerfile the deploy targets build -- the ASH Dockerfile, the
Terraform wrapper and gate Dockerfiles, and the Dockerfiles each committed CDK template
writes -- and every rendered buildspec command, and require each ``bundle install`` among
them to run frozen with the lockfile copied in its stage. They first establish that the
image builds build the ASH Dockerfile, so the check covers what the templates run. The
checker is also run over small synthetic Dockerfiles, so a checker that stops finding
anything fails rather than passing.
"""

from __future__ import annotations

import json
import re
import shlex

import pytest
import yaml

from tests.unit.deploy.buildspec_extraction import (
    CDK_TEMPLATE_DIR,
    REPO_ROOT,
    heredoc_body,
    load_template,
)

pytestmark = pytest.mark.unit

ASH_DOCKERFILE = REPO_ROOT / "Dockerfile"
GEM_ASSETS = REPO_ROOT / "automated_security_helper" / "assets"
TERRAFORM_MODULES = REPO_ROOT / "deploy" / "terraform" / "modules"
TERRAFORM_DOCKERFILES = [
    TERRAFORM_MODULES / "ash-image-pipeline" / "files" / "wrapper.Dockerfile",
    TERRAFORM_MODULES / "codecommit-gate" / "files" / "gate.Dockerfile",
]

_BUNDLE_INSTALL = re.compile(r"\bbundle\s+install\b")
# The CDK builds write each file with `cat > ash-src/<name> <<'ASH_CDK_EOF'`.
_CDK_FILE = re.compile(r"cat > ash-src/(?P<name>\S+) <<'ASH_CDK_EOF'")


# ---------------------------------------------------------------------------
# The checker
# ---------------------------------------------------------------------------


def dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    """Each instruction as (KEYWORD, arguments), continuation lines joined."""
    instructions: list[tuple[str, str]] = []
    current: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        # Docker skips comment and empty lines, inside a continuation too.
        if not line or line.startswith("#"):
            continue
        current.append(line.removesuffix("\\"))
        if line.endswith("\\"):
            continue
        keyword, _, arguments = " ".join(current).partition(" ")
        instructions.append((keyword.upper(), arguments.strip()))
        current = []
    return instructions


def _assignments(arguments: str) -> dict[str, str]:
    """``NAME=value`` pairs of an ARG or ENV instruction, plus ENV's ``NAME value``."""
    words = shlex.split(arguments)
    if len(words) == 2 and "=" not in words[0]:
        return {words[0]: words[1]}
    return {
        name: value
        for name, separator, value in (word.partition("=") for word in words)
        if separator
    }


def _frozen_inline(segment: str) -> bool:
    before = _BUNDLE_INSTALL.split(segment, maxsplit=1)[0]
    return re.search(r"\bBUNDLE_FROZEN=(['\"]?)true\1(\s|$)", before) is not None


def unfrozen_bundle_installs(dockerfile: str) -> list[str]:
    """Why each ``bundle install`` in a Dockerfile does not run frozen from a lockfile.

    Frozen means BUNDLE_FROZEN=true is in that RUN's environment: set on the command
    itself, or by an ARG or ENV earlier in the same stage. The lockfile has to have been
    copied in the same stage. A FROM starts a new stage and forgets both.
    """
    problems: list[str] = []
    frozen = False
    lockfile = False
    for keyword, arguments in dockerfile_instructions(dockerfile):
        if keyword == "FROM":
            frozen = False
            lockfile = False
        elif keyword in ("ARG", "ENV"):
            value = _assignments(arguments).get("BUNDLE_FROZEN")
            if value is not None:
                frozen = value.lower() == "true"
        elif keyword in ("COPY", "ADD"):
            if any(word.endswith("Gemfile.lock") for word in shlex.split(arguments)):
                lockfile = True
        elif keyword == "RUN":
            for segment in re.split(r"&&|\|\||;", arguments):
                if not _BUNDLE_INSTALL.search(segment):
                    continue
                if not (frozen or _frozen_inline(segment)):
                    problems.append(f"not frozen: {segment.strip()}")
                if not lockfile:
                    problems.append(
                        f"no Gemfile.lock copied in this stage: {segment.strip()}"
                    )
    return problems


def unfrozen_command_installs(command: str) -> list[str]:
    """Why each ``bundle install`` in a buildspec command does not run frozen."""
    return [
        f"not frozen: {segment.strip()}"
        for segment in re.split(r"&&|\|\||;|\n", command)
        if _BUNDLE_INSTALL.search(segment) and not _frozen_inline(segment)
    ]


# ---------------------------------------------------------------------------
# What the deploy targets build
# ---------------------------------------------------------------------------


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def _cdk_buildspecs() -> dict[str, dict]:
    """Every CodeBuild buildspec in the committed CDK templates, decoded."""
    found: dict[str, dict] = {}
    for path in sorted(CDK_TEMPLATE_DIR.glob("*.template.json")):
        stack = path.name.replace(".template.json", "")
        template = load_template(path)
        for logical_id, resource in template.get("Resources", {}).items():
            if resource.get("Type") != "AWS::CodeBuild::Project":
                continue
            spec = resource.get("Properties", {}).get("Source", {}).get("BuildSpec")
            if isinstance(spec, dict) and "Fn::Join" in spec:
                delimiter, parts = spec["Fn::Join"]
                spec = delimiter.join(
                    part if isinstance(part, str) else "CFN_SUBSTITUTION_PLACEHOLDER"
                    for part in parts
                )
            if isinstance(spec, str):
                found[f"cdk:{stack}:{logical_id}"] = json.loads(spec)
    return found


def _terraform_buildspecs() -> dict[str, dict]:
    """Every Terraform buildspec template, with its template variables filled.

    The variables are the base64 blobs of files the buildspec writes, which these tests
    read from the files themselves, so a placeholder is enough here.
    """
    found: dict[str, dict] = {}
    for path in sorted(TERRAFORM_MODULES.glob("*/buildspec*.yml.tftpl")):
        text = re.sub(r"(?<!\$)\$\{[a-z0-9_]+\}", "RENDERED", path.read_text("utf-8"))
        assert re.search(r"(?<!\$)\$\{", text) is None, (
            f"{path} has an unfilled variable"
        )
        found[f"terraform:{path.parent.name}/{path.name}"] = yaml.safe_load(
            text.replace("$${", "${")
        )
    return found


BUILDSPECS = {**_terraform_buildspecs(), **_cdk_buildspecs()}
COMMANDS = {
    name: [c for c in _strings(spec.get("phases", {})) if isinstance(c, str)]
    for name, spec in BUILDSPECS.items()
}


def _cdk_dockerfiles() -> dict[str, str]:
    """The Dockerfiles the committed CDK image builds write before building them."""
    found: dict[str, str] = {}
    for name, commands in COMMANDS.items():
        if not name.startswith("cdk:"):
            continue
        for command in commands:
            match = _CDK_FILE.search(command)
            if match and match.group("name").startswith("Dockerfile"):
                body = heredoc_body(command, delimiter="ASH_CDK_EOF")
                found[f"{name}:{match.group('name')}"] = body
    return found


DOCKERFILES = {
    "Dockerfile": ASH_DOCKERFILE.read_text(encoding="utf-8"),
    **{
        str(path.relative_to(REPO_ROOT)): path.read_text(encoding="utf-8")
        for path in TERRAFORM_DOCKERFILES
    },
    **_cdk_dockerfiles(),
}


def _ash_stage_builds() -> dict[str, list[str]]:
    """Each image build's `docker build` runs of the ASH Dockerfile, by buildspec.

    Those are the builds handed the fetched tree with INSTALL_ASH_REVISION=LOCAL.
    """
    builds: dict[str, list[str]] = {}
    for name, commands in COMMANDS.items():
        for command in commands:
            for piece in re.split(r"\n(?=\s*docker build)", command):
                if "docker build" in piece and "INSTALL_ASH_REVISION=LOCAL" in piece:
                    builds.setdefault(name, []).append(piece)
    return builds


# ---------------------------------------------------------------------------
# The real builds
# ---------------------------------------------------------------------------


def test_every_image_build_builds_the_ash_dockerfile():
    """Each image build runs `docker build` over the fetched ASH tree with no -f.

    That makes the ASH Dockerfile, at the pinned ref, the file they build, so it is
    the one whose `bundle install` the deploy targets run.
    """
    builds = _ash_stage_builds()
    assert sorted(builds) == sorted(
        [
            "terraform:ash-image-pipeline/buildspec.yml.tftpl",
            "cdk:AshAgentCore:ImageBuild31565E2D",
            "cdk:AshCodeCommitGate:ImageBuild31565E2D",
            "cdk:AshDistributedPipeline:ImageBuild31565E2D",
            "cdk:AshFargate:ImageBuild31565E2D",
            "cdk:AshImagePipeline:Arm64Build8C935C71",
            "cdk:AshImagePipeline:Amd64BuildA84A9F57",
        ]
    ), sorted(builds)
    for name, runs in builds.items():
        for build in runs:
            words = shlex.split(build.replace("\\\n", " "))
            assert "-f" not in words and not any(
                w == "--file" or w.startswith("--file=") for w in words
            ), f"{name}: {build!r} builds a Dockerfile other than the ASH one"


def test_the_ash_dockerfile_installs_gems_with_bundler():
    # Without this, a rename of the gem install would leave the checks below
    # iterating nothing in the one file that has it.
    runs = [
        a for k, a in dockerfile_instructions(DOCKERFILES["Dockerfile"]) if k == "RUN"
    ]
    assert any(_BUNDLE_INSTALL.search(run) for run in runs)


@pytest.mark.parametrize("name", sorted(DOCKERFILES))
def test_every_bundle_install_in_a_deployed_dockerfile_runs_frozen(name):
    assert unfrozen_bundle_installs(DOCKERFILES[name]) == []


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_every_bundle_install_in_a_rendered_buildspec_runs_frozen(name):
    for command in COMMANDS[name]:
        assert unfrozen_command_installs(command) == [], f"{name}: {command[:200]!r}"


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_no_image_build_overrides_bundle_frozen(name):
    """The setting is an ARG, so a `--build-arg` could turn it off; none does."""
    for command in COMMANDS[name]:
        assert not re.search(r"--build-arg[ =]['\"]?BUNDLE_FROZEN", command), (
            f"{name}: {command[:200]!r}"
        )


def test_the_lockfile_pins_what_the_gemfile_asks_for():
    """Frozen, Bundler refuses a Gemfile the lockfile does not match. Check it here too.

    An image build is where that refusal would otherwise surface first, twenty
    minutes in. The lockfile's Bundler version is also the one the Dockerfile
    installs, so the build reads the lockfile with the Bundler that wrote it.
    """
    gemfile = (GEM_ASSETS / "Gemfile").read_text(encoding="utf-8")
    lockfile = (GEM_ASSETS / "Gemfile.lock").read_text(encoding="utf-8")
    wanted = dict(re.findall(r'^gem "([^"]+)", "=?\s*([^"]+)"', gemfile, re.MULTILINE))
    section = lockfile.split("DEPENDENCIES\n", 1)[1].split("\n\n", 1)[0]
    locked = dict(re.findall(r"^\s+(\S+) \(= ([^)]+)\)", section, re.MULTILINE))
    assert wanted and wanted == locked

    bundled_with = re.search(r"BUNDLED WITH\n\s+(\S+)", lockfile)
    bundler_arg = re.search(
        r'^ARG BUNDLER_VERSION="([^"]+)"', DOCKERFILES["Dockerfile"], re.MULTILINE
    )
    assert bundled_with and bundler_arg
    assert bundled_with.group(1) == bundler_arg.group(1)


# ---------------------------------------------------------------------------
# Negative controls: the checker flags what it exists to catch
# ---------------------------------------------------------------------------


LOCKED_COPY = "COPY Gemfile Gemfile.lock /deps/"
RETRIED_INSTALL = "RUN apt-get update && \\\n    with-retry 'bundle install --jobs=4'"


def _dockerfile(*lines: str) -> str:
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize(
    "dockerfile",
    [
        _dockerfile("FROM base", LOCKED_COPY, "RUN bundle install --jobs=4"),
        _dockerfile(
            "FROM base",
            "COPY Gemfile /deps/",
            "ARG BUNDLE_FROZEN=true",
            RETRIED_INSTALL,
        ),
        _dockerfile(
            "FROM base", LOCKED_COPY, "ARG BUNDLE_FROZEN=false", "RUN bundle install"
        ),
        _dockerfile(
            "FROM base AS one",
            "ARG BUNDLE_FROZEN=true",
            "FROM base AS two",
            LOCKED_COPY,
            "RUN bundle install",
        ),
        _dockerfile("FROM base", LOCKED_COPY, RETRIED_INSTALL),
        _dockerfile("FROM base", LOCKED_COPY, "RUN BUNDLE_FROZEN=false bundle install"),
    ],
)
def test_an_unfrozen_or_unlocked_bundle_install_is_flagged(dockerfile):
    assert unfrozen_bundle_installs(dockerfile) != []


@pytest.mark.parametrize(
    "dockerfile",
    [
        _dockerfile(
            "FROM base", LOCKED_COPY, "ARG BUNDLE_FROZEN=true", RETRIED_INSTALL
        ),
        _dockerfile(
            "FROM base",
            "COPY Gemfile.lock Gemfile /deps/",
            "ENV BUNDLE_FROZEN=true",
            "RUN bundle install",
        ),
        _dockerfile(
            "FROM base",
            "COPY a/Gemfile a/Gemfile.lock /deps/",
            "RUN BUNDLE_FROZEN=true bundle install",
        ),
    ],
)
def test_a_frozen_install_from_a_copied_lockfile_passes(dockerfile):
    assert unfrozen_bundle_installs(dockerfile) == []


def test_an_unfrozen_buildspec_install_is_flagged():
    assert unfrozen_command_installs("cd x && bundle install") != []
    assert unfrozen_command_installs("BUNDLE_FROZEN=true bundle install") == []
