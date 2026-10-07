#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Both builds of the pull-request gate's Lambda image install only hashed pins.

Why this file exists
--------------------
The gate image is built two ways: by the Terraform codecommit-gate module from
``files/gate.Dockerfile``, and by the CDK ``lambda`` flavor, whose Dockerfile is
written out by ``deploy/cdk/lib/ash-image-build.ts`` and lands in the committed
templates. Both used to run ``pip install awslambdaric git-remote-codecommit`` with
no version, so every rebuild took whatever PyPI served that day into an image that
can approve pull requests. hadolint (DL3013) flagged the Terraform one; the CDK one
is a string inside TypeScript, which hadolint never sees.

Both now install ``gate-requirements.txt`` with ``--require-hashes``, and the CDK
build inlines that same file at synth time. These tests hold that in place:

* every ``pip install`` in either build reads a requirements file in hash mode and
  names no package of its own;
* every requirement in that file is ``name==version`` with at least one sha256;
* the copy embedded in each committed CDK template is that file, so a re-pin in
  one place and not the other fails here rather than shipping two different images.

The committed templates are what an adopter launches, so they are checked rather
than the TypeScript. ``synth-templates.sh --check`` keeps them equal to the source.

Each checker is also run against a synthetic unpinned input, so a checker that has
stopped finding anything fails rather than passing.
"""

from __future__ import annotations

import json
import pathlib
import re
import shlex
from typing import Any, Iterator

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
GATE_FILES = REPO_ROOT / "deploy/terraform/modules/codecommit-gate/files"
GATE_DOCKERFILE = GATE_FILES / "gate.Dockerfile"
REQUIREMENTS = GATE_FILES / "gate-requirements.txt"
CDK_TEMPLATES = REPO_ROOT / "deploy/cdk/templates"

# The CDK build writes each file with `cat > ash-src/<name> <<'ASH_CDK_EOF'`.
_HEREDOC = re.compile(
    r"cat > ash-src/(?P<name>[^ ]+) <<'ASH_CDK_EOF'\n(?P<body>.*?)\nASH_CDK_EOF",
    re.DOTALL,
)
_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}")


def dockerfile_runs(text: str) -> list[str]:
    """Each RUN instruction's command, continuation lines joined."""
    runs: list[str] = []
    current: list[str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if current is None:
            if re.match(r"^RUN\s", line):
                current = [line[3:].strip()]
            else:
                continue
        else:
            if line.startswith("#"):
                continue
            current.append(line)
        if current[-1].endswith("\\"):
            current[-1] = current[-1][:-1]
            continue
        runs.append(" ".join(current))
        current = None
    return runs


def unpinned_pip_installs(command: str) -> list[str]:
    """Why each ``pip install`` in ``command`` is not a hash-mode requirements install.

    Empty when every pip install is ``--require-hashes -r <file>`` and nothing else.
    """
    problems: list[str] = []
    for segment in re.split(r"&&|\|\||;", command):
        words = shlex.split(segment)
        pip_at = None
        for i, word in enumerate(words):
            if re.fullmatch(r"(.*/)?pip3?", word) or (
                word == "pip" and i and words[i - 1] == "-m"
            ):
                pip_at = i
                break
        if pip_at is None or words[pip_at + 1 : pip_at + 2] != ["install"]:
            continue
        args = words[pip_at + 2 :]
        if "--require-hashes" not in args:
            problems.append(f"no --require-hashes: {segment.strip()}")
        positional = []
        skip = False
        for arg in args:
            if skip:
                skip = False
                continue
            if arg in ("-r", "--requirement", "-c", "--constraint"):
                skip = True
                continue
            if not arg.startswith("-"):
                positional.append(arg)
        if positional:
            problems.append(
                f"installs {positional} outside the requirements file: {segment.strip()}"
            )
        if "-r" not in args and "--requirement" not in args:
            problems.append(f"no requirements file: {segment.strip()}")
    return problems


def requirement_problems(text: str) -> list[str]:
    """Why each requirement in ``text`` is not ``name==version`` with a sha256."""
    joined = re.sub(r"\\\n", " ", text)
    problems = []
    entries = 0
    for line in joined.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        entries += 1
        spec = line.split()[0]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.+!_-]+", spec):
            problems.append(f"not pinned with ==: {spec}")
        if not _HASH.search(line):
            problems.append(f"no sha256: {spec}")
    if entries == 0:
        problems.append("no requirements at all")
    return problems


def _flatten(value: Any) -> str:
    """A CloudFormation value as text, with intrinsics other than Join made opaque."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "Fn::Join" in value:
        sep, parts = value["Fn::Join"]
        return sep.join(_flatten(p) for p in parts)
    return "TOKEN"


def cdk_buildspecs() -> Iterator[tuple[str, str]]:
    for path in sorted(CDK_TEMPLATES.glob("*.template.json")):
        template = json.loads(path.read_text(encoding="utf-8"))
        for logical_id, resource in template["Resources"].items():
            if resource["Type"] != "AWS::CodeBuild::Project":
                continue
            spec = resource["Properties"]["Source"].get("BuildSpec")
            if spec is None:
                continue
            text = _flatten(spec)
            if text.lstrip().startswith("{"):
                # BuildSpec.fromObject is JSON: decode it and keep its strings, which
                # is where each heredoc sits, one command per string.
                text = "\n".join(_strings(json.loads(text)))
            yield f"{path.name}:{logical_id}", text


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _stripped(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if line.strip() and not line.startswith("#")
    )


def _cdk_gate_builds() -> list[tuple[str, dict[str, str]]]:
    builds = []
    for where, spec in cdk_buildspecs():
        files = {m.group("name"): m.group("body") for m in _HEREDOC.finditer(spec)}
        if "Dockerfile.lambda" in files:
            builds.append((where, files))
    return builds


# ---------------------------------------------------------------------------
# The real builds
# ---------------------------------------------------------------------------


def test_the_requirements_file_pins_every_entry_by_version_and_hash():
    assert requirement_problems(REQUIREMENTS.read_text(encoding="utf-8")) == []


def test_the_terraform_gate_image_installs_only_the_hashed_file():
    runs = dockerfile_runs(GATE_DOCKERFILE.read_text(encoding="utf-8"))
    pip_runs = [r for r in runs if "pip" in r]
    assert pip_runs, (
        "gate.Dockerfile runs no pip install; the checker has nothing to check"
    )
    for run in pip_runs:
        assert unpinned_pip_installs(run) == [], run


def test_the_cdk_gate_image_is_present_in_the_committed_templates():
    # Without this, a renamed heredoc would leave the next two tests iterating nothing.
    builds = _cdk_gate_builds()
    assert {where.split(":")[0] for where, _ in builds} >= {
        "AshCodeCommitGate.template.json"
    }


def test_the_cdk_gate_image_installs_only_the_hashed_file():
    for where, files in _cdk_gate_builds():
        pip_runs = [
            r for r in dockerfile_runs(files["Dockerfile.lambda"]) if "pip" in r
        ]
        assert pip_runs, f"{where}: Dockerfile.lambda runs no pip install"
        for run in pip_runs:
            assert unpinned_pip_installs(run) == [], f"{where}: {run}"


def test_the_cdk_gate_image_embeds_the_same_requirements_as_terraform():
    expected = _stripped(REQUIREMENTS.read_text(encoding="utf-8"))
    for where, files in _cdk_gate_builds():
        assert "gate-requirements.txt" in files, (
            f"{where} writes no gate-requirements.txt"
        )
        assert _stripped(files["gate-requirements.txt"]) == expected, (
            f"{where} embeds different pins from {REQUIREMENTS.relative_to(REPO_ROOT)}. "
            "Re-run deploy/cdk/scripts/synth-templates.sh after changing the file."
        )


# ---------------------------------------------------------------------------
# Negative controls: each checker fires on what it exists to catch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "pip install --no-cache-dir awslambdaric git-remote-codecommit",
        "python3 -m pip install --no-cache-dir --break-system-packages awslambdaric boto3",
        "pip install -r /tmp/r.txt",
        "pip install --require-hashes -r /tmp/r.txt extra-package",
        "true && /usr/local/bin/pip install awslambdaric==4.2.0",
    ],
)
def test_an_unpinned_pip_install_is_caught(command):
    assert unpinned_pip_installs(command) != []


def test_a_hashed_requirements_install_is_accepted():
    assert (
        unpinned_pip_installs(
            "python3 -m pip install --no-cache-dir --break-system-packages --require-hashes -r /tmp/r.txt && rm /tmp/r.txt"
        )
        == []
    )


@pytest.mark.parametrize(
    "text",
    [
        "awslambdaric\n",
        "awslambdaric>=4 \\\n    --hash=sha256:" + "a" * 64 + "\n",
        "awslambdaric==4.2.0\n",
        "# only a comment\n",
    ],
)
def test_an_unpinned_requirement_is_caught(text):
    assert requirement_problems(text) != []


def test_a_multiline_run_is_joined_before_checking():
    runs = dockerfile_runs(
        "FROM x\nRUN pip install \\\n    --no-cache-dir \\\n    awslambdaric\nUSER 1\n"
    )
    assert runs == ["pip install  --no-cache-dir  awslambdaric"]
    assert unpinned_pip_installs(runs[0]) != []
