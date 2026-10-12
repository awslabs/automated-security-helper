#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The generated cdk-constructs buildspecs check ASH_VERSION before pip sees it.

Why this file exists
--------------------
The three committed ``deploy/cdk-constructs/buildspec*.yml`` files install ASH with
``pip install "git+https://...@$ASH_VERSION"``, and ``ASH_VERSION`` is a build
environment variable a consumer may override. pip clones the repository and then runs
``git show-ref <ref>`` and ``git checkout -q <ref>`` with the ref as its own argument
(measured with pip 25.0.1 and 21.3.1, git 2.50.1). git reads an argument that starts
with ``-`` as an option: a ref of ``-f`` made ``git checkout -q -f`` succeed, and pip
went on to build the default branch rather than fail.

The install phase now starts with a shell check that accepts a tag, a branch name that
follows git's ref-name rules, or a commit id, and stops the build on anything else, so
pip is never started with such a ref.

These tests run each committed install phase as CodeBuild does, one shell that stops at
the first failing command, with ``python3`` replaced by a stand-in that records its
arguments. A refused ref has to stop the phase before the stand-in runs; an accepted one
has to reach it unchanged, which is the control. One refused value is
``--upload-pack=<script>``, where the script leaves a marker, so the marker also shows
that nothing ran it.
"""

from __future__ import annotations

import os
import pathlib
import shlex
import subprocess

import pytest
import yaml

from tests.unit.deploy.buildspec_extraction import REPO_ROOT, posix_shell
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="executes POSIX buildspec commands destined for a Linux build container",
)

CONSTRUCTS = REPO_ROOT / "deploy" / "cdk-constructs"
BUILDSPECS = sorted(CONSTRUCTS.glob("buildspec*.yml"))
REQUIREMENT = "git+https://github.com/awslabs/automated-security-helper.git@"

ACCEPTED = [
    "v3.7.0",
    "main",
    "feature/x",
    "eddfeecf9adb672023ab7998688d54199b0a0441",
]

REFUSED = [
    "-f",
    "--orphan",
    "",
    "v1..2",
    "feature/.hidden",
    "release.lock",
    "a//b",
    "trailing/",
    "has space",
    "x$(id)",
]


def test_every_generated_buildspec_was_found():
    assert [p.name for p in BUILDSPECS] == [
        "buildspec-merge.yml",
        "buildspec-shard.yml",
        "buildspec.yml",
    ]


def _install_commands(path: pathlib.Path) -> list[str]:
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    commands = spec["phases"]["install"]["commands"]
    assert any(REQUIREMENT in c for c in commands), f"{path.name} no longer uses pip"
    return commands


def _run_install(
    path: pathlib.Path, ash_version: str, tmp_path: pathlib.Path
) -> tuple[subprocess.CompletedProcess, list[list[str]]]:
    """Run the install phase with a recording `python3`; return the run and its calls."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "python3.log"
    stand_in = bin_dir / "python3"
    stand_in.write_text(
        "#!/bin/sh\n"
        f'for word in "$@"; do printf \'%s\\n\' "$word"; done >> {shlex.quote(str(log))}\n'
        f"printf '%s\\n' -- >> {shlex.quote(str(log))}\n",
        encoding="utf-8",
    )
    stand_in.chmod(0o755)
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
    env["ASH_VERSION"] = ash_version
    script = "\n".join(
        f'{command}\nash_rc=$?; [ "$ash_rc" -eq 0 ] || exit "$ash_rc"'
        for command in _install_commands(path)
    )
    run = subprocess.run(
        [posix_shell(env), "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=CHILD_TIMEOUT_SECONDS,
    )
    calls: list[list[str]] = []
    if log.exists():
        current: list[str] = []
        for word in log.read_text(encoding="utf-8").splitlines():
            if word == "--":
                calls.append(current)
                current = []
            else:
                current.append(word)
    return run, calls


@pytest.mark.parametrize("path", BUILDSPECS, ids=lambda p: p.name)
@pytest.mark.parametrize("ref", ACCEPTED)
def test_control_an_accepted_ref_reaches_pip_unchanged(path, ref, tmp_path):
    run, calls = _run_install(path, ref, tmp_path)
    assert run.returncode == 0, run.stderr
    assert len(calls) == 1 and calls[0][-1] == REQUIREMENT + ref, calls


@pytest.mark.parametrize("path", BUILDSPECS, ids=lambda p: p.name)
@pytest.mark.parametrize("ref", REFUSED)
def test_a_refused_ref_stops_the_install_before_pip(path, ref, tmp_path):
    run, calls = _run_install(path, ref, tmp_path)
    assert calls == [], f"{path.name}: pip ran with ASH_VERSION={ref!r}: {calls}"
    assert run.returncode != 0
    assert "ASH_VERSION must be" in run.stderr, run.stderr


@pytest.mark.parametrize("path", BUILDSPECS, ids=lambda p: p.name)
def test_an_upload_pack_ref_never_reaches_pip(path, tmp_path):
    marker = tmp_path / "upload-pack-ran"
    script = tmp_path / "upload-pack.sh"
    script.write_text(
        f'#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexec git upload-pack "$@"\n',
        encoding="utf-8",
    )
    script.chmod(0o755)
    run, calls = _run_install(path, f"--upload-pack={script}", tmp_path)
    assert calls == [], f"{path.name}: pip ran with the ref: {calls}"
    assert not marker.exists()
    assert run.returncode != 0
