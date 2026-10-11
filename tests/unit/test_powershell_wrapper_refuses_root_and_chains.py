# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``Invoke-ASH`` refuses a root build, a GID of 0 and a config chain it cannot mount.

utils/ash_helpers.ps1, matching ``ash --mode container`` and ``./ash``:

- Run as root (``id -u`` is 0) with the default ``-BuildTarget non-root`` and no
  ``-ContainerUID``, it refuses to build and names ``-BuildTarget ci``, the opt-in
  for the image that runs as root. ``-ContainerUID`` or ``-ContainerGID`` of 0 is
  refused the same way, and so is one that is not a number. An unprivileged caller
  builds as before.
- A ``-Config`` outside the source directory is mounted on its own, without the
  files it extends, so one with an ``extends`` entry is refused.
- Every refusal ends the run with its exit code when Invoke-ASH runs from a script
  or ``pwsh -Command``, and throws in a session a person types into, where ``exit``
  would close that session (``Test-AshInteractiveSession``).

The text tests run everywhere. The ones that run the script need ``pwsh``: they
skip on a developer machine without it and fail in CI, as
test_powershell_default_runner_discovery.py does.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 - running pwsh against the wrapper is the point
from pathlib import Path
from typing import Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")
_IN_CI = "true" in (os.environ.get("CI"), os.environ.get("GITHUB_ACTIONS"))


def _text() -> str:
    return HELPERS.read_text(encoding="utf-8")


def test_every_exit_goes_through_the_one_refusal_helper():
    lines = [line.strip() for line in _text().splitlines()]
    exits = [i for i, line in enumerate(lines) if re.match(r"exit\b", line)]
    helper = next(
        i for i, line in enumerate(lines) if line.startswith("function Stop-AshRefusal")
    )

    assert exits, "no exit found"
    assert all(helper < i < helper + 25 for i in exits), [lines[i] for i in exits]
    body = "\n".join(lines[helper : helper + 25])
    assert "if (Test-AshInteractiveSession)" in body
    assert "throw" in body


def test_the_root_refusal_names_the_opt_in():
    text = _text()

    assert "id -u" in text
    assert re.search(r"Pass -BuildTarget ci to build the image that runs as root", text)


@pytest.fixture
def pwsh():
    if PWSH is None:
        if _IN_CI:
            pytest.fail("pwsh is not on PATH; CI runners must run this test")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")
    return PWSH


@pytest.mark.parametrize(
    ("arguments", "interactive"),
    [
        pytest.param([], True, id="bare"),
        pytest.param(["-NoProfile", "-NoLogo"], True, id="profile-flags"),
        pytest.param(["-NoExit", "-Command", "x"], True, id="no-exit"),
        pytest.param(["-Command", "x"], False, id="command"),
        pytest.param(["-c", "x"], False, id="c"),
        pytest.param(["-NoProfile", "-File", "a.ps1"], False, id="file"),
        pytest.param(["a.ps1"], False, id="positional-script"),
        pytest.param(["-EncodedCommand", "eAA="], False, id="encoded"),
        pytest.param(["-NonInteractive"], False, id="non-interactive"),
    ],
)
def test_the_session_test_reads_the_command_line(arguments, interactive, pwsh):
    quoted = ",".join(f"'{a}'" for a in ["pwsh", *arguments])
    script = (
        f". '{HELPERS.as_posix()}'; "
        f"if (Test-AshInteractiveSession -Arguments @({quoted})) {{ exit 10 }} "
        "else { exit 11 }"
    )
    result = subprocess.run(  # nosec B603 - fixed interpreter, script built here
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == (10 if interactive else 11), result.stderr


@pytest.fixture
def host(tmp_path, pwsh):
    """A PATH with a recording docker and an ``id`` that reports a chosen UID."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker-args.txt"
    runner = bin_dir / "docker"
    runner.write_text(
        f"#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{log}'\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    (tmp_path / "src").mkdir()

    def invoke(arguments: str, uid: Optional[str] = "1000"):
        if uid is not None:
            fake_id = bin_dir / "id"
            fake_id.write_text(f"#!/bin/sh\necho {uid}\n", encoding="utf-8")
            fake_id.chmod(0o755)
        script = (
            f"$ErrorActionPreference = 'Stop'; . '{HELPERS.as_posix()}'; "
            f"Invoke-ASH -OCIRunner docker -SourceDir src -OutputDir out {arguments}; "
            "exit [int]$LASTEXITCODE"
        )
        env = {k: v for k, v in os.environ.items() if k not in ("PATH", "ASH_CONFIG")}
        env["PATH"] = os.pathsep.join(
            [
                bin_dir.as_posix(),
                Path(pwsh).resolve().parent.as_posix(),
                "/usr/bin",
                "/bin",
            ]
        )
        result = subprocess.run(  # nosec B603 - fixed interpreter, script built here
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
        )
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return result, calls

    return invoke


pytestmark_posix = pytest.mark.skipif(
    os.name == "nt", reason="the stand-in docker and id are POSIX shell scripts"
)


@pytestmark_posix
def test_a_root_caller_is_refused_with_the_opt_in_named(host):
    result, calls = host("-NoRun", uid="0")

    assert result.returncode == 3, result.stdout + result.stderr
    assert calls == []
    assert "-BuildTarget ci" in result.stderr


@pytestmark_posix
def test_a_root_caller_that_asks_for_ci_builds_it(host):
    result, calls = host("-NoRun -BuildTarget ci", uid="0")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "build" in calls and "ci" in calls


@pytestmark_posix
def test_an_unprivileged_caller_builds_non_root(host):
    """Control."""
    result, calls = host("-NoRun", uid="1000")

    assert result.returncode == 0, result.stdout + result.stderr
    assert calls[calls.index("--target") + 1] == "non-root"


@pytestmark_posix
@pytest.mark.parametrize(
    "arguments",
    [
        "-NoRun -ContainerUID 1000 -ContainerGID 0",
        "-NoRun -ContainerUID 0",
        "-NoRun -ContainerUID 1x",
    ],
    ids=["gid-0", "uid-0", "uid-not-a-number"],
)
def test_an_id_the_non_root_stage_cannot_use_is_refused(arguments, host):
    result, calls = host(arguments)

    assert result.returncode == 3, result.stdout + result.stderr
    assert calls == []


@pytestmark_posix
def test_an_outside_config_with_extends_is_refused(host, tmp_path):
    (tmp_path / "base.yaml").write_text("project_name: p\n", encoding="utf-8")
    config = tmp_path / "ash.yaml"
    config.write_text("extends: base.yaml\n", encoding="utf-8")

    result, calls = host(f"-NoBuild -Config '{config.as_posix()}'")

    assert result.returncode == 3, result.stdout + result.stderr
    assert calls == []
    assert "extends" in result.stderr


@pytestmark_posix
def test_an_outside_config_without_extends_still_runs(host, tmp_path):
    """Control."""
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result, calls = host(f"-NoBuild -Config '{config.as_posix()}'")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "run" in calls


@pytestmark_posix
def test_a_missing_config_names_the_path(host):
    result, calls = host("-NoBuild -Config missing.yaml")

    assert result.returncode == 3, result.stdout + result.stderr
    assert calls == []
    assert "Config file not found: missing.yaml" in result.stderr
