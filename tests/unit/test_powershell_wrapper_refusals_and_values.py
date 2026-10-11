# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``Invoke-ASH`` exits with the code it means, and runs no part of a path it is given.

Two defects in utils/ash_helpers.ps1:

- Each refusal wrote its message with ``Write-Error`` and then ran ``exit 3``. Under
  ``$ErrorActionPreference = 'Stop'``, which GitHub Actions sets for every ``pwsh``
  step and many scripts set themselves, ``Write-Error`` is a terminating error, so
  the ``exit 3`` never ran and the caller saw exit 1. The message is now written to
  stderr directly, which never throws.
- The build and run commands were assembled as strings for ``Invoke-Expression``
  with the operator's paths and values spliced into them, so PowerShell parsed those
  values as code: a source directory named ``a$(...)`` ran what was in the
  parentheses. The command strings now name each value by its variable
  (``"$sourceDirFull"``), which ``Invoke-Expression`` expands as a value without
  parsing it. ``AshArgs``, the arguments passed through to ASH as written, is still
  parsed again; that is the documented limit of passing it through at all.

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
from typing import List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
PWSH = shutil.which("pwsh")
_IN_CI = "true" in (os.environ.get("CI"), os.environ.get("GITHUB_ACTIONS"))

#: Variables the command strings may still splice in: the commands themselves, the
#: runner and its wrapper
#: (a command name and a prefix meant to be split), the fixed stage, the lists
#: assembled from constants or from references, YES/NO and the terminal size, and
#: AshArgs, passed through as written.
SPLICE_ALLOWED = {
    "buildCmd",
    "runCmd",
    "RESOLVED_OCI_RUNNER",
    "OCI_WRAPPER",
    "BuildTarget",
    "buildArgs",
    "runArgs",
    "ashCmdArgs",
    "configMountArg",
    "AshArgs",
    "ashDebug",
    "Offline",
    "COLUMNS",
    "LINES",
    "i",
    "null",
}

_SINGLE_QUOTED = re.compile(r"'[^']*'")
#: A variable reference; a backtick before ``$`` makes it a literal dollar sign.
_VARIABLE = re.compile(r"(?<!`)\$(?:\{([^}]+)\}|((?:env:)?[A-Za-z_]\w*))")


def _command_lines(text: str) -> List[str]:
    """The lines that add to a command Invoke-Expression runs."""
    lines: List[str] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            lines.append(line)
            continue
        if re.match(r"\$(buildCmd|runCmd)\s*\+=\s*@\($", line):
            in_block = True
            continue
        if re.match(
            r"(\$(buildCmd|runCmd)\s*\+=|\$configMountArg\s*=|\$ashCmdArgs\.Add\()",
            line,
        ):
            lines.append(line)
    return lines


def _spliced(lines: List[str]) -> List[str]:
    """Each variable a command line splices into the string, outside single quotes."""
    found = []
    for line in lines:
        for match in _VARIABLE.finditer(_SINGLE_QUOTED.sub("''", line)):
            name = match.group(1) or match.group(2)
            if name not in SPLICE_ALLOWED:
                found.append(f"{name}: {line}")
    return found


def test_the_commands_name_operator_values_instead_of_splicing_them():
    lines = _command_lines(HELPERS.read_text(encoding="utf-8"))

    assert len(lines) > 20, "the command assembly was not found"
    assert _spliced(lines) == []


def test_the_check_sees_a_spliced_value():
    """Control for the checker: the old form of two lines."""
    old = [
        '$runCmd += "--mount `"type=bind,source=$sourceDirFull,destination=/src`""',
        "$ashCmdArgs.Add($scanner)",
    ]
    new = [
        "$runCmd += '--mount \"type=bind,source=$sourceDirFull,destination=/src\"'",
        '$ashCmdArgs.Add("`$Scanners[$i]")',
    ]

    assert len(_spliced(old)) == 2
    assert _spliced(new) == []


def test_no_refusal_writes_with_write_error_before_it_exits():
    lines = [line.strip() for line in HELPERS.read_text(encoding="utf-8").splitlines()]
    exits = [i for i, line in enumerate(lines) if re.fullmatch(r"exit \d+", line)]

    assert exits, "no exit found"
    for index in exits:
        before = [line for line in lines[max(0, index - 3) : index] if line]
        assert not any(line.startswith("Write-Error") for line in before[-1:]), lines[
            index - 1
        ]


@pytest.fixture
def pwsh():
    if PWSH is None:
        if _IN_CI:
            pytest.fail("pwsh is not on PATH; CI runners must run this test")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")
    return PWSH


@pytest.fixture
def recording_docker(tmp_path, pwsh) -> Path:
    """A PATH whose docker writes its arguments, one per line, and succeeds."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker-args.txt"
    if os.name == "nt":
        (bin_dir / "docker.cmd").write_text("@exit /b 0\r\n", encoding="utf-8")
    else:
        runner = bin_dir / "docker"
        runner.write_text(
            f"#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '{log}'\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
    return bin_dir


def _invoke(pwsh, tmp_path: Path, bin_dir: Path, arguments: str):
    script = (
        f"$ErrorActionPreference = 'Stop'; . '{HELPERS.as_posix()}'; "
        f"Invoke-ASH -OCIRunner docker -NoBuild {arguments}; "
        "exit [int]$LASTEXITCODE"
    )
    env = {k: v for k, v in os.environ.items() if k not in ("PATH", "ASH_CONFIG")}
    env["PATH"] = os.pathsep.join(
        [bin_dir.as_posix(), Path(pwsh).resolve().parent.as_posix()]
    )
    return subprocess.run(  # nosec B603 - fixed interpreter, script built here
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param("-SourceDir src -OutputDir out -Config missing.yaml", id="config"),
        pytest.param("-SourceDir src -OutputDir 'o,readonly=false'", id="mount-path"),
    ],
)
def test_a_refusal_exits_3_under_error_action_stop(
    arguments, pwsh, recording_docker, tmp_path
):
    (tmp_path / "src").mkdir()

    result = _invoke(pwsh, tmp_path, recording_docker, arguments)

    assert result.returncode == 3, result.stdout + result.stderr
    assert not (tmp_path / "docker-args.txt").exists()


@pytest.mark.skipif(
    os.name == "nt",
    reason="the recording runner is a POSIX shell script; Windows gets a .cmd stub",
)
def test_a_source_path_is_passed_as_a_value_and_not_run(
    pwsh, recording_docker, tmp_path
):
    source = tmp_path / "a$(New-Item -ItemType File -Path ran)"
    source.mkdir()

    result = _invoke(
        pwsh,
        tmp_path,
        recording_docker,
        f"-SourceDir '{source.as_posix()}' -OutputDir out",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "ran").exists(), "a part of the path was run"
    args = (tmp_path / "docker-args.txt").read_text(encoding="utf-8").splitlines()
    assert f"type=bind,source={source},destination=/src,readonly" in args
