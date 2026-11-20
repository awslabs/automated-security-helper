# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Running a bash snippet from a unit test the same way on Linux, macOS and Windows.

Three things differ on a Windows runner, and each one fails a test that ignores it:

- `bash` on PATH is C:\\Windows\\System32\\bash.exe, the WSL stub, which exits 1 without
  a WSL distribution. Git for Windows ships a real bash.exe next to git, under the Git
  install's bin directory, and that is the one used here.
- Text-mode stdin turns "\\n" into "\\r\\n", and bash does not strip the "\\r", so a
  script or input fed as text arrives with a stray character on every line. Scripts and
  input go in as bytes with LF line ends.
- A native path such as C:\\Users\\x has a drive colon, which breaks PATH, and
  backslashes, which bash reads as escapes. bash_path() turns it into /c/Users/x.

Only when no Git bash can be found does a test skip, and it says why.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path, PureWindowsPath
from typing import Mapping, Optional, Union

import pytest


def bash_exe() -> str:
    """A bash that runs scripts: on Windows, Git's, never the WSL stub on PATH."""
    if os.name != "nt":
        found = shutil.which("bash")
        if found is None:
            pytest.skip("no bash on PATH")
        return found
    git = shutil.which("git")
    if git is None:
        pytest.skip(
            "no git on PATH, so no Git for Windows bash; the WSL stub cannot run"
        )
    for parent in Path(git).resolve().parents:
        candidate = parent / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    pytest.skip(f"no Git for Windows bash.exe above {git}; the WSL stub cannot run")


def bash_path(path: Union[str, Path]) -> str:
    """path as bash on this host names it: unchanged on POSIX, /c/x/y on Windows."""
    if os.name != "nt":
        return str(path)
    win = PureWindowsPath(str(path))
    drive = win.drive.rstrip(":").lower()
    rest = "/".join(win.parts[1:])
    return f"/{drive}/{rest}" if drive else win.as_posix()


def run_bash(
    script: str,
    stdin: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> "subprocess.CompletedProcess[str]":
    """Runs script with bash_exe(), script and stdin as LF bytes; output decoded."""
    done = subprocess.run(
        [bash_exe(), "-c", script.replace("\r\n", "\n")],
        input=None if stdin is None else stdin.replace("\r\n", "\n").encode("utf-8"),
        capture_output=True,
        env=None if env is None else dict(env),
        check=False,
    )
    return subprocess.CompletedProcess(
        done.args,
        done.returncode,
        done.stdout.decode("utf-8", "replace").replace("\r\n", "\n"),
        done.stderr.decode("utf-8", "replace").replace("\r\n", "\n"),
    )


def write_lf(path: Path, text: str, executable: bool = False) -> None:
    """Writes text with LF line ends whatever the host, optionally chmod 0755."""
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))
    if executable:
        path.chmod(0o755)
