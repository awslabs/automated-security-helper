# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""tests/utils/posix_bash.py picks a bash that runs scripts, on every host.

The Windows half is exercised here with a faked os.name and PATH, because a Linux run
is where a mistake in it would otherwise go unnoticed until a Windows unit cell fails.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.utils import posix_bash


class _Nt:
    name = "nt"


def test_on_windows_it_takes_gits_bash_not_the_wsl_stub(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_root = tmp_path / "Git"
    (git_root / "cmd").mkdir(parents=True)
    (git_root / "bin").mkdir()
    (git_root / "cmd" / "git.exe").write_bytes(b"")
    (git_root / "bin" / "bash.exe").write_bytes(b"")
    stub = tmp_path / "System32" / "bash.exe"
    found = {"git": str(git_root / "cmd" / "git.exe"), "bash": str(stub)}
    monkeypatch.setattr(shutil, "which", lambda name: found.get(name))
    monkeypatch.setattr(posix_bash, "os", _Nt)
    assert posix_bash.bash_exe() == str((git_root / "bin" / "bash.exe").resolve())

    found.pop("git")
    with pytest.raises(pytest.skip.Exception, match="no git on PATH"):
        posix_bash.bash_exe()


@pytest.mark.parametrize(
    ("native", "expected"),
    [
        (r"C:\Users\runner\work\x", "/c/Users/runner/work/x"),
        (r"D:\a\_temp\pytest-0\t", "/d/a/_temp/pytest-0/t"),
    ],
)
def test_on_windows_a_path_has_no_drive_colon_or_backslash(
    monkeypatch: pytest.MonkeyPatch, native: str, expected: str
) -> None:
    monkeypatch.setattr(posix_bash, "os", _Nt)
    assert posix_bash.bash_path(native) == expected


def test_scripts_and_stdin_go_in_with_lf_line_ends(tmp_path: Path) -> None:
    # `cat -A`-free check: count carriage returns bash actually received.
    done = posix_bash.run_bash(
        "printf '%s' \"$(cat)\" | tr -cd '\\r' | wc -c\r\n",
        stdin="a\r\nb\r\n",
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "0"
    target = tmp_path / "f.sh"
    posix_bash.write_lf(target, "x\r\ny\r\n", executable=True)
    assert target.read_bytes() == b"x\ny\n"
