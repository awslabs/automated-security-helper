# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""setup-ash's entry-point check: `ash` on PATH must be the ASH just installed.

Why this file exists
--------------------
setup-ash used to append ``$env:APPDATA\\Python\\Scripts`` to GITHUB_PATH on
Windows. zizmor's github-env audit reported the write, and the directory never held
``ash.exe``: pip put it in the interpreter's own Scripts directory, which
setup-python already has on PATH. The write is gone. In its place,
``.github/actions/setup-ash/locate_entry_point.py`` checks the contract callers rely
on and exposes the directory as the action's ``scripts-dir`` output. These tests pin
the three outcomes that matter: found and reachable, not installed, and shadowed by
another ``ash``, which on Windows is the Almquist shell Git for Windows and MSYS2
ship.

The script runs here against temporary directories, not a real install. Whether a
hosted runner's PATH really reaches the install is what the step checks in CI.
"""

from __future__ import annotations

import importlib.util
import os
import stat
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION_DIR = REPO_ROOT / ".github" / "actions" / "setup-ash"
SCRIPT = ACTION_DIR / "locate_entry_point.py"
EXE = "ash.exe" if os.name == "nt" else "ash"


@pytest.fixture
def locate():
    spec = importlib.util.spec_from_file_location("locate_entry_point", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _entry_point(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    exe = directory / EXE
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return exe


def test_found_and_on_path_writes_the_output(locate, tmp_path, monkeypatch, capsys):
    scripts = tmp_path / "scripts"
    _entry_point(scripts)
    output = tmp_path / "github_output"
    monkeypatch.setattr(locate, "candidate_dirs", lambda: [str(scripts)])
    monkeypatch.setenv("PATH", str(scripts))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert locate.main() == 0
    assert output.read_text(encoding="utf-8") == f"scripts-dir={scripts}\n"
    assert "ash resolves to" in capsys.readouterr().out


def test_nothing_installed_fails_by_name(locate, tmp_path, monkeypatch, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    output = tmp_path / "github_output"
    monkeypatch.setattr(locate, "candidate_dirs", lambda: [str(empty)])
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert locate.main() == 1
    assert "::error::" in capsys.readouterr().out
    assert not output.exists(), "a failed check must not hand callers a directory"


def test_a_shadowing_ash_earlier_on_path_fails(locate, tmp_path, monkeypatch, capsys):
    scripts = tmp_path / "scripts"
    _entry_point(scripts)
    shadow = tmp_path / "msys64" / "usr" / "bin"
    _entry_point(shadow)
    monkeypatch.setattr(locate, "candidate_dirs", lambda: [str(scripts)])
    monkeypatch.setenv("PATH", os.pathsep.join([str(shadow), str(scripts)]))
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    assert locate.main() == 1
    out = capsys.readouterr().out
    assert "::error::" in out and str(shadow) in out


def test_installed_but_not_on_path_fails(locate, tmp_path, monkeypatch, capsys):
    scripts = tmp_path / "scripts"
    _entry_point(scripts)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setattr(locate, "candidate_dirs", lambda: [str(scripts)])
    monkeypatch.setenv("PATH", str(elsewhere))
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    assert locate.main() == 1
    assert "resolves to nothing" in capsys.readouterr().out


def test_the_candidates_come_from_this_interpreter(locate):
    """Control: the real candidate list is non-empty and includes the scheme's dir."""
    import sysconfig

    dirs = locate.candidate_dirs()
    assert sysconfig.get_path("scripts") in dirs
    assert len(dirs) == len(set(dirs))


def test_the_action_runs_the_check_and_exposes_its_output():
    """The script is only a guard if setup-ash runs it and maps what it writes."""
    action = yaml.safe_load((ACTION_DIR / "action.yml").read_text(encoding="utf-8"))
    (step,) = [
        s for s in action["runs"]["steps"] if SCRIPT.name in str(s.get("run", ""))
    ]
    assert step.get("shell") == "pwsh", (
        "the check should run under pwsh so it sees the runner's PATH, not one Git "
        "Bash has rearranged"
    )
    assert "inputs.install-ash == 'true'" in str(step.get("if", ""))
    assert "exit $LASTEXITCODE" in step["run"]
    value = action["outputs"]["scripts-dir"]["value"]
    assert value == f"${{{{ steps.{step['id']}.outputs.scripts-dir }}}}"
