# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A uv command ``ash dependencies install`` runs finds no project or ``.venv`` in the tree.

Measured with uv 0.12.22, run as the standalone binary from a directory holding a
``.venv`` whose ``python`` records that it ran, and a ``pyproject.toml`` whose build
backend records that it ran:

- ``uv pip list`` and ``uv pip install`` ran the ``.venv`` python. So did ``uv run``,
  with or without ``--no-project``, ``--isolated`` or ``UV_PROJECT_ENVIRONMENT``.
  ``UV_NO_CONFIG`` changes nothing. ``--python`` (``UV_PYTHON``) and ``--system``
  stop it.
- ``uv run`` built the project, running its build backend, with ``UV_PYTHON`` too.
  ``--no-project`` (``UV_NO_PROJECT``) stops it.
- ``uv tool run`` and ``uv tool install`` did neither, and read only the user's uv
  configuration.

The empty start directory every install command now gets keeps uv away from the tree
when the system's temporary directory is outside it. uv also looks in every parent
directory, so with TMPDIR inside the tree it found the tree's ``.venv`` from there.
A uv command other than ``uv tool`` therefore also gets ``UV_NO_PROJECT=1`` and
``UV_PYTHON`` set to ASH's interpreter, unless it names an interpreter itself or the
operator set one. ``python -m uv`` was not affected by the ``.venv``: run that way,
uv uses the interpreter that started it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.cli import dependencies as dependencies_module

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the planted .venv python is a shell script"
)


def _uv() -> str:
    beside = Path(sys.executable).with_name("uv")
    found = str(beside) if beside.is_file() else shutil.which("uv")
    if found is None:
        pytest.skip("no uv binary")
    return found


def _plant_venv(repo: Path, marker: Path) -> None:
    """A ``.venv`` whose python appends to ``marker`` and then runs ASH's."""
    bin_dir = repo / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    python = bin_dir / "python"
    python.write_text(
        f'#!/bin/sh\necho venv >> "{marker}"\nexec "{sys.executable}" "$@"\n',
        encoding="utf-8",
    )
    python.chmod(0o755)
    (bin_dir / "python3").symlink_to("python")
    version = ".".join(map(str, sys.version_info[:3]))
    (repo / ".venv" / "pyvenv.cfg").write_text(
        f"home = {Path(sys.executable).parent}\n"
        f"include-system-site-packages = false\nversion = {version}\n",
        encoding="utf-8",
    )


def _plant_project(repo: Path, marker: Path) -> None:
    """A project whose build backend appends to ``marker`` when uv builds it."""
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "planted-project"\nversion = "0.0.1"\n\n'
        '[build-system]\nrequires = []\nbuild-backend = "planted_backend"\n'
        'backend-path = ["."]\n',
        encoding="utf-8",
    )
    (repo / "planted_backend.py").write_text(
        f"open({str(marker)!r}, 'a').write('project\\n')\n", encoding="utf-8"
    )


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("UV_") and key not in ("UV_CACHE_DIR", "UV_OFFLINE"):
            monkeypatch.delenv(key)
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONSAFEPATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("UV_OFFLINE", "1")
    path = tmp_path / "repo"
    path.mkdir()
    return path


def _run_from(argv: List[str], cwd: Path) -> None:
    subprocess.run(argv, cwd=cwd, capture_output=True, check=False, timeout=120)


def _through_the_installer(argv: List[str], repo: Path, monkeypatch) -> None:
    monkeypatch.setattr(dependencies_module, "print", lambda *a, **k: None)
    monkeypatch.chdir(repo)
    dependencies_module.run_command(argv)


CASES = [
    pytest.param(["pip", "list"], _plant_venv, "venv", id="uv-pip-list-venv"),
    pytest.param(
        ["run", "--offline", "python", "-c", "pass"],
        _plant_venv,
        "venv",
        id="uv-run-venv",
    ),
    pytest.param(
        ["run", "--offline", "python", "-c", "pass"],
        _plant_project,
        "project",
        id="uv-run-project",
    ),
]


@pytest.mark.parametrize(("args", "plant", "mark"), CASES)
def test_control_uv_uses_the_planted_file_from_the_repository(
    repo, tmp_path, args, plant, mark
):
    marker = tmp_path / "MARKER"
    plant(repo, marker)
    _run_from([_uv(), *args], repo)
    assert mark in marker.read_text(encoding="utf-8")


@pytest.mark.parametrize(("args", "plant", "mark"), CASES)
def test_control_uv_finds_the_planted_file_from_a_directory_below_it(
    repo, tmp_path, args, plant, mark
):
    """uv looks in parent directories, so an empty directory alone is not enough."""
    marker = tmp_path / "MARKER"
    plant(repo, marker)
    below = repo / "tmp" / "empty"
    below.mkdir(parents=True)
    _run_from([_uv(), *args], below)
    assert mark in marker.read_text(encoding="utf-8")


@pytest.mark.parametrize(("args", "plant", "mark"), CASES)
@pytest.mark.parametrize("tmpdir", ["outside", "inside"])
def test_the_installer_runs_uv_without_the_trees_project_or_venv(
    repo, tmp_path, monkeypatch, args, plant, mark, tmpdir
):
    marker = tmp_path / "MARKER"
    plant(repo, marker)
    if tmpdir == "inside":
        # The empty start directory is then created under the tree.
        inside = repo / "tmp"
        inside.mkdir()
        monkeypatch.setenv("TMPDIR", str(inside))
        monkeypatch.setattr(tempfile, "tempdir", None)
    _through_the_installer([_uv(), *args], repo, monkeypatch)
    assert not marker.exists(), marker.read_text(encoding="utf-8")


def test_the_overrides_leave_uv_tool_and_a_named_interpreter_alone(monkeypatch):
    from automated_security_helper.cli.dependencies import uv_child_overrides

    monkeypatch.delenv("UV_PYTHON", raising=False)
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)
    assert uv_child_overrides(["uv", "pip", "list"]) == {
        "UV_NO_PROJECT": "1",
        "UV_PYTHON": sys.executable,
    }
    assert uv_child_overrides(["/opt/bin/uv.exe", "--color", "never", "run", "x"]) == {
        "UV_NO_PROJECT": "1",
        "UV_PYTHON": sys.executable,
    }
    assert uv_child_overrides(["uv", "tool", "install", "bandit"]) == {}
    assert uv_child_overrides(["uvx", "bandit"]) == {}
    assert uv_child_overrides(["npm", "install", "-g", "x"]) == {}
    for named in (
        ["--python", "/x/python"],
        ["-p", "3.12"],
        ["--python=3.12"],
        ["--system"],
    ):
        assert uv_child_overrides(["uv", "pip", "install", *named, "x"]) == {
            "UV_NO_PROJECT": "1"
        }
    assert uv_child_overrides(["uv", "run", "--project", "/x", "y"]) == {
        "UV_PYTHON": sys.executable
    }
    monkeypatch.setenv("UV_PYTHON", "/operator/python")
    assert uv_child_overrides(["uv", "pip", "list"]) == {"UV_NO_PROJECT": "1"}
