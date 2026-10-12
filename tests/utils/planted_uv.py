"""A tree that uv would use if it looked there: a ``.venv`` and a project.

Each records that it was used by appending a word to a marker file: the ``.venv``'s
python writes ``venv`` and then runs ASH's, and the project's build backend writes
``project`` when uv builds it. The python is a shell script, so tests using these
skip on Windows.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

#: uv commands that, run from the tree, use a planted file (measured with uv 0.12.22).
#: Each is (arguments after ``uv``, planting function name, word the plant writes).
PIP_LIST = ["pip", "list"]
RUN = ["run", "--offline", "python", "-c", "pass"]


def uv_binary() -> str:
    """The standalone uv binary: run as ``python -m uv`` it ignores a ``.venv``."""
    beside = Path(sys.executable).with_name("uv")
    found = str(beside) if beside.is_file() else shutil.which("uv")
    if found is None:
        pytest.skip("no uv binary")
    return found


def plant_venv(repo: Path, marker: Path) -> None:
    """A ``.venv`` whose python appends ``venv`` to ``marker`` and then runs ASH's."""
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


def plant_project(repo: Path, marker: Path) -> None:
    """A project whose build backend appends ``project`` to ``marker`` when built."""
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "planted-project"\nversion = "0.0.1"\n\n'
        '[build-system]\nrequires = []\nbuild-backend = "planted_backend"\n'
        'backend-path = ["."]\n',
        encoding="utf-8",
    )
    (repo / "planted_backend.py").write_text(
        f"open({str(marker)!r}, 'a').write('project\\n')\n", encoding="utf-8"
    )


def clear_uv_environment(monkeypatch) -> None:
    """Leave uv only the cache and offline settings, and no active environment."""
    for key in list(os.environ):
        if key.startswith("UV_") and key not in ("UV_CACHE_DIR", "UV_OFFLINE"):
            monkeypatch.delenv(key)
    for key in ("VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONSAFEPATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("UV_OFFLINE", "1")
