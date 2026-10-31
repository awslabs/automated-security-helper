# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/version_bump.py set`` keeps pyproject.toml's mode and its symlink.

Why this file exists
--------------------
The version writer replaced pyproject.toml by writing a ``NamedTemporaryFile``
beside it and renaming that over the name. ``mkstemp`` creates its file at mode
0600, so after a ``set`` the checkout's pyproject.toml was readable only by its
owner: git does not record the mode bits below the executable bit, so nothing in
the diff showed it, but a container build or another user on a shared checkout
could no longer read the file. And a pyproject.toml that was a symlink stopped
being one, because the rename replaced the link at the name with a plain file
instead of writing the file the link pointed to.

What is asserted
----------------
After a ``set``, the file's permission bits are what they were, whether the
umask would have given them or not (0644 and 0600 both), and a symlinked
pyproject.toml is still the same link while the file it points to carries the
new version. Each test builds its own tree under ``tmp_path`` and points the
script's own-checkout lookup elsewhere, so no run touches this repository's
pyproject.toml.
"""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.version_management import (
    update_version_in_pyproject,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="permission bits and symlinks are POSIX semantics",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_bump.py"
MODULE = "automated_security_helper.utils.version_management"

PYPROJECT = (
    "[project]\n"
    'name = "automated-security-helper"\n'
    'version = "1.2.3"\n'
    "\n"
    "[tool.commitizen]\n"
    'version = "1.2.3"\n'
)


def _load_version_bump(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "version_bump_keeps_the_file_under_test", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _checkout(root: Path) -> Path:
    """A project tree with a pyproject.toml and one templated doc."""
    root.mkdir()
    root.joinpath("pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    root.joinpath("README.md.template").write_text(
        "pip install git+https://example.invalid/ash.git@v{{VERSION}}\n",
        encoding="utf-8",
    )
    root.joinpath("README.md").write_text(
        "pip install git+https://example.invalid/ash.git@v1.2.3\n", encoding="utf-8"
    )
    return root


@pytest.fixture
def project(tmp_path, monkeypatch):
    """The project root under test; the script's own checkout is a stand-in."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    elsewhere.joinpath("pyproject.toml").write_text(
        PYPROJECT.replace("1.2.3", "0.0.1"), encoding="utf-8"
    )
    monkeypatch.setattr(f"{MODULE}.get_project_root", lambda: elsewhere)
    return _checkout(tmp_path / "project")


def _set(module, project: Path, version: str) -> bool:
    bumper = module.VersionBumper(project)
    bumper.template_manager.target_files = ["README.md"]
    return bumper.set_version(version)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class TestSetKeepsTheMode:
    @pytest.mark.parametrize("mode", [0o644, 0o600], ids=["0644", "0600"])
    def test_the_file_keeps_the_mode_it_had(self, project, monkeypatch, mode):
        pyproject = project / "pyproject.toml"
        os.chmod(pyproject, mode)
        assert _mode(pyproject) == mode

        module = _load_version_bump(monkeypatch)
        assert _set(module, project, "2.0.0") is True

        assert _mode(pyproject) == mode
        text = pyproject.read_text(encoding="utf-8")
        assert text.count('version = "2.0.0"') == 2, text
        assert "1.2.3" not in text

    def test_a_world_readable_file_stays_readable_whatever_the_umask(
        self, project, monkeypatch
    ):
        # The staging file is created under the process umask; the mode the
        # target had is what survives, so a restrictive umask changes nothing.
        pyproject = project / "pyproject.toml"
        os.chmod(pyproject, 0o644)
        before = os.umask(0o077)
        try:
            assert update_version_in_pyproject("2.0.0", project_root=project) is True
        finally:
            os.umask(before)
        assert _mode(pyproject) == 0o644
        assert 'version = "2.0.0"' in pyproject.read_text(encoding="utf-8")


class TestSetWritesThroughASymlinkedPyproject:
    def test_the_link_survives_and_its_target_changes(self, project, monkeypatch):
        real_dir = project.parent / "real"
        real_dir.mkdir()
        real = real_dir / "pyproject.toml"
        link = project / "pyproject.toml"
        real.write_text(link.read_text(encoding="utf-8"), encoding="utf-8")
        link.unlink()
        link.symlink_to(real)

        module = _load_version_bump(monkeypatch)
        assert _set(module, project, "2.0.0") is True

        assert link.is_symlink(), "the link was replaced by a plain file"
        assert os.readlink(link) == str(real)
        text = real.read_text(encoding="utf-8")
        assert text.count('version = "2.0.0"') == 2, text
        assert link.read_text(encoding="utf-8") == text
        # The doc beside the link is regenerated with the version just written.
        assert (
            project.joinpath("README.md").read_text(encoding="utf-8")
            == "pip install git+https://example.invalid/ash.git@v2.0.0\n"
        )

    def test_a_relative_link_is_resolved_from_its_own_directory(
        self, project, monkeypatch
    ):
        real_dir = project.parent / "real"
        real_dir.mkdir()
        real = real_dir / "pyproject.toml"
        link = project / "pyproject.toml"
        os.chmod(link, 0o640)
        real.write_text(link.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(real, 0o640)
        link.unlink()
        link.symlink_to(Path("..") / "real" / "pyproject.toml")

        assert update_version_in_pyproject("2.0.0", project_root=project) is True

        assert link.is_symlink()
        assert os.readlink(link) == os.path.join("..", "real", "pyproject.toml")
        assert 'version = "2.0.0"' in real.read_text(encoding="utf-8")
        # The target's own mode is the one kept, read through the link.
        assert _mode(real) == 0o640
        # Nothing was staged or left in the directory that holds the link.
        assert sorted(p.name for p in project.iterdir()) == [
            "README.md",
            "README.md.template",
            "pyproject.toml",
        ]
