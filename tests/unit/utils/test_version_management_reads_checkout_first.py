# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_version reads the checkout it is imported from before installed metadata.

Why this file exists
--------------------
``get_version()`` asked ``importlib.metadata`` first and read pyproject.toml only
when no distribution was installed. In a checkout with an editable install, which
is every development environment and CI, the metadata records the version at
install time while pyproject.toml moves with the tree. So ``version_bump.py set``
wrote the new version into pyproject.toml, then regenerated every templated doc
with ``get_version()`` and stamped the OLD version into them; and a second
``bump`` without a reinstall computed from the old base and wrote the old
version back over the new one. ``--version`` in such an environment named the
version of the install, not of the tree, and with two installs on sys.path it
named whichever came first rather than the one imported.

The same functions took no project root, so ``version_bump.py --project-root``
redirected the docs it regenerated and nothing else: the version was read from,
and written into, the checkout the script was imported from.

What is asserted
----------------
The order (pyproject.toml of the checkout, then the distribution that owns this
package, then "unknown"), the project-root argument on reads and writes, the
refusal to take another project's pyproject.toml as ASH's version, and the two
writing fixes that share the function: both version tables move together, and a
failed write leaves the file as it was.
"""

from __future__ import annotations

import importlib.metadata
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.utils import version_management
from automated_security_helper.utils.version_management import (
    get_version,
    get_version_from_pyproject,
    update_version_in_pyproject,
)

pytestmark = pytest.mark.unit

MODULE = "automated_security_helper.utils.version_management"


def _write_pyproject(root: Path, version: str, name: str = "automated-security-helper"):
    root.joinpath("pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\n', encoding="utf-8"
    )


class _FakeDistribution:
    def __init__(self, version: str, package_dir: Path):
        self.version = version
        self._package_dir = package_dir

    def locate_file(self, path):
        return self._package_dir if path == "automated_security_helper" else Path(path)


class TestTheCheckoutComesFirst:
    def test_the_checkouts_pyproject_wins_over_installed_metadata(self, tmp_path):
        _write_pyproject(tmp_path, "9.9.9")
        with (
            patch(f"{MODULE}.get_project_root", return_value=tmp_path),
            patch(f"{MODULE}.importlib.metadata.version", return_value="1.0.0"),
            patch(f"{MODULE}.importlib.metadata.distributions", return_value=iter([])),
        ):
            assert get_version() == "9.9.9"

    def test_project_root_selects_the_checkout_read(self, tmp_path):
        _write_pyproject(tmp_path, "9.9.9")
        with patch(f"{MODULE}.importlib.metadata.version", return_value="1.0.0"):
            assert get_version(project_root=tmp_path) == "9.9.9"
            assert get_version_from_pyproject(tmp_path) == "9.9.9"

    def test_another_projects_pyproject_is_not_a_version_of_ash(self, tmp_path):
        _write_pyproject(tmp_path, "9.9.9", name="some-other-project")
        assert get_version_from_pyproject(tmp_path) is None
        with (
            patch(f"{MODULE}.importlib.metadata.version", return_value="1.0.0"),
            patch(f"{MODULE}.importlib.metadata.distributions", return_value=iter([])),
        ):
            assert get_version(project_root=tmp_path) == "1.0.0"

    def test_the_distribution_owning_this_package_is_preferred(self, tmp_path):
        own_dir = Path(version_management.__file__).resolve().parent.parent
        other = _FakeDistribution("0.0.1", tmp_path / "elsewhere" / "pkg")
        own = _FakeDistribution("5.5.5", own_dir)
        with (
            patch(f"{MODULE}.get_version_from_pyproject", return_value=None),
            patch(f"{MODULE}.importlib.metadata.version", return_value="0.0.1"),
            patch(
                f"{MODULE}.importlib.metadata.distributions",
                return_value=iter([other, own]),
            ),
        ):
            assert get_version() == "5.5.5"

    def test_unknown_when_nothing_answers(self, tmp_path):
        with (
            patch(f"{MODULE}.importlib.metadata.distributions", return_value=iter([])),
            patch(
                f"{MODULE}.importlib.metadata.version",
                side_effect=importlib.metadata.PackageNotFoundError("none"),
            ),
        ):
            assert get_version(project_root=tmp_path) == "unknown"


class TestUpdateVersionInPyproject:
    def test_project_root_selects_the_checkout_written(self, tmp_path):
        _write_pyproject(tmp_path, "1.0.0")
        assert update_version_in_pyproject("2.0.0", project_root=tmp_path) is True
        assert 'version = "2.0.0"' in tmp_path.joinpath("pyproject.toml").read_text()

    def test_both_version_tables_move_together(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\n"
            'name = "automated-security-helper"\n'
            'version = "1.0.0"\n'
            "\n"
            "[tool.commitizen]\n"
            'name = "cz_conventional_commits"\n'
            'version = "1.0.0"\n'
            "\n"
            "[tool.other]\n"
            'foo = {version = "2.0.0"}\n'
            'version = "3.3.3"\n',
            encoding="utf-8",
        )
        assert update_version_in_pyproject("3.0.0", project_root=tmp_path) is True
        text = pyproject.read_text(encoding="utf-8")
        assert text.count('version = "3.0.0"') == 2, text
        # A dependency's inline table and another tool's key are not the release.
        assert 'foo = {version = "2.0.0"}' in text
        assert 'version = "3.3.3"' in text

    def test_a_failed_write_leaves_the_file_as_it_was(self, tmp_path, monkeypatch):
        _write_pyproject(tmp_path, "1.0.0")
        before = tmp_path.joinpath("pyproject.toml").read_text(encoding="utf-8")

        def refuse(*args, **kwargs):
            raise OSError("disk full")

        # The rename is the shared atomic-write helper's, so the refusal is
        # planted on the os module it calls, not on this module's own name.
        monkeypatch.setattr(os, "replace", refuse)
        assert update_version_in_pyproject("2.0.0", project_root=tmp_path) is False
        assert tmp_path.joinpath("pyproject.toml").read_text(encoding="utf-8") == before
        assert [p.name for p in tmp_path.iterdir()] == ["pyproject.toml"]
