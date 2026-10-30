# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/version_bump.py`` reads and writes the checkout it is pointed at.

Why this file exists
--------------------
``--project-root`` selected the docs that were regenerated and nothing else. The
current version came from ``get_version()`` with no root, which asked the
installed distribution's metadata first, and the pyproject.toml edit went to the
checkout the script was imported from. So ``set`` on another checkout edited one
tree's pyproject.toml and regenerated the other tree's docs; ``bump`` after a
``set`` without a reinstall computed from the stale installed version and wrote
the old version back; and every regenerated doc carried the installed version,
not the one just written.

Separately, ``set`` printed "Successfully updated" and returned 0 when a template
failed to render: ``generate_from_template`` reports the error and returns False,
``generate_all_from_templates`` only counts, and nothing compared the count with
the templates that exist. Compared with the templates that exist, a listed target
whose template was missing still read as success: it is reported as an error and
never counted, so the count is compared with the targets instead.

How the two checkouts are told apart
------------------------------------
Every test builds two trees under ``tmp_path``: ``project``, the one passed as
``--project-root``, and ``elsewhere``, which stands in for the script's own
checkout (``get_project_root`` is patched to it). Installed metadata is patched to
a third version. An assertion that ``project`` changed and ``elsewhere`` did not
is what separates the fixed behavior from the old one, and it keeps the test from
ever touching this repository's own pyproject.toml.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_bump.py"
MODULE = "automated_security_helper.utils.version_management"


def _load_version_bump(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "version_bump_under_test", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _checkout(root: Path, version: str, template: bool = True) -> Path:
    root.mkdir()
    root.joinpath("pyproject.toml").write_text(
        "[project]\n"
        'name = "automated-security-helper"\n'
        f'version = "{version}"\n'
        "\n"
        "[tool.commitizen]\n"
        f'version = "{version}"\n',
        encoding="utf-8",
    )
    if template:
        root.joinpath("README.md.template").write_text(
            "pip install git+https://example.invalid/ash.git@v{{VERSION}}\n",
            encoding="utf-8",
        )
        root.joinpath("README.md").write_text(
            f"pip install git+https://example.invalid/ash.git@v{version}\n",
            encoding="utf-8",
        )
    return root


@pytest.fixture
def two_checkouts(tmp_path, monkeypatch):
    """(the project root under test, the stand-in for the script's own checkout)."""
    project = _checkout(tmp_path / "project", "1.2.3")
    elsewhere = _checkout(tmp_path / "elsewhere", "0.0.1", template=False)
    monkeypatch.setattr(f"{MODULE}.get_project_root", lambda: elsewhere)
    return project, elsewhere


def _bumper(module, project: Path):
    bumper = module.VersionBumper(project)
    bumper.template_manager.target_files = ["README.md"]
    return bumper


class TestTheProjectRootIsTheCheckoutReadAndWritten:
    def test_current_version_comes_from_the_project_root(
        self, two_checkouts, monkeypatch
    ):
        project, _elsewhere = two_checkouts
        module = _load_version_bump(monkeypatch)
        with patch(f"{MODULE}.importlib.metadata.version", return_value="9.9.9"):
            assert _bumper(module, project).get_current_version() == "1.2.3"

    def test_set_edits_the_project_root_and_renders_its_docs_with_the_new_version(
        self, two_checkouts, monkeypatch, capsys
    ):
        project, elsewhere = two_checkouts
        module = _load_version_bump(monkeypatch)
        with patch(f"{MODULE}.importlib.metadata.version", return_value="9.9.9"):
            assert _bumper(module, project).set_version("2.0.0") is True
        pyproject = project.joinpath("pyproject.toml").read_text(encoding="utf-8")
        assert pyproject.count('version = "2.0.0"') == 2, pyproject
        assert (
            project.joinpath("README.md").read_text(encoding="utf-8")
            == "pip install git+https://example.invalid/ash.git@v2.0.0\n"
        )
        # The script's own checkout is not the one being bumped.
        assert 'version = "0.0.1"' in elsewhere.joinpath("pyproject.toml").read_text(
            encoding="utf-8"
        )
        assert "Current version: 1.2.3" in capsys.readouterr().out

    def test_bump_computes_from_the_project_roots_version(
        self, two_checkouts, monkeypatch
    ):
        project, _elsewhere = two_checkouts
        module = _load_version_bump(monkeypatch)
        with patch(f"{MODULE}.importlib.metadata.version", return_value="9.9.9"):
            assert _bumper(module, project).bump_version("patch") is True
        pyproject = project.joinpath("pyproject.toml").read_text(encoding="utf-8")
        assert 'version = "1.2.4"' in pyproject
        assert "9.9" not in pyproject


class TestAFailedRegenerationFailsTheSet:
    def test_a_template_that_does_not_render_fails_the_set(
        self, two_checkouts, monkeypatch, capsys
    ):
        project, _elsewhere = two_checkouts
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        monkeypatch.setattr(
            bumper.template_manager, "generate_from_template", lambda path: False
        )
        assert bumper.set_version("2.0.0") is False
        out = capsys.readouterr().out
        assert "Successfully updated" not in out
        assert "not regenerated" in out

    def test_an_exception_while_regenerating_fails_the_set(
        self, two_checkouts, monkeypatch, capsys
    ):
        project, _elsewhere = two_checkouts
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)

        def explode():
            raise ValueError("template placeholder missing")

        monkeypatch.setattr(
            bumper.template_manager, "generate_all_from_templates", explode
        )
        assert bumper.set_version("2.0.0") is False
        assert "Successfully updated" not in capsys.readouterr().out

    def test_a_target_with_no_template_fails_the_set(
        self, two_checkouts, monkeypatch, capsys
    ):
        """A listed target whose template is missing is reported as an error.

        Counted against the templates that exist rather than the targets, the
        miss was invisible: the set printed "Successfully updated" and returned
        True while the target's page kept the release it was written at.
        """
        project, _elsewhere = two_checkouts
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        bumper.template_manager.target_files = ["README.md", "docs/missing.md"]
        assert bumper.set_version("2.0.0") is False
        out = capsys.readouterr().out
        assert "Successfully updated" not in out
        assert "missing.md.template does not exist" in out
        assert "1 of 2 targets were not regenerated" in out
        # The target with a template was still rendered with the new version.
        assert (
            project.joinpath("README.md").read_text(encoding="utf-8")
            == "pip install git+https://example.invalid/ash.git@v2.0.0\n"
        )
