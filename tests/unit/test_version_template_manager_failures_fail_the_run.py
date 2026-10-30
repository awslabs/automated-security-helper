# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``generate`` and ``convert`` exit non-zero when a file fails, and never write "unknown".

Why this file exists
--------------------
``generate_from_template`` and ``convert_to_template`` catch every exception, print it and
return False. ``generate_all_from_templates`` and ``convert_all_to_templates`` only count
the Trues, and ``main`` printed "Successfully generated N files" and fell off the end, so
the process exited 0 whatever failed: a target with no template, a doc that could not be
written, a template that could not be read. The release workflow runs ``generate`` and
passed with stale docs. ``main`` now exits 1 and names the files, using the new
``failures`` list, which also tells a failed file from one skipped for a reason that is
not an error (a template kept, no version reference).

``generate`` also rendered ``get_version()`` without looking at it. When neither the
checkout's pyproject.toml nor the installed metadata names a version, that function
returns the word "unknown", and every pin in every generated doc became "unknown". The
render now refuses it.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"
VERSION_MODULE = "automated_security_helper.utils.version_management"
REPO = "automated-security-" + "helper"
PIN_TEMPLATE = (
    f"pip install git+https://github.com/awslabs/{REPO}.git@v{{{{VERSION}}}}\n"
)
PIN_RENDERED = f"pip install git+https://github.com/awslabs/{REPO}.git@v1.2.3\n"
PIN_STALE = f"pip install git+https://github.com/awslabs/{REPO}.git@v1.0.0\n"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager_failures", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load_module()


def _project(root: Path, *, with_version: bool = True) -> Path:
    root.mkdir(exist_ok=True)
    if with_version:
        root.joinpath("pyproject.toml").write_text(
            "[project]\n"
            f'name = "{REPO}"\n'
            'version = "1.2.3"\n'
            "\n"
            "[tool.commitizen]\n"
            'version = "1.2.3"\n',
            encoding="utf-8",
        )
    root.joinpath("README.md.template").write_text(PIN_TEMPLATE, encoding="utf-8")
    root.joinpath("README.md").write_text(PIN_STALE, encoding="utf-8")
    return root


def _run(monkeypatch, root: Path, action: str, targets: list[str]):
    """Run main() for action against root, with the manager's targets replaced."""
    original_init = module.VersionTemplateManager.__init__

    def init(self, project_root):
        original_init(self, project_root)
        self.target_files = list(targets)

    monkeypatch.setattr(module.VersionTemplateManager, "__init__", init)
    monkeypatch.setattr(
        sys,
        "argv",
        ["version_template_manager.py", action, "--project-root", str(root)],
    )
    return module.main()


class TestGenerateExitStatus:
    def test_a_clean_run_exits_zero_and_writes_the_version(
        self, tmp_path, monkeypatch, capsys
    ):
        """The control."""
        root = _project(tmp_path / "project")
        assert (_run(monkeypatch, root, "generate", ["README.md"]) or 0) == 0
        assert root.joinpath("README.md").read_text(encoding="utf-8") == PIN_RENDERED
        assert "Successfully generated 1 files" in capsys.readouterr().out

    def test_a_target_with_no_template_exits_one(self, tmp_path, monkeypatch, capsys):
        root = _project(tmp_path / "project")
        status = _run(monkeypatch, root, "generate", ["README.md", "docs/missing.md"])
        captured = capsys.readouterr()
        assert status == 1
        assert "Successfully generated" not in captured.out
        assert "missing.md.template" in captured.err

    def test_a_doc_that_cannot_be_written_exits_one(
        self, tmp_path, monkeypatch, capsys
    ):
        root = _project(tmp_path / "project")
        root.joinpath("README.md").unlink()
        root.joinpath("README.md").mkdir()  # open(..., "w") on a directory raises
        status = _run(monkeypatch, root, "generate", ["README.md"])
        captured = capsys.readouterr()
        assert status == 1
        assert "Successfully generated" not in captured.out
        assert "README.md.template" in captured.err

    def test_the_failures_list_names_the_files(self, tmp_path):
        root = _project(tmp_path / "project")
        manager = module.VersionTemplateManager(root)
        manager.target_files = ["README.md", "docs/missing.md"]
        assert manager.generate_all_from_templates() == 1
        assert manager.failures == [root / "docs/missing.md.template"]
        manager.target_files = ["README.md"]
        assert manager.generate_all_from_templates() == 1
        assert manager.failures == []


class TestAnUnknownVersionIsNotRendered:
    def test_generate_keeps_the_doc_when_no_version_is_found(
        self, tmp_path, monkeypatch, capsys
    ):
        root = _project(tmp_path / "project", with_version=False)
        # No pyproject.toml in the root and no installed metadata: get_version()
        # falls through to its "unknown" last resort.
        monkeypatch.setattr(f"{VERSION_MODULE}._installed_version", lambda: None)
        manager = module.VersionTemplateManager(root)
        assert manager.generate_from_template(root / "README.md.template") is False
        assert root.joinpath("README.md").read_text(encoding="utf-8") == PIN_STALE
        assert "unknown" not in root.joinpath("README.md").read_text(encoding="utf-8")
        assert "no version could be determined" in capsys.readouterr().out

    def test_the_cli_exits_one_when_no_version_is_found(
        self, tmp_path, monkeypatch, capsys
    ):
        root = _project(tmp_path / "project", with_version=False)
        monkeypatch.setattr(f"{VERSION_MODULE}._installed_version", lambda: None)
        assert _run(monkeypatch, root, "generate", ["README.md"]) == 1
        assert root.joinpath("README.md").read_text(encoding="utf-8") == PIN_STALE


class TestConvertExitStatus:
    def test_a_doc_that_cannot_be_read_exits_one(self, tmp_path, monkeypatch, capsys):
        root = tmp_path / "project"
        root.mkdir()
        root.joinpath("README.md").mkdir()  # open(..., "r") on a directory raises
        status = _run(monkeypatch, root, "convert", ["README.md"])
        captured = capsys.readouterr()
        assert status == 1
        assert "Successfully converted" not in captured.out
        assert "README.md" in captured.err

    def test_a_template_kept_is_not_a_failure(self, tmp_path, monkeypatch, capsys):
        """The control: skipping a file for a reason that is not an error exits 0."""
        root = _project(tmp_path / "project")
        assert (_run(monkeypatch, root, "convert", ["README.md"]) or 0) == 0
        assert "Successfully converted 0 files" in capsys.readouterr().out
        assert root.joinpath("README.md.template").read_text(encoding="utf-8") == (
            PIN_TEMPLATE
        )
