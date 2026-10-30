# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/build_integration.py: the pre-build, validate and version-info actions.

* every action reads the version of the ``--project-root`` tree, not of the
  checkout the version module was imported from;
* a template that failed to generate fails the pre-build step instead of being
  counted out of a success, whether the count or the manager's failures list
  says so;
* ``validate`` refuses a root whose version is unknown, as ``pre-build`` does;
* ``run_command`` returns False for a binary that cannot be started.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def build_integration(script_loader):
    return script_loader("build_integration")


def _project_root(tmp_path: Path, name: str = "automated-security-helper") -> Path:
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "9.9.9"\n', encoding="utf-8"
    )
    (root / "automated_security_helper").mkdir()
    (root / "automated_security_helper" / "__init__.py").write_text(
        "", encoding="utf-8"
    )
    return root


class _FakeTemplateManager:
    def __init__(self, templates: int, generated: int, failures=()):
        self._templates = [Path(f"doc{i}.md.template") for i in range(templates)]
        self._generated = generated
        self.failures = list(failures)

    def list_templates(self):
        return list(self._templates)

    def generate_all_from_templates(self):
        return self._generated


class TestPreBuild:
    def test_reads_the_version_of_the_project_root(
        self, build_integration, tmp_path, capsys
    ):
        root = _project_root(tmp_path)
        assert build_integration.BuildIntegrator(root).pre_build_check() is True
        assert "Current version: 9.9.9" in capsys.readouterr().out

    def test_a_template_that_did_not_generate_fails_the_step(
        self, build_integration, tmp_path, capsys
    ):
        integrator = build_integration.BuildIntegrator(_project_root(tmp_path))
        integrator.template_manager = _FakeTemplateManager(templates=3, generated=2)
        assert integrator.pre_build_check() is False
        out = capsys.readouterr().out
        assert "only 2 of 3 templates were generated" in out
        assert "completed successfully" not in out

    def test_every_template_generated_is_a_success(self, build_integration, tmp_path):
        integrator = build_integration.BuildIntegrator(_project_root(tmp_path))
        integrator.template_manager = _FakeTemplateManager(templates=3, generated=3)
        assert integrator.pre_build_check() is True

    def test_a_template_the_manager_lists_as_failed_fails_the_step(
        self, build_integration, tmp_path, capsys
    ):
        """At the base the manager's failures list was never read, so a count that
        happened to match still printed success over a partial generation."""
        integrator = build_integration.BuildIntegrator(_project_root(tmp_path))
        integrator.template_manager = _FakeTemplateManager(
            templates=3, generated=3, failures=[Path("docs/guide.md.template")]
        )
        assert integrator.pre_build_check() is False
        out = capsys.readouterr().out
        assert "1 template(s) were not generated: docs/guide.md.template" in out
        assert "completed successfully" not in out


class TestValidate:
    def test_refuses_a_root_whose_version_is_unknown(
        self, build_integration, tmp_path, capsys, monkeypatch
    ):
        """get_version falls back to the installed distribution's metadata, so a
        foreign pyproject alone does not read as unknown where ASH is installed;
        the unknown answer is forced to test the refusal itself."""
        root = _project_root(tmp_path, name="some-other-project")
        monkeypatch.setattr(
            build_integration, "get_version", lambda root=None: "unknown"
        )
        assert build_integration.BuildIntegrator(root).validate_build_environment() is (
            False
        )
        assert "Could not determine version" in capsys.readouterr().out

    def test_passes_with_a_versioned_root(self, build_integration, tmp_path, capsys):
        root = _project_root(tmp_path)
        assert build_integration.BuildIntegrator(root).validate_build_environment() is (
            True
        )
        assert "current version: 9.9.9" in capsys.readouterr().out


class TestVersionInfo:
    def test_writes_the_project_roots_version(self, build_integration, tmp_path):
        root = _project_root(tmp_path)
        output = tmp_path / "version_info.txt"
        assert build_integration.BuildIntegrator(root).create_version_info_file(output)
        assert "Version: 9.9.9\n" in output.read_text(encoding="utf-8")


class TestRunCommand:
    def test_a_missing_binary_returns_false(
        self, build_integration, monkeypatch, capsys
    ):
        def missing(*args, **kwargs):
            raise FileNotFoundError(2, "No such file or directory", "no-such-tool")

        monkeypatch.setattr(build_integration.subprocess, "run", missing)
        assert build_integration.run_command(["no-such-tool", "--version"]) is False
        assert "could not be started" in capsys.readouterr().out

    def test_a_failing_command_returns_false(
        self, build_integration, monkeypatch, capsys
    ):
        def failing(*args, **kwargs):
            raise subprocess.CalledProcessError(1, args[0], stderr="boom")

        monkeypatch.setattr(build_integration.subprocess, "run", failing)
        assert build_integration.run_command(["tool"]) is False
        assert "Command failed" in capsys.readouterr().out
