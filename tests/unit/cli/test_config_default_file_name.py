# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A new config file gets the name discovery treats as current.

Discovery (config/config_sources.py, #313) reads the `ashrc` names and
`[tool.ash]` after the older `.ash.*`/`ash.*` names, and its warning calls the
older names deprecated. So `ash config init` and `ash config wizard`
create a config under a current name, and so does `ash inspect findings` when it
writes a suppression and finds no config, never `.ash/.ash.yaml` or
`<cwd>/.ash.yaml`. Existing files under the old names keep loading.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.config_sources import discover_config_source
from automated_security_helper.core.constants import (
    ASH_DEFAULT_CONFIG_FILE_NAME,
    ASH_RC_FILE_NAMES,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def project(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "demo"
    root.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return root


def _run(*args: str, stdin: str | None = None):
    return CliRunner().invoke(app, ["config", *args], input=stdin)


def test_default_name_is_a_current_yaml_source():
    assert ASH_DEFAULT_CONFIG_FILE_NAME in ASH_RC_FILE_NAMES
    # The writers write YAML, and refuse TOML.
    assert ASH_DEFAULT_CONFIG_FILE_NAME.endswith((".yaml", ".yml"))


class TestInit:
    def test_writes_the_current_name_where_a_scan_finds_it(self, project):
        result = _run("init")

        assert result.exit_code == 0, result.output
        written = project / ASH_DEFAULT_CONFIG_FILE_NAME
        assert written.is_file()
        assert not (project / ".ash" / ".ash.yaml").exists()
        assert discover_config_source(project).selected.path == written
        assert "project_name: demo" in written.read_text(encoding="utf-8")

    def test_keeps_scan_output_out_of_git(self, project):
        assert _run("init").exit_code == 0

        gitignore = project / ".ash" / ".gitignore"
        assert "ash_output" in gitignore.read_text(encoding="utf-8")

    @pytest.mark.parametrize("existing", [".ash/.ash.yaml", ".ash.yaml", "ash.yml"])
    @pytest.mark.parametrize("force", [False, True], ids=["plain", "force"])
    def test_refuses_to_add_a_second_source(self, project, existing, force):
        path = project / existing
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("project_name: existing\n", encoding="utf-8")

        result = _run("init", *(["--force"] if force else []))

        assert result.exit_code == 1, result.output
        assert existing.split("/")[-1] in result.output
        assert not (project / ASH_DEFAULT_CONFIG_FILE_NAME).exists()
        assert path.read_text(encoding="utf-8") == "project_name: existing\n"

    def test_refuses_to_shadow_a_pyproject_table(self, project):
        (project / "pyproject.toml").write_text(
            '[tool.ash]\nproject_name = "existing"\n', encoding="utf-8"
        )

        result = _run("init")

        assert result.exit_code == 1, result.output
        assert "pyproject.toml" in result.output
        assert not (project / ASH_DEFAULT_CONFIG_FILE_NAME).exists()

    def test_force_overwrites_the_current_name(self, project):
        (project / ASH_DEFAULT_CONFIG_FILE_NAME).write_text("project_name: old\n")

        assert _run("init").exit_code == 1
        result = _run("init", "--force")

        assert result.exit_code == 0, result.output
        text = (project / ASH_DEFAULT_CONFIG_FILE_NAME).read_text(encoding="utf-8")
        assert "project_name: demo" in text

    def test_an_explicit_old_name_is_written(self, project):
        result = _run("init", "--config", ".ash/.ash.yaml")

        assert result.exit_code == 0, result.output
        assert (project / ".ash" / ".ash.yaml").is_file()


def _wizard_answers() -> str:
    from automated_security_helper.cli.config import (
        _get_reporter_names,
        _get_scanner_names,
    )

    lines = ["demo"]
    lines += [""] * (len(_get_scanner_names()) + len(_get_reporter_names()))
    lines += ["n", ""]  # no offline reminder, no plugin modules
    return "\n".join(lines) + "\n"


class TestWizard:
    def test_creates_the_current_name(self, project):
        result = _run("wizard", stdin=_wizard_answers())

        assert result.exit_code == 0, result.output
        assert (project / ASH_DEFAULT_CONFIG_FILE_NAME).is_file()
        assert not (project / ".ash" / ".ash.yaml").exists()

    def test_edits_the_config_a_scan_uses(self, project):
        existing = project / ".ash.yaml"
        existing.write_text("project_name: existing\n", encoding="utf-8")

        result = _run("wizard", stdin=_wizard_answers())

        assert result.exit_code == 0, result.output
        assert not (project / ASH_DEFAULT_CONFIG_FILE_NAME).exists()
        assert "project_name: demo" in existing.read_text(encoding="utf-8")


class TestInspectSuppressionTarget:
    def test_new_file_gets_the_current_name(self, project):
        from automated_security_helper.cli.inspect.inspect_findings_app import (
            _resolve_suppression_config_path,
        )

        assert (
            _resolve_suppression_config_path(None)
            == project / ASH_DEFAULT_CONFIG_FILE_NAME
        )

    def test_an_existing_config_is_used(self, project):
        from automated_security_helper.cli.inspect.inspect_findings_app import (
            _resolve_suppression_config_path,
        )

        existing = project / ".ash" / ".ash.yaml"
        existing.parent.mkdir()
        existing.write_text("project_name: existing\n", encoding="utf-8")

        assert _resolve_suppression_config_path(None) == existing


@pytest.mark.parametrize("command", ["validate", "lint"])
def test_no_config_to_check(project, command):
    result = _run(command)

    assert result.exit_code == 1, result.output
    assert "ash config init" in result.output
