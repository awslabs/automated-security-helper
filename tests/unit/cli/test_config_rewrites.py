# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config update` and `ash config wizard` write only configs a scan accepts.

`update` writes no internal-only field (`name`, `extension`,
`build: null`) back into the file, and a `--set` it cannot parse writes
nothing and exits 3; neither command replaces an `!ENV` reference with the
value it resolves to. `wizard` refuses to overwrite a config it cannot load
or parse. Every writer writes a `.json` config as JSON.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.config import (
    _get_reporter_names,
    _get_scanner_names,
    config_app,
)
from automated_security_helper.config.config_validator import ConfigValidator

pytestmark = pytest.mark.unit

INVALID_CONFIG_EXIT = 3

STARTING_CONFIG = textwrap.dedent(
    """\
    project_name: demo
    fail_on_findings: true
    scanners:
      bandit:
        enabled: true
    """
)


@pytest.fixture
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash" / ".ash.yaml"
    path.parent.mkdir()
    path.write_text(STARTING_CONFIG, encoding="utf-8")
    return path


def _update(config_file: Path, *sets: str):
    args = ["update", str(config_file)]
    for value in sets:
        args += ["--set", value]
    return CliRunner().invoke(config_app, args)


SUPPRESSION = {"rule_id": "CVE-2024-0001", "path": "requirements.txt", "reason": "r"}


class TestUpdate:
    def test_an_appended_suppression_holds_only_the_fields_it_sets(self, config_file):
        """Each list item was written with every unset field as `null`."""
        result = _update(
            config_file, f"global_settings.suppressions+={json.dumps([SUPPRESSION])}"
        )

        assert result.exit_code == 0, result.output
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert data["global_settings"]["suppressions"] == [SUPPRESSION]
        assert ConfigValidator.check_config_file(config_file).errors == []

    @pytest.mark.parametrize(
        "suffix",
        [
            pytest.param(" ", id="space"),
            pytest.param("\r\n", id="crlf"),
            pytest.param("\r", id="cr"),
            pytest.param("\t", id="tab"),
        ],
    )
    def test_a_list_with_trailing_whitespace_is_still_a_list(self, config_file, suffix):
        """`$(cat file)` keeps a CR, and the value is read as a list, not a string."""
        result = _update(
            config_file,
            f"global_settings.suppressions+={json.dumps([SUPPRESSION])}{suffix}",
        )

        assert result.exit_code == 0, result.output
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert data["global_settings"]["suppressions"] == [SUPPRESSION]

    def test_written_file_has_no_internal_fields(self, config_file):
        result = _update(config_file, "global_settings.severity_threshold=LOW")

        assert result.exit_code == 0, result.output
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert data["global_settings"]["severity_threshold"] == "LOW"
        assert "build" not in data
        assert "name" not in data["scanners"]["bandit"]
        assert all("extension" not in r for r in data["reporters"].values())
        check = ConfigValidator.check_config_file(config_file)
        assert check.errors == []
        assert check.warnings == [], check.warnings

    def test_customized_mcp_resource_management_is_kept(self, config_file):
        config_file.write_text(
            STARTING_CONFIG + "mcp-resource-management:\n  max_concurrent_scans: 7\n",
            encoding="utf-8",
        )

        result = _update(config_file, "fail_on_findings=false")

        assert result.exit_code == 0, result.output
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert data["mcp-resource-management"]["max_concurrent_scans"] == 7

    def test_unknown_top_level_keys_are_kept(self, config_file):
        # The model ignores keys it does not declare; a rewrite must not delete them.
        config_file.write_text(STARTING_CONFIG + "from_a_newer_version: 1\n")

        result = _update(config_file, "fail_on_findings=false")

        assert result.exit_code == 0, result.output
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert data["from_a_newer_version"] == 1
        assert data["fail_on_findings"] is False

    @pytest.mark.parametrize(
        "bad_set",
        [
            pytest.param("fail_on_findings", id="no-equals"),
            pytest.param("=true", id="no-key"),
            pytest.param("fail_on_findings=maybe", id="invalid-value"),
        ],
    )
    def test_bad_set_writes_nothing_and_exits_3(self, config_file, bad_set):
        result = _update(config_file, "global_settings.severity_threshold=LOW", bad_set)

        assert result.exit_code == INVALID_CONFIG_EXIT, result.output
        assert config_file.read_text(encoding="utf-8") == STARTING_CONFIG
        # The key, or for a --set with none the format it should have.
        assert "fail_on_findings" in result.output or "key.path=value" in result.output

    def test_invalid_existing_file_exits_3(self, config_file):
        config_file.write_text("project_name: demo\nfail_on_findings: banana\n")

        result = _update(config_file, "global_settings.severity_threshold=LOW")

        assert result.exit_code == INVALID_CONFIG_EXIT, result.output
        assert "fail_on_findings" in result.output

    def test_env_references_are_not_replaced(self, config_file, monkeypatch):
        monkeypatch.setenv("ASH_TEST_DEMO_NAME", "value-from-env")
        text = "project_name: !ENV ${ASH_TEST_DEMO_NAME:demo}\nfail_on_findings: true\n"
        config_file.write_text(text, encoding="utf-8")

        result = _update(config_file, "fail_on_findings=false")

        assert result.exit_code == 1, result.output
        assert "!ENV" in result.output
        assert config_file.read_text(encoding="utf-8") == text


def _wizard_answers(project_name: str) -> str:
    lines = [project_name]
    lines += [""] * len(_get_scanner_names())
    lines += [""] * len(_get_reporter_names())
    lines.append("n")  # the ASH_OFFLINE reminder comment
    lines.append("")  # no plugin modules
    return "\n".join(lines) + "\n"


class TestWizard:
    def test_refuses_to_overwrite_a_config_it_cannot_load(self, config_file):
        text = "project_name: demo\nfail_on_findings: banana\n"
        config_file.write_text(text, encoding="utf-8")

        result = CliRunner().invoke(
            config_app,
            ["wizard", "--config", str(config_file)],
            input=_wizard_answers("demo"),
        )

        assert result.exit_code == INVALID_CONFIG_EXIT, result.output
        assert "fail_on_findings" in result.output
        assert config_file.read_text(encoding="utf-8") == text

    def test_refuses_to_overwrite_a_config_that_does_not_parse(self, config_file):
        text = "project_name: [unclosed\n"
        config_file.write_text(text, encoding="utf-8")

        result = CliRunner().invoke(
            config_app,
            ["wizard", "--config", str(config_file)],
            input=_wizard_answers("demo"),
        )

        assert result.exit_code == INVALID_CONFIG_EXIT, result.output
        assert config_file.read_text(encoding="utf-8") == text

    def test_env_references_are_not_replaced(self, config_file, monkeypatch):
        monkeypatch.setenv("ASH_TEST_DEMO_NAME", "value-from-env")
        text = "project_name: !ENV ${ASH_TEST_DEMO_NAME:demo}\n"
        config_file.write_text(text, encoding="utf-8")

        result = CliRunner().invoke(
            config_app,
            ["wizard", "--config", str(config_file)],
            input=_wizard_answers("demo"),
        )

        assert result.exit_code == 1, result.output
        assert "!ENV" in result.output
        assert config_file.read_text(encoding="utf-8") == text

    def test_unknown_top_level_keys_are_kept(self, config_file):
        config_file.write_text("project_name: demo\nfrom_a_newer_version: 1\n")

        result = CliRunner().invoke(
            config_app,
            ["wizard", "--config", str(config_file)],
            input=_wizard_answers("demo"),
        )

        assert result.exit_code == 0, result.output
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert data["from_a_newer_version"] == 1

    def test_edits_a_valid_config(self, config_file):
        result = CliRunner().invoke(
            config_app,
            ["wizard", "--config", str(config_file)],
            input=_wizard_answers("renamed"),
        )

        assert result.exit_code == 0, result.output
        check = ConfigValidator.check_config_file(config_file)
        assert check.errors == [] and check.warnings == [], check
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert data["project_name"] == "renamed"


class TestJsonConfigs:
    """A `.json` config is rewritten as JSON.

    `update`, `init --config x.json` and `lint --fix` write no YAML and no `#`
    schema comment into it, so the loader parses the file and a scan reads that
    configuration.
    """

    @pytest.fixture
    def json_config(self, tmp_path: Path, monkeypatch) -> Path:
        monkeypatch.chdir(tmp_path)
        path = tmp_path / ".ash.json"
        path.write_text(
            json.dumps(
                {
                    "project_name": "demo",
                    "scanners": {"bandit": {"enabled": True, "name": "bandit"}},
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_update_writes_json(self, json_config):
        result = _update(json_config, "fail_on_findings=false")

        assert result.exit_code == 0, result.output
        data = json.loads(json_config.read_text(encoding="utf-8"))
        assert data["fail_on_findings"] is False
        assert ConfigValidator.check_config_file(json_config).scan_accepts

    def test_update_keeps_the_schema_key(self, json_config):
        data = json.loads(json_config.read_text(encoding="utf-8"))
        data["$schema"] = "https://example.invalid/AshConfig.json"
        json_config.write_text(json.dumps(data), encoding="utf-8")

        result = _update(json_config, "fail_on_findings=false")

        assert result.exit_code == 0, result.output
        written = json.loads(json_config.read_text(encoding="utf-8"))
        assert written["$schema"] == "https://example.invalid/AshConfig.json"

    def test_lint_fix_writes_json(self, json_config):
        result = CliRunner().invoke(
            config_app,
            ["lint", "--config", str(json_config), "--fix", "--non-interactive"],
        )

        assert result.exit_code == 0, result.output
        data = json.loads(json_config.read_text(encoding="utf-8"))
        assert data == {
            "project_name": "demo",
            "scanners": {"bandit": {"enabled": True}},
        }

    def test_lint_fix_unused_refuses_json(self, json_config):
        before = json_config.read_text(encoding="utf-8")
        result = CliRunner().invoke(
            config_app,
            ["lint", "--config", str(json_config), "--fix-unused", "--non-interactive"],
        )

        assert result.exit_code == 1, result.output
        assert "JSON" in result.output
        assert json_config.read_text(encoding="utf-8") == before

    def test_a_saved_suppression_keeps_the_file_json(self, json_config):
        # What the `ash inspect findings` suppression dialog calls.
        from automated_security_helper.config.ash_config import (
            add_suppression_to_config,
        )
        from automated_security_helper.models.core import AshSuppression

        suppression = AshSuppression(rule_id="B101", path="app.py", reason="tests")
        add_suppression_to_config(json_config, suppression)
        add_suppression_to_config(json_config, suppression)  # a duplicate is skipped

        data = json.loads(json_config.read_text(encoding="utf-8"))
        assert data["global_settings"]["suppressions"] == [
            {"rule_id": "B101", "path": "app.py", "reason": "tests"}
        ]
        assert data["scanners"]["bandit"]["name"] == "bandit"  # nothing else changed
        assert ConfigValidator.check_config_file(json_config).scan_accepts

    @pytest.mark.parametrize("name", ["session.json", "session.yaml"])
    def test_save_writes_what_the_commands_write(self, tmp_path, name):
        """AshConfig.save, which the MCP server writes session configs with."""
        from automated_security_helper.config.ash_config import AshConfig

        config = AshConfig(project_name="saved")
        target = tmp_path / name

        config.save(target, as_written=False)

        text = target.read_text(encoding="utf-8")
        if name.endswith(".json"):
            json.loads(text)
        assert "extension:" not in text and '"extension"' not in text
        check = ConfigValidator.check_config_file(target)
        assert check.errors == [] and check.warnings == [], check
        # The fields, not the models: a loaded config carries private attributes
        # the loader sets (_loaded_from, resolve_config.load_config_file), which
        # pydantic's == compares, so a loaded config never equals a built one.
        assert AshConfig.from_file(target).model_dump() == config.model_dump()

    def test_init_writes_json(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        target = tmp_path / "ash.json"

        result = CliRunner().invoke(config_app, ["init", "--config", str(target)])

        assert result.exit_code == 0, result.output
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["project_name"] == tmp_path.name
        assert ConfigValidator.check_config_file(target).warnings == []


class TestRefusalsAndMessages:
    def test_update_drops_a_build_section_the_file_had(self, config_file):
        """`build` is a model field the writer leaves out; the file's own copy of
        it is not carried over as an unknown key."""
        config_file.write_text(
            STARTING_CONFIG + "build:\n  build_mode: ONLINE\n", encoding="utf-8"
        )

        result = _update(config_file, "global_settings.severity_threshold=LOW")

        assert result.exit_code == 0, result.output
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert "build" not in data
        assert data["global_settings"]["severity_threshold"] == "LOW"

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["update", "--set", "fail_on_findings=false"], id="update"),
            pytest.param(["wizard"], id="wizard"),
            pytest.param(["lint", "--fix", "-y"], id="lint-fix"),
        ],
    )
    def test_a_bare_reference_is_named_in_the_refusal(
        self, config_file, monkeypatch, args
    ):
        """A `${VAR:default}` reference, not only `!ENV`, makes a rewrite refuse,
        and the refusal names both forms."""
        monkeypatch.setenv("ASH_TEST_DEMO_NAME", "value-from-env")
        text = (
            "project_name: ${ASH_TEST_DEMO_NAME:demo}\n"
            "fail_on_findings: true\nbuild:\n  build_mode: ONLINE\n"
        )
        config_file.write_text(text, encoding="utf-8")

        result = CliRunner().invoke(
            config_app,
            [args[0], "--config", str(config_file), *args[1:]],
            input=_wizard_answers("demo"),
        )

        assert result.exit_code == 1, result.output
        flat = " ".join(result.output.split())
        assert "environment references (${VAR} or !ENV)" in flat, flat
        assert config_file.read_text(encoding="utf-8") == text

    @pytest.mark.parametrize("command", ["update", "wizard"])
    def test_an_invalid_file_is_described_without_pydantic_text(
        self, config_file, command
    ):
        """pydantic's own text quotes each input (`input_value=1`)."""
        text = "project_name: demo\nfail_on_findings: 1\n"
        config_file.write_text(text, encoding="utf-8")

        args = ["update", str(config_file), "--set", "fail_on_findings=false"]
        if command == "wizard":
            args = ["wizard", "--config", str(config_file)]
        result = CliRunner().invoke(config_app, args, input=_wizard_answers("demo"))

        assert result.exit_code == INVALID_CONFIG_EXIT, result.output
        flat = " ".join(result.output.split())
        assert "Invalid value at 'fail_on_findings'" in flat, flat
        assert "input_value" not in flat, flat
        assert "errors.pydantic.dev" not in flat, flat
        assert config_file.read_text(encoding="utf-8") == text


class TestTomlTargets:
    """`init` and `wizard` write YAML, so a `.toml` target is refused.

    They wrote YAML into it, which the TOML reader then refused (exit 3 from
    validate), and `init --config pyproject.toml --force` would have replaced
    the project's pyproject.toml with YAML.
    """

    @pytest.mark.parametrize("command", ["init", "wizard"])
    def test_a_new_toml_file_is_refused(self, tmp_path, monkeypatch, command):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        target = tmp_path / "ash.toml"

        result = CliRunner().invoke(
            config_app,
            [command, "--config", str(target)],
            input=_wizard_answers("demo"),
        )

        assert result.exit_code == 1, result.output
        assert "TOML" in result.output, result.output
        assert not target.exists()

    @pytest.mark.parametrize("command", ["init", "wizard"])
    def test_pyproject_is_not_overwritten(self, tmp_path, monkeypatch, command):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        pyproject = tmp_path / "pyproject.toml"
        text = '[project]\nname = "x"\n\n[tool.ash]\nproject_name = "x"\n'
        pyproject.write_text(text, encoding="utf-8")
        extra = ["--force"] if command == "init" else []

        result = CliRunner().invoke(
            config_app,
            [command, "--config", str(pyproject), *extra],
            input=_wizard_answers("demo"),
        )

        assert result.exit_code == 1, result.output
        assert "TOML" in result.output, result.output
        assert pyproject.read_text(encoding="utf-8") == text


PYPROJECT_TEXT = '[project]\nname = "x"\n\n[tool.ash]\nproject_name = "x"\n'
TAB_INDENTED_JSON = '{\n\t"project_name": "x"\n}\n'


class TestSuffixCase:
    """A config's format follows its suffix in upper or lower case alike.

    The checks matched `.toml` and `.json` in lower case only. A file system
    that ignores case (the default on macOS and Windows) opens the project's
    pyproject.toml for `PYPROJECT.TOML`, and `init --config PYPROJECT.TOML
    --force` replaced it with YAML; a scan read it as YAML. `ash.JSON` was read
    as YAML and rewritten as YAML. These tests name the files in other cases
    on a file system that keeps them apart, which is what the checks see.
    """

    @pytest.fixture(autouse=True)
    def _in_tmp(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_CONFIG", raising=False)

    @pytest.mark.parametrize("command", ["init", "wizard"])
    @pytest.mark.parametrize("name", ["ash.TOML", "ash.Toml"])
    def test_a_new_toml_file_is_refused(self, tmp_path, command, name):
        target = tmp_path / name

        result = CliRunner().invoke(
            config_app,
            [command, "--config", str(target)],
            input=_wizard_answers("demo"),
        )

        assert result.exit_code == 1, result.output
        assert "TOML" in result.output, result.output
        assert not target.exists()

    @pytest.mark.parametrize("command", ["init", "wizard"])
    def test_pyproject_is_not_overwritten(self, tmp_path, command):
        pyproject = tmp_path / "PYPROJECT.TOML"
        pyproject.write_text(PYPROJECT_TEXT, encoding="utf-8")
        extra = ["--force"] if command == "init" else []

        result = CliRunner().invoke(
            config_app,
            [command, "--config", str(pyproject), *extra],
            input=_wizard_answers("demo"),
        )

        assert result.exit_code == 1, result.output
        assert "TOML" in result.output, result.output
        assert pyproject.read_text(encoding="utf-8") == PYPROJECT_TEXT

    @pytest.mark.parametrize("flag", ["--fix", "--fix-unused"])
    def test_lint_fix_refuses_toml(self, tmp_path, flag):
        target = tmp_path / "PyProject.Toml"
        target.write_text(PYPROJECT_TEXT, encoding="utf-8")

        result = CliRunner().invoke(
            config_app, ["lint", "--config", str(target), flag, "--non-interactive"]
        )

        assert result.exit_code == 1, result.output
        assert target.read_text(encoding="utf-8") == PYPROJECT_TEXT

    @pytest.mark.parametrize("method", ["fix", "fix_unused_suppressions"])
    def test_the_linter_itself_refuses_toml(self, tmp_path, method):
        """ConfigLinter refuses as well, not only the command in front of it."""
        from automated_security_helper.config.config_linter import ConfigLinter

        target = tmp_path / "ASH.TOML"
        target.write_text('project_name = "x"\n', encoding="utf-8")

        with pytest.raises(ValueError, match="by hand"):
            getattr(ConfigLinter, method)(target)
        assert target.read_text(encoding="utf-8") == 'project_name = "x"\n'

    def test_a_saved_suppression_refuses_toml(self, tmp_path):
        from automated_security_helper.config.ash_config import (
            add_suppression_to_config,
        )
        from automated_security_helper.models.core import AshSuppression

        target = tmp_path / "PYPROJECT.TOML"
        target.write_text(PYPROJECT_TEXT, encoding="utf-8")

        with pytest.raises(ValueError, match="TOML"):
            add_suppression_to_config(
                target, AshSuppression(rule_id="B101", path="app.py", reason="r")
            )
        assert target.read_text(encoding="utf-8") == PYPROJECT_TEXT

    @pytest.mark.parametrize(
        "name, text",
        [
            pytest.param("PYPROJECT.TOML", PYPROJECT_TEXT, id="pyproject"),
            pytest.param("ash.TOML", 'project_name = "x"\n', id="toml"),
            # Indented with a tab, which JSON allows and YAML refuses.
            pytest.param("ash.JSON", TAB_INDENTED_JSON, id="json"),
        ],
    )
    def test_the_file_is_read_in_its_format(self, tmp_path, name, text):
        """What validate and a scan read. pyproject's other tables are not
        settings, YAML reads neither TOML file the way TOML does, and it
        refuses JSON indented with tabs."""
        from automated_security_helper.config.config_sources import read_config_file

        target = tmp_path / name
        target.write_text(text, encoding="utf-8")

        assert read_config_file(target) == {"project_name": "x"}
        result = CliRunner().invoke(config_app, ["validate", "--config", str(target)])
        assert result.exit_code == 0, result.output

    def test_update_writes_json(self, tmp_path):
        target = tmp_path / "ash.JSON"
        target.write_text('{"project_name": "demo"}', encoding="utf-8")

        result = _update(target, "fail_on_findings=false")

        assert result.exit_code == 0, result.output
        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["fail_on_findings"] is False
        assert ConfigValidator.check_config_file(target).scan_accepts

    def test_init_writes_json(self, tmp_path):
        target = tmp_path / "ash.JSON"

        result = CliRunner().invoke(config_app, ["init", "--config", str(target)])

        assert result.exit_code == 0, result.output
        assert json.loads(target.read_text(encoding="utf-8"))["project_name"]

    def test_lint_fix_writes_json(self, tmp_path):
        target = tmp_path / "ash.Json"
        target.write_text(
            json.dumps(
                {
                    "project_name": "demo",
                    "scanners": {"bandit": {"enabled": True, "name": "bandit"}},
                }
            ),
            encoding="utf-8",
        )

        result = CliRunner().invoke(
            config_app, ["lint", "--config", str(target), "--fix", "--non-interactive"]
        )

        assert result.exit_code == 0, result.output
        assert json.loads(target.read_text(encoding="utf-8")) == {
            "project_name": "demo",
            "scanners": {"bandit": {"enabled": True}},
        }

    def test_lint_fix_unused_refuses_json(self, tmp_path):
        target = tmp_path / "ash.JSON"
        target.write_text('{"project_name": "demo"}', encoding="utf-8")

        result = CliRunner().invoke(
            config_app,
            ["lint", "--config", str(target), "--fix-unused", "--non-interactive"],
        )

        assert result.exit_code == 1, result.output
        assert "JSON" in result.output
        assert target.read_text(encoding="utf-8") == '{"project_name": "demo"}'

    def test_a_saved_suppression_keeps_the_file_json(self, tmp_path):
        from automated_security_helper.config.ash_config import (
            add_suppression_to_config,
        )
        from automated_security_helper.models.core import AshSuppression

        target = tmp_path / "ash.JSON"
        target.write_text('{"project_name": "demo"}', encoding="utf-8")

        add_suppression_to_config(
            target, AshSuppression(rule_id="B101", path="app.py", reason="r")
        )

        data = json.loads(target.read_text(encoding="utf-8"))
        assert data["global_settings"]["suppressions"] == [
            {"rule_id": "B101", "path": "app.py", "reason": "r"}
        ]

    def test_a_value_an_upper_case_toml_file_reads_is_hidden(
        self, tmp_path, monkeypatch
    ):
        """The checks read an environment-read file again literally and in its
        own format (`ash.TOML` as TOML), and the warning names the setting
        without its value. The path has no trailing "/", which
        would be read as the directory and everything under it, so that the
        directory warning is printed."""
        monkeypatch.setenv("ASH_TEST_PROBE", "SECRETDIRZQ")
        (tmp_path / "SECRETDIRZQ").mkdir()
        target = tmp_path / "ash.TOML"
        target.write_text(
            'project_name = "demo"\n\n[[global_settings.ignore_paths]]\n'
            'path = "${ASH_TEST_PROBE:vendor}"\nreason = "r"\n',
            encoding="utf-8",
        )

        for command in ("validate", "lint"):
            result = CliRunner().invoke(config_app, [command, "--config", str(target)])

            assert "points to a directory" in result.output, result.output
            assert "SECRETDIRZQ" not in result.output, result.output

    def test_the_literal_reader_reads_json(self, tmp_path):
        from automated_security_helper.config.config_sources import (
            read_config_file_literally,
        )

        target = tmp_path / "ash.JSON"
        target.write_text(TAB_INDENTED_JSON, encoding="utf-8")

        assert read_config_file_literally(target) == {"project_name": "x"}

    def test_a_toml_file_holds_no_yaml_environment_reference(self, tmp_path):
        """Read as YAML, this file is one scalar that is a reference."""
        from automated_security_helper.config.config_sources import (
            uses_env_references,
        )

        target = tmp_path / "ash.TOML"
        target.write_text("${ASH_TEST_PROBE:x}\n", encoding="utf-8")

        assert uses_env_references(target) is False

    def test_a_toml_file_that_does_not_parse_is_reported_as_toml(self, tmp_path):
        target = tmp_path / "ash.TOML"
        target.write_text("project_name = \n", encoding="utf-8")

        check = ConfigValidator.check_config_file(target)

        assert check.errors and check.errors[0].startswith("TOML parsing error:"), check

    def test_update_shows_a_json_file_as_json(self, tmp_path, monkeypatch):
        import automated_security_helper.cli.config as config_module

        lexers = []
        real_syntax = config_module.Syntax

        def recording_syntax(*args, **kwargs):
            lexers.append(kwargs.get("lexer"))
            return real_syntax(*args, **kwargs)

        monkeypatch.setattr(config_module, "Syntax", recording_syntax)
        target = tmp_path / "ash.JSON"
        target.write_text('{"project_name": "demo"}', encoding="utf-8")

        result = _update(target, "fail_on_findings=false")

        assert result.exit_code == 0, result.output
        assert lexers == ["json"], lexers

    def test_the_linter_refuses_to_comment_in_json(self, tmp_path):
        from automated_security_helper.config.config_linter import ConfigLinter

        target = tmp_path / "ash.JSON"
        target.write_text('{"project_name": "demo"}', encoding="utf-8")

        with pytest.raises(ValueError, match="JSON cannot hold"):
            ConfigLinter.fix_unused_suppressions(target)
