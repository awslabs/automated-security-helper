"""Tests for cli/config.py — covers init, get, update, validate commands."""

from pathlib import Path

import yaml
from unittest.mock import patch
from typer.testing import CliRunner

from automated_security_helper.cli.config import (
    INVALID_CONFIG_EXIT_CODE,
    config_app,
)
from automated_security_helper.config.config_writer import IndentableYamlDumper


runner = CliRunner()


class TestIndentableYamlDumper:
    """Tests for the YAML dumper helper."""

    def test_dump_produces_valid_yaml(self):
        data = {"project_name": "test", "scanners": {"bandit": {"enabled": True}}}
        output = yaml.dump(data, Dumper=IndentableYamlDumper, default_flow_style=False)
        parsed = yaml.safe_load(output)
        assert parsed["project_name"] == "test"


class TestConfigInit:
    """Tests for the config init command."""

    def test_init_creates_config_file(self, tmp_path):
        config_path = tmp_path / ".ash" / ".ash.yaml"
        result = runner.invoke(
            config_app,
            ["init", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert config_path.exists()

    def test_init_refuses_overwrite_without_force(self, tmp_path):
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("existing: true")

        result = runner.invoke(
            config_app,
            ["init", "--config", str(config_path)],
        )
        assert result.exit_code == 1

    def test_init_overwrites_with_force(self, tmp_path):
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("existing: true")

        result = runner.invoke(
            config_app,
            ["init", "--config", str(config_path), "--force"],
        )
        assert result.exit_code == 0
        content = config_path.read_text()
        assert "project_name" in content or "project-name" in content

    def test_init_creates_gitignore(self, tmp_path):
        config_path = tmp_path / ".ash" / ".ash.yaml"
        result = runner.invoke(
            config_app,
            ["init", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        gitignore_path = tmp_path / ".ash" / ".gitignore"
        assert gitignore_path.exists()
        assert "ash_output" in gitignore_path.read_text()


class TestConfigGet:
    """Tests for the config get command."""

    def test_get_nonexistent_file_errors(self, tmp_path):
        """Exit 3, the code for a config that cannot be used, as `ash scan` exits."""
        result = runner.invoke(
            config_app,
            ["get", str(tmp_path / "nonexistent.yaml")],
        )
        assert result.exit_code == INVALID_CONFIG_EXIT_CODE
        assert "nonexistent.yaml" in "".join(result.output.split())

    def test_get_existing_config(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project-name: test-project\n")

        with patch(
            "automated_security_helper.cli.config.resolve_config"
        ) as mock_resolve:
            from automated_security_helper.config.ash_config import AshConfig

            mock_resolve.return_value = AshConfig(project_name="test-project")
            result = runner.invoke(
                config_app,
                ["get", str(config_path)],
            )
            assert result.exit_code == 0


class TestConfigGetRefusesUnparseableFiles:
    """``ash config get`` on a file that does not parse.

    resolve_config logs a file it cannot parse and returns the default
    configuration, which is right for a scan and wrong for this command: it
    exited 0 and printed the defaults as though they were the file's contents.
    It now exits 3, the CLI's documented code for an invalid configuration and
    the code this command already used for a file that parses but does not
    validate.
    """

    INVALID_YAML = "project_name: test\nreporters: [unclosed\n"

    def _assert_refused(self, result, path):
        assert result.exit_code == 3, result.output
        # The parse refusal is printed as it is: it already names the file and
        # says it could not be parsed, with no restating header (W2).
        assert "could not be parsed" in result.output
        assert "could not parse" not in result.output.replace("could not be parsed", "")
        assert str(path) in result.output
        # The defaults were not printed in its place.
        assert "global_settings" not in result.output

    def test_a_named_file_with_a_yaml_syntax_error(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(self.INVALID_YAML, encoding="utf-8")
        result = runner.invoke(config_app, ["get", str(config_path)])
        self._assert_refused(result, config_path)

    def test_a_discovered_file_with_a_yaml_syntax_error(self, tmp_path, monkeypatch):
        (tmp_path / ".ash").mkdir()
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.write_text(self.INVALID_YAML, encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(config_app, ["get"])
        self._assert_refused(result, Path(".ash") / ".ash.yaml")

    def test_a_json_file_that_does_not_parse(self, tmp_path):
        config_path = tmp_path / "ash.json"
        config_path.write_text('{"project_name": ', encoding="utf-8")
        result = runner.invoke(config_app, ["get", str(config_path)])
        self._assert_refused(result, config_path)

    def test_a_valid_file_still_prints(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project_name: printed-project\n", encoding="utf-8")
        result = runner.invoke(config_app, ["get", str(config_path)])
        assert result.exit_code == 0, result.output
        assert "printed-project" in result.output

    def test_no_config_file_still_prints_the_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(config_app, ["get"])
        assert result.exit_code == 0, result.output
        assert "global_settings" in result.output


class TestConfigUpdate:
    """Tests for the config update command."""

    def test_update_no_modifications(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project-name: test-project\n")

        with patch(
            "automated_security_helper.cli.config.AshConfig.from_file"
        ) as mock_load:
            from automated_security_helper.config.ash_config import AshConfig

            mock_load.return_value = AshConfig(project_name="test-project")
            result = runner.invoke(
                config_app,
                ["update", str(config_path)],
            )
            assert result.exit_code == 0

    def test_update_nonexistent_file(self, tmp_path):
        result = runner.invoke(
            config_app,
            ["update", str(tmp_path / "nonexistent.yaml"), "--set", "project_name=new"],
        )
        assert result.exit_code == INVALID_CONFIG_EXIT_CODE

    def test_update_dry_run(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project-name: test-project\n")

        with patch(
            "automated_security_helper.cli.config.AshConfig.from_file"
        ) as mock_load:
            from automated_security_helper.config.ash_config import AshConfig

            mock_load.return_value = AshConfig(project_name="test-project")
            result = runner.invoke(
                config_app,
                [
                    "update",
                    str(config_path),
                    "--set",
                    "project_name=new-name",
                    "--dry-run",
                ],
            )
            # Should succeed without writing
            assert "Dry run" in result.output or result.exit_code == 0

    def test_update_applies_modifications(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_content = "# yaml-language-server: $schema=...\nproject-name: test\n"
        config_path.write_text(config_content)

        with patch(
            "automated_security_helper.cli.config.AshConfig.from_file"
        ) as mock_load:
            from automated_security_helper.config.ash_config import AshConfig

            mock_load.return_value = AshConfig(project_name="test")
            result = runner.invoke(
                config_app,
                [
                    "update",
                    str(config_path),
                    "--set",
                    "project_name=updated",
                ],
            )
            # Should write the file or display it
            assert result.exit_code == 0

    def test_update_finds_config_auto(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        ash_dir = tmp_path / ".ash"
        ash_dir.mkdir()
        config_path = ash_dir / ".ash.yaml"
        config_path.write_text("project-name: test-project\n")

        with patch(
            "automated_security_helper.cli.config.AshConfig.from_file"
        ) as mock_load:
            from automated_security_helper.config.ash_config import AshConfig

            mock_load.return_value = AshConfig(project_name="test-project")
            result = runner.invoke(
                config_app,
                ["update", "--set", "project_name=new"],
            )
            # Should find config automatically
            assert result.exit_code == 0 or "not found" not in result.output.lower()


class TestConfigValidate:
    """Tests for the config validate command."""

    def test_validate_nonexistent_file(self):
        """A config that is not there cannot be loaded: exit 3, as a scan refuses it."""
        result = runner.invoke(
            config_app,
            ["validate", "--config", "/nonexistent/path.yaml"],
        )
        assert result.exit_code == INVALID_CONFIG_EXIT_CODE

    def test_validate_valid_config(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project-name: test\n")

        from automated_security_helper.config.config_validator import ConfigCheck

        with patch(
            "automated_security_helper.config.config_validator.ConfigValidator.check_config_file"
        ) as mock_check:
            mock_check.return_value = ConfigCheck()
            result = runner.invoke(
                config_app,
                ["validate", "--config", str(config_path)],
            )
            assert result.exit_code == 0
            mock_check.assert_called_once()

    def test_validate_invalid_config(self, tmp_path):
        from automated_security_helper.config.config_validator import ConfigCheck

        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project-name: test\ninvalid_section: true\n")

        with patch(
            "automated_security_helper.config.config_validator.ConfigValidator.check_config_file"
        ) as mock_check:
            mock_check.return_value = ConfigCheck(
                errors=[
                    "Invalid value at 'invalid_section': Extra inputs are not permitted"
                ]
            )
            result = runner.invoke(
                config_app,
                ["validate", "--config", str(config_path)],
            )
            # 3: the exit code a scan gives for an invalid configuration.
            assert result.exit_code == 3
            assert "invalid_section" in result.output


class TestConfigValidatePluginDependencies:
    """Tests for the validate_plugin_dependencies command."""

    def test_nonexistent_config_errors(self, tmp_path):
        result = runner.invoke(
            config_app,
            ["validate-plugin-dependencies", str(tmp_path / "nonexistent.yaml")],
        )
        assert result.exit_code == INVALID_CONFIG_EXIT_CODE

    def test_valid_config_passes(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project-name: test\n")

        with patch(
            "automated_security_helper.cli.config.resolve_config"
        ) as mock_resolve:
            from automated_security_helper.config.ash_config import AshConfig

            mock_resolve.return_value = AshConfig(project_name="test")
            result = runner.invoke(
                config_app,
                ["validate-plugin-dependencies", str(config_path)],
            )
            assert result.exit_code == 0

    def test_invalid_config_fails(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project-name: test\n")

        with patch(
            "automated_security_helper.cli.config.resolve_config",
            side_effect=Exception("Invalid config"),
        ):
            result = runner.invoke(
                config_app,
                ["validate-plugin-dependencies", str(config_path)],
            )
            assert result.exit_code != 0
