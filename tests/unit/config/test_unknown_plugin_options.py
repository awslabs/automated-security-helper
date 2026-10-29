# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An option a plugin does not declare refuses the config, naming plugin and key.

A key the plugin does not declare is not kept, unvalidated and unread:
``scanners.bandit.options.severity_level: HIGH`` (the option is
``severity_threshold``) would leave bandit gating at the global threshold, and
nothing would say so.

So:

* a built-in plugin's options are checked when the config loads, because its
  config section is a typed field of the config model; the scan exits 3, and
  the error's location names the plugin (``scanners.bandit.options``) and the
  message names the key, with "did you mean" when one is close;
* a plugin loaded from ``ash_plugin_modules`` is configured through a section
  the config model cannot type, so its options are checked as soon as the
  plugins are loaded, before anything is converted or scanned, also exit 3;
* a section for a plugin that is not loaded cannot be checked, and is left as
  it is.

``offline`` is declared on every scanner's options: ASH reads it for every
scanner (``ScannerPluginBase._scanner_offline``), including those that do not
declare it themselves, so refusing it would break configs that work.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import UNREADABLE_EXPIRATION_NOTE
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)

AshConfig.model_rebuild()


def _config(**sections):
    return AshConfig.model_validate({"project_name": "t", **sections})


class TestBuiltInPlugins:
    def test_scanner_option_typo_is_refused_with_a_suggestion(self):
        with pytest.raises(ValidationError) as excinfo:
            _config(scanners={"bandit": {"options": {"severity_level": "HIGH"}}})
        message = str(excinfo.value)
        assert "scanners.bandit.options" in message, message
        assert "severity_level" in message
        assert "did you mean 'severity_threshold'" in message

    def test_reporter_option_typo_is_refused(self):
        with pytest.raises(ValidationError) as excinfo:
            _config(
                reporters={"markdown": {"options": {"include_detailed_finding": False}}}
            )
        message = str(excinfo.value)
        assert "reporters.markdown.options" in message
        assert "did you mean 'include_detailed_findings'" in message

    def test_converter_option_typo_is_refused(self):
        with pytest.raises(ValidationError) as excinfo:
            _config(converters={"jupyter": {"options": {"tool_versoin": ">=7"}}})
        assert "did you mean 'tool_version'" in str(excinfo.value)

    def test_an_unrelated_key_is_named_without_a_suggestion(self):
        with pytest.raises(ValidationError) as excinfo:
            _config(scanners={"bandit": {"options": {"colour": "blue"}}})
        assert "colour" in str(excinfo.value)
        assert "did you mean" not in str(excinfo.value)

    def test_the_config_file_exits_3(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text(
            "project_name: demo\n"
            "scanners:\n"
            "  bandit:\n"
            "    options:\n"
            "      severity_level: HIGH\n",
            encoding="utf-8",
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=source)
        assert "severity_level" in str(excinfo.value)

    def test_declared_options_load(self):
        config = _config(
            scanners={
                "bandit": {
                    "options": {
                        "confidence_level": "high",
                        "severity_threshold": "HIGH",
                        "scan_timeout": 60,
                    }
                },
                "cdk-nag": {"options": {"nag_packs": {"AwsSolutionsChecks": True}}},
            },
            converters={"jupyter": {"options": {"tool_version": ">=7.16.0,<8.0.0"}}},
        )
        assert config.scanners.bandit.options.confidence_level == "high"

    def test_offline_is_accepted_and_read_on_a_scanner_that_never_declared_it(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        config = BanditScannerConfig.model_validate({"options": {"offline": True}})
        from automated_security_helper.base.plugin_context import PluginContext

        context = PluginContext(
            source_dir=tmp_path, output_dir=tmp_path / "out", config=_config()
        )
        scanner = BanditScanner(context=context, config=config)
        assert scanner._scanner_offline() is True


class TestLoadedPlugins:
    """A plugin from ash_plugin_modules is checked once the plugins are loaded."""

    @staticmethod
    def _engine(tmp_path, config, scanners=(TrivyRepoScanner,)):
        from automated_security_helper.core.execution_engine import (
            ScanExecutionEngine,
        )
        from automated_security_helper.plugins import ash_plugin_manager

        context = MagicMock()
        context.config = config
        context.source_dir = tmp_path
        context.output_dir = tmp_path / "out"
        context.work_dir = tmp_path / "work"

        def plugin_modules(plugin_type, *args, **kwargs):
            return list(scanners) if plugin_type == "scanner" else []

        with patch.object(ash_plugin_manager, "plugin_modules", plugin_modules):
            return ScanExecutionEngine(context=context, asharp_model=MagicMock())

    def test_an_unknown_option_of_a_loaded_plugin_exits_3(self, tmp_path):
        config = _config(
            scanners={"trivy-repo": {"options": {"skip_dirs": ["tests/test_data"]}}}
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            self._engine(tmp_path, config)
        message = str(excinfo.value)
        assert "scanner 'trivy-repo'" in message, message
        assert "skip_dirs" in message

    def test_a_typo_gets_a_suggestion(self, tmp_path):
        config = _config(scanners={"trivy-repo": {"options": {"ignore_unfix": True}}})
        with pytest.raises(ASHConfigValidationError) as excinfo:
            self._engine(tmp_path, config)
        assert "did you mean 'ignore_unfixed'" in str(excinfo.value)

    def test_declared_options_of_a_loaded_plugin_load(self, tmp_path):
        config = _config(scanners={"trivy-repo": {"options": {"ignore_unfixed": True}}})
        self._engine(tmp_path, config)

    @pytest.mark.parametrize("key", ["trivy_repo", "TrivyRepo", "trivyrepo"])
    def test_every_spelling_the_plugin_reads_is_checked(self, tmp_path, key):
        """get_plugin_config finds the section under these spellings too, so the
        check has to look there as well."""
        config = _config(scanners={key: {"options": {"skip_dirs": ["x"]}}})
        with pytest.raises(ASHConfigValidationError) as excinfo:
            self._engine(tmp_path, config)
        assert f"scanners.{key}.options" in str(excinfo.value)

    def test_a_plugin_validator_keeps_its_own_message(self, tmp_path):
        """ferret-scan refuses `debug` with a pointer to `ferret_debug`; the
        check reports the plugin's own validation error rather than a generic
        "Unknown key"."""
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
            FerretScanScanner,
        )

        config = _config(scanners={"ferret-scan": {"options": {"debug": True}}})
        with pytest.raises(ASHConfigValidationError) as excinfo:
            self._engine(tmp_path, config, scanners=(FerretScanScanner,))
        message = str(excinfo.value)
        assert "scanners.ferret-scan.options" in message
        assert "Use 'ferret_debug: true' instead" in message, message

    def test_an_invalid_value_of_a_loaded_plugin_is_refused_too(self, tmp_path):
        config = _config(
            scanners={"trivy-repo": {"options": {"ignore_unfixed": "sometimes"}}}
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            self._engine(tmp_path, config)
        assert "ignore_unfixed" in str(excinfo.value)

    def test_a_section_for_a_plugin_that_is_not_loaded_is_left_alone(self, tmp_path):
        config = _config(scanners={"not-loaded": {"options": {"anything": 1}}})
        self._engine(tmp_path, config)

    def test_the_section_left_alone_is_logged_without_an_env_read_key(
        self, tmp_path, monkeypatch
    ):
        """The debug line names the section's key, and names a key the config file
        read from the environment by its place, not by its value."""
        from automated_security_helper.config import plugin_option_check

        canary = "ash-canary-7f3e-0123456789"
        monkeypatch.setenv("ASH_PROBE_VALUE", canary)
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text(
            "project_name: t\nscanners:\n  ${ASH_PROBE_VALUE}:\n    enabled: true\n",
            encoding="utf-8",
        )
        config = resolve_config(config_file)
        # The control: the key was read from the environment.
        assert canary in (config.scanners.model_extra or {}), config.scanners
        with patch.object(plugin_option_check, "ASH_LOGGER") as log:
            plugin_option_check.refuse_unknown_plugin_options(
                config, {"scanner": [TrivyRepoScanner]}
            )
        logged = " ".join(str(call) for call in log.mock_calls)
        # The control: the section was logged as not checked.
        assert "were not checked" in logged, logged
        assert canary not in logged, logged


class TestStoredResults:
    """A results file written with an option the plugin no longer declares loads."""

    REPO_RESULTS = (
        Path(__file__).resolve().parents[2]
        / "test_data"
        / "outputs"
        / "ash_aggregated_results.json"
    )

    @staticmethod
    def _warnings(text):
        with patch("automated_security_helper.models.asharp_model.ASH_LOGGER") as log:
            AshAggregatedResults.model_validate_json(text)
        return [str(c.args[0]) for c in log.warning.call_args_list]

    def test_community_plugins_declared_options_load_without_warnings(self):
        """A community or AWS plugin's section is not typed by the config model,
        so a results file cannot check its options. Its declared options must not
        be reported as unknown because the generic base does not declare them."""
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        data["ash_config"]["scanners"]["trivy-repo"] = {
            "enabled": True,
            "options": {"ignore_unfixed": True, "scanners": ["vuln"]},
        }
        data["ash_config"]["reporters"]["aws-security-hub"] = {
            "enabled": False,
            "options": {"aws_region": "us-east-1"},
        }
        # The fixture's TBD expirations warn, as they should, each naming where it
        # is (one is under scanners.bandit.options); nothing else warns.
        warnings = self._warnings(json.dumps(data))
        assert warnings, "the fixture's expirations no longer warn"
        assert all(UNREADABLE_EXPIRATION_NOTE in w for w in warnings), warnings

    def test_the_repository_results_fixture_loads_without_warnings(self):
        assert self._warnings(self.REPO_RESULTS.read_text(encoding="utf-8")) == []

    FIXTURE = (
        Path(__file__).resolve().parents[2]
        / "test_data"
        / "outputs"
        / "written_before_expiration_checks"
        / "ash_aggregated_results.json"
    )

    def test_loads_and_warns(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        data["ash_config"]["scanners"]["bandit"]["options"]["severity_level"] = "HIGH"
        with patch("automated_security_helper.models.asharp_model.ASH_LOGGER") as log:
            model = AshAggregatedResults.model_validate_json(json.dumps(data))
        options = model.ash_config.scanners.bandit.options
        assert options.model_extra == {"severity_level": "HIGH"}
        warnings = [str(c.args[0]) for c in log.warning.call_args_list]
        # Named by the section that holds it; the stored key is shown as <key>.
        assert any(
            "unknown key <key> in 'scanners.bandit.options'" in w for w in warnings
        ), warnings
        assert not [w for w in warnings if "severity_level" in w], warnings


def test_a_plugin_with_no_options_says_so():
    """The YAML reporter declares no options (``YAMLReporterConfigOptions`` is
    ``ReporterOptionsBase`` with nothing added); the message said "Accepted
    keys: ." The archive converter this test first used now declares its
    extraction limits, so it is no longer a plugin without options."""
    with pytest.raises(ValidationError) as excinfo:
        AshConfig.model_validate(
            {"project_name": "p", "reporters": {"yaml": {"options": {"x": 1}}}}
        )
    message = str(excinfo.value)
    assert "Unknown key 'x'" in message
    assert "Accepted keys: ." not in message
    assert "the plugin declares no options" in message, message


def test_a_plugin_built_from_a_dict_refuses_an_unknown_option(tmp_path):
    """Outside a results file the generic options bases still refuse.

    A plugin's ``config`` is its own config model or the generic
    ``ScannerPluginConfigBase``. If the generic branch accepted what the
    plugin's own model refused, the plugin would be built with the generic
    config, and run with its defaults, whatever the section said.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.base.uv_tool_mixin import UVToolMixin

    (tmp_path / "src").mkdir()
    (tmp_path / "out").mkdir()
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        config=AshConfig(project_name="p"),
    )
    with patch.object(UVToolMixin, "_get_uv_tool_version", return_value=None):
        with pytest.raises(ValidationError) as excinfo:
            TrivyRepoScanner(context=context, config={"options": {"bogus": 1}})
    errors = excinfo.value.errors()
    assert errors and all("bogus" in error["msg"] for error in errors), errors


def test_the_schema_says_unknown_options_are_refused():
    schema = AshConfig.model_json_schema()
    definitions = schema.get("$defs", {})
    for name in (
        "BanditScannerConfigOptions",
        "MarkdownReporterConfigOptions",
        "JupyterConverterConfigOptions",
        "AshSuppression",
        "IgnorePathWithReason",
    ):
        assert definitions[name].get("additionalProperties") is False, name


class TestTheResultsSchemaMatchesTheLoader:
    """AshAggregatedResults.json accepts the unknown keys a results load keeps.

    The config schema says ``additionalProperties: false`` for ignore paths,
    suppressions and plugin options, because a configuration file with an unknown
    key there is refused. A results file is loaded tolerantly, so one written by
    another ASH version keeps such a key with a warning; a results schema that
    refused it would call a file invalid that ASH reads.
    """

    RESULTS = TestStoredResults.REPO_RESULTS

    @staticmethod
    def _schemas():
        from automated_security_helper.schemas.generate_schemas import (
            generate_schemas,
        )

        return generate_schemas("dict")

    def _with_unknown_keys(self):
        data = json.loads(self.RESULTS.read_text(encoding="utf-8"))
        settings = data["ash_config"]["global_settings"]
        settings["ignore_paths"][0]["owner"] = "team-a"
        settings["suppressions"] = [
            {"path": "src/a.py", "reason": "r", "rule_id": "B101", "ticket": "T-1"}
        ]
        data["ash_config"]["scanners"]["bandit"]["options"]["severity_level"] = "HIGH"
        return data

    def test_the_loader_keeps_them(self):
        data = self._with_unknown_keys()
        with patch("automated_security_helper.models.asharp_model.ASH_LOGGER"):
            model = AshAggregatedResults.model_validate_json(json.dumps(data))
        settings = model.ash_config.global_settings
        assert settings.ignore_paths[0].model_extra == {"owner": "team-a"}
        assert settings.suppressions[0].model_extra == {"ticket": "T-1"}
        options = model.ash_config.scanners.bandit.options
        assert options.model_extra == {"severity_level": "HIGH"}

    def test_the_results_schema_accepts_them(self):
        import jsonschema

        data = self._with_unknown_keys()
        schema = self._schemas()["AshAggregatedResults"]
        errors = list(jsonschema.Draft202012Validator(schema).iter_errors(data))
        assert errors == [], [error.message for error in errors]

    def test_the_config_schema_still_refuses_them(self):
        import jsonschema

        config = self._with_unknown_keys()["ash_config"]
        schema = self._schemas()["AshConfig"]
        messages = sorted(
            error.message
            for error in jsonschema.Draft202012Validator(schema).iter_errors(config)
        )
        assert len(messages) == 3, messages
        for key in ("owner", "ticket", "severity_level"):
            assert any(f"'{key}'" in message for message in messages), messages

    def test_the_unmodified_results_file_validates(self):
        """The control: without the injected keys the file was already valid,
        so the test above measures the keys, not some other schema mismatch."""
        import jsonschema

        data = json.loads(self.RESULTS.read_text(encoding="utf-8"))
        schema = self._schemas()["AshAggregatedResults"]
        assert list(jsonschema.Draft202012Validator(schema).iter_errors(data)) == []


class TestConfigCommands:
    """validate and lint do not load plugin modules, so they say what they skip."""

    @staticmethod
    def _write(tmp_path, body):
        config = tmp_path / ".ash.yaml"
        config.write_text(body, encoding="utf-8")
        return config

    def test_lint_says_options_of_loaded_plugins_are_checked_by_the_scan(
        self, tmp_path
    ):
        from automated_security_helper.config.config_linter import (
            ConfigLinter,
            LintSeverity,
        )

        config = self._write(
            tmp_path,
            "project_name: t\n"
            "ash_plugin_modules:\n"
            "  - automated_security_helper.plugin_modules.ash_trivy_plugins\n"
            "scanners:\n"
            "  trivy-repo:\n"
            "    options:\n"
            "      skip_dirs: [x]\n",
        )
        issues = ConfigLinter.lint(config, source_dir=tmp_path).issues
        notes = [
            i
            for i in issues
            if i.severity == LintSeverity.INFO and "ash_plugin_modules" in i.message
        ]
        assert len(notes) == 1, issues
        assert "scanners.trivy-repo" in notes[0].message
        assert "A scan checks the options" in notes[0].message
        assert "exit code 3" in notes[0].message

    def test_no_note_for_built_in_sections_only(self, tmp_path):
        from automated_security_helper.config.plugin_option_check import (
            options_checked_at_scan_note,
        )

        assert (
            options_checked_at_scan_note(
                {"project_name": "t", "scanners": {"bandit": {"options": {}}}}
            )
            is None
        )
