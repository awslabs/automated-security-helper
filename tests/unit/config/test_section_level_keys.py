# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A key at a plugin's section level, beside ``enabled``, refuses the config.

A plugin's section declares ``enabled``, ``name``, ``options`` (and a
reporter's ``extension``). Any other key there, kept, would never be read:
``scanners.bandit.severity_threshold: HIGH`` beside ``enabled: true`` would load,
and bandit would gate at the global threshold, because the option lives under
``options``. Old docs showed keys that way.

Such a key stops the run with exit code 3 at every entry point that loads a
config: a project config, a workspace project's config, the MCP config tools,
and, for a plugin loaded from ``ash_plugin_modules``, the scan once the plugins
are loaded. When the key is one of the plugin's options the message says to
move it under ``options``; otherwise it names the key as unknown. A results
file written with such a key still loads, with a warning.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

MOVE = "{where}.{key} is not a section-level key; move {key} under options"
INTERNAL = (
    "{kind} '{plugin}' contains internal-only field '{key}' - "
    "this should not be in user configs."
)


def _config(**sections):
    return AshConfig.model_validate({"project_name": "t", **sections})


class TestBuiltInSections:
    @pytest.mark.parametrize(
        "segment,plugin,key,value",
        [
            ("scanners", "bandit", "severity_threshold", "HIGH"),
            ("scanners", "cdk-nag", "nag_packs", {"AwsSolutionsChecks": True}),
            ("reporters", "markdown", "include_detailed_findings", False),
        ],
    )
    def test_an_option_written_beside_enabled_says_to_move_it(
        self, segment, plugin, key, value
    ):
        with pytest.raises(ValidationError) as excinfo:
            _config(**{segment: {plugin: {"enabled": True, key: value}}})
        message = str(excinfo.value)
        assert MOVE.format(where=f"{segment}.{plugin}", key=key) in message, message

    @pytest.mark.parametrize(
        "segment,kind,plugin,key,value",
        [
            # bandit and jupyter declare tool_version and install_timeout as
            # options: the message names the field as internal-only all the
            # same, rather than only telling the operator to move it.
            ("scanners", "Scanner", "bandit", "tool_version", "1.7.5"),
            ("scanners", "Scanner", "bandit", "install_timeout", 10),
            ("scanners", "Scanner", "cdk-nag", "extension", "txt"),
            ("converters", "Converter", "jupyter", "tool_version", ">=7"),
            ("converters", "Converter", "archive", "install_timeout", 10),
        ],
    )
    def test_an_internal_only_field_is_refused_as_one(
        self, segment, kind, plugin, key, value
    ):
        """Older ``ash config init`` versions wrote these beside ``enabled``.

        They were ASH's own bookkeeping, not settings, so the advice to move one
        under ``options`` would turn a leaked ``tool_version`` into a version
        constraint. The model names them as internal-only fields, which is the
        message ``ash config validate`` prints and ``ash config lint --fix``
        removes.
        """
        with pytest.raises(ValidationError) as excinfo:
            _config(**{segment: {plugin: {"enabled": True, key: value}}})
        message = str(excinfo.value)
        assert INTERNAL.format(kind=kind, plugin=plugin, key=key)[:-1] in message, (
            message
        )
        assert "is not a section-level key" not in message, message
        assert "Unknown key" not in message, message

    @pytest.mark.parametrize(
        "segment,plugin,key,hint",
        [
            ("scanners", "bandit", "tool_version", "a version constraint"),
            ("scanners", "bandit", "install_timeout", "an install timeout"),
            ("scanners", "checkov", "tool_version", "a version constraint"),
            ("scanners", "semgrep", "tool_version", "a version constraint"),
            ("converters", "jupyter", "tool_version", "a version constraint"),
        ],
    )
    def test_an_internal_field_the_plugin_also_declares_says_where_the_option_goes(
        self, segment, plugin, key, hint
    ):
        """tool_version and install_timeout are real options of these plugins.

        One written a level too high may be a pin the operator meant, so the
        refusal says where it goes for that.
        """
        with pytest.raises(ValidationError) as excinfo:
            _config(**{segment: {plugin: {key: "x"}}})
        message = str(excinfo.value)
        assert f"if you meant {hint}, put it under options" in message, message

    @pytest.mark.parametrize(
        "segment,plugin,key",
        [
            ("scanners", "cdk-nag", "extension"),
            ("converters", "archive", "install_timeout"),
        ],
    )
    def test_an_internal_field_the_plugin_does_not_declare_gets_no_options_hint(
        self, segment, plugin, key
    ):
        with pytest.raises(ValidationError) as excinfo:
            _config(**{segment: {plugin: {key: "x"}}})
        assert "under options" not in str(excinfo.value), str(excinfo.value)

    def test_a_loaded_plugin_that_declares_the_option_gets_the_hint(self):
        """The loaded-plugin check uses the plugin's own class, so it knows."""
        from automated_security_helper.base.plugin_config import section_key_problems
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
            FerretScannerConfig,
        )

        problems = section_key_problems(
            FerretScannerConfig, {"tool_version": "==1.2.3"}, "scanners.ferret-scan"
        )

        assert problems == [
            (
                "Scanner 'ferret-scan' contains internal-only field 'tool_version' - "
                "this should not be in user configs; if you meant a version "
                "constraint, put it under options."
            )
        ], problems

    def test_internal_only_fields_and_other_keys_are_each_named_once(self):
        with pytest.raises(ValidationError) as excinfo:
            _config(
                scanners={
                    "bandit": {
                        "tool_version": "1.7.5",
                        "severity_threshold": "HIGH",
                        "install_timeout": 10,
                    }
                }
            )
        errors = excinfo.value.errors()
        assert [error["loc"] for error in errors] == [("scanners", "bandit")]
        assert errors[0]["msg"] == (
            "Value error, "
            + INTERNAL.format(kind="Scanner", plugin="bandit", key="tool_version")[:-1]
            + "; if you meant a version constraint, put it under options. "
            + MOVE.format(where="scanners.bandit", key="severity_threshold")
            + ". "
            + INTERNAL.format(kind="Scanner", plugin="bandit", key="install_timeout")[
                :-1
            ]
            + "; if you meant an install timeout, put it under options."
        )

    def test_a_declared_internal_field_loads(self):
        """``name``, and a reporter's ``extension``, are declared section keys."""
        config = _config(
            scanners={"bandit": {"name": "bandit"}},
            reporters={"html": {"extension": "html"}},
        )
        assert isinstance(config, AshConfig)

    def test_an_unknown_key_is_named_as_unknown(self):
        with pytest.raises(ValidationError) as excinfo:
            _config(scanners={"bandit": {"enabled": True, "colour": "blue"}})
        message = str(excinfo.value)
        assert "Unknown key 'colour'" in message, message
        assert "move colour under options" not in message

    def test_the_declared_section_keys_load(self):
        config = _config(
            scanners={
                "bandit": {
                    "enabled": False,
                    "name": "bandit",
                    "options": {"severity_threshold": "HIGH"},
                }
            },
            reporters={"markdown": {"enabled": True, "extension": "md"}},
        )
        assert config.scanners.bandit.enabled is False
        assert config.scanners.bandit.options.severity_threshold == "HIGH"

    def test_the_reported_case_exits_3_from_a_config_file(self, tmp_path):
        """``scanners.bandit.severity_threshold: HIGH`` beside ``enabled: true``
        loaded, and was ignored."""
        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text(
            "project_name: demo\n"
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
            "    severity_threshold: HIGH\n",
            encoding="utf-8",
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=source)
        assert MOVE.format(where="scanners.bandit", key="severity_threshold") in str(
            excinfo.value
        )


class TestOtherEntryPoints:
    @staticmethod
    def _project_config(project):
        ash_dir = project / ".ash"
        ash_dir.mkdir(parents=True)
        (ash_dir / "ash.yaml").write_text(
            "scanners:\n  bandit:\n    enabled: true\n    severity_threshold: HIGH\n",
            encoding="utf-8",
        )

    def test_a_workspace_project_config_is_refused(self, tmp_path):
        from automated_security_helper.workspace.resolver import resolve_workspace

        self._project_config(tmp_path / "api")
        workspace = tmp_path / "dev.code-workspace"
        workspace.write_text(json.dumps({"folders": [{"path": "api"}]}))
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_workspace(workspace)
        message = str(excinfo.value)
        assert "Project 'api'" in message
        assert MOVE.format(where="scanners.bandit", key="severity_threshold") in message

    def test_the_mcp_get_config_tool_refuses_it(self, tmp_path):
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        self._project_config(tmp_path)
        # An error result, as the tool answers every refusal; the error escaped it.
        result = mcp_get_config(config_path=str(tmp_path / ".ash" / "ash.yaml"))
        assert result.get("success") is False, result
        assert "severity_threshold" in result["error"], result

    def test_validate_and_the_mcp_validate_tool_report_it(self, tmp_path):
        from automated_security_helper.cli.mcp_tools import mcp_validate_config

        config = tmp_path / ".ash.yaml"
        config.write_text(
            "project_name: demo\n"
            "scanners:\n  bandit:\n    enabled: true\n    severity_threshold: HIGH\n",
            encoding="utf-8",
        )
        valid, errors = ConfigValidator.validate_config_file(config)
        expected = MOVE.format(where="scanners.bandit", key="severity_threshold")
        assert valid is False and any(expected in e for e in errors), errors
        result = mcp_validate_config(config_content=config.read_text())
        assert result["valid"] is False, result
        assert any(expected in e["message"] for e in result["errors"]), result


class TestLoadedPlugins:
    """A plugin from ash_plugin_modules is checked once the plugins are loaded."""

    @staticmethod
    def _engine(tmp_path, config):
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
            return [TrivyRepoScanner] if plugin_type == "scanner" else []

        with patch.object(ash_plugin_manager, "plugin_modules", plugin_modules):
            return ScanExecutionEngine(context=context, asharp_model=MagicMock())

    def test_an_option_beside_enabled_exits_3(self, tmp_path):
        config = _config(
            scanners={"trivy-repo": {"enabled": True, "ignore_unfixed": True}}
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            self._engine(tmp_path, config)
        assert MOVE.format(where="scanners.trivy-repo", key="ignore_unfixed") in str(
            excinfo.value
        )

    def test_an_unknown_key_beside_enabled_exits_3(self, tmp_path):
        config = _config(scanners={"trivy-repo": {"enabled": True, "colour": "blue"}})
        with pytest.raises(ASHConfigValidationError) as excinfo:
            self._engine(tmp_path, config)
        assert "Unknown key 'colour'" in str(excinfo.value)

    def test_a_section_with_declared_keys_loads(self, tmp_path):
        config = _config(
            scanners={
                "trivy-repo": {"enabled": True, "options": {"ignore_unfixed": True}}
            }
        )
        self._engine(tmp_path, config)


class TestTheModelAndTheSchemaAgree:
    """A config refused by the model is refused by AshConfig.json, and the
    message is ASH's one line rather than pydantic's ``extra_forbidden``.

    The plugin config models keep ``extra="allow"``: a results file is validated
    with the same models under ``TOLERATE_STORED_CONFIG`` and keeps such a key
    with a warning, which ``extra="forbid"`` would turn into a refusal of the
    whole file. On every config path the before-validator refuses the key, so
    the config contract is "no extra keys", which AshConfig.json states; the
    results schema states the results contract (additionalProperties true).
    """

    CASES = [
        ("scanners", "bandit", {"enabled": True, "severity_threshold": "HIGH"}),
        ("reporters", "markdown", {"enabled": True, "colour": "blue"}),
        ("converters", "jupyter", {"colour": "blue"}),
    ]

    def test_an_internal_only_field_is_refused_by_both_too(self):
        """The model names the section in its internal-only wording, at its location."""
        import jsonschema

        from automated_security_helper.schemas.generate_schemas import (
            generate_schemas,
        )

        data = {"project_name": "t", "converters": {"jupyter": {"tool_version": ">=7"}}}
        with pytest.raises(ValidationError) as excinfo:
            AshConfig.model_validate(data)
        (error,) = excinfo.value.errors()
        assert error["type"] == "value_error", error
        assert error["loc"] == ("converters", "jupyter"), error
        assert "\n" not in error["msg"], error["msg"]
        assert "Converter 'jupyter' contains internal-only field" in error["msg"]

        schema = generate_schemas("dict")["AshConfig"]
        schema_errors = list(jsonschema.Draft202012Validator(schema).iter_errors(data))
        assert schema_errors, "AshConfig.json accepts what the model refuses"

    @pytest.mark.parametrize("segment,plugin,section", CASES)
    def test_the_model_and_the_config_schema_both_refuse_it(
        self, segment, plugin, section
    ):
        import jsonschema

        from automated_security_helper.schemas.generate_schemas import (
            generate_schemas,
        )

        data = {"project_name": "t", segment: {plugin: section}}
        with pytest.raises(ValidationError) as excinfo:
            AshConfig.model_validate(data)
        (error,) = excinfo.value.errors()
        assert error["type"] == "value_error", error
        assert "\n" not in error["msg"], error["msg"]
        assert f"{segment}.{plugin}" in error["msg"], error["msg"]

        schema = generate_schemas("dict")["AshConfig"]
        schema_errors = list(jsonschema.Draft202012Validator(schema).iter_errors(data))
        assert schema_errors, "AshConfig.json accepts what the model refuses"

    def test_forbid_would_refuse_a_results_file_that_loads_today(self):
        """Why ``extra`` stays ``allow``, measured on a copy of the model."""
        from pydantic import ConfigDict

        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScannerConfig,
        )
        from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

        class Forbidding(BanditScannerConfig):
            model_config = ConfigDict(extra="forbid")

        stored = {"enabled": True, "severity_threshold": "HIGH"}
        kept = BanditScannerConfig.model_validate(
            stored, context={TOLERATE_STORED_CONFIG: []}
        )
        assert kept.model_extra == {"severity_threshold": "HIGH"}
        with pytest.raises(ValidationError) as excinfo:
            Forbidding.model_validate(stored, context={TOLERATE_STORED_CONFIG: []})
        assert excinfo.value.errors()[0]["type"] == "extra_forbidden"


class TestStoredResults:
    FIXTURE = (
        Path(__file__).resolve().parents[2]
        / "test_data"
        / "outputs"
        / "ash_aggregated_results.json"
    )

    def test_a_results_file_with_one_loads_and_warns(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        data["ash_config"]["scanners"]["bandit"]["severity_threshold"] = "HIGH"
        with patch("automated_security_helper.models.asharp_model.ASH_LOGGER") as log:
            model = AshAggregatedResults.model_validate_json(json.dumps(data))
        assert model.ash_config.scanners.bandit.model_extra == {
            "severity_threshold": "HIGH"
        }
        warnings = [str(c.args[0]) for c in log.warning.call_args_list]
        # Named by the section that holds it, never by the key: a stored key is
        # the results file's data (utils/unknown_keys.UNKNOWN_KEY_NOTE).
        located = [w for w in warnings if "unknown key <key> in 'scanners.bandit'" in w]
        assert located, warnings
        assert not [w for w in warnings if "severity_threshold" in w], warnings

    def test_a_community_plugin_section_in_results_loads_without_warnings(self):
        """A results file cannot know a community plugin's own config class, so
        its section is read against the generic base, which declares only the
        shared keys. A key the plugin itself declares must not be reported as
        unknown because the stand-in does not declare it."""
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        data["ash_config"]["scanners"]["trivy-repo"] = {
            "enabled": True,
            "plugin_level_setting": "declared by the plugin, not the base",
        }
        with patch("automated_security_helper.models.asharp_model.ASH_LOGGER") as log:
            AshAggregatedResults.model_validate_json(json.dumps(data))
        warnings = [str(c.args[0]) for c in log.warning.call_args_list]
        assert not [w for w in warnings if "plugin_level_setting" in w], warnings

    def test_the_config_schema_refuses_it_and_the_results_schema_accepts_it(self):
        from automated_security_helper.schemas.generate_schemas import (
            generate_schemas,
        )

        schemas = generate_schemas("dict")
        config_defs = schemas["AshConfig"]["$defs"]
        results_defs = schemas["AshAggregatedResults"]["$defs"]
        for name in ("BanditScannerConfig", "MarkdownReporterConfig"):
            assert config_defs[name].get("additionalProperties") is False, name
            assert results_defs[name].get("additionalProperties") is True, name
