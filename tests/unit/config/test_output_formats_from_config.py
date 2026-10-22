# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``output_formats`` in a config file chooses the reports, below ``--output-formats``.

Why this exists
---------------
``ReportPhase`` already read ``config.output_formats`` and let the command line
replace it, but ``AshConfig`` declared no such field and ignores unknown keys, so
the value was dropped while the file loaded. A config asking for ``[sarif]`` got
every enabled report, with no warning from the scan; only ``ash config
validate`` said the key was unknown.

The precedence asserted here is: an explicit ``--output-formats`` list, then the
config's ``output_formats``, then every enabled reporter. Each layer is tested
through the real ``ReportPhase`` and the real reporter registry, because the
defect sat between a value being configured and a file appearing on disk.

Known limitations
-----------------
* Workspace-level reports (``reports/`` at the workspace root) are built from
  ASH's default config, not from any project's (see ``workspace/reporting.py``),
  so a project's ``output_formats`` narrows that project's reports only.
"""

from pathlib import Path
from typing import List, Optional, Sequence
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.main import app
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    resolve_config,
)
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
import automated_security_helper.plugin_modules.ash_builtin as builtin_plugins


def _write_config(directory: Path, body: str) -> Path:
    config_path = directory / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(body, encoding="utf-8")
    return config_path


def _reports_written(
    tmp_path: Path, config: AshConfig, cli_formats: Optional[Sequence[str]]
) -> List[str]:
    """Run the real report phase and return the report filenames it wrote.

    Over the built-in reporters only. The plugin registry is process-wide, so it
    holds the AWS reporters once any test in this process has imported them, and
    two of those ship enabled and make AWS calls in their dependency check.
    """
    output_dir = tmp_path / "out"
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=config,
    )
    phase = ReportPhase(
        plugins=list(builtin_plugins.ASH_REPORTERS),
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    )
    reports_dir = output_dir / "reports"
    phase.execute(
        report_dir=reports_dir,
        cli_output_formats=list(cli_formats) if cli_formats else None,
        aggregated_results=AshAggregatedResults(),
        python_based_plugins_only=False,
    )
    return sorted(p.name for p in reports_dir.iterdir()) if reports_dir.exists() else []


class TestTheConfigKeepsTheValue:
    def test_the_model_keeps_output_formats(self):
        config = AshConfig.model_validate(
            {"project_name": "p", "output_formats": ["sarif", "github-ghas"]}
        )

        assert config.output_formats == [ExportFormat.SARIF, ExportFormat.GITHUB_GHAS]

    def test_a_config_file_keeps_output_formats(self, tmp_path):
        config_path = _write_config(
            tmp_path, "project_name: p\noutput_formats:\n  - sarif\n  - markdown\n"
        )

        config = resolve_config(config_path=config_path, source_dir=tmp_path)

        assert config.output_formats == [ExportFormat.SARIF, ExportFormat.MARKDOWN]

    def test_the_default_is_empty(self):
        """Empty means every enabled reporter, the behavior with no config at all."""
        assert AshConfig().output_formats == []

    def test_an_override_sets_it(self):
        config = apply_config_overrides(AshConfig(), ['output_formats=["csv"]'])

        assert config.output_formats == [ExportFormat.CSV]

    def test_a_misspelled_name_is_refused(self, tmp_path):
        """A typo in the config is an invalid config, as it is on the command line.

        Before the field existed the whole key was dropped, so a misspelling was as
        silent as a correct spelling.
        """
        config_path = _write_config(
            tmp_path, "project_name: p\noutput_formats:\n  - sarfi\n"
        )

        with pytest.raises(ASHConfigValidationError, match="output_formats"):
            resolve_config(config_path=config_path, source_dir=tmp_path)

    def test_config_validate_accepts_the_key(self, tmp_path):
        config_path = _write_config(
            tmp_path, "project_name: p\noutput_formats:\n  - sarif\n"
        )

        valid, errors = ConfigValidator.validate_config_file(config_path)

        assert valid, errors

    def test_the_scan_results_record_it(self):
        """``ash merge`` reads the scan's config back from the results file."""
        model = AshAggregatedResults(
            ash_config=AshConfig(project_name="p", output_formats=["sarif"])
        )

        reloaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

        assert reloaded.ash_config.output_formats == [ExportFormat.SARIF]


class TestPrecedence:
    def test_the_config_list_narrows_the_reports(self, tmp_path):
        config = AshConfig(project_name="p", output_formats=["sarif", "github-ghas"])

        assert _reports_written(tmp_path, config, None) == [
            "ash.ghas.sarif",
            "ash.sarif",
        ]

    def test_the_command_line_replaces_the_config_list(self, tmp_path):
        config = AshConfig(project_name="p", output_formats=["sarif"])

        assert _reports_written(tmp_path, config, ["markdown"]) == ["ash.summary.md"]

    def test_with_neither_every_enabled_reporter_writes(self, tmp_path):
        written = _reports_written(tmp_path, AshConfig(project_name="p"), None)

        for filename in (
            "ash.sarif",
            "ash.summary.md",
            "ash.ghas.sarif",
            "ash.gl-sast-report.json",
            "ash.cdx.json",
        ):
            assert filename in written
        # The two reporters that ship disabled stay off.
        assert "ash.yaml" not in written
        assert "ash.spdx.json" not in written

    def test_the_config_list_does_not_enable_a_disabled_reporter(self, tmp_path):
        """Like the flag, the config list narrows; ``reporters.<name>.enabled`` enables."""
        config = AshConfig(project_name="p", output_formats=["yaml", "sarif"])

        assert _reports_written(tmp_path, config, None) == ["ash.sarif"]


def test_ash_scan_without_the_flag_leaves_the_choice_to_the_config(tmp_path):
    """No ``-f`` reaches the scan as an empty list, which the report phase reads as
    "use the config". A non-empty default here would override every config."""
    source = tmp_path / "src"
    source.mkdir()
    with patch("automated_security_helper.cli.scan.run_ash_scan") as mock_run:
        result = CliRunner().invoke(
            app,
            ["scan", "--source-dir", str(source), "--output-dir", str(tmp_path / "o")],
        )

    assert result.exit_code == 0, result.output
    assert mock_run.call_args.kwargs["output_formats"] == []


class TestOtherSpellings:
    """A single name, a comma list and null, as the command line's ``-f`` allows."""

    @pytest.mark.parametrize(
        "body, expected",
        [
            ("output_formats: sarif\n", [ExportFormat.SARIF]),
            (
                "output_formats: sarif, markdown\n",
                [ExportFormat.SARIF, ExportFormat.MARKDOWN],
            ),
            ("output_formats: null\n", []),
            ("output_formats:\n", []),
        ],
        ids=["single-name", "comma-list", "null", "empty-value"],
    )
    def test_a_config_file_spelling(self, tmp_path, body, expected):
        config_path = _write_config(tmp_path, "project_name: p\n" + body)

        config = resolve_config(config_path=config_path, source_dir=tmp_path)

        assert config.output_formats == expected

    @pytest.mark.parametrize(
        "override, expected",
        [
            ("output_formats=sarif", [ExportFormat.SARIF]),
            (
                "output_formats=sarif,markdown",
                [ExportFormat.SARIF, ExportFormat.MARKDOWN],
            ),
            ("output_formats=null", []),
        ],
    )
    def test_an_override_spelling(self, override, expected):
        assert (
            apply_config_overrides(AshConfig(), [override]).output_formats == expected
        )

    @pytest.mark.parametrize(
        "value, valid",
        [
            (["sarif", "github-ghas"], True),
            ("sarif", True),
            (None, True),
            ("sarfi", False),
        ],
    )
    def test_the_published_schema_admits_the_same_spellings(self, value, valid):
        """An editor validating against AshConfig.json agrees with the loader."""
        import jsonschema

        validator = jsonschema.Draft202012Validator(AshConfig.model_json_schema())
        errors = list(
            validator.iter_errors({"project_name": "p", "output_formats": value})
        )

        assert (not errors) is valid, errors

    def test_a_misspelled_name_in_a_comma_list_is_refused(self, tmp_path):
        """Located at the entry. The name itself prints as ``<value>``, as it
        does in a list, since a refusal repeats no value from the file."""
        config_path = _write_config(
            tmp_path, "project_name: p\noutput_formats: sarif, sarfi\n"
        )

        with pytest.raises(ASHConfigValidationError, match=r"output_formats\[1\]"):
            resolve_config(config_path=config_path, source_dir=tmp_path)


class TestTheConfigWritesBack:
    """A config holding ``output_formats`` survives every path that writes it out.

    ``model_dump()`` in Python mode returned the ``ExportFormat`` members
    themselves. ``ash config get``, ``update`` and ``wizard`` dump that with
    PyYAML's full ``Dumper``, which writes
    ``!!python/object/apply:...ExportFormat`` tags; ``AshConfig.save`` uses
    ``safe_dump``, which raises. A file each writer produces loads again, so
    ``ash scan`` keeps the file's ``severity_threshold: LOW`` after one
    ``ash config update --set project_name=x``.

    Asserted on the model's own dump first, so the guarantee does not depend on
    which writer a command uses.
    """

    CONFIG = {"project_name": "p", "output_formats": ["sarif", "github-ghas"]}

    def test_the_python_dump_holds_plain_strings(self):
        dumped = AshConfig.model_validate(self.CONFIG).model_dump(by_alias=True)

        assert dumped["output_formats"] == ["sarif", "github-ghas"]
        assert all(type(value) is str for value in dumped["output_formats"])

    def test_both_yaml_dumpers_write_a_loadable_file(self, tmp_path):
        import yaml

        dumped = AshConfig.model_validate(self.CONFIG).model_dump(by_alias=True)
        for dump in (yaml.dump, yaml.safe_dump):
            text = dump(dumped)
            assert "!!python" not in text
            config_path = _write_config(tmp_path, text)
            reloaded = resolve_config(config_path=config_path, source_dir=tmp_path)
            assert reloaded.output_formats == [
                ExportFormat.SARIF,
                ExportFormat.GITHUB_GHAS,
            ]

    def test_save_round_trips(self, tmp_path):
        config_path = tmp_path / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True)

        AshConfig.model_validate(self.CONFIG).save(config_path, as_written=False)

        reloaded = resolve_config(config_path=config_path, source_dir=tmp_path)
        assert reloaded.output_formats == [ExportFormat.SARIF, ExportFormat.GITHUB_GHAS]

    def test_config_update_then_get_round_trips(self, tmp_path, monkeypatch):
        import re

        from automated_security_helper.cli.config import config_app

        config_path = _write_config(
            tmp_path,
            "project_name: p\noutput_formats:\n  - sarif\nglobal_settings:\n"
            "  severity_threshold: LOW\n",
        )
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()

        updated = runner.invoke(
            config_app, ["update", str(config_path), "--set", "project_name=x"]
        )
        assert updated.exit_code == 0, updated.output
        assert "!!python" not in config_path.read_text(encoding="utf-8")

        reloaded = resolve_config(config_path=config_path, source_dir=tmp_path)
        assert reloaded.project_name == "x"
        assert reloaded.output_formats == [ExportFormat.SARIF]
        assert reloaded.global_settings.severity_threshold == "LOW"

        got = runner.invoke(config_app, ["get"])
        assert got.exit_code == 0, got.output
        # rich highlights the YAML, so read it with the escape codes removed.
        printed = re.sub(r"\x1b\[[0-9;]*m", "", got.stdout)
        assert "!!python" not in printed
        # Each line is padded to the console width.
        assert re.search(r"^output_formats: *\n- sarif *$", printed, re.MULTILINE)

    def test_the_mcp_session_config_round_trips(self, tmp_path, monkeypatch):
        from automated_security_helper.cli.mcp.profile_registry import (
            materialize_session_config,
        )

        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))

        written = materialize_session_config(
            "session-a", AshConfig.model_validate(self.CONFIG)
        )

        reloaded = AshConfig.from_file(Path(written))
        assert reloaded.output_formats == [ExportFormat.SARIF, ExportFormat.GITHUB_GHAS]


def test_no_other_enum_typed_field_can_come_from_a_config_file():
    """Every enum-typed config field is covered by the round trips above.

    An ``Enum`` member in a Python-mode dump is what broke the YAML writers, so a
    new enum-typed field must either store its value (``use_enum_values``) or
    serialize to one, and get a round trip of its own. ``build.custom_scanners``
    is skipped: it holds scanner plugin instances, which a config file cannot
    construct (validating one from a mapping raises), so no file can carry it.
    """
    import enum
    import typing

    from pydantic import BaseModel

    def args(annotation):
        found = [annotation]
        for arg in typing.get_args(annotation):
            found += args(arg)
        return found

    seen = set()
    enum_fields = set()

    def walk(model, path):
        if model in seen:
            return
        seen.add(model)
        stores_values = model.model_config.get("use_enum_values", False)
        for name, field in model.model_fields.items():
            here = f"{path}.{name}" if path else name
            if here == "build.custom_scanners":
                continue
            for arg in args(field.annotation):
                if not isinstance(arg, type):
                    continue
                if issubclass(arg, enum.Enum) and not stores_values:
                    enum_fields.add(here)
                elif issubclass(arg, BaseModel):
                    walk(arg, here)

    walk(AshConfig, "")

    assert enum_fields == {"output_formats"}, (
        f"enum-typed config fields without a tested string dump: "
        f"{sorted(enum_fields - {'output_formats'})}"
    )
