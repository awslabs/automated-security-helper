"""Tests pinning that a bad --config-overrides value stops the run.

``apply_config_overrides`` used to log and carry on: a malformed override was
skipped, and a merged configuration that failed validation was thrown away in
favour of the original. Either way the scan continued with settings the operator
had not chosen, and reported success.

The tests here come in pairs on purpose. Every "this is refused" case is matched
by a case proving a well-formed override still takes effect, so a change that
simply rejected everything could not pass.
"""

from pathlib import Path

import pytest
import typer
from pydantic import ValidationError

from automated_security_helper.cli.config import config_app
from automated_security_helper.cli.report import report_command
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    resolve_config,
)
from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator


class TestMalformedOverridesRefused:
    """An override string that is not 'key.path=value' is refused."""

    def test_override_without_equals_raises(self):
        with pytest.raises(ASHConfigValidationError) as exc_info:
            apply_config_overrides(AshConfig(project_name="test"), ["no_equals_here"])

        message = str(exc_info.value)
        assert "no_equals_here" in message
        assert "key.path=value" in message

    def test_override_with_empty_key_path_raises(self):
        """'=LOW' names no setting, and used to be applied under the '' key."""
        with pytest.raises(ASHConfigValidationError, match="key.path=value"):
            apply_config_overrides(AshConfig(project_name="test"), ["=LOW"])


class TestInvalidMergedConfigRefused:
    """A well-formed override that produces an invalid config is refused."""

    def test_unknown_key_under_a_closed_section_raises(self):
        with pytest.raises(ASHConfigValidationError) as exc_info:
            apply_config_overrides(
                get_default_config(), ["global_settings.bogus_key=1"]
            )

        assert "bogus_key" in str(exc_info.value)

    def test_invalid_enum_value_raises(self):
        with pytest.raises(ASHConfigValidationError) as exc_info:
            apply_config_overrides(
                get_default_config(), ["global_settings.severity_threshold=NOPE"]
            )

        assert "severity_threshold" in str(exc_info.value)

    def test_the_underlying_validation_error_is_chained(self):
        """The pydantic detail must stay reachable for anyone debugging."""
        with pytest.raises(ASHConfigValidationError) as exc_info:
            apply_config_overrides(
                get_default_config(), ["global_settings.bogus_key=1"]
            )

        assert isinstance(exc_info.value.__cause__, ValidationError)

    def test_a_failure_applying_one_override_raises(self, monkeypatch):
        """Defensive branch: nothing in the current parser reaches it.

        Injecting the failure is the only way to reach it, and it is worth
        keeping covered so a future parser change cannot start swallowing.
        """

        def boom(*_args, **_kwargs):
            raise RuntimeError("parser blew up")

        monkeypatch.setattr(
            "automated_security_helper.config.resolve_config._apply_config_override",
            boom,
        )

        with pytest.raises(ASHConfigValidationError) as exc_info:
            apply_config_overrides(get_default_config(), ["project_name=x"])

        assert "project_name=x" in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    def test_a_valid_override_is_not_discarded_by_a_later_invalid_one(self):
        """The sharpest form of the old behaviour.

        Both overrides used to be dropped and the scan ran at the default
        threshold, so an operator who asked for LOW silently got MEDIUM.
        """
        with pytest.raises(ASHConfigValidationError):
            apply_config_overrides(
                get_default_config(),
                [
                    "global_settings.severity_threshold=LOW",
                    "global_settings.bogus_key=1",
                ],
            )

    def test_the_two_failure_kinds_report_differently(self):
        """A malformed string and an invalid merge are not the same problem."""
        with pytest.raises(ASHConfigValidationError) as malformed:
            apply_config_overrides(get_default_config(), ["no_equals_here"])
        with pytest.raises(ASHConfigValidationError) as invalid_merge:
            apply_config_overrides(
                get_default_config(), ["global_settings.bogus_key=1"]
            )

        assert str(malformed.value) != str(invalid_merge.value)
        assert "key.path=value" in str(malformed.value)
        assert "key.path=value" not in str(invalid_merge.value)


class TestGoodOverridesStillApply:
    """The paired half: refusing bad input must not mean refusing everything."""

    def test_severity_threshold_override_applies(self):
        result = apply_config_overrides(
            get_default_config(), ["global_settings.severity_threshold=LOW"]
        )
        assert result.global_settings.severity_threshold == "LOW"

    def test_compact_report_override_applies(self):
        """The one override ASH synthesises itself, for `scan --compact-report`."""
        assert get_default_config().reporters.markdown.options.compact is False

        result = apply_config_overrides(
            get_default_config(), ["reporters.markdown.options.compact=true"]
        )
        assert result.reporters.markdown.options.compact is True

    def test_unknown_scanner_name_is_still_accepted(self):
        """Config may name a scanner supplied by a plugin that is not loaded.

        ScannerConfigSegment is extra="allow", so this never reached the
        validation branch and must keep working after it starts raising.
        """
        result = apply_config_overrides(
            get_default_config(), ["scanners.not_a_loaded_scanner.enabled=false"]
        )
        assert result.scanners.not_a_loaded_scanner == {"enabled": False}

    def test_no_overrides_is_a_noop(self):
        config = AshConfig(project_name="test")
        assert apply_config_overrides(config, []) is config
        assert apply_config_overrides(config, None) is config


class TestResolveConfigPropagates:
    """resolve_config has three swallow-all handlers; none may eat this."""

    def test_default_config_branch_propagates(self):
        """source_dir=None returns the default config without touching disk."""
        with pytest.raises(ASHConfigValidationError):
            resolve_config(
                source_dir=None, config_overrides=["global_settings.bogus_key=1"]
            )

    def test_file_branch_propagates_without_being_relabelled(self, tmp_path):
        """The from-file branch sits inside `except ValidationError`.

        A pydantic ValidationError raised there would be rewritten as a
        complaint about the config *file*, which is the wrong diagnosis for a
        bad override.
        """
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: from-file\n", encoding="utf-8")

        with pytest.raises(ASHConfigValidationError) as exc_info:
            resolve_config(
                config_path=config_file,
                source_dir=tmp_path,
                config_overrides=["global_settings.bogus_key=1"],
            )

        assert "ash config lint" not in str(exc_info.value)

    def test_config_path_without_source_dir_propagates(self, tmp_path):
        """The shape `report` and `config get` actually use.

        Since #446 an explicit config_path skips the source_dir short circuit,
        so these two commands reach apply_config_overrides through the from-file
        route rather than the default-config route. Both routes must raise.
        """
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: from-file\n", encoding="utf-8")

        with pytest.raises(ASHConfigValidationError):
            resolve_config(
                config_path=config_file,
                config_overrides=["global_settings.bogus_key=1"],
            )

    def test_config_path_without_source_dir_applies_a_good_override(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: from-file\n", encoding="utf-8")

        config = resolve_config(
            config_path=config_file,
            config_overrides=["global_settings.severity_threshold=LOW"],
        )

        assert config.project_name == "from-file"
        assert config.global_settings.severity_threshold == "LOW"

    def test_good_override_through_a_config_file_still_applies(self, tmp_path):
        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: from-file\n", encoding="utf-8")

        config = resolve_config(
            config_path=config_file,
            source_dir=tmp_path,
            config_overrides=["global_settings.severity_threshold=LOW"],
        )

        assert config.project_name == "from-file"
        assert config.global_settings.severity_threshold == "LOW"


class TestExitCode:
    """Exit code 3 is the documented code for an invalid configuration."""

    def test_contract_says_three_is_invalid_config(self):
        assert ASH_EXIT_CODES[3] == "invalid config"

    def test_orchestrator_init_raises_the_exception_scan_maps_to_three(self, tmp_path):
        """run_ash_scan catches ASHConfigValidationError and exits 3."""
        source = tmp_path / "src"
        source.mkdir()

        with pytest.raises(ASHConfigValidationError):
            ASHScanOrchestrator.create(
                source_dir=source,
                output_dir=tmp_path / "out",
                config_path=None,
                config_overrides=["global_settings.bogus_key=1"],
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

    def test_config_get_exits_three(self, tmp_path):
        from typer.testing import CliRunner

        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: from-file\n", encoding="utf-8")

        result = CliRunner().invoke(
            config_app,
            [
                "get",
                str(config_file),
                "--config-overrides",
                "global_settings.bogus_key=1",
            ],
        )

        assert result.exit_code == 3, result.output

    def test_config_get_still_succeeds_with_a_good_override(self, tmp_path):
        from typer.testing import CliRunner

        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: from-file\n", encoding="utf-8")

        result = CliRunner().invoke(
            config_app,
            [
                "get",
                str(config_file),
                "--config-overrides",
                "global_settings.severity_threshold=LOW",
            ],
        )

        assert result.exit_code == 0, result.output

    def test_report_exits_three(self, tmp_path):
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        with pytest.raises(typer.Exit) as exc_info:
            report_command(
                output_dir=str(output_dir),
                config_overrides=["global_settings.bogus_key=1"],
            )

        assert exc_info.value.exit_code == 3

    def test_report_reaches_its_own_error_when_the_override_is_good(self, tmp_path):
        """A good override must let report proceed to its results-file check."""
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        with pytest.raises(typer.Exit) as exc_info:
            report_command(
                output_dir=str(output_dir),
                config_overrides=["global_settings.severity_threshold=LOW"],
            )

        assert exc_info.value.exit_code == 1
        assert not Path(output_dir, "ash_aggregated_results.json").exists()
