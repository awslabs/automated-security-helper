"""Tests pinning that a bad --config-overrides value stops the run.

``apply_config_overrides`` used to log and carry on: a malformed override was
skipped, and a merged configuration that failed validation was thrown away in
favour of the original. Either way the scan continued with settings the operator
had not chosen, and reported success.

The tests here come in pairs on purpose. Every "this is refused" case is matched
by a case proving a well-formed override still takes effect, so a change that
simply rejected everything could not pass.
"""

import importlib
import json
import logging
from pathlib import Path
from typing import Any

import pytest
import typer
from pydantic import BaseModel, ValidationError

from automated_security_helper.cli.config import config_app
from automated_security_helper.cli.report import report_command
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    build_config,
    resolve_config,
)
from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ASHRespelledOverrideError,
)
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.utils.log import current_run_log_scope, run_log_scope
from tests.utils.helpers import (
    CHILD_TIMEOUT_SECONDS,
    importing_this_checkout,
    mark_git_checkout,
)

# Each class carries its own tier. One of them starts a child Python, which is an
# integration test (tests/NAMING_CONVENTIONS.md, "Test tiers"), so a module-level
# ``unit`` would give its test two tiers and collection would refuse the session.


@pytest.mark.unit
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


@pytest.mark.unit
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

    def test_the_underlying_validation_error_is_kept(self):
        """The pydantic detail must stay reachable for anyone debugging: on
        ``validation_error``, not chained, since a traceback prints a chained
        error's text, inputs and all."""
        with pytest.raises(ASHConfigValidationError) as exc_info:
            apply_config_overrides(
                get_default_config(), ["global_settings.bogus_key=1"]
            )

        assert isinstance(exc_info.value.validation_error, ValidationError)
        assert exc_info.value.__cause__ is None

    def test_a_failure_applying_one_override_raises(self, monkeypatch):
        """The branch for a failure the parser raises, such as a value nested
        too deep for json to read. Injected here so any failure reaches it.

        The refusal names the key and the exception's type: the exception's
        text, like the value, can be a credential the override passed.
        """

        def boom(*_args, **_kwargs):
            raise RuntimeError("parser blew up on x")

        monkeypatch.setattr(
            "automated_security_helper.config.resolve_config._apply_config_override",
            boom,
        )

        with pytest.raises(ASHConfigValidationError) as exc_info:
            apply_config_overrides(get_default_config(), ["project_name=x"])

        message = str(exc_info.value)
        assert "'project_name'" in message
        assert "RuntimeError" in message
        assert "=x" not in message
        assert "blew up" not in message
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestExitCode:
    """Exit code 3 is the documented code for an invalid configuration."""

    def test_contract_says_three_is_invalid_config(self):
        assert ASH_EXIT_CODES[3] == "invalid config or refused input"

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


@pytest.mark.unit
class TestWhitespaceAroundAKeyIsRefused:
    """An override is applied to its key exactly as written. With a space before
    it, " reporters.aws-security-hub.options.archive_resolved_findings=false"
    wrote a top-level " reporters" key that nothing reads, and the repository's
    archive_resolved_findings: true reached the reporter. Whitespace around the
    key, or around one of its segments, is refused instead."""

    @pytest.mark.parametrize(
        "override",
        [
            " reporters.aws-security-hub.options.archive_resolved_findings=false",
            "reporters.aws-security-hub.options.archive_resolved_findings =false",
            "reporters. aws-security-hub.enabled=false",
            "reporters.aws-security-hub .enabled=false",
            "\treporters.aws-security-hub.enabled=false",
        ],
        ids=["leading", "trailing", "segment-leading", "segment-trailing", "tab"],
    )
    def test_the_override_is_refused(self, override):
        with pytest.raises(ASHConfigValidationError) as exc_info:
            apply_config_overrides(AshConfig(project_name="test"), [override])

        assert "whitespace" in str(exc_info.value)

    @pytest.mark.parametrize(
        "override",
        [
            "reporters..aws-security-hub.options.archive_resolved_findings=false",
            ".reporters.aws-security-hub.enabled=false",
            "reporters.aws-security-hub.enabled.=false",
            f"reporters.aws-security-hub{chr(0x200B)}.enabled=false",
            f"{chr(0xFEFF)}reporters.aws-security-hub.enabled=false",
            f"reporters.aws-security-hub{chr(0xA0)}.enabled=false",
            "reporters.aws security hub.enabled=true",
            f"reporters.{chr(0x202E)}buh-ytiruces-swa.enabled=false",
            f"reporters.{chr(0x2066)}aws-security-hub{chr(0x2069)}.enabled=false",
            f"reporters.aws-security{chr(0x200C)}-hub.enabled=false",
            f"reporters.aws-security{chr(0x200D)}-hub.enabled=false",
            f"reporters.aws-security{chr(0xAD)}-hub.enabled=false",
        ],
        ids=[
            "empty-part",
            "leading-dot",
            "trailing-dot",
            "zero-width-space",
            "byte-order-mark",
            "no-break-space",
            "inner-space",
            "right-to-left-override",
            "left-to-right-isolate",
            "zero-width-non-joiner",
            "zero-width-joiner",
            "soft-hyphen",
        ],
    )
    def test_a_key_part_that_is_empty_spaced_or_unprintable_is_refused(self, override):
        """Each was applied to a key nothing reads, so the setting it meant to
        override kept the config file's value: "a..b" and a leading "." wrote an
        empty key, a zero-width space or a byte order mark wrote a key that prints
        like the real one, and "aws security hub" wrote a section of its own. A
        trailing "." wrote {'': False} into the section. A bidirectional control
        makes a key display as another: the right-to-left override shows the
        reversed name as aws-security-hub. The zero-width joiner and non-joiner and
        the soft hyphen do not print either; some scripts need them in text, but no
        configuration key holds one, so they are refused too."""
        with pytest.raises(ASHConfigValidationError) as exc_info:
            apply_config_overrides(AshConfig(project_name="test"), [override])

        assert "whitespace" in str(exc_info.value)

    def test_a_value_may_still_hold_spaces(self):
        config = apply_config_overrides(
            AshConfig(project_name="test"), ["project_name=two words"]
        )

        assert config.project_name == "two words"

    def test_report_exits_three(self, tmp_path):
        output_dir = tmp_path / "out"
        output_dir.mkdir()

        with pytest.raises(typer.Exit) as exc_info:
            report_command(
                output_dir=str(output_dir),
                config_overrides=[" reporters.aws-security-hub.enabled=false"],
            )

        assert exc_info.value.exit_code == 3


#: The config models of the plugins the append tests read back, by plugin name, as
#: (module under plugin_modules, class name). Imported by name when a test needs
#: one: importing a plugin package registers its plugins for the whole process,
#: which resolve_config deliberately never does.
_PLUGIN_MODELS = {
    "bedrock-summary-reporter": (
        "ash_aws_plugins.bedrock_summary_reporter",
        "BedrockSummaryReporterConfig",
    ),
    "ferret-scan": ("ash_ferret_plugins.ferret_scanner", "FerretScannerConfig"),
    "guarddog": ("ash_guarddog_plugins.guarddog_scanner", "GuardDogScannerConfig"),
    "trivy-repo": ("ash_trivy_plugins.trivy_repo_scanner", "TrivyRepoScannerConfig"),
}

#: The list options of those plugins whose default is not empty, as (config
#: segment, plugin kind, plugin, option, value to append). No value is the first
#: item of its option's default.
_NON_EMPTY_LIST_OPTIONS = [
    pytest.param(
        "reporters",
        "reporter",
        "bedrock-summary-reporter",
        "exclude_scanner_types",
        ["IAC"],
        id="bedrock-summary-reporter-exclude_scanner_types",
    ),
    pytest.param(
        "reporters",
        "reporter",
        "bedrock-summary-reporter",
        "include_sections",
        ["custom_notes"],
        id="bedrock-summary-reporter-include_sections",
    ),
    pytest.param(
        "scanners",
        "scanner",
        "guarddog",
        "ecosystems",
        ["npm"],
        id="guarddog-ecosystems",
    ),
    pytest.param(
        "scanners",
        "scanner",
        "trivy-repo",
        "scanners",
        ["secret"],
        id="trivy-repo-scanners",
    ),
]

#: (config segment, plugin kind, plugin) of a section that no plugin ASH ships
#: reads, one for each plugin segment.
_UNREAD_SECTIONS = [
    pytest.param("reporters", "reporter", "acme-findings-exporter", id="reporters"),
    pytest.param("scanners", "scanner", "acme-scanner", id="scanners"),
    pytest.param("converters", "converter", "acme-converter", id="converters"),
]

#: The same, for the tests of which application of the overrides logs the warning,
#: under names no other test uses.
_SECTIONS_OF_THE_APPLICATION_TESTS = [
    pytest.param("reporters", "reporter", "orbit-exporter", id="reporters"),
    pytest.param("scanners", "scanner", "orbit-scanner", id="scanners"),
    pytest.param("converters", "converter", "orbit-converter", id="converters"),
]

_BEDROCK = "bedrock-summary-reporter"
_BEDROCK_EXCLUDED_TYPES = f"reporters.{_BEDROCK}.options.exclude_scanner_types"

_KIND_OF_SEGMENT = {
    "reporters": "reporter",
    "scanners": "scanner",
    "converters": "converter",
}

#: A value to append to each row of UNTYPED_LIST_OPTION_DEFAULTS, valid as an item
#: of that option (read from the plugin's options model), by plugin and option name
#: under ``options``. A row with no entry here fails the test that reads it.
_PROBE_ITEMS: dict[tuple[str, str], Any] = {
    ("bedrock-summary-reporter", "compliance_frameworks"): "probe-framework",
    ("bedrock-summary-reporter", "exclude_scanner_types"): "IAC",
    ("bedrock-summary-reporter", "exclude_sections"): "probe-section",
    ("bedrock-summary-reporter", "include_sections"): "custom_notes",
    ("ferret-scan", "exclude_patterns"): "vendor/**",
    ("guarddog", "ecosystems"): "npm",
    ("guarddog", "exclude_rules"): "probe-rule",
    ("guarddog", "excluded_paths"): {"path": "vendor/", "reason": "probe"},
    ("guarddog", "rules"): "probe-rule",
    ("trivy-repo", "scanners"): "secret",
}


def _untyped_list_option_table():
    """``UNTYPED_LIST_OPTION_DEFAULTS``, or an empty mapping where the name does not
    exist, so that this module still collects there: the table feeds ``parametrize``
    at collection, and an import that failed would take every test of the file with
    it. An empty table holds no row, so
    ``test_the_defaults_table_the_cases_are_built_from_has_rows`` fails in its place."""
    try:
        from automated_security_helper.plugin_manifests import (
            UNTYPED_LIST_OPTION_DEFAULTS,
        )
    except ImportError:
        return {}
    return UNTYPED_LIST_OPTION_DEFAULTS


#: One case for each row of the table the append reads its defaults from, built from
#: the table itself, so a row added to it is covered without being listed here.
_TABLE_ROWS = [
    pytest.param(segment, plugin, path, id=f"{plugin}-{'.'.join(path[1:])}")
    for segment, plugins in _untyped_list_option_table().items()
    for plugin, options in plugins.items()
    for path in options
]


def _plugin_config_class(plugin: str) -> type:
    module, name = _PLUGIN_MODELS[plugin]
    return getattr(
        importlib.import_module(f"automated_security_helper.plugin_modules.{module}"),
        name,
    )


def _effective_list(config: AshConfig, kind: str, plugin: str, option: str) -> list:
    """The list the plugin runs with: its own config model, built from the section
    ``get_plugin_config`` returns, as the scan builds it."""
    model = _plugin_config_class(plugin).model_validate(
        config.get_plugin_config(kind, plugin)
    )
    return list(getattr(model.options, option))


def _read_path(model: BaseModel, path: tuple[str, ...]) -> Any:
    """The value at *path* (``("options", "rules")``) of a plugin's config model."""
    value: Any = model
    for part in path:
        value = getattr(value, part)
    return value


def _as_json(value: Any) -> Any:
    """*value* with each model in it dumped as JSON, so lists of models compare."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, (list, tuple)):
        return [_as_json(item) for item in value]
    return value


def _as_the_plugin_reads(plugin: str, path: tuple[str, ...], items: list) -> list:
    """*items* as the plugin's own config model reads them at *path*, as JSON."""
    document: Any = items
    for part in reversed(path):
        document = {part: document}
    model = _plugin_config_class(plugin).model_validate(document)
    return _as_json(_read_path(model, path))


def _warnings_naming(caplog, key: str) -> list[str]:
    """The texts of the warnings the test captured that name *key*."""
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and key in record.getMessage()
    ]


def _resolve_config_module():
    """The module itself: ``resolve_config`` is a function in this file's names."""
    return importlib.import_module("automated_security_helper.config.resolve_config")


def _bedrock_default_excluded_types() -> list:
    """The default of the Bedrock reporter's ``exclude_scanner_types``, read from its
    options model, so a test that expects it does not copy the model's literal."""
    return list(_plugin_config_class(_BEDROCK)().options.exclude_scanner_types)


def _scalars(value: Any) -> list:
    """Every value in *value* that is not a list, a tuple or a dict, however deep, and
    every key of a dict in it."""
    if isinstance(value, dict):
        return [
            leaf
            for key, item in value.items()
            for leaf in (*_scalars(key), *_scalars(item))
        ]
    if isinstance(value, (list, tuple)):
        return [leaf for item in value for leaf in _scalars(item)]
    return [value]


@pytest.mark.unit
class TestAppendOntoAnUntypedPluginOption:
    """``+=`` on a plugin option that no config file wrote adds to its default.

    A plugin whose section is not a typed field of the configuration (an alpha
    scanner, an AWS reporter, a plugin a module outside ASH adds) is kept as the
    mapping the file wrote, so an option the file left out is absent from the
    document the overrides are applied to, though the plugin's model gives it a
    default. The append used to start the list from the items it was given, which
    replaced that default; ``=`` replaced it as intended. Where ASH has no default
    list to add to (a section no plugin ASH ships reads, such as a plugin from a
    module outside ASH, which loads after the overrides are applied) the list
    still starts from the items. The application that builds the run's own
    configuration names the key in one warning for each run
    (``warn_unread_appends``). The same overrides are applied again to other
    bases (the trusted views, the replays, the MCP gate), which can lack a key the
    real document holds, and those applications never warn.

    An append is not refused for having no default to add to. A respelling of a
    section the file wrote is refused, since the append would land in a section
    the plugin does not read.
    """

    @pytest.fixture(autouse=True)
    def _each_test_starts_with_no_key_warned_of(self):
        """The keys already warned of are the process's: each test sees none, and
        the process's own are put back."""
        warned = _resolve_config_module()._APPEND_TO_UNREAD_SECTION_WARNED
        held = set(warned)
        warned.clear()
        try:
            yield
        finally:
            warned.clear()
            warned.update(held)

    @pytest.mark.parametrize(
        ("segment", "kind", "plugin", "option", "value"), _NON_EMPTY_LIST_OPTIONS
    )
    def test_an_append_adds_to_the_options_default(
        self, segment, kind, plugin, option, value
    ):
        default = list(getattr(_plugin_config_class(plugin)().options, option))
        assert default, "control: the option has a default to keep"
        assert default[0] not in value, "control: no value is the default's first item"
        key = f"{segment}.{plugin}.options.{option}"

        replaced = apply_config_overrides(AshConfig(), [f"{key}={json.dumps(value)}"])
        assert _effective_list(replaced, kind, plugin, option) == value

        appended = apply_config_overrides(AshConfig(), [f"{key}+={json.dumps(value)}"])
        assert _effective_list(appended, kind, plugin, option) == default + value

    def test_the_bedrock_reporter_is_built_with_the_default_and_the_append(
        self, tmp_path
    ):
        """The list the reporter itself is built with, which decides which findings
        go to the model, not only the section it reads. Building it makes no call
        to AWS."""
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
            BedrockSummaryReporter,
            BedrockSummaryReporterConfig,
        )

        AshAggregatedResults.model_rebuild()
        BedrockSummaryReporterConfig.model_rebuild()
        BedrockSummaryReporter.model_rebuild()
        default = _bedrock_default_excluded_types()
        config = apply_config_overrides(
            AshConfig(), [f'{_BEDROCK_EXCLUDED_TYPES}+=["IAC"]']
        )

        reporter = BedrockSummaryReporter(
            context=PluginContext(
                source_dir=tmp_path,
                output_dir=tmp_path,
                work_dir=tmp_path / "work",
                config=config,
            ),
            config=config.get_plugin_config("reporter", _BEDROCK),
        )

        assert reporter.config.options.exclude_scanner_types == [*default, "IAC"]

    def test_an_append_under_the_spelling_the_plugin_reads_adds_the_default(self):
        """The section a plugin reads is found under any spelling the lookup
        accepts (``BedrockSummaryReporter`` names ``bedrock-summary-reporter``), so
        an append under that spelling is to the section the reporter reads."""
        default = _bedrock_default_excluded_types()
        config = apply_config_overrides(
            AshConfig(),
            ['reporters.BedrockSummaryReporter.options.exclude_scanner_types+=["IAC"]'],
        )

        assert _effective_list(
            config, "reporter", _BEDROCK, "exclude_scanner_types"
        ) == [*default, "IAC"]

    def test_an_append_to_a_key_the_file_wrote_extends_it_and_adds_no_default(self):
        written = AshConfig.model_validate(
            {"reporters": {_BEDROCK: {"options": {"exclude_scanner_types": ["IAC"]}}}}
        )

        config = apply_config_overrides(
            written, [f'{_BEDROCK_EXCLUDED_TYPES}+=["SCA"]']
        )

        assert _effective_list(
            config, "reporter", _BEDROCK, "exclude_scanner_types"
        ) == ["IAC", "SCA"]

    def test_an_append_beside_another_written_option_adds_the_default(self):
        """The file writes the reporter's section with one option, not the list the
        append is for: the list starts from the plugin's default, and the option the
        file wrote is kept."""
        written = AshConfig.model_validate(
            {"reporters": {_BEDROCK: {"options": {"summary_style": "technical"}}}}
        )
        default = _bedrock_default_excluded_types()

        config = apply_config_overrides(
            written, [f'{_BEDROCK_EXCLUDED_TYPES}+=["IAC"]']
        )

        assert _effective_list(
            config, "reporter", _BEDROCK, "exclude_scanner_types"
        ) == [*default, "IAC"]
        assert config.get_plugin_config("reporter", _BEDROCK) == {
            "options": {
                "summary_style": "technical",
                "exclude_scanner_types": [*default, "IAC"],
            }
        }

    def test_an_append_beside_a_section_with_no_options_adds_the_default(self):
        """The file writes the reporter's section with no ``options`` key at all: the
        append creates it, starts the list from the plugin's default, and the key the
        file wrote is kept."""
        written = AshConfig.model_validate({"reporters": {_BEDROCK: {"enabled": True}}})
        default = _bedrock_default_excluded_types()

        config = apply_config_overrides(
            written, [f'{_BEDROCK_EXCLUDED_TYPES}+=["IAC"]']
        )

        assert _effective_list(
            config, "reporter", _BEDROCK, "exclude_scanner_types"
        ) == [*default, "IAC"]
        assert config.get_plugin_config("reporter", _BEDROCK) == {
            "enabled": True,
            "options": {"exclude_scanner_types": [*default, "IAC"]},
        }

    def test_a_respelled_written_section_is_refused_and_changes_nothing(self):
        """``BedrockSummaryReporter`` reads as the section the file wrote, but the
        override walk would add it beside that section as a key of its own, and the
        append would then be to a section the reporter does not read. It is refused,
        naming the key the file wrote, and the configuration it was applied to is as
        it was."""
        key = "reporters.BedrockSummaryReporter.options.exclude_scanner_types"
        written = AshConfig.model_validate(
            {"reporters": {_BEDROCK: {"options": {"exclude_scanner_types": ["IAC"]}}}}
        )

        with pytest.raises(ASHRespelledOverrideError) as refused:
            apply_config_overrides(written, [f'{key}+=["SCA"]'])

        assert f"reporters.{_BEDROCK}" in str(refused.value)
        reporters = written.model_dump()["reporters"]
        assert reporters[_BEDROCK]["options"]["exclude_scanner_types"] == ["IAC"]
        assert "BedrockSummaryReporter" not in reporters

    def test_the_underscore_spelling_of_a_section_the_file_wrote_is_that_section(self):
        """A key that differs from one the document holds only in ``-`` against
        ``_`` is that key: the append extends the list the file wrote, and no second
        section appears beside it."""
        twin = _BEDROCK_EXCLUDED_TYPES.replace("-", "_")
        assert twin != _BEDROCK_EXCLUDED_TYPES, "control: the spelling differs"
        written = AshConfig.model_validate(
            {"reporters": {_BEDROCK: {"options": {"exclude_scanner_types": ["IAC"]}}}}
        )

        config = apply_config_overrides(written, [f'{twin}+=["SCA"]'])

        reporters = config.model_dump()["reporters"]
        assert reporters[_BEDROCK]["options"]["exclude_scanner_types"] == ["IAC", "SCA"]
        assert [key for key in reporters if "bedrock" in key.lower()] == [_BEDROCK]

    def test_an_append_to_a_written_external_list_extends_it(self, caplog):
        """A plugin from a module outside ASH has no row in the defaults table, so no
        default to add to. When the file wrote the list, the append extends it and
        nothing is warned of: the warning is for a list the document lacks."""
        key = "reporters.acme-written-exporter.options.destinations"
        unread = "reporters.acme-findings-exporter.options.destinations"
        warned = _resolve_config_module()._APPEND_TO_UNREAD_SECTION_WARNED
        assert key not in warned, "control: no earlier append has warned of the key"
        written = AshConfig.model_validate(
            {
                "reporters": {
                    "acme-written-exporter": {"options": {"destinations": ["a"]}}
                }
            }
        )

        with caplog.at_level("WARNING", logger="ash"):
            config = apply_config_overrides(written, [f'{key}+=["b"]'])
            apply_config_overrides(AshConfig(), [f'{unread}+=["x"]'])

        assert config.get_plugin_config("reporter", "acme-written-exporter") == {
            "options": {"destinations": ["a", "b"]}
        }
        assert _warnings_naming(caplog, key) == []
        assert len(_warnings_naming(caplog, unread)) == 1, "control: the capture works"

    def test_an_append_to_an_option_whose_default_is_empty_starts_the_list(self):
        assert _plugin_config_class("guarddog")().options.rules == [], "control"

        config = apply_config_overrides(
            AshConfig(), ['scanners.guarddog.options.rules+=["typosquatting"]']
        )

        assert _effective_list(config, "scanner", "guarddog", "rules") == [
            "typosquatting"
        ]

    def test_two_appends_accumulate_after_the_default(self):
        default = _bedrock_default_excluded_types()
        config = apply_config_overrides(
            AshConfig(),
            [
                f'{_BEDROCK_EXCLUDED_TYPES}+=["IAC"]',
                f'{_BEDROCK_EXCLUDED_TYPES}+=["SCA"]',
            ],
        )

        assert _effective_list(
            config, "reporter", _BEDROCK, "exclude_scanner_types"
        ) == [*default, "IAC", "SCA"]

    def test_a_later_set_replaces_the_default_and_the_appends(self):
        config = apply_config_overrides(
            AshConfig(),
            [
                f'{_BEDROCK_EXCLUDED_TYPES}+=["IAC"]',
                f'{_BEDROCK_EXCLUDED_TYPES}=["SCA"]',
            ],
        )

        assert _effective_list(
            config, "reporter", _BEDROCK, "exclude_scanner_types"
        ) == ["SCA"]

    def test_an_append_onto_a_whole_section_adds_no_default(self, caplog):
        """Only an override that lands at an option inside an untyped section is
        read against the plugin's defaults. One at the section itself has no option
        to read a default for: it is refused, or it is applied as the items it was
        given, and what it writes holds none of the plugin's default items.

        Either way it logs no warning that no plugin reads the section, which would
        be false: the section is the Bedrock reporter's, and ASH ships it. A
        plugin's row is found through the sections the document holds, and the
        override walk has not made this one yet, so a guard that let a two-segment
        key through to that lookup would find no row and log that warning. It is
        the guard's only visible effect, so the append is applied through
        ``build_config``, the application that logs the warning."""
        rows = _untyped_list_option_table().get("reporters", {}).get(_BEDROCK, {})
        defaults = [item for row in rows.values() for item in row]
        assert defaults, "control: the table has default items for the plugin"
        key = f"reporters.{_BEDROCK}"
        unread = "reporters.vesper-exporter.options.channels"

        with caplog.at_level("WARNING", logger="ash"):
            try:
                config = build_config({}, [f"{key}+=[1]"])
            except ASHConfigValidationError:
                config = None
            build_config({}, [f'{unread}+=["x"]'])

        assert _warnings_naming(caplog, key) == []
        assert len(_warnings_naming(caplog, unread)) == 1, "control: the capture works"
        if config is not None:
            written = config.get_plugin_config("reporter", _BEDROCK)
            assert [leaf for leaf in _scalars(written) if leaf in defaults] == []

    def test_a_typed_section_keeps_its_default_as_before(self):
        default = list(AshConfig().scanners.checkov.options.frameworks)
        assert default, "control: the typed option has a default to keep"

        config = apply_config_overrides(
            AshConfig(), ['scanners.checkov.options.frameworks+=["terraform"]']
        )

        assert list(config.scanners.checkov.options.frameworks) == [
            *default,
            "terraform",
        ]

    def test_the_defaults_table_the_cases_are_built_from_has_rows(self):
        assert _TABLE_ROWS, "control: the table holds no row to build a case from"

    @pytest.mark.parametrize(("segment", "plugin", "path"), _TABLE_ROWS)
    def test_every_row_of_the_defaults_table_keeps_its_default_under_an_append(
        self, segment, plugin, path
    ):
        """The list the plugin runs with, read through its own config model, is the
        option's default followed by the appended item, for every row of the table
        and not only the options the tests above name."""
        option = ".".join(path[1:])
        probe = _PROBE_ITEMS.get((plugin, option))
        assert probe is not None, (
            f"{segment}.{plugin}.{option} has no probe item: add one to "
            "_PROBE_ITEMS, valid as an item of that option"
        )
        key = f"{segment}.{plugin}.{'.'.join(path)}"
        default = _as_json(_read_path(_plugin_config_class(plugin)(), path))

        config = apply_config_overrides(AshConfig(), [f"{key}+={json.dumps([probe])}"])

        section = config.get_plugin_config(_KIND_OF_SEGMENT[segment], plugin)
        model = _plugin_config_class(plugin).model_validate(section)
        assert _as_json(_read_path(model, path)) == [
            *default,
            *_as_the_plugin_reads(plugin, path, [probe]),
        ]

    def test_the_trusted_reporter_view_keeps_the_default(self):
        """The operator's overrides are replayed onto the trusted base, which holds
        no section for the reporter just as a default configuration does. The append
        starts from the reporter's default there too."""
        from automated_security_helper.config.resolve_config import (
            _with_reporter_overrides,
        )

        default = _bedrock_default_excluded_types()
        view = _with_reporter_overrides(
            AshConfig(), [f'{_BEDROCK_EXCLUDED_TYPES}+=["IAC"]'], AshConfig()
        )

        options = view.model_dump(by_alias=True)["reporters"][_BEDROCK]["options"]
        assert options["exclude_scanner_types"] == [*default, "IAC"]

    def test_an_external_reporters_section_survives_the_trusted_replay(self):
        """The repository's own file holds the reporter's section and the trusted
        base does not, so the replayed ``+=`` meets an option the base lacks. The
        view keeps the whole section, its ``enabled`` included, with the appended
        items as the list."""
        from automated_security_helper.config.resolve_config import (
            _with_reporter_overrides,
        )

        key = "reporters.acme-findings-exporter"
        resolved = AshConfig.model_validate(
            {
                "reporters": {
                    "acme-findings-exporter": {"options": {"destinations": ["in-tree"]}}
                }
            }
        )

        view = _with_reporter_overrides(
            AshConfig(),
            [f"{key}.enabled=true", f'{key}.options.destinations+=["ops"]'],
            resolved,
        )

        section = view.model_dump(by_alias=True)["reporters"]["acme-findings-exporter"]
        assert section["enabled"] is True
        assert section["options"]["destinations"] == ["ops"]

    @pytest.mark.parametrize(("segment", "kind", "plugin"), _UNREAD_SECTIONS)
    def test_an_append_to_a_section_no_shipped_plugin_reads_is_applied_and_warned_of(
        self, caplog, segment, kind, plugin
    ):
        key = f"{segment}.{plugin}.options.destinations"

        with caplog.at_level("WARNING", logger="ash"):
            config = apply_config_overrides(
                AshConfig(), [f'{key}+=["appended-value-7f3a"]']
            )

        assert config.get_plugin_config(kind, plugin) == {
            "options": {"destinations": ["appended-value-7f3a"]}
        }
        warnings = _warnings_naming(caplog, key)
        assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
        assert f"No plugin ASH ships reads {segment}.{plugin} " in warnings[0]
        assert f"{key}=[...]" in warnings[0]
        assert "appended-value-7f3a" not in warnings[0]

    def test_the_same_append_applied_twice_warns_once(self, caplog):
        """The same overrides are applied again to other bases (the trusted views,
        the replays, the MCP gate): each key is named once for the process."""
        key = "reporters.acme-findings-exporter.options.destinations"
        other = "scanners.acme-scanner.options.destinations"

        with caplog.at_level("WARNING", logger="ash"):
            apply_config_overrides(AshConfig(), [f'{key}+=["first"]'])
            apply_config_overrides(AshConfig(), [f'{key}+=["second"]'])
            apply_config_overrides(AshConfig(), [f'{other}+=["first"]'])

        assert len(_warnings_naming(caplog, key)) == 1
        assert len(_warnings_naming(caplog, other)) == 1, "control: a key of its own"

    @pytest.mark.parametrize(
        ("segment", "kind", "plugin"), _SECTIONS_OF_THE_APPLICATION_TESTS
    )
    def test_an_append_warns_only_when_the_application_asks_for_the_warning(
        self, caplog, segment, kind, plugin
    ):
        """The same overrides are applied to other bases as well as to the run's own
        configuration (the trusted views, the replays, the MCP gate), and there a
        key the real document holds can be missing. Only the application that builds
        the run's own configuration asks for the warning, with
        ``warn_unread_appends``; the others leave it off and say nothing about the
        section."""
        key = f"{segment}.{plugin}.options.channels"
        override = f'{key}+=["appended-value-4c1e"]'
        written = {"options": {"channels": ["appended-value-4c1e"]}}

        with caplog.at_level("WARNING", logger="ash"):
            quiet = apply_config_overrides(AshConfig(), [override])
            assert _warnings_naming(caplog, key) == [], "no flag: no warning"
            asked = apply_config_overrides(
                AshConfig(), [override], warn_unread_appends=True
            )

        assert quiet.get_plugin_config(kind, plugin) == written
        assert asked.get_plugin_config(kind, plugin) == written
        warnings = _warnings_naming(caplog, key)
        assert len(warnings) == 1, [r.getMessage() for r in caplog.records]

    def test_a_key_is_warned_of_once_in_each_run(self, caplog):
        """The warning is once for each key in each run, not once for the process:
        the MCP server runs every scan in one process, and each scan's log has to
        name the key its overrides append to. Inside one run the key applied again
        is named once."""
        key = "reporters.nimbus-exporter.options.channels"

        with caplog.at_level("WARNING", logger="ash"):
            with run_log_scope():
                first_run = current_run_log_scope()
                apply_config_overrides(
                    AshConfig(), [f'{key}+=["a"]'], warn_unread_appends=True
                )
                apply_config_overrides(
                    AshConfig(), [f'{key}+=["b"]'], warn_unread_appends=True
                )
                within_the_first_run = len(_warnings_naming(caplog, key))
            with run_log_scope():
                second_run = current_run_log_scope()
                apply_config_overrides(
                    AshConfig(), [f'{key}+=["c"]'], warn_unread_appends=True
                )

        assert first_run is not None and second_run is not None, "control: in a run"
        assert first_run != second_run, "control: two runs are two scopes"
        assert within_the_first_run == 1
        assert len(_warnings_naming(caplog, key)) == 2

    @pytest.mark.parametrize(
        ("segment", "plugin", "other", "replay"),
        [
            pytest.param(
                "reporters",
                "halo-exporter",
                "halo-other-exporter",
                "_with_reporter_overrides",
                id="reporters",
            ),
            pytest.param(
                "scanners",
                "halo-linter",
                "halo-other-linter",
                "_with_scanner_overrides",
                id="scanners",
            ),
        ],
    )
    def test_a_replay_of_an_append_onto_a_list_the_file_wrote_says_nothing(
        self, tmp_path, monkeypatch, caplog, segment, plugin, other, replay
    ):
        """The repository's own config file writes an external plugin's list and the
        operator appends to it. The scan's own application extends the file's list
        with no warning. The same override is then replayed onto the trusted base
        (``_with_reporter_overrides``, ``_with_scanner_overrides``), which holds no
        such section, so the replayed list starts from the appended items, and the
        replay used to log that no plugin reads the section and advise ``=[...]``
        for a list the scan had extended. Only the control key, which the file did
        not write, is named, once.

        ``resolve_config`` returns before the trusted replays when its chain holds
        no file inside the scanned tree, so the file is the repository's, in a
        checkout under ``source_dir``. The test records what the replay returns and
        fails its control when none ran, or when the one that ran did not meet a
        base without the file's list."""
        monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
        module = _resolve_config_module()
        replayed: list = []
        original = getattr(module, replay)

        def recording(*args, **kwargs):
            view = original(*args, **kwargs)
            replayed.append(view)
            return view

        monkeypatch.setattr(module, replay, recording)

        def list_the_replay_started(view) -> Any:
            section = view.model_dump(by_alias=True)[segment].get(plugin) or {}
            return (section.get("options") or {}).get("channels")

        key = f"{segment}.{plugin}.options.channels"
        control = f"{segment}.{other}.options.channels"
        checkout = tmp_path / "checkout"
        mark_git_checkout(checkout)
        (checkout / ".ash.yaml").write_text(
            f"project_name: repo\n{segment}:\n  {plugin}:\n    options:\n"
            '      channels: ["base-a", "base-b"]\n',
            encoding="utf-8",
        )

        with caplog.at_level("WARNING", logger="ash"):
            config = resolve_config(
                source_dir=checkout,
                config_overrides=[
                    f'{key}+=["extra-a", "extra-b"]',
                    f'{control}+=["control-a"]',
                ],
            )

        written = (getattr(config, segment).model_extra or {})[plugin]
        assert written["options"]["channels"] == [
            "base-a",
            "base-b",
            "extra-a",
            "extra-b",
        ]
        assert replayed, "control: the trusted replay did not run"
        assert ["extra-a", "extra-b"] in [
            list_the_replay_started(view) for view in replayed
        ], "control: the replay did not meet a base without the file's list"
        assert len(_warnings_naming(caplog, control)) == 1, "control: the capture works"
        assert _warnings_naming(caplog, key) == []

    def test_the_warned_keys_stay_bounded_in_a_long_lived_process(self, caplog):
        module = _resolve_config_module()
        warned = module._APPEND_TO_UNREAD_SECTION_WARNED
        bound = module._APPEND_TO_UNREAD_SECTION_BOUND
        warned.update(f"filler-{index}" for index in range(bound))
        key = "reporters.acme-findings-exporter.options.destinations"

        with caplog.at_level("WARNING", logger="ash"):
            apply_config_overrides(AshConfig(), [f'{key}+=["x"]'])

        assert len(_warnings_naming(caplog, key)) == 1
        assert key in warned
        assert len(warned) <= bound

    @pytest.mark.parametrize(("segment", "kind", "plugin"), _UNREAD_SECTIONS)
    def test_the_same_key_set_with_equals_is_accepted(self, segment, kind, plugin):
        key = f"{segment}.{plugin}.options.destinations"

        config = apply_config_overrides(AshConfig(), [f'{key}=["set-value-7f3a"]'])

        assert config.get_plugin_config(kind, plugin) == {
            "options": {"destinations": ["set-value-7f3a"]}
        }

    def test_an_append_to_a_shipped_plugins_non_list_option_is_left_to_the_plugin(
        self, caplog
    ):
        """The plugin's own options model refuses the list when the plugin loads,
        as it does on main; the append adds no warning of its own."""
        key = f"reporters.{_BEDROCK}.options.aws_region"
        unread = "reporters.acme-findings-exporter.options.destinations"

        with caplog.at_level("WARNING", logger="ash"):
            config = apply_config_overrides(AshConfig(), [f"{key}+=us-east-1"])
            apply_config_overrides(AshConfig(), [f'{unread}+=["x"]'])

        section = config.get_plugin_config("reporter", _BEDROCK)
        assert section == {"options": {"aws_region": ["us-east-1"]}}
        assert _warnings_naming(caplog, key) == []
        assert len(_warnings_naming(caplog, unread)) == 1, "control: the capture works"
        with pytest.raises(ValidationError):
            _plugin_config_class(_BEDROCK).model_validate(section)

    def test_an_append_to_a_plugin_with_no_list_option_is_not_warned_of(self, caplog):
        """A shipped plugin with no list option at all (the S3 reporter) has an empty
        row in the defaults table, so the section is read by a plugin ASH ships: the
        append is applied with no warning that no plugin reads it, and the plugin's
        own options model decides about the value when the plugin loads."""
        key = "reporters.s3.options.bucket_name"
        unread = "reporters.acme-findings-exporter.options.destinations"
        warned = _resolve_config_module()._APPEND_TO_UNREAD_SECTION_WARNED
        assert key not in warned, "control: no earlier append has warned of the key"

        with caplog.at_level("WARNING", logger="ash"):
            config = apply_config_overrides(AshConfig(), [f"{key}+=appended-bucket"])
            apply_config_overrides(AshConfig(), [f'{unread}+=["x"]'])

        section = config.get_plugin_config("reporter", "s3")
        assert section == {"options": {"bucket_name": ["appended-bucket"]}}
        assert _warnings_naming(caplog, key) == []
        assert len(_warnings_naming(caplog, unread)) == 1, "control: the capture works"

    def test_the_same_option_set_with_equals_is_accepted(self):
        config = apply_config_overrides(
            AshConfig(), [f"reporters.{_BEDROCK}.options.aws_region=us-east-1"]
        )

        assert config.get_plugin_config("reporter", _BEDROCK) == {
            "options": {"aws_region": "us-east-1"}
        }

    def test_config_get_exits_zero_for_the_append_and_for_the_set(self, tmp_path):
        from typer.testing import CliRunner

        config_file = tmp_path / ".ash.yaml"
        config_file.write_text("project_name: from-file\n", encoding="utf-8")
        key = "reporters.acme-findings-exporter.options.destinations"

        appended = CliRunner().invoke(
            config_app, ["get", str(config_file), "--config-overrides", f'{key}+=["x"]']
        )
        assigned = CliRunner().invoke(
            config_app, ["get", str(config_file), "--config-overrides", f'{key}=["x"]']
        )

        assert appended.exit_code == 0, appended.output
        assert assigned.exit_code == 0, assigned.output


@pytest.mark.integration
class TestAnAppendImportsNoPluginModule:
    """Applying ``+=`` to a shipped plugin's option imports no plugin module.

    The list an append starts from comes from ``UNTYPED_LIST_OPTION_DEFAULTS``, not
    from the plugin's options model, because importing a plugin module registers
    its plugins and a scan runs every plugin registered: an append to the Bedrock
    reporter's option must not enlist the reporter. Only a fresh interpreter shows
    what an operation imports, since this process has imported the module for its
    other tests.

    Building ``AshConfig`` imports the built-in plugins' config classes, which its
    typed sections need, so the child cannot be asked for no plugin module at all.
    It is asked for the same set before and after the append, and for none under the
    reporter's package.
    """

    def test_applying_an_append_imports_no_plugin_module(self, tmp_path):
        import subprocess  # nosec B404 - starts a fresh interpreter to watch imports
        import sys

        module = _plugin_config_class(_BEDROCK).__module__
        package = module.rpartition(".")[0]
        default = _bedrock_default_excluded_types()
        code = (
            "import importlib, json, sys\n"
            "from automated_security_helper.config.ash_config import AshConfig\n"
            "from automated_security_helper.config.resolve_config import (\n"
            "    apply_config_overrides,\n"
            ")\n"
            "override, plugin, module = sys.argv[1:]\n"
            "def loaded():\n"
            "    return sorted(m for m in sys.modules if '.plugin_modules.' in m)\n"
            "base = AshConfig()\n"
            "before = loaded()\n"
            "config = apply_config_overrides(base, [override])\n"
            "after = loaded()\n"
            "section = config.get_plugin_config('reporter', plugin)\n"
            "importlib.import_module(module)\n"
            "print(json.dumps({\n"
            "    'before': before,\n"
            "    'after': after,\n"
            "    'value': section['options']['exclude_scanner_types'],\n"
            "    'control': loaded(),\n"
            "}))\n"
        )

        result = subprocess.run(  # nosec B603 - fixed argv: this interpreter, literal probe
            [
                sys.executable,
                "-c",
                importing_this_checkout(code),
                f'{_BEDROCK_EXCLUDED_TYPES}+=["IAC"]',
                _BEDROCK,
                module,
            ],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=CHILD_TIMEOUT_SECONDS,
        )

        def under_the_package(names: list) -> list:
            return [n for n in names if n == package or n.startswith(f"{package}.")]

        assert result.returncode == 0, result.stderr[-2000:]
        child = json.loads(result.stdout.strip().splitlines()[-1])
        assert child["value"] == [*default, "IAC"], "control: the append took effect"
        assert under_the_package(child["control"]), "control: an import is recorded"
        assert under_the_package(child["after"]) == []
        assert child["after"] == child["before"], sorted(
            set(child["after"]) - set(child["before"])
        )
