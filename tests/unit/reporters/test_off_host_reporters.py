# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Reporters that send findings off the host declare it, and run only when enabled.

A reporter class sets ``sends_off_host = True`` when its report goes to a remote
service (the four AWS reporters). Such a reporter runs only when its section of
the config sets ``enabled: true``; its own default does not count. ``ash report``,
the report phase of a scan and the workspace report step all apply that rule.
``ash merge`` applies it to the operator's own ``--config`` only: the config the
shards carried is not one the operator of the merge supplied, so its ``enabled``
is ignored in both directions.

The class attribute replaces a check on the reporter's module name, which only
knew ASH's own AWS package: a reporter from any other package could send
findings anywhere and still look local.
"""

import ast
import importlib
import inspect
from typing import Literal

import pytest
import typer

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)

#: Packages whose import means a module can talk to the network.
NETWORK_MODULES = frozenset(
    {
        "aiohttp",
        "boto3",
        "botocore",
        "ftplib",
        "http.client",
        "httpx",
        "requests",
        "smtplib",
        "socket",
        "urllib.request",
        "urllib3",
    }
)

PLUGIN_PACKAGES = (
    "automated_security_helper.plugin_modules.ash_builtin",
    "automated_security_helper.plugin_modules.ash_aws_plugins",
    "automated_security_helper.plugin_modules.ash_ferret_plugins",
    "automated_security_helper.plugin_modules.ash_snyk_plugins",
    "automated_security_helper.plugin_modules.ash_trivy_plugins",
)


def _shipped_reporters():
    reporters = []
    for package in PLUGIN_PACKAGES:
        reporters.extend(importlib.import_module(package).ASH_REPORTERS)
    return reporters


def _imported_modules(module) -> set:
    names = set()
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def _does_network_io(reporter_class) -> bool:
    imported = _imported_modules(inspect.getmodule(reporter_class))
    return any(
        name == network or name.startswith(network + ".")
        for name in imported
        for network in NETWORK_MODULES
    )


class TestEveryReporterThatDoesNetworkIoDeclaresIt:
    def test_the_base_reporter_is_local(self):
        assert ReporterPluginBase.sends_off_host is False

    @pytest.mark.parametrize(
        "reporter_class", _shipped_reporters(), ids=lambda cls: cls.__name__
    )
    def test_the_declaration_matches_the_imports(self, reporter_class):
        """A reporter module that imports a network client declares sends_off_host."""
        assert reporter_class.sends_off_host is _does_network_io(reporter_class)

    def test_the_off_host_reporters_are_the_four_aws_ones(self):
        """Control: the import scan finds the reporters it is meant to find."""
        off_host = {
            cls.__name__ for cls in _shipped_reporters() if _does_network_io(cls)
        }

        assert off_host == {
            "BedrockSummaryReporter",
            "CloudWatchLogsReporter",
            "S3Reporter",
            "SecurityHubReporter",
        }


# Reporters defined here, so the rule is checked on a class from a package that
# is not ASH's AWS one, which is what the module-name check could not see.


class _OffHostConfig(ReporterPluginConfigBase):
    name: Literal["fake-off-host"] = "fake-off-host"
    extension: str = "off-host.json"
    # On by default, so only the off-host rule can keep it from running.
    enabled: bool = True


class _LocalConfig(ReporterPluginConfigBase):
    name: Literal["fake-local"] = "fake-local"
    extension: str = "local.json"
    enabled: bool = True


@pytest.fixture
def ran():
    return []


@pytest.fixture
def reporters(ran):
    class FakeOffHostReporter(ReporterPluginBase[_OffHostConfig]):
        sends_off_host = True

        def model_post_init(self, context):
            if self.config is None:
                self.config = _OffHostConfig()
            return super().model_post_init(context)

        def report(self, model):
            ran.append("fake-off-host")
            return "{}"

    class FakeLocalReporter(ReporterPluginBase[_LocalConfig]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = _LocalConfig()
            return super().model_post_init(context)

        def report(self, model):
            ran.append("fake-local")
            return "{}"

    return FakeOffHostReporter, FakeLocalReporter


def _config(off_host_section=None):
    from automated_security_helper.config.ash_config import AshConfig

    reporters = {}
    if off_host_section is not None:
        reporters["fake-off-host"] = off_host_section
    return AshConfig.model_validate({"reporters": reporters})


def _context(tmp_path, config):
    from automated_security_helper.base.plugin_context import PluginContext

    output_dir = tmp_path / "out"
    return PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=config,
    )


class TestTheReportPhase:
    def _run(self, tmp_path, reporters, config, output_formats=None):
        from automated_security_helper.core.phases.report_phase import ReportPhase
        from automated_security_helper.core.progress import LiveProgressDisplay
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        context = _context(tmp_path, config)
        model = AshAggregatedResults()
        phase = ReportPhase(
            plugins=list(reporters),
            plugin_context=context,
            progress_display=LiveProgressDisplay(show_progress=False),
            asharp_model=model,
        )
        phase._execute_phase(
            report_dir=context.output_dir / "reports",
            aggregated_results=model,
            cli_output_formats=output_formats,
            python_based_plugins_only=False,
        )

    @pytest.mark.parametrize(
        "section", [None, {}, {"enabled": False}], ids=["no-section", "empty", "off"]
    )
    def test_an_off_host_reporter_its_config_does_not_enable_is_not_run(
        self, tmp_path, reporters, ran, section
    ):
        self._run(tmp_path, reporters, _config(section))

        assert ran == ["fake-local"]

    @pytest.mark.parametrize("section", [None, {}], ids=["no-section", "empty"])
    def test_asking_for_it_says_it_is_disabled_whatever_its_own_default(
        self, tmp_path, reporters, ran, caplog, section
    ):
        """Its own default is on, but the phase sets it off (``_disable``), so the
        requested format is reported as disabled: the setting to change is in the
        config. Left on, it would be reported as failing its dependency check."""
        import logging

        with caplog.at_level(logging.ERROR):
            self._run(tmp_path, reporters, _config(section), ["fake-off-host"])

        assert ran == []
        assert (
            "No report will be written for requested format 'fake-off-host': "
            "its reporter is disabled in the configuration"
        ) in caplog.text
        assert "dependencies are not satisfied" not in caplog.text

    @pytest.mark.parametrize(
        "section",
        [
            {"extension": "off-host.json"},
            {"enabled": "true"},
            # Values the reporter's own model refuses: it is not run either way,
            # and the operator is told why, not shown its model's error.
            {"enabled": None},
            {"enabled": ["true"]},
            {"enabled": "[/x]"},
        ],
        ids=[
            "no-enabled-key",
            "enabled-not-a-boolean",
            "enabled-null",
            "enabled-a-list",
            "enabled-markup",
        ],
    )
    def test_a_section_that_configures_it_without_enabling_it_warns(
        self, tmp_path, reporters, ran, caplog, section
    ):
        """An operator who wrote a section for it expects it to run; say why not,
        once, at WARNING, and log no error for it."""
        import logging

        with caplog.at_level(logging.WARNING):
            self._run(tmp_path, reporters, _config(section))

        assert ran == ["fake-local"]
        records = [
            record
            for record in caplog.records
            if record.levelno == logging.WARNING
            and "fake-off-host" in record.getMessage()
        ]
        assert len(records) == 1, caplog.text
        message = records[0].getMessage()
        assert "reporters.fake-off-host.enabled" in message
        # The text is logged as written, not read as markup.
        assert getattr(records[0], "markup", None) is False, vars(records[0])
        if "enabled" in section:
            # Says what type it is set to, never the value, and that only the
            # boolean counts.
            value = section["enabled"]
            kind = "null" if value is None else f"a {type(value).__name__}"
            assert f"sets enabled to {kind}," in message, message
            if value is not None:
                assert repr(value) not in message, message
            assert "boolean" in message, message
        else:
            assert "does not set" in message, message
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR], (
            caplog.text
        )

    def test_the_warning_names_a_reporter_whose_name_reads_as_markup(
        self, tmp_path, ran, caplog
    ):
        """A reporter named "[/x]" is named as written, with markup off."""
        import logging

        class _MarkupNamedConfig(ReporterPluginConfigBase):
            name: Literal["[/x]"] = "[/x]"
            extension: str = "markup.json"
            enabled: bool = True

        class MarkupNamedReporter(ReporterPluginBase[_MarkupNamedConfig]):
            sends_off_host = True

            def model_post_init(self, context):
                if self.config is None:
                    self.config = _MarkupNamedConfig()
                return super().model_post_init(context)

            def report(self, model):
                ran.append("[/x]")
                return "{}"

        from automated_security_helper.config.ash_config import AshConfig

        config = AshConfig.model_validate(
            {"reporters": {"[/x]": {"extension": "markup.json"}}}
        )
        with caplog.at_level(logging.WARNING):
            self._run(tmp_path, [MarkupNamedReporter], config)

        assert ran == []
        records = [
            record
            for record in caplog.records
            if record.levelno == logging.WARNING and "[/x]" in record.getMessage()
        ]
        assert len(records) == 1, caplog.text
        assert "reporters.[/x].enabled" in records[0].getMessage()
        assert getattr(records[0], "markup", None) is False, vars(records[0])

    def test_a_requested_format_that_leaves_it_out_does_not_warn(
        self, tmp_path, reporters, ran, caplog
    ):
        """Asked for other formats, the reporter would not run whatever its section
        says, so its section is not worth a warning."""
        import logging

        with caplog.at_level(logging.WARNING):
            self._run(
                tmp_path,
                reporters,
                _config({"extension": "off-host.json"}),
                ["fake-local"],
            )

        assert ran == ["fake-local"]
        assert not [
            record
            for record in caplog.records
            if record.levelno >= logging.WARNING
            and "fake-off-host" in record.getMessage()
        ], caplog.text

    @pytest.mark.parametrize(
        "section", [None, {}, {"enabled": False}], ids=["no-section", "empty", "off"]
    )
    def test_no_section_or_one_that_turns_it_off_does_not_warn(
        self, tmp_path, reporters, ran, caplog, section
    ):
        """Control: left alone, or turned off on purpose, it is skipped quietly."""
        import logging

        with caplog.at_level(logging.WARNING):
            self._run(tmp_path, reporters, _config(section))

        assert ran == ["fake-local"]
        assert not [
            record
            for record in caplog.records
            if record.levelno >= logging.WARNING
            and "fake-off-host" in record.getMessage()
        ], caplog.text

    def test_an_off_host_reporter_its_config_enables_is_run(
        self, tmp_path, reporters, ran
    ):
        """Control: ``enabled: true`` in its section runs it."""
        self._run(tmp_path, reporters, _config({"enabled": True}))

        assert sorted(ran) == ["fake-local", "fake-off-host"]


class TestTheReportCommand:
    def _report(self, tmp_path, monkeypatch, reporters, overrides):
        from automated_security_helper.cli import report as report_module
        from automated_security_helper.core.enums import AshLogLevel
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        output_dir = tmp_path / "out"
        output_dir.mkdir(parents=True)
        (output_dir / "ash_aggregated_results.json").write_text(
            AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
        )
        # On the class, not the instance: undoing an instance patch leaves the
        # bound method behind as an instance attribute, which then hides every
        # later patch of the class (the off_scope_reporter fixture's, say).
        monkeypatch.setattr(
            type(report_module.ash_plugin_manager),
            "plugin_modules",
            lambda self, plugin_type=None, **kwargs: list(reporters),
        )
        monkeypatch.setattr(report_module, "load_plugins", lambda **kwargs: None)
        return report_module.report_command(
            report_format="fake-off-host",
            output_dir=str(output_dir),
            log_level=AshLogLevel.ERROR,
            config=None,
            config_overrides=overrides,
            verbose=False,
            debug=False,
            color=False,
        )

    def test_an_off_host_reporter_that_defaults_to_on_is_refused(
        self, tmp_path, monkeypatch, reporters, ran
    ):
        with pytest.raises(typer.Exit) as raised:
            self._report(tmp_path, monkeypatch, reporters, [])

        assert raised.value.exit_code == 1
        assert ran == []

    def test_the_same_reporter_runs_when_the_config_enables_it(
        self, tmp_path, monkeypatch, reporters, ran
    ):
        """Control."""
        self._report(
            tmp_path, monkeypatch, reporters, ["reporters.fake-off-host.enabled=true"]
        )

        assert ran == ["fake-off-host"]


class TestTheWorkspaceReportStep:
    @pytest.mark.parametrize(
        "section, expected",
        [(None, "disabled"), ({"enabled": True}, None)],
        ids=["not-enabled", "enabled"],
    )
    def test_an_off_host_reporter_is_considered_only_when_enabled(
        self, tmp_path, reporters, section, expected
    ):
        from automated_security_helper.base.reporter_plugin import (
            ReporterWorkspaceBehaviour,
        )
        from automated_security_helper.workspace.reporting import _selected_reporters

        off_host, _ = reporters

        class MergedOffHostReporter(off_host):
            workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

        selected = list(
            _selected_reporters(
                context=_context(tmp_path, _config()),
                config_lookup=lambda key: section,
                output_formats=[],
                python_based_plugins_only=False,
                reporter_classes=[MergedOffHostReporter],
                check_dependencies=False,
            )
        )

        assert [skipped for _, _, skipped in selected] == [expected]


class TestTheMergeCommand:
    """``ash merge`` runs an off-host reporter only when the operator's ``--config`` enables it.

    The shards' recorded configuration came from whatever config each shard's scan
    read, a file in the scanned repository included, so it decides nothing about
    a reporter that sends findings off the host, in either direction: its
    ``enabled`` is ignored, with a warning when it disagrees with the operator.
    """

    def _merge(self, tmp_path, monkeypatch, reporters, shard_section, operator_section):
        import logging

        from automated_security_helper.cli import merge as merge_module
        from automated_security_helper.core.enums import AshLogLevel
        from tests.unit.cli.test_merge import build_shards, write_shards

        shards = build_shards(2)
        for shard in shards:
            shard.ash_config.reporters = _config(shard_section).reporters
        shard_paths = write_shards(tmp_path / "artifacts", shards)
        config_path = None
        if operator_section is not None:
            config_path = tmp_path / "operator" / "ash-config.yaml"
            config_path.parent.mkdir(parents=True)
            config_path.write_text(
                "reporters:\n  fake-off-host:\n"
                + "".join(
                    f"    {key}: {str(value).lower()}\n"
                    for key, value in operator_section.items()
                ),
                encoding="utf-8",
            )

        # On the class, for the reason TestTheReportCommand._report gives.
        monkeypatch.setattr(
            type(merge_module.ash_plugin_manager),
            "plugin_modules",
            lambda self, plugin_type=None, **kwargs: list(reporters),
        )
        monkeypatch.setattr(merge_module, "load_plugins", lambda **kwargs: None)
        # get_logger replaces the ASH logger's handlers, so the command's warnings
        # are read from a logger of its own.
        warnings = []

        class _Recorder(logging.Handler):
            def emit(self, record):
                if record.levelno >= logging.WARNING:
                    warnings.append(record.getMessage())

        recorder_logger = logging.getLogger("test-merge-off-host")
        recorder_logger.handlers = [_Recorder()]
        recorder_logger.propagate = False
        monkeypatch.setattr(
            merge_module, "get_logger", lambda **kwargs: recorder_logger
        )

        try:
            merge_module.merge_command(
                results=shard_paths,
                output_dir=str(tmp_path / "merged"),
                output_formats=None,
                min_severity="low",
                ignore_suppressions=False,
                fail_on_findings=False,
                fail_on_incomplete_scanners=None,
                config=str(config_path) if config_path else None,
                log_level=AshLogLevel.ERROR,
                verbose=False,
                debug=False,
                color=False,
            )
        except typer.Exit as exit_:
            assert exit_.exit_code == 0, exit_.exit_code
        return warnings

    def test_a_shards_enabled_true_does_not_run_it(
        self, tmp_path, monkeypatch, reporters, ran
    ):
        warnings = self._merge(
            tmp_path, monkeypatch, reporters, {"enabled": True}, None
        )

        assert ran == ["fake-local"]
        assert any(
            "fake-off-host" in message and "enabled: true" in message
            for message in warnings
        ), warnings

    def test_the_operators_config_runs_it(self, tmp_path, monkeypatch, reporters, ran):
        warnings = self._merge(
            tmp_path, monkeypatch, reporters, None, {"enabled": True}
        )

        assert sorted(ran) == ["fake-local", "fake-off-host"]
        assert not any("fake-off-host" in message for message in warnings), warnings

    def test_a_shards_enabled_false_does_not_stop_the_operators_reporter(
        self, tmp_path, monkeypatch, reporters, ran
    ):
        warnings = self._merge(
            tmp_path, monkeypatch, reporters, {"enabled": False}, {"enabled": True}
        )

        assert sorted(ran) == ["fake-local", "fake-off-host"]
        assert any(
            "fake-off-host" in message and "enabled: false" in message
            for message in warnings
        ), warnings

    def test_an_operator_config_that_does_not_enable_it_does_not_run_it(
        self, tmp_path, monkeypatch, reporters, ran
    ):
        """Its own default (on, for this fake) does not count either."""
        self._merge(tmp_path, monkeypatch, reporters, None, {"enabled": False})

        assert ran == ["fake-local"]
