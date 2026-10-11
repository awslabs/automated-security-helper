# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Reporters that send findings off the host declare it, and run only when enabled.

A reporter class sets ``sends_off_host = True`` when its report goes to a remote
service (the four AWS reporters). Such a reporter runs only when its section of
the config sets ``enabled: true``; its own default does not count. ``ash report``,
the report phase of a scan and the workspace report step all apply that rule, and
``ash merge`` runs none of them, because its config is the one the shards carried,
not one the operator of the merge supplied.

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
    def _run(self, tmp_path, reporters, config):
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
            cli_output_formats=None,
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
        monkeypatch.setattr(
            report_module.ash_plugin_manager,
            "plugin_modules",
            lambda plugin_type=None, **kwargs: list(reporters),
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
    def test_ash_merge_runs_no_off_host_reporter_even_when_the_shards_enable_it(
        self, tmp_path, monkeypatch, reporters, ran
    ):
        from automated_security_helper.cli import merge as merge_module
        from automated_security_helper.core.enums import AshLogLevel
        from tests.unit.cli.test_merge import build_shards, write_shards

        shards = build_shards(2)
        for shard in shards:
            # The shards' own config turns it on, which is the config ash merge
            # reports with.
            shard.ash_config.reporters = _config({"enabled": True}).reporters
        shard_paths = write_shards(tmp_path / "artifacts", shards)

        monkeypatch.setattr(
            merge_module.ash_plugin_manager,
            "plugin_modules",
            lambda plugin_type=None, **kwargs: list(reporters),
        )
        monkeypatch.setattr(merge_module, "load_plugins", lambda **kwargs: None)

        try:
            merge_module.merge_command(
                results=shard_paths,
                output_dir=str(tmp_path / "merged"),
                output_formats=None,
                min_severity="low",
                ignore_suppressions=False,
                fail_on_findings=False,
                fail_on_incomplete_scanners=None,
                log_level=AshLogLevel.ERROR,
                verbose=False,
                debug=False,
                color=False,
            )
        except typer.Exit as exit_:
            assert exit_.exit_code == 0, exit_.exit_code

        assert ran == ["fake-local"]
