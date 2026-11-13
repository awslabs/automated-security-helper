# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter's dependency check runs only for a reporter the run will use.

Why this exists
---------------
The AWS reporters' ``validate_plugin_dependencies`` contact AWS with whatever
credentials the environment holds: Bedrock and S3 call STS
``GetCallerIdentity``, Security Hub ``DescribeHub``. Bedrock, S3 and CloudWatch
Logs ship enabled, and the plugin registry is process-wide, so once
``ash_aws_plugins`` was imported into a process (a config naming it, an MCP
server that ran such a scan, a test suite) every later run there can check them:

- a ``ReportPhase`` that ran the enabled/dependency filter over every registered
  reporter and applied the requested output formats afterwards would have
  ``-f sarif`` call STS for the Bedrock reporter nobody selected;
- workspace reporting checking the dependencies of every reporter would check the
  per-project ones it never runs at workspace level.

So the requested formats are applied first, and workspace reporting checks a
reporter's dependencies last, only for one that produces an artefact at
workspace level. A reporter that is enabled and selected is checked: the
controls below say so.

How a request is caught
-----------------------
Fake credentials are in the environment, so an unstubbed botocore client signs
its request and sends it. The suite's guard (``tests/conftest.py``,
``_refuse_botocore_requests_off_this_machine``) refuses any request that leaves
this machine, fails the test and records it (``aws_network_violations``). The
tests also record which AWS reporters' checks ran.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import botocore.session
import pytest
from botocore.stub import Stubber

# Imported for its side effect too: the AWS reporters register themselves in the
# process-wide plugin registry, as they do in a process that loaded them.
import automated_security_helper.plugin_modules.ash_aws_plugins  # noqa: F401
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins import (
    bedrock_summary_reporter as bedrock_module,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import load_plugins
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

pytestmark = pytest.mark.unit

AWS_REPORTERS = (
    BedrockSummaryReporter,
    CloudWatchLogsReporter,
    S3Reporter,
    SecurityHubReporter,
)

REGION = "us-east-1"
ACCOUNT = "123456789012"


@pytest.fixture
def fake_credentials(monkeypatch, tmp_path):
    """Credentials botocore will sign with, and nothing else it could read."""
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_SESSION_TOKEN",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-creds"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")  # pragma: allowlist secret
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")  # pragma: allowlist secret
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@pytest.fixture
def aws_checks(monkeypatch) -> List[str]:
    """The AWS reporters whose dependency check ran, in order. Each still runs."""
    ran: List[str] = []
    for reporter_class in AWS_REPORTERS:
        original = reporter_class.validate_plugin_dependencies

        def recording(self, _original=original):
            ran.append(type(self).__name__)
            return _original(self)

        monkeypatch.setattr(reporter_class, "validate_plugin_dependencies", recording)
    return ran


def _context(tmp_path: Path, config: AshConfig) -> PluginContext:
    output_dir = tmp_path / "out"
    return PluginContext(
        source_dir=tmp_path,
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=config,
    )


def _run_report_phase(
    tmp_path: Path, requested: Optional[List[str]], config_overrides: List[str] = ()
) -> List[str]:
    """The real ReportPhase over the real registry; the filenames it wrote."""
    config = AshConfig()
    if config_overrides:
        from automated_security_helper.config.resolve_config import (
            apply_config_overrides,
        )

        config = apply_config_overrides(config, list(config_overrides))
    context = _context(tmp_path, config)
    ash_plugin_manager.set_context(context)
    load_plugins(plugin_context=context)
    reporters = ash_plugin_manager.plugin_modules(plugin_type="reporter")
    assert {cls.__name__ for cls in AWS_REPORTERS} <= {
        cls.__name__ for cls in reporters
    }, "the AWS reporters are not registered, so this test proves nothing"

    reports_dir = context.output_dir / "reports"
    ReportPhase(
        plugins=reporters,
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    ).execute(
        report_dir=reports_dir,
        cli_output_formats=requested,
        aggregated_results=AshAggregatedResults(),
        python_based_plugins_only=False,
    )
    return sorted(p.name for p in reports_dir.iterdir()) if reports_dir.exists() else []


# --------------------------------------------------------------------------- #
# The report phase
# --------------------------------------------------------------------------- #


def test_a_report_phase_checks_no_aws_reporter_it_was_not_asked_for(
    tmp_path, fake_credentials, aws_checks, aws_network_violations
):
    """``-f sarif`` with the AWS plugins loaded: no AWS reporter's check runs,
    even one the operator enabled, and nothing is sent to STS."""
    written = _run_report_phase(
        tmp_path,
        ["sarif"],
        config_overrides=["reporters.bedrock-summary-reporter.enabled=true"],
    )

    assert written == ["ash.sarif"]
    assert aws_checks == []
    assert aws_network_violations == []


@pytest.mark.parametrize(
    "config_class",
    [
        "BedrockSummaryReporterConfig",
        "CloudWatchLogsReporterConfig",
        "S3ReporterConfig",
        "SecurityHubReporterConfig",
    ],
)
def test_the_aws_reporters_ship_disabled(config_class):
    """Each sends findings to AWS with the host's credentials, and its check asks
    AWS whose they are, so only the operator's config turns one on."""
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        bedrock_summary_reporter,
        cloudwatch_logs_reporter,
        s3_reporter,
        security_hub_reporter,
    )

    modules = (
        bedrock_summary_reporter,
        cloudwatch_logs_reporter,
        s3_reporter,
        security_hub_reporter,
    )
    [config] = [getattr(m, config_class) for m in modules if hasattr(m, config_class)]
    assert config().enabled is False


def test_a_report_phase_with_every_format_checks_no_aws_reporter_by_default(
    tmp_path, fake_credentials, aws_checks, aws_network_violations
):
    """No ``-f``: every enabled reporter is used, and with ASH's default config no
    AWS reporter is enabled, so none is checked and nothing is sent to STS."""
    written = _run_report_phase(tmp_path, None)

    assert "ash.sarif" in written
    assert not [name for name in written if "bedrock" in name or "s3" in name]
    assert aws_checks == []
    assert aws_network_violations == []


class _FixedClientSession:
    """Stands in for ``boto3.Session``, handing out prepared clients by name."""

    def __init__(self, clients: Dict[str, Any]):
        self._clients = clients

    def client(self, service_name, **_: Any):
        return self._clients[service_name]


def _stubbed(service_name: str):
    session = botocore.session.Session()
    # Not secrets: the Stubber answers before anything is signed or sent.
    session.set_credentials("testing", "testing")  # pragma: allowlist secret
    client = session.create_client(service_name, region_name=REGION)
    stub = Stubber(client)
    stub.activate()
    return client, stub


def test_a_selected_and_enabled_bedrock_reporter_is_checked(
    tmp_path, fake_credentials, aws_checks, aws_network_violations, monkeypatch
):
    """Control: Bedrock asked for by name and enabled by the operator is checked
    against (stubbed) STS and Bedrock, passes, and runs."""
    model_id = BedrockSummaryReporterConfigOptions().model_id
    sts, sts_stub = _stubbed("sts")
    sts_stub.add_response(
        "get_caller_identity",
        {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/ci", "UserId": "X"},
    )
    bedrock, bedrock_stub = _stubbed("bedrock")
    model = {
        "modelArn": f"arn:aws:bedrock:{REGION}::foundation-model/{model_id}",
        "modelId": model_id,
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": ["ON_DEMAND"],
        "modelLifecycle": {"status": "ACTIVE"},
    }
    bedrock_stub.add_response(
        "list_foundation_models",
        {"modelSummaries": [model]},
        {"byOutputModality": "TEXT"},
    )
    bedrock_stub.add_response(
        "list_inference_profiles", {"inferenceProfileSummaries": []}
    )
    bedrock_stub.add_response("list_foundation_models", {"modelSummaries": [model]})
    monkeypatch.setattr(
        bedrock_module.boto3,
        "Session",
        lambda **_: _FixedClientSession({"sts": sts, "bedrock": bedrock}),
    )
    reported: List[str] = []
    monkeypatch.setattr(
        BedrockSummaryReporter,
        "report",
        lambda self, model: reported.append(type(self).__name__) or "summary",
    )

    written = _run_report_phase(
        tmp_path,
        ["bedrock-summary-reporter"],
        config_overrides=["reporters.bedrock-summary-reporter.enabled=true"],
    )

    assert aws_checks == ["BedrockSummaryReporter"]
    sts_stub.assert_no_pending_responses()
    bedrock_stub.assert_no_pending_responses()
    assert reported == ["BedrockSummaryReporter"]
    assert written == ["ash.bedrock.summary.md"]
    assert aws_network_violations == []


# --------------------------------------------------------------------------- #
# Workspace reporting
# --------------------------------------------------------------------------- #


def _plan(root: Path, *keys: str) -> WorkspacePlan:
    root.mkdir(parents=True, exist_ok=True)
    workspace_file = root / "fixture.code-workspace"
    workspace_file.write_text("{}", encoding="utf-8")
    projects = []
    for key in keys:
        (root / key).mkdir(parents=True, exist_ok=True)
        projects.append(
            ProjectPlan(
                key=key,
                relative_path=key,
                path=(root / key).as_posix(),
                label=key,
                display_label=key,
                severity_threshold="MEDIUM",
            )
        )
    return WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=root.as_posix(),
        projects=projects,
    )


class _Orchestrator:
    """A project scan that finds nothing, so only the workspace step is real."""

    def __init__(self, **_: Any):
        pass

    @classmethod
    def create(cls, **kwargs):
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        return AshAggregatedResults()


@pytest.mark.parametrize(
    "output_formats",
    [("sarif",), ()],
    ids=["sarif-only", "every-format"],
)
def test_a_workspace_run_checks_no_aws_reporter_at_workspace_level(
    tmp_path, fake_credentials, aws_checks, aws_network_violations, output_formats
):
    """The AWS reporters are per-project: workspace reporting never runs them,
    so it never checks them either, whichever formats were asked for."""
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        execute_workspace,
    )

    execute_workspace(
        _plan(tmp_path / "ws", "api", "web"),
        ProjectScanSettings(
            output_dir=tmp_path / "out",
            phases=("scan", "report"),
            output_formats=output_formats,
            max_parallel_projects=2,
        ),
        orchestrator_factory=_Orchestrator.create,
    )

    assert (tmp_path / "out" / "reports").is_dir()
    assert aws_checks == []
    assert aws_network_violations == []


class _RemoteMergedConfig(ReporterPluginConfigBase):
    name: str = "fake-remote-merged"
    extension: str = "remote.txt"
    enabled: bool = True


class _RemoteMergedReporter(ReporterPluginBase[_RemoteMergedConfig]):
    """A workspace-level reporter whose dependency check would contact a service."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED
    checked: List[str] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _RemoteMergedConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        _RemoteMergedReporter.checked.append(self.config.name)
        return True

    def report(self, model) -> str:
        return ""


@pytest.mark.parametrize(
    "output_formats, expected_checks, expected_skip",
    [
        (["fake-remote-merged"], ["fake-remote-merged"], None),
        ([], ["fake-remote-merged"], None),
        (["sarif"], [], "not-in-requested-output-formats"),
    ],
    ids=["asked-for", "every-format", "not-asked-for"],
)
def test_a_workspace_level_reporter_is_checked_only_when_it_will_run(
    tmp_path, output_formats, expected_checks, expected_skip
):
    """Control: a reporter that produces a workspace artefact is still checked
    when it is enabled and selected, and only then."""
    from automated_security_helper.workspace.reporting import _selected_reporters

    _RemoteMergedReporter.checked = []
    [(_, _, skipped)] = list(
        _selected_reporters(
            context=_context(tmp_path, AshConfig()),
            config_lookup=lambda key: None,
            output_formats=output_formats,
            python_based_plugins_only=False,
            reporter_classes=[_RemoteMergedReporter],
        )
    )

    assert _RemoteMergedReporter.checked == expected_checks
    assert skipped == expected_skip


class _RemotePerProjectConfig(ReporterPluginConfigBase):
    name: str = "fake-remote-per-project"
    extension: str = "remote-per-project.txt"
    enabled: bool = True


class _RemotePerProjectReporter(ReporterPluginBase[_RemotePerProjectConfig]):
    """Enabled and per-project, as an AWS reporter the operator turned on is."""

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT
    checked: List[str] = []

    def model_post_init(self, context):
        if self.config is None:
            self.config = _RemotePerProjectConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        _RemotePerProjectReporter.checked.append(self.config.name)
        return True

    def report(self, model) -> str:  # pragma: no cover - never run at workspace level
        raise AssertionError("a per-project reporter ran at workspace level")


@pytest.mark.parametrize(
    "output_formats",
    [["fake-remote-per-project"], []],
    ids=["asked-for", "every-format"],
)
def test_an_enabled_per_project_reporter_is_not_checked_at_workspace_level(
    tmp_path, output_formats
):
    """Enabled and requested, but workspace reporting does not run it: each
    project's own scan checked it, so it is not checked again here."""
    from automated_security_helper.workspace.reporting import _selected_reporters

    _RemotePerProjectReporter.checked = []
    [(_, behaviour, skipped)] = list(
        _selected_reporters(
            context=_context(tmp_path, AshConfig()),
            config_lookup=lambda key: None,
            output_formats=output_formats,
            python_based_plugins_only=False,
            reporter_classes=[_RemotePerProjectReporter],
        )
    )

    assert behaviour is ReporterWorkspaceBehaviour.PER_PROJECT
    assert skipped is None
    assert _RemotePerProjectReporter.checked == []


# --------------------------------------------------------------------------- #
# Reporters outside the run's own plugin modules
# --------------------------------------------------------------------------- #
#
# The registry is process-wide: a module registers its reporters the first time
# anything in the process imports it, an earlier MCP session or an earlier test
# among them. A scan's engine resolves only ASH's built-ins and the modules the
# run names (loader.plugins_of), but workspace reporting, `ash report` and `ash
# merge` read every reporter the process held, and checked and ran any that was
# enabled. Each case below registers a reporter the run does not name, the way
# an earlier test or session does, and runs a step that does not ask for it by
# module.

#: What the off-scope reporter saw, in order.
_OFF_SCOPE_EVENTS: List[str] = []


class _OffScopeConfig(ReporterPluginConfigBase):
    name: str = "fake-off-scope"
    extension: str = "off-scope.txt"
    enabled: bool = True


class _OffScopeReporter(ReporterPluginBase[_OffScopeConfig]):
    """Enabled, workspace-level, and its check asks STS whose credentials these are."""

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        _OFF_SCOPE_EVENTS.append("built")
        if self.config is None:
            self.config = _OffScopeConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        import boto3

        _OFF_SCOPE_EVENTS.append("checked")
        boto3.Session(region_name="us-west-2").client("sts").get_caller_identity()
        return True

    def report(self, model) -> str:
        _OFF_SCOPE_EVENTS.append("ran")
        return "sent somewhere"


@pytest.fixture
def off_scope_reporter(monkeypatch):
    """_OffScopeReporter among the registry's reporters for one test, as another
    run's module would leave it.

    Added where the registry is read (``plugin_modules``) rather than registered,
    because a test does not reach into the manager's registry state
    (test_project_isolation.py's test_nothing_outside_the_manager_touches_the_registry).
    Every caller's ``filter_callback`` still applies to it.
    """
    manager_class = type(ash_plugin_manager)
    resolve = manager_class.plugin_modules

    def with_off_scope(self, plugin_type, filter_callback=lambda x: True, *a, **k):
        found = list(resolve(self, plugin_type))
        if plugin_type == "reporter":
            found.append(_OffScopeReporter)
        return [plugin for plugin in found if filter_callback(plugin, *a, **k)]

    # An earlier test that patched plugin_modules on the manager instance leaves
    # the bound method behind as an instance attribute when its patch is undone,
    # and that would hide this patch of the class.
    assert "plugin_modules" not in vars(ash_plugin_manager), (
        "an earlier test patched plugin_modules on the plugin manager instance; "
        "patch type(ash_plugin_manager) instead"
    )
    _OFF_SCOPE_EVENTS.clear()
    monkeypatch.setattr(manager_class, "plugin_modules", with_off_scope)
    assert _OffScopeReporter in ash_plugin_manager.plugin_modules("reporter")
    yield _OFF_SCOPE_EVENTS


def test_a_workspace_run_leaves_out_a_reporter_registered_by_another_run(
    tmp_path, fake_credentials, off_scope_reporter, aws_network_violations
):
    """Every format, so a reporter it saw would count as asked for."""
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        execute_workspace,
    )

    execute_workspace(
        _plan(tmp_path / "ws", "api", "web"),
        ProjectScanSettings(
            output_dir=tmp_path / "out",
            phases=("scan", "report"),
            max_parallel_projects=2,
        ),
        orchestrator_factory=_Orchestrator.create,
    )

    assert off_scope_reporter == []
    assert not (tmp_path / "out" / "reports" / "ash.off-scope.txt").exists()
    manifest = (tmp_path / "out" / "reports").glob("*.json")
    assert not any("fake-off-scope" in p.read_text(encoding="utf-8") for p in manifest)
    assert aws_network_violations == []


def _shards_enabling(tmp_path: Path, overrides: List[str]) -> List[str]:
    from automated_security_helper.config.resolve_config import apply_config_overrides
    from tests.unit.cli.test_merge import build_shards, write_shards

    shards = build_shards(2)
    for shard in shards:
        shard.ash_config = apply_config_overrides(shard.ash_config, overrides)
    return write_shards(tmp_path / "artifacts", shards)


def _merge(tmp_path: Path, shard_paths: List[str], *extra: str):
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    args = ["merge"]
    for path in shard_paths:
        args += ["--results", path]
    args += ["--output-dir", str(tmp_path / "merged"), *extra]
    return CliRunner().invoke(app, args)


def test_ash_merge_leaves_out_a_reporter_registered_by_another_run(
    tmp_path, fake_credentials, off_scope_reporter, aws_network_violations
):
    result = _merge(tmp_path, _shards_enabling(tmp_path, []))

    assert (tmp_path / "merged" / "reports" / "ash.sarif").is_file(), result.output
    assert off_scope_reporter == []
    assert aws_network_violations == []


@pytest.mark.parametrize("formats", [["--output-formats", "sarif"], []])
def test_ash_merge_checks_no_aws_reporter_its_shards_did_not_load(
    tmp_path, fake_credentials, aws_checks, aws_network_violations, formats
):
    """The shards' config enables Bedrock but names no plugin module, and this
    process imported ash_aws_plugins anyway: Bedrock is not this run's."""
    result = _merge(
        tmp_path,
        _shards_enabling(tmp_path, ["reporters.bedrock-summary-reporter.enabled=true"]),
        *formats,
    )

    assert (tmp_path / "merged" / "reports" / "ash.sarif").is_file(), result.output
    assert aws_checks == []
    assert aws_network_violations == []


def _report(tmp_path: Path, report_format: str, *extra: str):
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    output_dir = tmp_path / "out"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ash_aggregated_results.json").write_text(
        AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
    )
    return CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            report_format,
            "--output-dir",
            str(output_dir),
            "--log-level",
            "ERROR",
            "--no-color",
            *extra,
        ],
    )


@pytest.fixture
def aws_reporters_built(monkeypatch) -> List[str]:
    """The AWS reporters constructed, in order. Each is still constructed."""
    built: List[str] = []
    for reporter_class in AWS_REPORTERS:
        original = reporter_class.model_post_init

        def recording(self, context, _original=original):
            built.append(type(self).__name__)
            return _original(self, context)

        monkeypatch.setattr(reporter_class, "model_post_init", recording)
    return built


def test_ash_report_builds_no_reporter_from_a_module_its_config_does_not_load(
    tmp_path,
    fake_credentials,
    off_scope_reporter,
    aws_reporters_built,
    aws_checks,
    aws_network_violations,
):
    """`--format sarif`, with ash_aws_plugins and another run's reporter in the
    process and a config that names neither: neither is built or checked."""
    result = _report(
        tmp_path,
        "sarif",
        "--config-overrides",
        "reporters.bedrock-summary-reporter.enabled=true",
    )

    assert result.exit_code == 0, result.output
    assert off_scope_reporter == []
    assert aws_reporters_built == []
    assert aws_checks == []
    assert aws_network_violations == []


def test_ash_report_does_not_find_a_reporter_its_config_does_not_load(
    tmp_path, fake_credentials, off_scope_reporter, aws_network_violations
):
    """Asked for by name, another run's reporter is not one this run has."""
    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    result = _report(tmp_path, "fake-off-scope")

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert "not found" in result.output
    assert "ran" not in off_scope_reporter
    assert aws_network_violations == []


def test_a_report_phase_built_without_reporters_runs_none(
    tmp_path, fake_credentials, off_scope_reporter, aws_network_violations
):
    """No reporter list means no reporters: nothing is built or written.

    Every caller that runs reporters hands the phase its run's list (the scan's
    engine and ash merge); a phase built without one takes nothing from the
    process-wide registry, another run's reporter included.
    """
    context = _context(tmp_path, AshConfig())
    ash_plugin_manager.set_context(context)
    load_plugins(plugin_context=context)
    reports_dir = context.output_dir / "reports"

    ReportPhase(
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=AshAggregatedResults(),
    ).execute(
        report_dir=reports_dir,
        cli_output_formats=None,
        aggregated_results=AshAggregatedResults(),
        python_based_plugins_only=False,
    )

    written = (
        sorted(p.name for p in reports_dir.iterdir()) if reports_dir.exists() else []
    )
    assert written == []
    assert off_scope_reporter == []
    assert aws_network_violations == []


def test_a_report_phase_takes_every_argument_engine_phase_takes():
    """ReportPhase names EnginePhase's parameters itself, so a call is checked
    against them; one EnginePhase gains has to be added here too."""
    import inspect

    from automated_security_helper.base.engine_phase import EnginePhase

    def names(function) -> List[str]:
        return [
            name
            for name, parameter in inspect.signature(function).parameters.items()
            if parameter.kind
            not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        ]

    assert names(ReportPhase.__init__) == names(EnginePhase.__init__)


def test_a_report_phase_hands_every_argument_to_engine_phase(tmp_path, monkeypatch):
    """Each argument reaches EnginePhase as given, the reporter list included."""
    from automated_security_helper.base.engine_phase import EnginePhase

    received: Dict[str, Any] = {}

    def recording_init(self, **kwargs):
        received.update(kwargs)
        self.plugin_context = kwargs["plugin_context"]
        self.plugins = kwargs["plugins"] or []

    monkeypatch.setattr(EnginePhase, "__init__", recording_init)
    context = _context(tmp_path, AshConfig())
    reporters = [object]
    display = object()
    model = AshAggregatedResults()

    def handlers(_plugin) -> bool:
        return True

    ReportPhase(
        plugin_context=context,
        plugins=reporters,
        progress_display=display,
        asharp_model=model,
        plugin_filter=handlers,
    )

    assert received == {
        "plugin_context": context,
        "plugins": reporters,
        "progress_display": display,
        "asharp_model": model,
        "plugin_filter": handlers,
    }
    assert received["plugins"] is reporters


def _handlers_a_notification_calls(phase, monkeypatch) -> List[str]:
    """Which of two handlers a notification from *phase* calls.

    Both are subscribed to an event of this test's own: ``kept``, which
    ``_only_kept`` lets through, and ``other``. The check is on the handlers
    called, not on the argument the phase hands the plugin manager the filter
    in, so it holds whatever that argument is named.

    They are subscribed, through the manager's own API, to a manager of this
    test's own, which the phase notifies in place of the process-wide one; the
    process-wide registry is not touched.
    """
    from automated_security_helper.base import engine_phase
    from automated_security_helper.plugins.plugin_manager import AshPluginManager

    called: List[str] = []

    def kept(**_event_data: Any) -> None:
        called.append("kept")

    def other(**_event_data: Any) -> None:
        called.append("other")

    event = "a notification only this test's handlers are subscribed to"
    manager = AshPluginManager()
    manager.subscribe(event, kept)
    manager.subscribe(event, other)
    monkeypatch.setattr(engine_phase, "ash_plugin_manager", manager)
    phase.notify_event(event)
    return called


def _only_kept(handler: Any) -> bool:
    return getattr(handler, "__name__", None) == "kept"


def test_a_phase_given_no_filter_notifies_every_handler(tmp_path, monkeypatch):
    """The control: with no filter, a notification calls both handlers."""
    phase = ReportPhase(plugin_context=_context(tmp_path, AshConfig()), plugins=[])

    assert _handlers_a_notification_calls(phase, monkeypatch) == ["kept", "other"]


def test_a_report_phase_takes_the_plugin_filter_an_engine_passes(tmp_path, monkeypatch):
    """An engine can hand each phase, when it builds it, the filter for the
    event handlers its notifications reach (plugin_filter=). The report phase
    takes it, and its notifications call only the handlers it lets through."""
    phase = ReportPhase(
        plugin_context=_context(tmp_path, AshConfig()),
        plugins=[],
        plugin_filter=_only_kept,
    )

    assert _handlers_a_notification_calls(phase, monkeypatch) == ["kept"]


def test_a_scan_phase_takes_the_plugin_filter_an_engine_passes(tmp_path, monkeypatch):
    """The scan phase names its constructor's arguments too, and its
    notifications call only the handlers the filter lets through, as the report
    phase's do."""
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    phase = ScanPhase(
        plugin_context=_context(tmp_path, AshConfig()),
        plugins=[],
        plugin_filter=_only_kept,
    )

    assert _handlers_a_notification_calls(phase, monkeypatch) == ["kept"]
