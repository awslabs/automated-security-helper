# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every plugin that sends data off the host is the operator's to configure, not a client's.

A plugin that sends the repository's content, its findings or its dependency list off
the host does so with the operator's credentials, network and trust. An MCP client's
runtime overrides must not configure, enable or disable one, or change what it sends or
where, whatever a profile's ``denied_paths`` says. So each such plugin's whole section
is in ``ALWAYS_DENIED_PATHS`` (``**`` also matches the section itself). A workspace
scan's ``scanners`` and ``excluded_scanners`` arguments, which are not overrides, can
still leave a scanner out of a run, never add one.

A client's ``enabled: false`` of an off-host reporter is the one write these allow: it
asks for nothing beyond the profile, so it is accepted, it takes no effect, and a
warning says it was ignored. The reporter runs as the operator's profile has it, which
the scans at the end of this file show from the requests the reporter makes.

This file classifies every scanner, reporter and converter the plugin packages ship.
A new plugin, or a plugin that starts to declare a network, fails here until it is
classified: off the host (and denied), or local, with what it does instead.
"""

from __future__ import annotations

import asyncio
import copy
import importlib
import json
import logging
import pkgutil
import socket
import subprocess
import traceback
import typing
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import boto3
import botocore.client
import pytest
import yaml
from pydantic import BaseModel

import automated_security_helper.plugin_modules as plugin_packages
from automated_security_helper.config.ash_config import (
    ALWAYS_DENIED_PATHS,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    check_runtime_ops,
)
from tests.utils.secret_bearing_scan import (
    isolate_from_aws,
    load_results,
    write_fixture_tree,
)

Plugin = Tuple[str, str]  # (config section, plugin name)

#: What each plugin sends off the host, and where in its code.
OFF_HOST: Dict[Plugin, str] = {
    ("scanners", "snyk-code"): (
        "the source, uploaded for analysis by `snyk code test` "
        "(snyk_code_scanner.py:76)"
    ),
    ("scanners", "npm-audit"): (
        "each package's dependency list, to the registry's advisory service, by "
        "`npm/pnpm/yarn audit` (npm_audit_scanner.py:1309, :1338)"
    ),
    ("scanners", "semgrep"): (
        "usage metrics about the run, to the Semgrep server: `--metrics auto` online "
        "by default and `on` when the option says so (_grep_scanner_base.py:79, "
        ":270; semgrep_scanner.py:60)"
    ),
    ("scanners", "opengrep"): (
        "the same usage metrics, with an opengrep older than 1.7.0, set by its "
        "`metrics` option (opengrep_scanner.py:69, :277)"
    ),
    ("scanners", "trivy-repo"): (
        "usage data to Aqua when `disable_telemetry` is false "
        "(_trivy_scanner_base.py, `--disable-telemetry`). Online it also fetches "
        "its databases and checks bundle (`_shared_update_flags`); every scan gets "
        "`--offline-scan` (SCAN_FLAGS), so it makes no dependency lookups"
    ),
    ("scanners", "trivy"): (
        "the same, through the same base (_trivy_scanner_base.py): usage data to "
        "Aqua when `disable_telemetry` is false, and online it fetches its "
        "vulnerability and Java databases"
    ),
    ("scanners", "zizmor"): (
        "the workflows' action and repository references, with the GitHub token in "
        "ASH's environment, to the GitHub API, when `online_audits` is set "
        "(zizmor_scanner.py `_online`)"
    ),
    ("scanners", "detect-secrets"): (
        "each candidate secret, to the service that issued it, when the "
        "verification filter is configured (detect_secrets_scanner.py:245-268)"
    ),
    ("reporters", "s3"): "the results, to an S3 bucket (s3_reporter.py:230, :305)",
    ("reporters", "aws-security-hub"): (
        "requests to Security Hub and STS with the operator's credentials "
        "(security_hub_reporter.py:122-128)"
    ),
    ("reporters", "cloudwatch-logs"): (
        "the results, to a CloudWatch Logs group (cloudwatch_logs_reporter.py:209, "
        ":284)"
    ),
    ("reporters", "bedrock-summary-reporter"): (
        "findings, to a Bedrock model for a summary "
        "(bedrock_summary_reporter.py:1254; bedrock_pipeline.py:137)"
    ),
}

#: Plugins that send nothing off the host, and what network they use, if any.
LOCAL: Dict[Plugin, str] = {
    ("scanners", "bandit"): "reads the files",
    ("scanners", "cdk-nag"): "evaluates the templates in a local child",
    ("scanners", "cfn-nag"): "reads the templates",
    ("scanners", "checkov"): (
        "fetches its policies online (checkov_scanner.py:224); sends nothing "
        "about the repository"
    ),
    ("scanners", "grype"): (
        "fetches its vulnerability database online (grype_scanner.py:102, :149); "
        "matches locally"
    ),
    ("scanners", "syft"): (
        "checks for updates online (syft_scanner.py:71); catalogs locally"
    ),
    ("scanners", "ferret-scan"): "reads the files (ferret_scanner.py:412, :548)",
    ("scanners", "actionlint"): (
        "reads the workflow files; runs shellcheck and pyflakes on this host"
    ),
    ("scanners", "cfn-lint"): "reads the templates",
    ("scanners", "cfn-guard"): "reads the templates and its installed rules bundle",
    ("scanners", "gitleaks"): "reads the files",
    ("reporters", "csv"): "writes a file",
    ("reporters", "cyclonedx"): "writes a file",
    ("reporters", "flat-json"): "writes a file",
    ("reporters", "github-ghas"): "writes a file; a pipeline step may upload it",
    ("reporters", "gitlab-cyclonedx"): "writes a file",
    ("reporters", "gitlab-sast"): "writes a file",
    ("reporters", "html"): "writes a file",
    ("reporters", "junitxml"): "writes a file",
    ("reporters", "markdown"): "writes a file",
    ("reporters", "ocsf"): "writes a file",
    ("reporters", "sarif"): "writes a file",
    ("reporters", "spdx"): "writes a file",
    ("reporters", "text"): "writes a file",
    ("reporters", "unused-suppressions"): "writes a file",
    ("reporters", "yaml"): "writes a file",
    ("converters", "archive"): "extracts archives in the work directory",
    ("converters", "jupyter"): (
        "converts notebooks with nbconvert, which it installs from the package "
        "index when missing"
    ),
}

#: Local plugins that still declare a network, for what they fetch (see LOCAL).
FETCH_ONLY = {("scanners", "grype")}

_KINDS = {
    "ASH_SCANNERS": "scanners",
    "ASH_REPORTERS": "reporters",
    "ASH_CONVERTERS": "converters",
}


def _config_name(plugin_class) -> str:
    annotation = plugin_class.model_fields["config"].annotation
    for candidate in (annotation, *typing.get_args(annotation)):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate().name
    raise AssertionError(f"{plugin_class.__name__} has no config model")


def _shipped_plugins() -> Dict[Plugin, type]:
    """Every plugin each package under plugin_modules declares."""
    found: Dict[Plugin, type] = {}
    for package in pkgutil.iter_modules(plugin_packages.__path__):
        if not package.ispkg:
            continue
        module = importlib.import_module(f"{plugin_packages.__name__}.{package.name}")
        for attribute, section in _KINDS.items():
            for plugin_class in getattr(module, attribute, None) or []:
                found[(section, _config_name(plugin_class))] = plugin_class
    return found


def test_the_inventory_finds_the_plugin_packages():
    """Control: the walk reaches every package, built-in and add-on."""
    names = {name for _, name in _shipped_plugins()}
    assert {"bandit", "snyk-code", "trivy-repo", "ferret-scan", "s3"} <= names


def test_every_shipped_plugin_is_classified():
    shipped = set(_shipped_plugins())
    assert not set(OFF_HOST) & set(LOCAL)
    unclassified = sorted(shipped - set(OFF_HOST) - set(LOCAL))
    assert unclassified == [], (
        f"classify each as OFF_HOST (and deny it) or LOCAL: {unclassified}"
    )
    assert sorted(set(OFF_HOST) | set(LOCAL)) == sorted(shipped), "stale entries"


def test_a_local_plugin_that_declares_a_network_says_what_it_fetches():
    for plugin, plugin_class in _shipped_plugins().items():
        requirements = getattr(plugin_class, "sandbox_requirements", None)
        if plugin in LOCAL and getattr(requirements, "network", False) is True:
            assert plugin in FETCH_ONLY, plugin


def test_every_off_host_plugin_is_always_denied():
    missing = [
        f"/{section}/{name}/**"
        for section, name in sorted(OFF_HOST)
        if f"/{section}/{name}/**" not in ALWAYS_DENIED_PATHS
    ]
    assert missing == [], missing


@pytest.mark.parametrize("plugin", sorted(OFF_HOST), ids=lambda p: "/".join(p))
def test_no_profile_lets_a_client_configure_an_off_host_plugin(plugin):
    """Its section, its options and ``enabled: true`` are refused under any profile.

    A scanner's ``enabled: false`` is refused too. A reporter's is accepted and
    takes no effect (runtime_patch._turns_an_off_host_reporter_off); the scans
    below hold both halves of that.
    """
    section, name = plugin
    policy = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/**"], denied_paths=[]
    )
    writes: List[Tuple[str, Any]] = [
        (f"/{section}/{name}", {"enabled": True, "options": {}}),
        (f"/{section}/{name}/enabled", True),
        (f"/{section}/{name}/options/anything", "else"),
    ]
    if section == "scanners":
        writes.append((f"/{section}/{name}/enabled", False))

    for path, value in writes:
        ops = [{"op": "add", "path": path, "value": value}]
        with pytest.raises(RuntimePatchDeniedError):
            check_runtime_ops(ops, allowlist=policy, config=None)


def test_control_a_local_plugin_stays_tunable():
    policy = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/**"], denied_paths=[]
    )

    ops: List[dict] = [
        {
            "op": "replace",
            "path": "/scanners/bandit/options/severity_threshold",
            "value": "HIGH",
        }
    ]
    check_runtime_ops(ops, allowlist=policy, config=None)


# ---------------------------------------------------------------------------
# A client's enabled of an off-host reporter, through a scan
# ---------------------------------------------------------------------------

OFF_HOST_REPORTERS = sorted(
    name for section, name in OFF_HOST if section == "reporters"
)

_AWS_PLUGINS = "automated_security_helper.plugin_modules.ash_aws_plugins"

#: The operator's region. Neither a default nor the environment here gives it, so a
#: request made in it was given it by the operator's section.
_REGION = "ap-southeast-2"

#: The options of each off-host reporter in the operator's section: every option it
#: needs to run, so that only ``enabled`` decides whether it does.
_OPERATOR_OPTIONS: Dict[str, Dict[str, Any]] = {
    "aws-security-hub": {"aws_region": _REGION, "account_id": "123456789012"},
    "bedrock-summary-reporter": {
        "aws_region": _REGION,
        "model_id": "stand-in-model",
        "max_retries": 0,
    },
    "cloudwatch-logs": {
        "aws_region": _REGION,
        "log_group_name": "ash-findings",
        "max_retries": 0,
    },
    "s3": {"aws_region": _REGION, "bucket_name": "ash-findings", "max_retries": 0},
}

#: The request each reporter makes when it runs, and the parameters of it that the
#: operator's options set: the one that sends the results, and for Security Hub,
#: whose report sends nothing yet, the DescribeHub its dependency check makes with
#: the operator's credentials.
_RUN_REQUESTS: Dict[str, Tuple[str, str, Dict[str, Any]]] = {
    "aws-security-hub": ("securityhub", "DescribeHub", {}),
    "bedrock-summary-reporter": (
        "bedrock-runtime",
        "Converse",
        {"modelId": "stand-in-model"},
    ),
    "cloudwatch-logs": ("logs", "PutLogEvents", {"logGroupName": "ash-findings"}),
    "s3": ("s3", "PutObject", {"Bucket": "ash-findings"}),
}

#: What the stand-in for AWS answers to the requests whose answer a reporter reads
#: before it sends. Every other request gets an empty answer.
_ANSWERS: Dict[str, Dict[str, Any]] = {
    "GetCallerIdentity": {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/operator",
        "UserId": "AIDASTANDIN",
    },
    "ListInferenceProfiles": {"inferenceProfileSummaries": []},
    "ListFoundationModels": {
        "modelSummaries": [
            {
                "modelId": "stand-in-model",
                "modelArn": f"arn:aws:bedrock:{_REGION}::foundation-model/stand-in-model",
                "modelName": "stand-in",
                "providerName": "stand-in",
                "modelLifecycle": {"status": "ACTIVE"},
                "inputModalities": ["TEXT"],
                "outputModalities": ["TEXT"],
                "inferenceTypesSupported": ["ON_DEMAND"],
            }
        ]
    },
    "Converse": {
        "output": {"message": {"role": "assistant", "content": [{"text": "summary"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
    },
}

#: How a client's change reaches a scan: ``select_profile``'s ``patch_ops``, writing
#: ``enabled`` (``patch_ops``) or adding a section that holds only it where the
#: profile has none (``patch_ops-section``), or its ``override_yaml``, each followed
#: by ``scan_directory`` under the session's config; or a workspace scan's
#: ``config_overrides``.
_CHANGES = ["patch_ops", "patch_ops-section", "override_yaml", "config_overrides"]

#: A section holding only ``enabled``, written over the operator's section, would
#: drop that section's other settings, so it is refused
#: (tests/unit/cli/mcp/test_select_profile_override_gate.py).
_CHANGES_OVER_A_SECTION = [c for c in _CHANGES if c != "patch_ops-section"]

_SESSION = "client"


@pytest.fixture
def aws_requests(monkeypatch, tmp_path) -> List[Dict[str, Any]]:
    """Each request botocore makes: its service, operation, region and parameters.

    Answered by a stand-in, so nothing reaches AWS, and behind the stand-in there
    are no credentials and the endpoint is a loopback port. boto3's default
    session, which ``boto3.client`` creates and keeps, starts each test unset.
    """
    isolate_from_aws(monkeypatch, tmp_path)
    monkeypatch.setattr(boto3, "DEFAULT_SESSION", None)
    made: List[Dict[str, Any]] = []

    def stand_in(client, operation_name, api_params):
        made.append(
            {
                "service": client.meta.service_model.service_name,
                "operation": operation_name,
                "region": client.meta.region_name,
                "params": dict(api_params),
            }
        )
        return copy.deepcopy(_ANSWERS.get(operation_name, {}))

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", stand_in)
    return made


@pytest.fixture
def other_traffic(monkeypatch) -> List[Tuple[str, Any]]:
    """Each connection a socket opens, refused, and each child process the off-host
    reporters' code starts.

    So that "no request" does not rest on every reporter sending through botocore.
    A scan starts child processes of its own (tool version checks, the scanners),
    so a child process is recorded when a frame of the reporters' package is on
    the stack that starts it.
    """
    reporters_dir = str(Path(importlib.import_module(_AWS_PLUGINS).__file__).parent)
    made: List[Tuple[str, Any]] = []

    def refused_connect(self, address, *args, **kwargs):
        made.append(("connect", address))
        raise ConnectionRefusedError(f"connection to {address!r} refused by the test")

    def refused_create_connection(address, *args, **kwargs):
        made.append(("create_connection", address))
        raise ConnectionRefusedError(f"connection to {address!r} refused by the test")

    real_init = subprocess.Popen.__init__

    def recorded_init(self, args, *rest, **kwargs):
        if any(
            frame.filename.startswith(reporters_dir)
            for frame in traceback.extract_stack()
        ):
            made.append(("popen", args))
        real_init(self, args, *rest, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", refused_connect)
    monkeypatch.setattr(socket, "create_connection", refused_create_connection)
    monkeypatch.setattr(subprocess.Popen, "__init__", recorded_init)
    return made


@pytest.fixture
def ash_warnings() -> Iterator[List[str]]:
    """The message of each WARNING or higher record logged to ASH's logger.

    Recorded by a filter on the logger, which a scan's logging setup keeps: it
    replaces the logger's handlers, not its filters.
    """
    messages: List[str] = []

    class _Recorder(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            if record.levelno >= logging.WARNING:
                messages.append(record.getMessage())
            return True

    logger = logging.getLogger("ash")
    recorder = _Recorder()
    logger.addFilter(recorder)
    yield messages
    logger.removeFilter(recorder)


@pytest.fixture
def mcp_server(tmp_path, monkeypatch):
    """The profile registry and sessions of one MCP server, under ``tmp_path``."""
    from automated_security_helper.cli.mcp import sessions
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
        clear_all_session_state,
    )

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    clear_profile_registry()
    clear_all_session_state()
    sessions.reset_default_registry_for_tests()
    yield
    clear_profile_registry()
    clear_all_session_state()
    sessions.reset_default_registry_for_tests()


#: A profile's runtime overrides that let a client change every reporters section
#: and deny nothing of its own.
_REPORTERS_ALLOWED = {
    "enabled": True,
    "allowed_paths": ["/reporters/**"],
    "denied_paths": [],
}


def _register_profile(
    tmp_path: Path,
    reporter: str,
    section: str,
    runtime_overrides: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Register an operator profile that allows client overrides.

    At every path, unless ``runtime_overrides`` says otherwise. ``section`` is what
    it holds for ``reporter``: every option the reporter needs and ``enabled:
    true`` (``"enabled"``), the options alone (``"options"``), or nothing
    (``"none"``). Returns the profile's document.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        set_profile_registry,
    )

    document: Dict[str, Any] = {
        "project_name": "operator",
        "ash_plugin_modules": [_AWS_PLUGINS],
        "global_settings": {
            "mcp": {
                "runtime_overrides": runtime_overrides
                or {"enabled": True, "allowed_paths": ["/**"]}
            }
        },
    }
    if section != "none":
        written: Dict[str, Any] = {"options": dict(_OPERATOR_OPTIONS[reporter])}
        if section == "enabled":
            written["enabled"] = True
        document["reporters"] = {reporter: written}
    path = tmp_path / "profile.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"operator={path}"]))
    return document


def _scan_directory(directory: Path) -> None:
    """Scan ``directory`` with ``scan_directory`` under the session's config, and wait.

    The scan runs as the tool runs it, but ``run_ash_scan`` is handed detect-secrets
    as the only scanner, with no network for it. The scan has to finish with
    results.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        resolve_session_config_path,
    )
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory
    from automated_security_helper.core.resource_management.scan_registry import (
        FINISHED_WITH_RESULTS,
        get_scan_registry,
    )
    from automated_security_helper.interactions import run_ash_scan as scan_module

    real_run_ash_scan = scan_module.run_ash_scan

    def detect_secrets_only(**kwargs: Any) -> Any:
        return real_run_ash_scan(
            **{**kwargs, "scanners": ["detect-secrets"], "offline": True}
        )

    async def scan() -> Dict[str, Any]:
        started = await mcp_scan_directory(
            str(directory),
            config_path=resolve_session_config_path(_SESSION),
            session_id=_SESSION,
        )
        running = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        await asyncio.gather(*running)
        return started

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(scan_module, "run_ash_scan", detect_secrets_only)
        started = asyncio.run(scan())
    assert started["success"] is True, started
    entry = get_scan_registry().get_scan(started["scan_id"])
    assert entry is not None
    assert entry.status in FINISHED_WITH_RESULTS, (entry.status, entry.error_message)


def _scan_with_client_enabled(
    tmp_path: Path,
    change: str,
    reporter: str,
    enabled: bool,
    profile: Dict[str, Any],
) -> Tuple[Dict[str, Any], Path]:
    """Send ``enabled`` for ``reporter`` as ``change`` says, then scan a tree with findings.

    Returns the answer of the tool that took the change (``select_profile``'s, or
    the workspace scan's) and the directory the scan writes its results to. Nothing
    is scanned after ``select_profile`` refuses the change.
    """
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    project = tmp_path / "ws" / "app"
    write_fixture_tree(project)
    if change == "config_overrides":
        bound = mcp_select_profile("operator", session_id=_SESSION)
        assert bound["success"] is True, bound
        workspace = project.parent / "dev.code-workspace"
        workspace.write_text(
            json.dumps({"folders": [{"path": "app"}]}), encoding="utf-8"
        )
        output = tmp_path / "out"
        result = asyncio.run(
            mcp_scan_workspace(
                str(workspace),
                config_overrides=[
                    f"reporters.{reporter}.enabled={str(enabled).lower()}"
                ],
                output_dir=str(output),
                scanners=["detect-secrets"],
                offline=True,
                session_id=_SESSION,
            )
        )
        return result, output
    if change == "override_yaml":
        restated = copy.deepcopy(profile)
        restated.setdefault("reporters", {}).setdefault(reporter, {})["enabled"] = (
            enabled
        )
        result = mcp_select_profile(
            "operator", override_yaml=yaml.safe_dump(restated), session_id=_SESSION
        )
    else:
        op: Dict[str, Any] = (
            {
                "op": "add",
                "path": f"/reporters/{reporter}",
                "value": {"enabled": enabled},
            }
            if change == "patch_ops-section"
            else {
                "op": "add",
                "path": f"/reporters/{reporter}/enabled",
                "value": enabled,
            }
        )
        result = mcp_select_profile("operator", patch_ops=[op], session_id=_SESSION)
    if result["success"] is True:
        _scan_directory(project)
    return result, project / ".ash" / "ash_output"


@pytest.mark.parametrize("change", _CHANGES_OVER_A_SECTION)
@pytest.mark.parametrize("reporter", OFF_HOST_REPORTERS)
@pytest.mark.usefixtures("mcp_server")
def test_a_client_s_enabled_false_leaves_the_operator_s_reporter_running(
    tmp_path, aws_requests, other_traffic, ash_warnings, reporter, change
):
    """The operator's profile enables the reporter. The client's ``false`` is
    accepted, the reporter still runs with the operator's settings, and a warning
    says the client's value was ignored."""
    profile = _register_profile(tmp_path, reporter, "enabled")

    result, _ = _scan_with_client_enabled(tmp_path, change, reporter, False, profile)

    assert result["success"] is True, result
    service, operation, params = _RUN_REQUESTS[reporter]
    sent = [
        request
        for request in aws_requests
        if (request["service"], request["operation"]) == (service, operation)
    ]
    assert sent, aws_requests
    for request in sent:
        assert params.items() <= request["params"].items(), request
    assert {request["region"] for request in aws_requests} == {_REGION}, aws_requests
    assert other_traffic == []
    ignored = [
        message
        for message in ash_warnings
        if message.startswith(f"Ignoring reporters.{reporter}.enabled from ")
    ]
    assert ignored, ash_warnings
    for message in ignored:
        assert message.endswith(KEEP_A_SETTING), message
        if change == "config_overrides":
            assert "config_overrides" in message, message


@pytest.mark.parametrize("change", _CHANGES)
@pytest.mark.parametrize("reporter", OFF_HOST_REPORTERS)
@pytest.mark.usefixtures("mcp_server")
def test_a_client_s_enabled_false_runs_nothing_the_operator_did_not_enable(
    tmp_path, aws_requests, other_traffic, reporter, change
):
    """The operator's section sets every option but not ``enabled``, or there is
    no section, so the reporter is off. The client's ``false`` is accepted, the
    scan finds results a reporter would send, and nothing leaves the host."""
    section = "none" if change == "patch_ops-section" else "options"
    profile = _register_profile(tmp_path, reporter, section)

    result, output = _scan_with_client_enabled(
        tmp_path, change, reporter, False, profile
    )

    assert result["success"] is True, result
    assert load_results(output).sarif.get_all_results()
    assert aws_requests == []
    assert other_traffic == []


@pytest.mark.parametrize("change", _CHANGES)
@pytest.mark.parametrize("reporter", OFF_HOST_REPORTERS)
@pytest.mark.usefixtures("mcp_server")
def test_a_client_s_enabled_true_is_refused(
    tmp_path, aws_requests, other_traffic, reporter, change
):
    """The negative: a client cannot turn on a reporter the operator left off.

    Refused under a denied entry of the reporter's own section: its whole section,
    or, for a whole section written, the first of its entries the list holds.
    """
    section = "none" if change == "patch_ops-section" else "options"
    profile = _register_profile(tmp_path, reporter, section)

    result, output = _scan_with_client_enabled(
        tmp_path, change, reporter, True, profile
    )

    assert result["success"] is False, result
    assert f"denied_paths entry '/reporters/{reporter}/" in str(result.get("error")), (
        result
    )
    assert not (output / "ash_aggregated_results.json").exists()
    assert aws_requests == []
    assert other_traffic == []


# ---------------------------------------------------------------------------
# A client's settings for an off-host reporter, under /reporters/**
# ---------------------------------------------------------------------------

#: The three routes a client's runtime override takes: ``select_profile``'s
#: ``patch_ops`` or ``override_yaml``, each followed by ``scan_directory``, and a
#: workspace scan's ``config_overrides``.
_ROUTES = ["patch_ops", "override_yaml", "config_overrides"]

#: A reporters section no reporter shipped with ASH reads: a reporter a plugin
#: module brings, which may send findings anywhere its options say.
_PLUGIN_REPORTER = "hook-reporter"


def _client_change_then_scan(
    tmp_path: Path,
    route: str,
    profile: Dict[str, Any],
    patch_op: Dict[str, Any],
    sections: Dict[str, Any],
    config_overrides: List[str],
) -> Tuple[Dict[str, Any], Path]:
    """Send one client change by ``route``, then scan a tree with findings.

    ``patch_op`` is the change as ``patch_ops`` sends it, ``sections`` as the
    reporters sections ``override_yaml`` restates over the profile's, and
    ``config_overrides`` as a workspace scan sends it. Returns the answer of the
    tool that took the change and the directory the scan writes its results to.
    Nothing is scanned after ``select_profile`` refuses the change.
    """
    from automated_security_helper.cli.mcp.workspace import mcp_scan_workspace
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    project = tmp_path / "ws" / "app"
    write_fixture_tree(project)
    if route == "config_overrides":
        bound = mcp_select_profile("operator", session_id=_SESSION)
        assert bound["success"] is True, bound
        workspace = project.parent / "dev.code-workspace"
        workspace.write_text(
            json.dumps({"folders": [{"path": "app"}]}), encoding="utf-8"
        )
        output = tmp_path / "out"
        result = asyncio.run(
            mcp_scan_workspace(
                str(workspace),
                config_overrides=config_overrides,
                output_dir=str(output),
                scanners=["detect-secrets"],
                offline=True,
                session_id=_SESSION,
            )
        )
        return result, output
    if route == "override_yaml":
        restated = copy.deepcopy(profile)
        restated.setdefault("reporters", {}).update(copy.deepcopy(sections))
        result = mcp_select_profile(
            "operator", override_yaml=yaml.safe_dump(restated), session_id=_SESSION
        )
    else:
        result = mcp_select_profile(
            "operator", patch_ops=[patch_op], session_id=_SESSION
        )
    if result["success"] is True:
        _scan_directory(project)
    return result, project / ".ash" / "ash_output"


#: A destination of the client's own for a reporter the operator enables: the
#: reporter, the option, and the client's value.
_CLIENT_DESTINATIONS = [
    ("s3", "bucket_name", "clients-bucket"),
    ("s3", "aws_region", "eu-west-1"),
    ("cloudwatch-logs", "log_group_name", "clients-group"),
]


@pytest.mark.parametrize("route", _ROUTES)
@pytest.mark.parametrize("reporter, option, value", _CLIENT_DESTINATIONS)
@pytest.mark.usefixtures("mcp_server")
def test_a_client_cannot_aim_an_operator_s_reporter_elsewhere(
    tmp_path, aws_requests, other_traffic, reporter, option, value, route
):
    """Under an allowlist of ``/reporters/**`` that denies nothing, a client's
    destination for a reporter the operator enables is refused, and nothing is
    scanned or sent."""
    profile = _register_profile(tmp_path, reporter, "enabled", _REPORTERS_ALLOWED)
    options = {**_OPERATOR_OPTIONS[reporter], option: value}

    result, output = _client_change_then_scan(
        tmp_path,
        route,
        profile,
        {
            "op": "add",
            "path": f"/reporters/{reporter}/options/{option}",
            "value": value,
        },
        {reporter: {"enabled": True, "options": options}},
        [f"reporters.{reporter}.options.{option}={value}"],
    )

    assert result["success"] is False, result
    assert f"/reporters/{reporter}" in str(result.get("error")), result
    assert not (output / "ash_aggregated_results.json").exists()
    assert aws_requests == []
    assert other_traffic == []


@pytest.mark.parametrize("route", _ROUTES)
@pytest.mark.usefixtures("mcp_server")
def test_enabled_false_sent_with_a_destination_is_refused(
    tmp_path, aws_requests, other_traffic, route
):
    """``enabled: false`` is accepted only on its own. Sent with a bucket, where
    the profile has no S3 section, the change is refused on every route."""
    profile = _register_profile(tmp_path, "s3", "none", _REPORTERS_ALLOWED)
    section = {"enabled": False, "options": {"bucket_name": "clients-bucket"}}

    result, output = _client_change_then_scan(
        tmp_path,
        route,
        profile,
        {"op": "add", "path": "/reporters/s3", "value": section},
        {"s3": section},
        [
            "reporters.s3.enabled=false",
            "reporters.s3.options.bucket_name=clients-bucket",
        ],
    )

    assert result["success"] is False, result
    assert "/reporters/s3" in str(result.get("error")), result
    assert not (output / "ash_aggregated_results.json").exists()
    assert aws_requests == []
    assert other_traffic == []


@pytest.mark.parametrize("route", _ROUTES)
@pytest.mark.usefixtures("mcp_server")
def test_a_client_cannot_configure_a_plugin_modules_reporter(
    tmp_path, aws_requests, other_traffic, route
):
    """A reporter a plugin module brings may send findings wherever its options
    say, and nothing about it says where, so its section is the operator's too:
    a client enabling one with a URL of its own is refused, whatever the
    allowlist says, and the refusal names the section."""
    profile = _register_profile(tmp_path, "s3", "none", _REPORTERS_ALLOWED)
    section = {"enabled": True, "options": {"url": "https://client.invalid/"}}

    result, output = _client_change_then_scan(
        tmp_path,
        route,
        profile,
        {"op": "add", "path": f"/reporters/{_PLUGIN_REPORTER}", "value": section},
        {_PLUGIN_REPORTER: section},
        [
            f"reporters.{_PLUGIN_REPORTER}.enabled=true",
            f"reporters.{_PLUGIN_REPORTER}.options.url=https://client.invalid/",
        ],
    )

    assert result["success"] is False, result
    assert f"reaches the {_PLUGIN_REPORTER!r} reporters section" in str(
        result.get("error")
    ), result
    assert not (output / "ash_aggregated_results.json").exists()
    assert aws_requests == []
    assert other_traffic == []


@pytest.mark.parametrize("route", _ROUTES)
@pytest.mark.usefixtures("mcp_server")
def test_control_a_client_still_sets_a_built_in_reporter(tmp_path, route):
    """Under the same allowlist, a built-in reporter's section is the client's to
    change: the scan runs."""
    profile = _register_profile(tmp_path, "s3", "none", _REPORTERS_ALLOWED)

    result, output = _client_change_then_scan(
        tmp_path,
        route,
        profile,
        {"op": "add", "path": "/reporters/markdown/enabled", "value": False},
        {"markdown": {"enabled": False}},
        ["reporters.markdown.enabled=false"],
    )

    assert result["success"] is True, result
    assert load_results(output).sarif.get_all_results()


@pytest.mark.usefixtures("mcp_server")
def test_control_the_operator_s_profile_still_enables_and_aims_s3(
    tmp_path, aws_requests, other_traffic
):
    """The operator's own profile, under the same allowlist, still turns S3 on and
    sends the results to the operator's bucket in the operator's region."""
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    _register_profile(tmp_path, "s3", "enabled", _REPORTERS_ALLOWED)
    project = tmp_path / "ws" / "app"
    write_fixture_tree(project)
    bound = mcp_select_profile("operator", session_id=_SESSION)
    assert bound["success"] is True, bound

    _scan_directory(project)

    puts = [
        r for r in aws_requests if (r["service"], r["operation"]) == ("s3", "PutObject")
    ]
    assert puts, aws_requests
    assert {r["params"]["Bucket"] for r in puts} == {"ash-findings"}
    assert {r["region"] for r in aws_requests} == {_REGION}, aws_requests
    assert other_traffic == []
