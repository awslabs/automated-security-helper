# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The Security Hub reporter's test doubles and builders, in one place.

Six test modules in this directory build results, models and reporters, answer
AWS clients with botocore Stubbers, and run ``report()`` the same way. They took
these helpers from ``test_security_hub_batch_import.py`` by importing its private
names, which made the modules depend on each other and on that module's
import-time state. This module holds the helpers under public names, the way
``bedrock_reporter_doubles.py`` does for the Bedrock summary reporter, and every
module imports them from here.

Every AWS client here is a real botocore client answered by a ``Stubber``. A
MagicMock accepts any parameter, so a finding missing a required ASFF field
would pass a mocked test and fail only against the service; a real client
validates every request against the Security Hub service model before the
Stubber answers it. Nothing is signed and no request leaves the process:
``block_network`` fails any request that reaches the send stage.

This is not a test file (pytest collects ``test_*.py`` only), so it defines no
test and carries no tier marker. The two autouse fixtures are imported by name
into each test module that needs them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import botocore.session
import pytest
from botocore.stub import Stubber

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.plugin_modules.ash_aws_plugins import (
    security_hub_reporter as securityhub_module,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
    SecurityHubReporterConfig,
    SecurityHubReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)

AshConfig.model_rebuild()

ACCOUNT = "123456789012"
REGION = "us-east-1"
PRODUCT_ARN = f"arn:aws:securityhub:{REGION}:{ACCOUNT}:product/{ACCOUNT}/default"


@pytest.fixture(autouse=True)
def isolated_aws_environment(monkeypatch, tmp_path):
    """Fake credentials and region; no profile, config file or metadata service.

    ``create_client`` resolves the profile eagerly, so an ``AWS_PROFILE`` that
    names a profile this machine lacks would raise before any stub is consulted.
    The instance metadata service is disabled so a credential lookup that finds
    nothing ends in NoCredentialsError instead of a network probe.
    """
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
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


@pytest.fixture(autouse=True)
def no_retry_sleep():
    """Retries back off with ``time.sleep``; the tests count attempts instead.

    The ``time`` name aws_utils looks up is replaced, not ``time.sleep`` itself:
    patching the attribute on the shared ``time`` module also recorded sleeps from
    threads other tests left running in the same worker, so the count depended
    on which tests ran first.
    """
    from types import SimpleNamespace

    sleeps: list[float] = []
    with patch(
        "automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils.time",
        SimpleNamespace(sleep=sleeps.append),
    ):
        yield sleeps


def block_network(client) -> None:
    """Fail the test if any request reaches the HTTP layer."""

    def _refuse(request, **_: Any):
        raise AssertionError(f"request reached the network: {request.url}")

    client.meta.events.register_first("before-send.*.*", _refuse)


def stubbed_client(service_name: str):
    """A real botocore client for ``service_name`` and its activated Stubber."""
    session = botocore.session.Session()
    # Not secrets: the Stubber answers before anything is signed.
    session.set_credentials("testing", "testing")  # pragma: allowlist secret
    client = session.create_client(service_name, region_name=REGION)
    block_network(client)
    stub = Stubber(client)
    stub.activate()
    return client, stub


class FixedClientSession:
    """Stands in for ``boto3.Session``, handing out prepared clients by name.

    Not a MagicMock: a client the test did not prepare raises KeyError, so a call
    to an unexpected service fails the test instead of answering with a mock.
    """

    def __init__(self, clients: dict):
        self._clients = clients

    def client(self, service_name, **_: Any):
        return self._clients[service_name]


class Capture:
    """Records the parameters of every call a client makes to ``operation``."""

    def __init__(self, client, operation: str = "BatchImportFindings") -> None:
        self.requests: list[dict] = []
        client.meta.events.register(
            f"provide-client-params.securityhub.{operation}", self._record
        )

    def _record(self, params: dict, **_: Any) -> None:
        self.requests.append(json.loads(json.dumps(params)))

    @property
    def findings(self) -> list[dict]:
        return [f for request in self.requests for f in request["Findings"]]


def make_result(
    rule_id: str = "B602",
    uri: str | None = "app/app.py",
    line: int | None = 9,
    message: str = "subprocess call with shell=True identified, security issue.",
    level: str = "error",
    issue_severity: str | None = "HIGH",
    scanner: str = "bandit",
    suppressed: bool = False,
    workspace_project: str | None = None,
    extra_properties: dict | None = None,
    fingerprints: dict | None = None,
    partial_fingerprints: dict | None = None,
    start_column: int | None = None,
) -> Result:
    properties: dict[str, Any] = {"scanner_name": scanner, "tags": [scanner]}
    if issue_severity is not None:
        properties["issue_severity"] = issue_severity
    if workspace_project is not None:
        properties["workspace_project"] = workspace_project
    properties.update(extra_properties or {})
    locations = None
    if uri is not None:
        locations = [
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=uri),
                        region=Region(
                            startLine=line, endLine=line, startColumn=start_column
                        )
                        if line is not None
                        else None,
                    )
                )
            )
        ]
    return Result(
        ruleId=rule_id,
        level=level,
        message=Message(text=message),
        locations=locations,
        properties=PropertyBag(**properties),
        fingerprints=fingerprints,
        partialFingerprints=partial_fingerprints,
        suppressions=(
            [Suppression(kind="external", justification="accepted risk")]
            if suppressed
            else None
        ),
    )


def make_model(
    results: list[Result],
    generated_at: str = "2026-01-15T12:00:00+00:00",
    report_id: str = "ASH-20260115",
    project_name: str | None = None,
    completed: tuple[str, ...] = (),
    changed_files_only: bool | None = False,
    scan_source: str | None = ".",
) -> AshAggregatedResults:
    """A results model. ``project_name`` sets the scan's recorded config;
    ``completed`` lists scanners recorded as having run to completion;
    ``changed_files_only`` is the marker a scan records (None: not recorded);
    ``scan_source`` is the scanned directory the scan records (None: not
    recorded)."""
    model = AshAggregatedResults(
        sarif=SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="AWS Labs - Automated Security Helper"
                        )
                    ),
                    results=results,
                )
            ],
        )
    )
    model.metadata.generated_at = generated_at
    model.metadata.report_id = report_id
    if project_name is not None:
        model.ash_config = AshConfig(project_name=project_name)
    for scanner in completed:
        model.scanner_results[scanner] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED
        )
    if changed_files_only is not None:
        model.metadata.changed_files_only = changed_files_only
    if scan_source is not None:
        model.metadata.scan_source = scan_source
    return model


def make_reporter(
    tmp_path: Path,
    *,
    findings_scope: str | None = "fixture-project",
    project_name: str = "fixture-project",
    account_id: str | None = ACCOUNT,
    region: str | None = REGION,
    max_retries: int = 2,
    archive: bool = False,
) -> SecurityHubReporter:
    """A reporter that is enabled. ``archive`` is off unless a test is about it,
    so the import tests need no GetFindings stub; its default is tested on its own.
    ``project_name`` is the ASH configuration's, which a repository's own config
    can set; the reporter must not read it."""
    source_dir = tmp_path / "checkout"
    source_dir.mkdir(exist_ok=True)
    return SecurityHubReporter(
        context=PluginContext(
            source_dir=source_dir,
            output_dir=tmp_path / "out",
            config=AshConfig(project_name=project_name),
        ),
        config=SecurityHubReporterConfig(
            enabled=True,
            options=SecurityHubReporterConfigOptions(
                aws_region=region,
                aws_profile=None,
                account_id=account_id,
                max_retries=max_retries,
                base_delay=0.0,
                max_delay=0.0,
                archive_resolved_findings=archive,
                findings_scope=findings_scope,
            ),
        ),
    )


def caller_identity(account: str) -> dict:
    return {
        "Account": account,
        "Arn": f"arn:aws:iam::{account}:user/ci",
        "UserId": "AIDAEXAMPLE",
    }


def import_ok(count: int) -> dict:
    return {"FailedCount": 0, "SuccessCount": count, "FailedFindings": []}


def report_with(reporter, model, clients: dict, *, caller: str | None = ACCOUNT):
    """report() against prepared clients.

    The send path asks STS whose credentials these are before anything is sent,
    so an STS client answering ``caller`` is added unless the test prepares its
    own, or passes ``caller=None`` to prove the account is never looked up.
    """
    clients = dict(clients)
    if caller is not None and "sts" not in clients:
        sts, sts_stub = stubbed_client("sts")
        sts_stub.add_response("get_caller_identity", caller_identity(caller))
        clients["sts"] = sts
    with patch.object(
        securityhub_module.boto3, "Session", lambda **_: FixedClientSession(clients)
    ):
        return reporter.report(model)


def validate_with(reporter, clients: dict) -> bool:
    with patch.object(
        securityhub_module.boto3, "Session", lambda **_: FixedClientSession(clients)
    ):
        return reporter.validate_plugin_dependencies()


def built_finding(reporter, result: Result) -> dict:
    """The one ASFF finding the reporter builds for ``result``."""
    [finding] = reporter.build_asff_findings(
        make_model([result]), account_id=ACCOUNT, region=REGION
    )
    return finding


def stored_finding(
    finding: dict,
    *,
    record_state: str = "ACTIVE",
    created_at: str = "2026-01-01T00:00:00.000Z",
    updated_at: str = "2026-01-10T00:00:00.000Z",
    **overrides: Any,
) -> dict:
    """``finding`` as GetFindings returns it after an earlier import."""
    stored = json.loads(json.dumps(finding))
    stored.update(
        RecordState=record_state,
        CreatedAt=created_at,
        UpdatedAt=updated_at,
        Region=REGION,
        Workflow={"Status": "NEW"},
        ProcessedAt=updated_at,
    )
    stored["Severity"] = {**stored["Severity"], "Normalized": 70}
    stored["ProductFields"] = {
        **stored["ProductFields"],
        "aws/securityhub/FindingId": f"{PRODUCT_ARN}/{stored['Id']}",
        "aws/securityhub/ProductName": "Default",
        "aws/securityhub/CompanyName": "Personal",
    }
    stored.update(overrides)
    return stored


def archive_run(tmp_path, model, stored_findings, *, expected_sent: int, reporter=None):
    """Run report() against GetFindings returning ``stored_findings``."""
    securityhub, stub = stubbed_client("securityhub")
    imports = Capture(securityhub)
    queries = Capture(securityhub, "GetFindings")
    stub.add_response("get_findings", {"Findings": stored_findings})
    stub.add_response("batch_import_findings", import_ok(expected_sent))
    document = json.loads(
        report_with(
            reporter or make_reporter(tmp_path, archive=True),
            model,
            {"securityhub": securityhub},
        )
    )
    stub.assert_no_pending_responses()
    return document, imports, queries
