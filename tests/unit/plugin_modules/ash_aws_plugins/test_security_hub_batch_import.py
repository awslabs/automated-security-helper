# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The aws-security-hub reporter imports findings with BatchImportFindings.

Until this file existed the reporter's ``report()`` was a stub: it logged that
nothing had been sent and returned ``{"message": "Security Hub integration in
development", "findings_count": N}``. These tests pin the behavior that replaced
it.

Every AWS client here is a real botocore client answered by a ``Stubber``, the
pattern test_bedrock_summary_reporter.py uses. A MagicMock accepts any parameter,
so a finding missing a required ASFF field would pass a mocked test and fail only
against the service; a real client validates every request against the
Security Hub service model before the Stubber answers it. Nothing is signed and
no request leaves the process: the ``no_network`` fixture fails any request that
reaches the send stage.

The limits the reporter is built on, quoted from the AWS documentation:

* BatchImportFindings, Request Body, Findings: "Array Members: Minimum number of
  1 item. Maximum number of 100 items."
  https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html
* Same page: "The maximum allowed size for a finding is 240 Kb."
* AwsSecurityFinding: Id and GeneratorId "Maximum length of 512", Title "Maximum
  length of 256", Description "Maximum length of 1024", Resources "Maximum number
  of 32 items", ProductFields "up to 50 key-value pairs ... the key can contain up
  to 128 characters, and the value can contain up to 2048 characters".
  https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFinding.html
* Required top-level attributes, and the product ARN form for a private product
  (``arn:aws:securityhub:<region>:<account-id>:product/<account-id>/default``).
  https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import botocore.exceptions
import botocore.session
import pytest
from botocore.stub import Stubber
from botocore.validate import ParamValidator
from pydantic import ValidationError

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
    SecurityHubImportError,
    SecurityHubReporter,
    SecurityHubReporterConfig,
    SecurityHubReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
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
from tests.utils.helpers import mark_git_checkout

AshConfig.model_rebuild()

ACCOUNT = "123456789012"
REGION = "us-east-1"
PRODUCT_ARN = f"arn:aws:securityhub:{REGION}:{ACCOUNT}:product/{ACCOUNT}/default"

#: The required top-level attributes, written out from the user guide page rather
#: than imported from the reporter, so the test cannot agree with a reporter that
#: dropped one from its own list.
#: https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html
ASFF_REQUIRED_FIELDS = (
    "AwsAccountId",
    "CreatedAt",
    "Description",
    "GeneratorId",
    "Id",
    "ProductArn",
    "Resources",
    "SchemaVersion",
    "Severity",
    "Title",
    "Types",
    "UpdatedAt",
)
SEVERITY_LABELS = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
TYPE_NAMESPACES = {
    "Software and Configuration Checks",
    "TTPs",
    "Effects",
    "Unusual Behaviors",
    "Sensitive Data Identifications",
}
#: The timestamp forms the API reference lists, reduced to the two this reporter
#: may emit: ``Z`` or a numeric offset, with optional fractional seconds.
#: https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps
TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})$"
)
FINDING_SIZE_LIMIT_BYTES = 240 * 1024


# --------------------------------------------------------------------------- #
# Fixtures and builders
# --------------------------------------------------------------------------- #


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


def _block_network(client) -> None:
    """Fail the test if any request reaches the HTTP layer."""

    def _refuse(request, **_: Any):
        raise AssertionError(f"request reached the network: {request.url}")

    client.meta.events.register_first("before-send.*.*", _refuse)


def _stubbed_client(service_name: str):
    """A real botocore client for ``service_name`` and its activated Stubber."""
    session = botocore.session.Session()
    # Not secrets: the Stubber answers before anything is signed.
    session.set_credentials("testing", "testing")  # pragma: allowlist secret
    client = session.create_client(service_name, region_name=REGION)
    _block_network(client)
    stub = Stubber(client)
    stub.activate()
    return client, stub


class _FixedClientSession:
    """Stands in for ``boto3.Session``, handing out prepared clients by name.

    Not a MagicMock: a client the test did not prepare raises KeyError, so a call
    to an unexpected service fails the test instead of answering with a mock.
    """

    def __init__(self, clients: dict):
        self._clients = clients

    def client(self, service_name, **_: Any):
        return self._clients[service_name]


class _Capture:
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


def _result(
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


def _model(
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


def _many(count: int) -> list[Result]:
    return [_result(line=index + 1) for index in range(count)]


def _reporter(
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


def _caller(account: str) -> dict:
    return {
        "Account": account,
        "Arn": f"arn:aws:iam::{account}:user/ci",
        "UserId": "AIDAEXAMPLE",
    }


def _ok(count: int) -> dict:
    return {"FailedCount": 0, "SuccessCount": count, "FailedFindings": []}


def _report_with(reporter, model, clients: dict, *, caller: str | None = ACCOUNT):
    """report() against prepared clients.

    The send path asks STS whose credentials these are before anything is sent,
    so an STS client answering ``caller`` is added unless the test prepares its
    own, or passes ``caller=None`` to prove the account is never looked up.
    """
    clients = dict(clients)
    if caller is not None and "sts" not in clients:
        sts, sts_stub = _stubbed_client("sts")
        sts_stub.add_response("get_caller_identity", _caller(caller))
        clients["sts"] = sts
    with patch.object(
        securityhub_module.boto3, "Session", lambda **_: _FixedClientSession(clients)
    ):
        return reporter.report(model)


# --------------------------------------------------------------------------- #
# Sending
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_zero_findings_makes_no_call_and_says_so(tmp_path):
    """BatchImportFindings needs at least one finding, so nothing is called.

    No STS client is prepared either, with ``account_id`` unset: a reporter that
    looked the account up for nothing would raise KeyError here.
    """
    securityhub, stub = _stubbed_client("securityhub")
    reporter = _reporter(tmp_path, account_id=None)

    document = json.loads(
        _report_with(reporter, _model([]), {"securityhub": securityhub}, caller=None)
    )

    stub.assert_no_pending_responses()
    assert document["findings"] == []
    assert document["imported"] == 0
    assert document["requests"] == 0


@pytest.mark.unit
def test_one_finding_is_imported_in_one_request(tmp_path):
    securityhub, stub = _stubbed_client("securityhub")
    capture = _Capture(securityhub)
    stub.add_response("batch_import_findings", _ok(1))

    document = json.loads(
        _report_with(
            _reporter(tmp_path), _model([_result()]), {"securityhub": securityhub}
        )
    )

    stub.assert_no_pending_responses()
    assert len(capture.requests) == 1
    assert len(capture.findings) == 1
    assert document["imported"] == 1
    assert document["product_arn"] == PRODUCT_ARN
    # The document records exactly what was sent.
    assert document["findings"] == capture.findings


@pytest.mark.unit
def test_more_than_one_hundred_findings_are_split_into_batches(tmp_path):
    """250 findings go out as 100 + 100 + 50: the documented per-request maximum."""
    securityhub, stub = _stubbed_client("securityhub")
    capture = _Capture(securityhub)
    for size in (100, 100, 50):
        stub.add_response("batch_import_findings", _ok(size))

    document = json.loads(
        _report_with(
            _reporter(tmp_path), _model(_many(250)), {"securityhub": securityhub}
        )
    )

    stub.assert_no_pending_responses()
    assert [len(r["Findings"]) for r in capture.requests] == [100, 100, 50]
    assert len({f["Id"] for f in capture.findings}) == 250
    assert document["imported"] == 250
    assert document["requests"] == 3


@pytest.mark.unit
def test_partial_failure_raises_and_names_the_rejected_findings(tmp_path, caplog):
    """A 200 response can still reject findings; that must not read as success."""
    securityhub, stub = _stubbed_client("securityhub")
    capture = _Capture(securityhub)
    stub.add_response(
        "batch_import_findings",
        {
            "FailedCount": 1,
            "SuccessCount": 2,
            "FailedFindings": [
                {
                    "Id": "placeholder",
                    "ErrorCode": "InvalidInput",
                    "ErrorMessage": "Finding is malformed",
                }
            ],
        },
    )
    reporter = _reporter(tmp_path)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(SecurityHubImportError) as raised:
            _report_with(reporter, _model(_many(3)), {"securityhub": securityhub})

    message = str(raised.value)
    assert "1 of 3" in message
    assert "InvalidInput" in message
    assert "placeholder" in caplog.text
    assert "Finding is malformed" in caplog.text
    assert len(capture.findings) == 3


@pytest.mark.unit
def test_every_finding_rejected_with_invalid_access_points_at_enabling_the_hub(
    tmp_path,
):
    """A disabled Security Hub answers 200 and lists every finding as InvalidAccess.

    https://docs.aws.amazon.com/securityhub/latest/userguide/finding-update-batchimportfindings.html:
    "If Security Hub CSPM is disabled, or the finding provider integration is not
    enabled, then the findings are returned in the FailedFindings list, with an
    InvalidAccess error."
    """
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_response(
        "batch_import_findings",
        {
            "FailedCount": 2,
            "SuccessCount": 0,
            "FailedFindings": [
                {"Id": f"id-{n}", "ErrorCode": "InvalidAccess", "ErrorMessage": "x"}
                for n in range(2)
            ],
        },
    )

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path), _model(_many(2)), {"securityhub": securityhub}
        )

    message = str(raised.value)
    assert "2 of 2" in message
    assert "enable-security-hub" in message
    assert REGION in message


@pytest.mark.parametrize(
    "code, status, expected",
    [
        ("InvalidAccessException", 401, "enable-security-hub"),
        ("AccessDeniedException", 403, "securityhub:BatchImportFindings"),
        ("InvalidInputException", 400, "InvalidInputException"),
    ],
)
@pytest.mark.unit
def test_client_error_raises_an_actionable_error(tmp_path, code, status, expected):
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_client_error(
        "batch_import_findings",
        service_error_code=code,
        service_message="refused",
        http_status_code=status,
    )

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path), _model(_many(1)), {"securityhub": securityhub}
        )

    assert expected in str(raised.value)
    assert code in str(raised.value)


@pytest.mark.unit
def test_a_failed_request_stops_the_import_and_counts_what_was_not_sent(tmp_path):
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_response("batch_import_findings", _ok(100))
    stub.add_client_error(
        "batch_import_findings",
        service_error_code="AccessDeniedException",
        service_message="denied",
        http_status_code=403,
    )

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path), _model(_many(250)), {"securityhub": securityhub}
        )

    # The third batch is never attempted after the second fails.
    stub.assert_no_pending_responses()
    message = str(raised.value)
    assert "100 of 250" in message
    assert "150" in message


@pytest.mark.unit
def test_throttling_is_retried_and_then_succeeds(tmp_path, no_retry_sleep):
    """LimitExceededException is the API's 429; the reporter backs off and retries."""
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_client_error(
        "batch_import_findings",
        service_error_code="LimitExceededException",
        service_message="Rate exceeded",
        http_status_code=429,
    )
    stub.add_response("batch_import_findings", _ok(1))

    document = json.loads(
        _report_with(
            _reporter(tmp_path, max_retries=2),
            _model(_many(1)),
            {"securityhub": securityhub},
        )
    )

    stub.assert_no_pending_responses()
    assert document["imported"] == 1
    assert len(no_retry_sleep) == 1


@pytest.mark.unit
def test_throttling_that_outlasts_the_retries_is_reported_as_throttling(tmp_path):
    securityhub, stub = _stubbed_client("securityhub")
    for _ in range(3):  # the first attempt and max_retries=2 retries
        stub.add_client_error(
            "batch_import_findings",
            service_error_code="LimitExceededException",
            service_message="Rate exceeded",
            http_status_code=429,
        )

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path, max_retries=2),
            _model(_many(1)),
            {"securityhub": securityhub},
        )

    stub.assert_no_pending_responses()
    assert "throttl" in str(raised.value).lower()
    assert "max_retries" in str(raised.value)


def _unconfigured_client(service_name: str, monkeypatch):
    """A real client whose credential chain finds nothing, with the network blocked."""
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    client = botocore.session.Session().create_client(service_name, region_name=REGION)
    _block_network(client)
    return client


@pytest.mark.unit
def test_no_credentials_raises_an_actionable_error(tmp_path, monkeypatch):
    securityhub = _unconfigured_client("securityhub", monkeypatch)

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path), _model(_many(1)), {"securityhub": securityhub}
        )

    # botocore's own "Unable to locate credentials" says "credentials" too, so
    # these pin the reporter's message, which says what to set.
    assert "found no AWS credentials" in str(raised.value)
    assert "aws_profile" in str(raised.value)


@pytest.mark.unit
def test_no_credentials_while_looking_up_the_account_is_actionable(
    tmp_path, monkeypatch
):
    """With ``account_id`` unset the account comes from STS, which needs credentials too."""
    sts = _unconfigured_client("sts", monkeypatch)
    securityhub = _unconfigured_client("securityhub", monkeypatch)

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path, account_id=None),
            _model(_many(1)),
            {"securityhub": securityhub, "sts": sts},
        )

    assert "found no AWS credentials" in str(raised.value)
    assert "aws_profile" in str(raised.value)


@pytest.mark.unit
def test_a_profile_that_does_not_exist_is_an_actionable_error(tmp_path, monkeypatch):
    """The real boto3.Session, so the error is the one an operator would see."""
    import botocore.endpoint

    def _refuse(*_: Any, **__: Any):
        raise AssertionError("request reached the network")

    monkeypatch.setattr(botocore.endpoint.Endpoint, "_send", _refuse)
    reporter = _reporter(tmp_path)
    reporter.config.options.aws_profile = "profile-this-machine-does-not-have"

    with pytest.raises(SecurityHubImportError) as raised:
        reporter.report(_model(_many(1)))

    assert "profile-this-machine-does-not-have" in str(raised.value)


@pytest.mark.unit
def test_the_account_is_looked_up_when_not_configured(tmp_path):
    sts, sts_stub = _stubbed_client("sts")
    sts_stub.add_response(
        "get_caller_identity",
        {
            "Account": "210987654321",
            "Arn": "arn:aws:iam::210987654321:user/ci",
            "UserId": "AIDAEXAMPLE",
        },
    )
    securityhub, stub = _stubbed_client("securityhub")
    capture = _Capture(securityhub)
    stub.add_response("batch_import_findings", _ok(1))

    _report_with(
        _reporter(tmp_path, account_id=None),
        _model(_many(1)),
        {"securityhub": securityhub, "sts": sts},
    )

    finding = capture.findings[0]
    assert finding["AwsAccountId"] == "210987654321"
    assert finding["ProductArn"] == (
        f"arn:aws:securityhub:{REGION}:210987654321:product/210987654321/default"
    )


@pytest.mark.unit
def test_a_missing_region_is_an_actionable_error(tmp_path):
    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(_reporter(tmp_path, region=None), _model(_many(1)), {})
    assert "aws_region" in str(raised.value)


# --------------------------------------------------------------------------- #
# The findings themselves
# --------------------------------------------------------------------------- #


def _varied_results() -> list[Result]:
    """Findings that push every field toward an edge the ASFF limits care about."""
    return [
        _result(),
        _result(
            rule_id="B105",
            line=5,
            level="note",
            issue_severity="LOW",
            message="Possible hardcoded password: 'hunter2-not-a-real-secret'",
        ),
        _result(
            rule_id="CVE-2018-18074-requests",
            uri="requirements.txt",
            line=1,
            issue_severity="CRITICAL",
            scanner="grype",
            message="A critical vulnerability in requests 2.19.1 was found",
        ),
        _result(rule_id="SECRET-KEYWORD", suppressed=True, scanner="detect-secrets"),
        _result(
            rule_id="NO-LOCATION",
            uri=None,
            line=None,
            level="warning",
            issue_severity=None,
        ),
        _result(
            rule_id="NO-LINE",
            uri="Dockerfile",
            line=None,
            level="none",
            issue_severity=None,
        ),
        _result(
            rule_id="R" * 600,
            uri="deep/" + "d/" * 1500 + "file.py",
            message="m" * 5000 + "\nsecond line",
            scanner="s" * 300,
        ),
        _result(rule_id="WS", workspace_project="api", message="   leading spaces"),
        _result(rule_id="EMPTY", message=""),
        _result(rule_id="UNICODE", message="Ünïcödé — non-ASCII text ✓"),
    ]


def _securityhub_validator_shape():
    model = botocore.session.Session().get_service_model("securityhub")
    return model.operation_model("BatchImportFindings").input_shape


@pytest.mark.unit
def test_every_finding_sent_carries_every_required_field_within_its_limits(tmp_path):
    """Validates each finding against the documented required fields and limits."""
    findings = _reporter(tmp_path).build_asff_findings(
        _model(_varied_results()), account_id=ACCOUNT, region=REGION
    )
    assert len(findings) == len(_varied_results())

    # botocore's own validation of the request against the service model: types,
    # required members and patterns.
    report = ParamValidator().validate(
        {"Findings": findings}, _securityhub_validator_shape()
    )
    assert not report.has_errors(), report.generate_report()

    for finding in findings:
        missing = [field for field in ASFF_REQUIRED_FIELDS if not finding.get(field)]
        assert not missing, (missing, finding.get("Id"))

        assert finding["SchemaVersion"] == "2018-10-08"
        assert finding["ProductArn"] == PRODUCT_ARN
        assert re.fullmatch(r"\d{12}", finding["AwsAccountId"])
        assert 1 <= len(finding["Id"]) <= 512
        assert 1 <= len(finding["GeneratorId"]) <= 512
        assert 1 <= len(finding["Title"]) <= 256
        assert 1 <= len(finding["Description"]) <= 1024
        for text in (finding["Title"], finding["Description"], finding["GeneratorId"]):
            assert text.strip(), finding["Id"]

        assert TIMESTAMP.match(finding["CreatedAt"]), finding["CreatedAt"]
        assert TIMESTAMP.match(finding["UpdatedAt"]), finding["UpdatedAt"]
        assert finding["CreatedAt"] == finding["UpdatedAt"]

        assert finding["Severity"]["Label"] in SEVERITY_LABELS
        provider = finding["FindingProviderFields"]
        assert provider["Severity"]["Label"] == finding["Severity"]["Label"]
        assert provider["Types"] == finding["Types"]
        assert 1 <= len(finding["Types"]) <= 50
        for finding_type in finding["Types"]:
            assert finding_type.split("/")[0] in TYPE_NAMESPACES, finding_type

        assert 1 <= len(finding["Resources"]) <= 32
        for resource in finding["Resources"]:
            assert resource["Type"] == "Other"
            assert resource["Id"].strip()
            assert len(resource["Type"]) <= 256

        product_fields = finding.get("ProductFields", {})
        assert len(product_fields) <= 50
        for key, value in product_fields.items():
            assert 1 <= len(key) <= 128 and key.strip()
            assert 1 <= len(value) <= 2048 and value.strip()

        assert finding["RecordState"] in {"ACTIVE", "ARCHIVED"}
        assert len(json.dumps(finding).encode("utf-8")) < FINDING_SIZE_LIMIT_BYTES


@pytest.mark.unit
def test_the_stubbed_service_accepts_the_request(tmp_path):
    """The same findings, sent through a real client, pass request validation."""
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_response("batch_import_findings", _ok(len(_varied_results())))

    _report_with(
        _reporter(tmp_path), _model(_varied_results()), {"securityhub": securityhub}
    )

    stub.assert_no_pending_responses()


@pytest.mark.unit
def test_no_code_snippet_or_secret_leaves_the_machine(tmp_path):
    results = _varied_results()
    results[0].locations[0].physicalLocation.root.region.snippet = ArtifactContent(
        text="subprocess.call(cmd)  # SNIPPET-MARKER"
    )
    findings = _reporter(tmp_path).build_asff_findings(
        _model(results), account_id=ACCOUNT, region=REGION
    )
    payload = json.dumps(findings)

    assert "SNIPPET-MARKER" not in payload
    assert "hunter2-not-a-real-secret" not in payload


@pytest.mark.parametrize(
    "level, issue_severity, label",
    [
        ("error", "CRITICAL", "CRITICAL"),
        ("error", "HIGH", "HIGH"),
        ("warning", "MEDIUM", "MEDIUM"),
        ("note", "LOW", "LOW"),
        ("none", "INFO", "INFORMATIONAL"),
        # With no issue_severity the level decides, the way ASH's own severity
        # counts and threshold gate decide it: error is CRITICAL there.
        ("error", None, "CRITICAL"),
        ("warning", None, "MEDIUM"),
        ("note", None, "LOW"),
        ("none", None, "INFORMATIONAL"),
    ],
)
@pytest.mark.unit
def test_ash_severity_maps_to_the_asff_label(tmp_path, level, issue_severity, label):
    [finding] = _reporter(tmp_path).build_asff_findings(
        _model([_result(level=level, issue_severity=issue_severity)]),
        account_id=ACCOUNT,
        region=REGION,
    )
    assert finding["Severity"]["Label"] == label
    assert finding["FindingProviderFields"]["Severity"]["Label"] == label


@pytest.mark.unit
def test_a_suppressed_finding_is_sent_archived_and_an_open_one_active(tmp_path):
    """Archived, not dropped: a finding imported before it was suppressed must close.

    Security Hub ignores BatchImportFindings updates to ``Workflow``, so the
    provider-owned ``RecordState`` is the field a later scan can still change.
    """
    open_finding, suppressed_finding = _reporter(tmp_path).build_asff_findings(
        _model([_result(rule_id="OPEN"), _result(rule_id="SUPP", suppressed=True)]),
        account_id=ACCOUNT,
        region=REGION,
    )
    assert open_finding["RecordState"] == "ACTIVE"
    assert suppressed_finding["RecordState"] == "ARCHIVED"
    assert suppressed_finding["ProductFields"]["ash/suppressed"] == "true"
    assert "Workflow" not in suppressed_finding


# --------------------------------------------------------------------------- #
# Finding identity
# --------------------------------------------------------------------------- #


def _ids(reporter, results, **model_kwargs) -> list[str]:
    return [
        f["Id"]
        for f in reporter.build_asff_findings(
            _model(results, **model_kwargs), account_id=ACCOUNT, region=REGION
        )
    ]


@pytest.mark.unit
def test_a_rescan_produces_the_same_ids_so_security_hub_updates_not_duplicates(
    tmp_path,
):
    """The Id must not change with the scan: not with report_id, not with the time."""
    reporter = _reporter(tmp_path)
    first = reporter.build_asff_findings(
        _model(
            _varied_results(),
            generated_at="2026-01-15T12:00:00+00:00",
            report_id="ASH-first-scan",
        ),
        account_id=ACCOUNT,
        region=REGION,
    )
    second = reporter.build_asff_findings(
        _model(
            _varied_results(),
            generated_at="2026-01-16T08:30:00+00:00",
            report_id="ASH-second-scan",
        ),
        account_id=ACCOUNT,
        region=REGION,
    )

    assert [f["Id"] for f in first] == [f["Id"] for f in second]
    # UpdatedAt has to move forward, or Security Hub ignores the re-import.
    assert all(a["UpdatedAt"] < b["UpdatedAt"] for a, b in zip(first, second))


@pytest.mark.parametrize(
    "changed",
    [
        {"rule_id": "B603"},
        {"line": 10},
        {"uri": "app/other.py"},
        {"scanner": "semgrep"},
        {"workspace_project": "web"},
    ],
)
@pytest.mark.unit
def test_a_different_finding_gets_a_different_id(tmp_path, changed):
    reporter = _reporter(tmp_path)
    assert _ids(reporter, [_result()]) != _ids(reporter, [_result(**changed)])


@pytest.mark.unit
def test_the_same_finding_in_another_findings_scope_gets_another_id(tmp_path):
    """Two repositories importing into one account must not overwrite each other."""
    first = _ids(_reporter(tmp_path, findings_scope="repo-one"), [_result()])
    second = _ids(_reporter(tmp_path, findings_scope="repo-two"), [_result()])
    assert first != second


@pytest.mark.unit
def test_project_name_does_not_change_the_id(tmp_path):
    """A repository's own config can set project_name, so it must not pick Ids."""
    base = _ids(_reporter(tmp_path, project_name="repo-one"), [_result()])
    renamed = _ids(
        _reporter(tmp_path, project_name="another-teams-repository"),
        [_result()],
        project_name="another-teams-repository",
    )
    assert renamed == base


@pytest.mark.unit
def test_the_message_and_severity_do_not_change_the_id(tmp_path):
    """A rewording or a re-rating is an update to the same finding, not a new one."""
    reporter = _reporter(tmp_path)
    assert _ids(reporter, [_result()]) == _ids(
        reporter, [_result(message="reworded by a newer scanner", issue_severity="LOW")]
    )


@pytest.mark.unit
def test_an_absolute_path_inside_the_scan_root_gets_the_relative_path_id(tmp_path):
    """The checkout path differs between machines; the Id must not depend on it."""
    reporter = _reporter(tmp_path)
    source_dir = Path(reporter.context.source_dir)
    absolute = _result(uri=(source_dir / "app" / "app.py").as_posix())
    assert _ids(reporter, [absolute]) == _ids(reporter, [_result(uri="app/app.py")])


def _converted(output_dir: Path, message: str = "secret") -> Result:
    """A result in a notebook the converter wrote under ``output_dir``, marked as
    the scanner executor marks it (``utils/scan_output_dirs``)."""
    uri = (output_dir / "converted" / "jupyter" / "nb-converted.py").as_posix()
    return _result(
        uri=uri,
        message=f"{message} in file '{uri}'",
        extra_properties={"converted_path": "jupyter/nb-converted.py"},
    )


@pytest.mark.unit
def test_a_converted_files_findings_keep_their_ids_wherever_the_output_dir_is(
    tmp_path,
):
    """Keyed by the path under the converted root with "tree": "converted", as the
    flattened finding id is (utils/finding_identity). Keyed by the absolute path,
    a scan with --output-dir out1 and one with out2 gave each finding two Ids. Two
    findings on one line are included, so the occurrence, which is taken from the
    message, is held to it too: the message names the file."""
    reporter = _reporter(tmp_path)
    outputs = [
        tmp_path / "out1",
        tmp_path / "out2",
        Path(reporter.context.source_dir) / ".ash" / "ash_output",
    ]
    ids = [
        _ids(reporter, [_converted(output, "first"), _converted(output, "second")])
        for output in outputs
    ]

    assert ids[0] == ids[1] == ids[2], ids
    assert len(set(ids[0])) == 2, ids[0]
    # The tree keeps it apart from a source file at the same relative path.
    assert _ids(reporter, [_converted(outputs[0])]) != _ids(
        reporter, [_result(uri="jupyter/nb-converted.py")]
    )


@pytest.mark.unit
def test_a_converted_files_finding_names_the_file_it_is_in(tmp_path):
    """The Id aside, ash/file and the resource say where it is."""
    reporter = _reporter(tmp_path)
    output = Path(reporter.context.source_dir) / ".ash" / "ash_output"
    [finding] = reporter.build_asff_findings(
        _model([_converted(output)]), account_id=ACCOUNT, region=REGION
    )
    written = ".ash/ash_output/converted/jupyter/nb-converted.py"
    assert finding["ProductFields"]["ash/file"] == written
    assert finding["Resources"][0]["Id"] == f"fixture-project/{written}"


@pytest.mark.unit
def test_the_project_a_results_file_was_written_for_keys_its_findings(tmp_path):
    """A workspace project's own results record the project in their metadata, and
    its findings may name none. They are keyed by it as a finding that names the
    project is, so the Id does not depend on which of the two says it."""
    reporter = _reporter(tmp_path)
    model = _model([_result()])
    model.metadata.workspace_project = "api"
    from_metadata = [
        f["Id"]
        for f in reporter.build_asff_findings(model, account_id=ACCOUNT, region=REGION)
    ]

    assert from_metadata == _ids(reporter, [_result(workspace_project="api")])
    assert from_metadata != _ids(reporter, [_result()])


@pytest.mark.unit
def test_a_dot_segment_in_the_path_does_not_change_the_id(tmp_path):
    reporter = _reporter(tmp_path)
    assert _ids(reporter, [_result(uri="./app/app.py")]) == _ids(
        reporter, [_result(uri="app/app.py")]
    )


def _located(start_column: int | None = None, **properties: Any) -> Result:
    result = _result(
        rule_id="CVE-2023-32681-requests",
        uri="requirements.txt",
        line=1,
        scanner="grype",
        extra_properties=properties,
    )
    result.locations[0].physicalLocation.root.region.startColumn = start_column
    return result


@pytest.mark.unit
def test_the_column_and_the_package_version_do_not_change_the_id(tmp_path):
    """A scanner that starts reporting columns, or an upgrade that is still
    vulnerable, updates the finding instead of opening a second one."""
    reporter = _reporter(tmp_path)
    before = _ids(
        reporter,
        [_located(package_name="requests", package_version="2.19.1")],
    )
    after = _ids(
        reporter,
        [_located(start_column=5, package_name="requests", package_version="2.20.0")],
    )
    assert before == after


@pytest.mark.unit
def test_a_different_package_or_package_path_gets_a_different_id(tmp_path):
    reporter = _reporter(tmp_path)
    base = _ids(reporter, [_located(package_name="requests", package_path="a")])
    assert base != _ids(reporter, [_located(package_name="urllib3", package_path="a")])
    assert base != _ids(reporter, [_located(package_name="requests", package_path="b")])


@pytest.mark.unit
def test_exact_duplicates_get_an_ordinal_and_are_all_sent(tmp_path):
    """Identity contract v2: same key, column and message is the only case ranked
    by order: the first has no ordinal, the next 1, then 2."""
    securityhub, stub = _stubbed_client("securityhub")
    capture = _Capture(securityhub)
    stub.add_response("batch_import_findings", _ok(3))

    document = json.loads(
        _report_with(
            _reporter(tmp_path),
            _model([_result(), _result(), _result()]),
            {"securityhub": securityhub},
        )
    )

    assert len({f["Id"] for f in capture.findings}) == 3
    assert document["duplicates_skipped"] == 0


@pytest.mark.unit
def test_two_results_sharing_a_fingerprint_at_one_place_are_two_findings(
    tmp_path, caplog
):
    """Two results of one scanner and rule with the same fingerprint at the same
    lines are two findings, not one reported twice.

    A fingerprint tells findings apart only across locations, so the identity
    key (utils/finding_identity.py) tells two results at one location apart
    whatever value they share; each gets its own Id, both are sent, and nothing
    is skipped as a duplicate or warned about as sent once.
    """
    securityhub, stub = _stubbed_client("securityhub")
    capture = _Capture(securityhub)
    stub.add_response("batch_import_findings", _ok(2))
    fingerprint = {"matchBasedId/v1": "4f1c0e"}

    with caplog.at_level(logging.WARNING):
        document = json.loads(
            _report_with(
                _reporter(tmp_path),
                _model(
                    [
                        _result(fingerprints=fingerprint),
                        _result(fingerprints=fingerprint, message="reworded"),
                    ]
                ),
                {"securityhub": securityhub},
            )
        )

    assert len(capture.findings) == 2
    assert len({finding["Id"] for finding in capture.findings}) == 2
    assert document["duplicates_skipped"] == 0
    assert not any("sent once" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# Dependency validation
# --------------------------------------------------------------------------- #


def _validate_with(reporter, clients: dict) -> bool:
    with patch.object(
        securityhub_module.boto3, "Session", lambda **_: _FixedClientSession(clients)
    ):
        return reporter.validate_plugin_dependencies()


@pytest.mark.unit
def test_validation_passes_against_an_enabled_hub(tmp_path):
    """As on main: DescribeHub only, because account_id is configured."""
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_response(
        "describe_hub",
        {"HubArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default"},
    )

    assert _validate_with(_reporter(tmp_path), {"securityhub": securityhub})
    stub.assert_no_pending_responses()


@pytest.mark.unit
def test_validation_looks_the_account_up_when_it_is_not_configured(tmp_path):
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_response(
        "describe_hub",
        {"HubArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default"},
    )
    sts, sts_stub = _stubbed_client("sts")
    sts_stub.add_response("get_caller_identity", _caller("210987654321"))
    reporter = _reporter(tmp_path, account_id=None)

    assert _validate_with(reporter, {"securityhub": securityhub, "sts": sts})
    sts_stub.assert_no_pending_responses()
    assert reporter.config.options.account_id == "210987654321"


@pytest.mark.unit
def test_the_send_path_refuses_an_account_id_that_is_not_the_callers(tmp_path):
    """With the default product ARN, only the finding's own account may import it.

    Checked in report(), before GetFindings or BatchImportFindings, so it holds
    for ``ash report`` too, which skips the dependency check.
    """
    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    queries = _Capture(securityhub, "GetFindings")

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path, archive=True),
            _model(_many(1), completed=("bandit",)),
            {"securityhub": securityhub},
            caller="999999999999",
        )

    message = str(raised.value)
    assert "999999999999" in message
    assert ACCOUNT in message
    assert imports.requests == [] and queries.requests == []
    stub.assert_no_pending_responses()


@pytest.mark.unit
def test_the_send_path_asks_sts_even_when_account_id_is_set(tmp_path):
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_response("batch_import_findings", _ok(1))
    sts, sts_stub = _stubbed_client("sts")
    sts_stub.add_response("get_caller_identity", _caller(ACCOUNT))

    _report_with(
        _reporter(tmp_path), _model(_many(1)), {"securityhub": securityhub, "sts": sts}
    )

    sts_stub.assert_no_pending_responses()
    stub.assert_no_pending_responses()


@pytest.mark.unit
def test_validation_fails_when_the_hub_is_not_enabled(tmp_path, caplog):
    """main's check and message. What to run to enable it is in the send path's
    error (test_client_error_raises_an_actionable_error, InvalidAccessException)."""
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_client_error(
        "describe_hub",
        service_error_code="InvalidAccessException",
        service_message="Account is not subscribed to AWS Security Hub",
        http_status_code=401,
    )

    with caplog.at_level(logging.ERROR):
        assert not _validate_with(_reporter(tmp_path), {"securityhub": securityhub})
    assert "not enabled" in caplog.text


# --------------------------------------------------------------------------- #
# Off unless enabled
# --------------------------------------------------------------------------- #


def _filter_enabled(reporter, context):
    """ReportPhase's own enabled/dependency filter, the step that decides a run."""
    from types import SimpleNamespace

    from automated_security_helper.base.engine_phase import EnginePhase

    return EnginePhase.filter_enabled_plugins(
        SimpleNamespace(phase_name="report"), [reporter], context
    )


def _reporter_from(config: AshConfig, tmp_path: Path) -> SecurityHubReporter:
    """Built the way ReportPhase builds it: from the ASH config's section."""
    from automated_security_helper.base.plugin_config import plugin_config_key

    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=config
    )
    return SecurityHubReporter(
        context=context,
        config=config.get_plugin_config(
            plugin_type="reporter", plugin_name=plugin_config_key(SecurityHubReporter)
        ),
    )


@pytest.mark.unit
def test_the_reporter_is_off_by_default():
    assert SecurityHubReporterConfig().enabled is False


@pytest.mark.parametrize(
    "reporters",
    [
        {},
        # A Region is all the old default needed: AWS_REGION in the environment
        # supplies it to every scan, so the reporter ran wherever credentials did.
        {"aws-security-hub": {"options": {"aws_region": REGION}}},
    ],
    ids=["no-section", "region-only"],
)
@pytest.mark.unit
def test_loading_the_aws_plugins_without_enabling_it_never_contacts_aws(
    tmp_path, reporters
):
    """A scan that loads ash_aws_plugins for S3 or Bedrock must not import findings.

    The reporter is off unless its section sets ``enabled: true``, so a scan that
    loads ash_aws_plugins for S3 or Bedrock imports nothing into Security Hub.
    """
    config = AshConfig.model_validate(
        {"project_name": "fixture-project", "reporters": reporters}
    )
    reporter = _reporter_from(config, tmp_path)
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))

    # Off, not merely dropped: with no Region the dependency check would also
    # drop an enabled reporter, so [] alone would pass for the wrong reason.
    assert reporter.config.enabled is False
    with patch.object(securityhub_module.boto3, "Session", session):
        kept = _filter_enabled(reporter, reporter.context)

    assert kept == []
    session.assert_not_called()


@pytest.mark.unit
def test_an_override_turns_it_off_whatever_the_repositorys_config_says(tmp_path):
    """The CI examples pass enabled=false on the jobs that must not import: a
    pull request can edit .ash/.ash.yaml, and its enabled: true must lose."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "checkout"
    (checkout / ".ash").mkdir(parents=True)
    (checkout / ".ash" / ".ash.yaml").write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        "      findings_scope: someone-elses-repo\n",
        encoding="utf-8",
    )
    # The control: the repository's own enabled: true does not apply either
    # (_confine_enabled in config/reporter_trust.py holds an off-host reporter's
    # enabled to the trusted base's), so the reporter is off with or without
    # the override, and the override below is the operator's word on top.
    control = resolve_config(source_dir=checkout)
    assert _reporter_from(control, tmp_path).config.enabled is False

    config = resolve_config(
        source_dir=checkout,
        config_overrides=["reporters.aws-security-hub.enabled=false"],
    )
    reporter = _reporter_from(config, tmp_path)
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))

    assert reporter.config.enabled is False
    with patch.object(securityhub_module.boto3, "Session", session):
        assert _filter_enabled(reporter, reporter.context) == []
        # The not-enabled refusal, not the missing-Region one that the
        # in-tree section (which sets no Region) would also meet.
        with pytest.raises(
            SecurityHubImportError, match="aws-security-hub is not enabled"
        ):
            reporter.report(_model([_result()]))
    session.assert_not_called()


@pytest.mark.unit
def test_enabled_true_in_the_config_turns_it_on(tmp_path):
    config = AshConfig.model_validate(
        {
            "project_name": "fixture-project",
            "reporters": {"aws-security-hub": {"enabled": True}},
        }
    )
    assert _reporter_from(config, tmp_path).config.enabled is True


# --------------------------------------------------------------------------- #
# Options only the operator sets: findings_scope, archive_resolved_findings
# --------------------------------------------------------------------------- #
#
# findings_scope decides which findings in the operator's account a scan updates
# and archives, and archive_resolved_findings whether it archives the ones it no
# longer reports. The operator ran `--ash-plugin-modules ash_aws_plugins` with
# --config-overrides for enabled and findings_scope and no --config. A pull
# request's .ash/.ash.yaml set archive_resolved_findings: true, and that
# survived, so a pull request that deletes files archived that scope's findings
# in the operator's account.

_OPERATOR_ENABLES = [
    "reporters.aws-security-hub.enabled=true",
    f"reporters.aws-security-hub.options.aws_region={REGION}",
]
_OPERATOR_SCOPE = "reporters.aws-security-hub.options.findings_scope=operator-scope"


def _checkout_with_config(tmp_path: Path, text: str) -> Path:
    checkout = tmp_path / "checkout"
    (checkout / ".ash").mkdir(parents=True)
    (checkout / ".ash" / ".ash.yaml").write_text(text, encoding="utf-8")
    return checkout


def _operator_only_warnings(caplog) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING
        and (
            ".options.findings_scope" in record.getMessage()
            or ".options.archive_resolved_findings" in record.getMessage()
        )
    ]


_AWS_PLUGINS = (
    "ash_plugin_modules+=automated_security_helper.plugin_modules.ash_aws_plugins"
)


def _sent_by_ash_report(
    checkout: Path,
    monkeypatch,
    *,
    config: Path | None = None,
    config_overrides: tuple[str, ...] = (),
    archives: bool,
) -> list[dict]:
    """What ``ash report --format aws-security-hub --config <config>`` imports for
    a results file in *checkout*, run from *checkout*, a git checkout.

    These are the positive halves of the confinement tests: the operator's
    setting reaches Security Hub, not only the repository's is kept out. They
    go through report_command, so the reporter gets its section the way the
    product gives it, whatever decides that. *config* defaults to the
    checkout's own ``.ash/.ash.yaml``: ash report discovers no config file, so
    without one named the repository's file would not be read at all. Security
    Hub and STS are stubbed: the import must happen, and GetFindings is
    answered only when *archives*, so archiving that was not asked for, or is
    missing, fails the stubber.
    """
    import typer

    from automated_security_helper.cli.report import report_command

    mark_git_checkout(checkout)
    if config is None:
        config = checkout / ".ash" / ".ash.yaml"
    output = checkout / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    (output / "ash_aggregated_results.json").write_text(
        _model([_result()], completed=("bandit",)).model_dump_json(),
        encoding="utf-8",
    )
    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    queries = _Capture(securityhub, "GetFindings")
    if archives:
        stub.add_response("get_findings", {"Findings": []})
    stub.add_response("batch_import_findings", _ok(1))
    sts, sts_stub = _stubbed_client("sts")
    sts_stub.add_response("get_caller_identity", _caller(ACCOUNT))
    clients = {"securityhub": securityhub, "sts": sts}
    monkeypatch.chdir(checkout)

    with patch.object(
        securityhub_module.boto3, "Session", lambda **_: _FixedClientSession(clients)
    ):
        try:
            report_command(
                report_format="aws-security-hub",
                output_dir=str(output),
                config=str(config) if config is not None else None,
                config_overrides=[_AWS_PLUGINS, *config_overrides],
            )
        except typer.Exit as exit_:
            assert exit_.exit_code == 0, exit_.exit_code

    stub.assert_no_pending_responses()
    assert len(queries.requests) == (1 if archives else 0), queries.requests
    return imports.findings


def _scope_of(findings: list[dict]) -> str:
    [finding] = findings
    return finding["ProductFields"]["ash/target"]


_OPERATOR_SENDS = (*_OPERATOR_ENABLES, _OPERATOR_SCOPE)


@pytest.mark.unit
def test_ash_report_sends_with_the_operators_scope_not_the_repositorys(
    tmp_path, monkeypatch
):
    """The positive half of test_a_repository_config_cannot_turn_archiving_on:
    the repository asks for archiving and names its own scope; the operator's
    scope is the one the import carries, and nothing is archived."""
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: victim\n"
        "      archive_resolved_findings: true\n",
    )

    sent = _sent_by_ash_report(
        checkout, monkeypatch, config_overrides=_OPERATOR_SENDS, archives=False
    )

    assert _scope_of(sent) == "operator-scope"


@pytest.mark.unit
def test_ash_report_archives_when_the_operators_overrides_ask(tmp_path, monkeypatch):
    """The positive half of
    test_the_operators_overrides_set_both_whatever_the_repository_says."""
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: victim\n"
        "      archive_resolved_findings: false\n",
    )

    sent = _sent_by_ash_report(
        checkout,
        monkeypatch,
        config_overrides=(
            *_OPERATOR_SENDS,
            "reporters.aws-security-hub.options.archive_resolved_findings=true",
        ),
        archives=True,
    )

    assert _scope_of(sent) == "operator-scope"


@pytest.mark.unit
def test_ash_report_takes_an_underscore_override_of_the_only_section(
    tmp_path, monkeypatch
):
    """The send for test_an_underscore_override_of_the_only_section_is_the_operators:
    underscore-spelled overrides of the one aws-security-hub section are the
    operator's, so they decide the scope and archiving the import uses."""
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      archive_resolved_findings: false\n"
        "      findings_scope: victim\n",
    )

    sent = _sent_by_ash_report(
        checkout,
        monkeypatch,
        config_overrides=tuple(_underscore_overrides()),
        archives=True,
    )

    assert _scope_of(sent) == "op"


@pytest.mark.unit
def test_ash_report_sends_to_the_overrides_section_beside_a_decoy(
    tmp_path, monkeypatch
):
    """The positive half of
    test_a_decoy_section_does_not_carry_the_operators_overrides_to_the_payload:
    with the overrides spelled as the section the reporter reads, they reach
    it, and the import carries the operator's scope, not the payload's."""
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        "      archive_resolved_findings: true\n"
        "      findings_scope: victim\n"
        "  aws_security_hub:\n"
        "    options: {}\n",
    )

    sent = _sent_by_ash_report(
        checkout, monkeypatch, config_overrides=_OPERATOR_SENDS, archives=False
    )

    assert _scope_of(sent) == "operator-scope"


@pytest.mark.unit
def test_ash_report_sends_with_the_operators_scope_past_a_linked_config(
    tmp_path, monkeypatch
):
    """The positive half of
    test_a_discovered_config_that_links_out_of_the_tree_is_confined."""
    payload = _payload_outside(tmp_path)
    checkout = tmp_path / "checkout"
    (checkout / ".ash").mkdir(parents=True)
    _symlink_or_skip(checkout / ".ash" / ".ash.yaml", payload)

    sent = _sent_by_ash_report(
        checkout, monkeypatch, config_overrides=_OPERATOR_SENDS, archives=False
    )

    assert _scope_of(sent) == "operator-scope"


@pytest.mark.unit
def test_ash_report_sends_with_the_overrides_beside_a_config_outside_the_tree(
    tmp_path, monkeypatch
):
    """With a --config outside the tree, the operator's overrides set the scope
    and turn archiving on, and both reach the import. The overrides are the
    operator's wherever the file is, so the scope the file names is not the one
    sent."""
    payload = _payload_outside(tmp_path)
    checkout = tmp_path / "checkout"
    (checkout / ".ash").mkdir(parents=True)

    sent = _sent_by_ash_report(
        checkout,
        monkeypatch,
        config=payload,
        config_overrides=(
            *_OPERATOR_SENDS,
            "reporters.aws-security-hub.options.archive_resolved_findings=true",
        ),
        archives=True,
    )

    assert _scope_of(sent) == "operator-scope"


@pytest.mark.unit
def test_the_scans_report_phase_sends_with_the_operators_scope(tmp_path):
    """The positive send through a scan's own report phase, from the config the
    scan discovers in the checkout. The repository's .ash/.ash.yaml asks for
    archiving and names its own scope; the operator's overrides turn the reporter
    on and set the scope. The import carries the operator's scope, and nothing
    is archived: GetFindings is never answered, so archiving the repository's
    file asked for fails the stubber. ash report confines every --config it is
    given, so this is the send that shows a scan judging its discovered file."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.phases.report_phase import ReportPhase
    from automated_security_helper.core.progress import LiveProgressDisplay

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: victim\n"
        "      archive_resolved_findings: true\n",
    )
    mark_git_checkout(checkout)
    config = resolve_config(
        source_dir=checkout,
        config_overrides=[_AWS_PLUGINS, *_OPERATOR_SENDS],
    )
    model = _model([_result()], completed=("bandit",))
    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    queries = _Capture(securityhub, "GetFindings")
    # The phase checks the reporter's dependencies first: DescribeHub, and
    # GetCallerIdentity with no account_id set; the import asks STS again.
    stub.add_response(
        "describe_hub",
        {"HubArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default"},
    )
    stub.add_response("batch_import_findings", _ok(1))
    sts, sts_stub = _stubbed_client("sts")
    sts_stub.add_response("get_caller_identity", _caller(ACCOUNT))
    sts_stub.add_response("get_caller_identity", _caller(ACCOUNT))
    clients = {"securityhub": securityhub, "sts": sts}
    output_dir = checkout / ".ash" / "ash_output"
    context = PluginContext(
        source_dir=checkout,
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=config,
    )
    phase = ReportPhase(
        plugins=[SecurityHubReporter],
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=model,
    )

    with patch.object(
        securityhub_module.boto3, "Session", lambda **_: _FixedClientSession(clients)
    ):
        phase._execute_phase(
            report_dir=output_dir / "reports",
            aggregated_results=model,
            python_based_plugins_only=False,
        )

    stub.assert_no_pending_responses()
    assert queries.requests == []
    assert _scope_of(imports.findings) == "operator-scope"


@pytest.mark.unit
def test_a_repository_config_cannot_turn_archiving_on(tmp_path, caplog):
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      archive_resolved_findings: true\n",
    )
    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            source_dir=checkout, config_overrides=[*_OPERATOR_ENABLES, _OPERATOR_SCOPE]
        )
    reporter = _reporter_from(config, tmp_path)

    assert reporter.config.options.archive_resolved_findings is False
    assert reporter.config.options.findings_scope == "operator-scope"
    [warning] = _operator_only_warnings(caplog)
    assert "reporters.aws-security-hub.options.archive_resolved_findings" in warning
    assert ".options.findings_scope" not in warning
    assert ".ash.yaml" in warning
    assert "--config-overrides" in warning
    assert "a config file outside the tree" in warning

    # Only the import: a GetFindings call, or an archive record in the import,
    # would not match what the Stubber expects.
    securityhub, stub = _stubbed_client("securityhub")
    queries = _Capture(securityhub, "GetFindings")
    imports = _Capture(securityhub)
    stub.add_response("batch_import_findings", _ok(1))
    document = json.loads(
        _report_with(
            reporter,
            _model([_result()], completed=("bandit",)),
            {"securityhub": securityhub},
        )
    )

    stub.assert_no_pending_responses()
    assert queries.requests == []
    assert [f["RecordState"] for f in imports.findings] == ["ACTIVE"]
    assert document["archived"] == 0


@pytest.mark.unit
def test_a_repository_findings_scope_leaves_it_unset_and_refused(tmp_path, caplog):
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: someone-elses-repo\n",
    )
    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=checkout, config_overrides=_OPERATOR_ENABLES)
    reporter = _reporter_from(config, tmp_path)
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))

    assert reporter.config.options.findings_scope is None
    [warning] = _operator_only_warnings(caplog)
    assert "findings_scope" in warning
    with patch.object(securityhub_module.boto3, "Session", session):
        with pytest.raises(
            SecurityHubImportError,
            match="reporters.aws-security-hub.options.findings_scope",
        ):
            reporter.report(_model([_result()], completed=("bandit",)))
    session.assert_not_called()


@pytest.mark.parametrize("archive", [True, False])
@pytest.mark.unit
def test_the_operators_overrides_set_both_whatever_the_repository_says(
    tmp_path, caplog, archive
):
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        f"      archive_resolved_findings: {str(not archive).lower()}\n"
        "      findings_scope: someone-elses-repo\n",
    )
    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            source_dir=checkout,
            config_overrides=[
                *_OPERATOR_ENABLES,
                _OPERATOR_SCOPE,
                (
                    "reporters.aws-security-hub.options.archive_resolved_findings="
                    f"{str(archive).lower()}"
                ),
            ],
        )
    options = _reporter_from(config, tmp_path).config.options

    assert options.findings_scope == "operator-scope"
    assert options.archive_resolved_findings is archive
    assert _operator_only_warnings(caplog) == []


@pytest.mark.unit
def test_a_config_file_outside_the_tree_sets_both(tmp_path, caplog):
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: someone-elses-repo\n",
    )
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: operator-scope\n"
        "      archive_resolved_findings: true\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
    options = _reporter_from(config, tmp_path).config.options

    assert options.findings_scope == "operator-scope"
    assert options.archive_resolved_findings is True
    assert _operator_only_warnings(caplog) == []


@pytest.mark.parametrize(
    "op,below,value",
    [
        ("replace", "", "patched-scope"),
        ("remove", "", None),
        ("test", "", "base-scope"),
        ("replace", "/0", "patched-scope"),
    ],
    ids=["replace", "remove", "test", "below-it"],
)
@pytest.mark.unit
def test_a_repository_patch_at_a_scope_left_out_of_its_base_still_loads(
    tmp_path, caplog, op, below, value
):
    """The repository's .ash/.ash.yaml extends its own base, which sets the
    scope, and patches it. The base's scope is left out before the patch
    applies, so the place the patch names is not in the document: the file
    still loads, as it would without the trust rules (a replace or a test of
    the scope, a remove of it, or a replace inside it), the scope is not what
    the repository's files wrote, and one warning charges them."""
    from automated_security_helper.config.resolve_config import resolve_config

    scope = "[base-scope]" if below else "base-scope"
    checkout = _checkout_with_config(
        tmp_path,
        "extends: base.yaml\n"
        "patch:\n"
        f"  - op: {op}\n"
        f"    path: /reporters/aws-security-hub/options/findings_scope{below}\n"
        + ("" if value is None else f"    value: {value}\n"),
    )
    (checkout / ".ash" / "base.yaml").write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        f"      findings_scope: {scope}\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=checkout)
    options = _reporter_from(config, tmp_path).config.options

    assert options.findings_scope not in ("base-scope", "patched-scope", ["base-scope"])
    [warning] = _operator_only_warnings(caplog)
    assert ".ash.yaml" in warning, warning
    assert "findings_scope" in warning, warning


@pytest.mark.parametrize("repository", ["leaves-them-alone", "sets-them"])
@pytest.mark.unit
def test_an_operator_file_keeps_both_over_a_repository_base(
    tmp_path, caplog, repository
):
    """The operator's file outside the tree sets both options and extends the
    repository's .ash/.ash.yaml, which either names neither or sets both; the
    operator's file is merged over it either way. Both are the operator's, and
    no warning charges the repository's file."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "project_name: checkout\n"
        if repository == "leaves-them-alone"
        else "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: someone-elses-repo\n"
        "      archive_resolved_findings: false\n",
    )
    # Beside the checkout, so its bases may be read from inside it.
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: operator-scope\n"
        "      archive_resolved_findings: true\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
    options = _reporter_from(config, tmp_path).config.options

    assert options.findings_scope == "operator-scope"
    assert options.archive_resolved_findings is True
    assert _operator_only_warnings(caplog) == []


@pytest.mark.unit
def test_the_reporter_runs_with_the_operator_s_config_that_extends_the_repository_s(
    tmp_path, caplog
):
    """An operator's --config outside the tree extends the repository's file
    and sets the reporter up. The section the reporter runs with
    (reporter_section) is that file's: the operator wrote it, so nothing is
    ignored and no warning charges the repository's file, which wrote none of
    it."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: operator-scope\n"
        "      archive_resolved_findings: true\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert section is not None, section
    assert section.get("enabled") is True, section
    options = section.get("options") or {}
    assert options.get("findings_scope") == "operator-scope", options
    assert options.get("archive_resolved_findings") is True, options
    assert _security_hub_warnings(caplog) == []


@pytest.mark.unit
def test_what_the_repository_s_base_wrote_inside_the_section_does_not_run(
    tmp_path, caplog
):
    """The same chain, with the repository's file writing its own key inside
    the reporter's section (aws_profile, not an operator-only option). The
    reporter sends findings off the host, so it runs with the operator's
    section, without that key, and one warning names the repository's file."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      aws_profile: repository-profile\n",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        "      findings_scope: operator-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "operator-scope", options
    assert "aws_profile" not in options, options
    [warning] = _security_hub_warnings(caplog)
    assert ".ash.yaml" in warning, warning
    assert "operator.yaml" not in warning, warning


@pytest.mark.unit
def test_an_override_sets_the_section_past_the_operator_s_own_file(tmp_path, caplog):
    """--config-overrides is the operator's strongest surface: with the same
    extends chain, an override of the scope beats the operator file's own
    value in the section the reporter runs with."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        "      findings_scope: operator-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            config_path=operator,
            source_dir=checkout,
            config_overrides=[
                "reporters.aws-security-hub.options.findings_scope=override-scope"
            ],
        )
        section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "override-scope", options
    assert _security_hub_warnings(caplog) == []


_REPOSITORY_CHOSE = "repository-chose-this"


def _base_the_repository_chose(tmp_path: Path, where: str) -> Path:
    """A config file outside the scanned tree that sets both off-host
    reporters up with values of the repository's choosing: beside the
    checkout, or in another checkout."""
    if where == "outside":
        base = tmp_path / "elsewhere.yaml"
    else:
        other = tmp_path / "other"
        mark_git_checkout(other)
        (other / ".ash").mkdir()
        base = other / ".ash" / ".ash.yaml"
    base.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        f"      aws_profile: {_REPOSITORY_CHOSE}\n"
        f"      findings_scope: {_REPOSITORY_CHOSE}\n"
        "  s3:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      bucket_name: {_REPOSITORY_CHOSE}\n",
        encoding="utf-8",
    )
    return base


@pytest.mark.parametrize("where", ["outside", "another-checkout"])
@pytest.mark.unit
def test_a_base_the_repository_s_file_reaches_is_the_repository_s(
    tmp_path, caplog, where
):
    """The operator's --config outside the tree extends the repository's
    .ash/.ash.yaml, which says only `extends:` a file outside the tree (beside
    it, or in another checkout). That base is reached through the
    repository's file, so the repository chose it, whatever directory it sits
    in: neither off-host reporter is turned on, and nothing it wrote is in the
    section either runs with."""
    import os

    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
    )

    base = _base_the_repository_chose(tmp_path, where)
    checkout = _checkout_with_config(
        tmp_path,
        "extends: "
        + Path(os.path.relpath(base, tmp_path / "checkout" / ".ash")).as_posix()
        + "\n",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "project_name: operator\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        hub = reporter_section(config, SecurityHubReporter)
        s3 = reporter_section(config, S3Reporter)

    # The control: the base was merged, and the destination step then held the
    # resolved sections to the operator's (_confine_enabled in
    # config/reporter_trust.py), naming the enabled it replaced; so the base's
    # setup reached the resolution and was ignored, not missed.
    resolved = config.get_plugin_config(plugin_type="reporter", plugin_name="s3")
    assert (resolved or {}).get("enabled") is False, resolved
    assert any(
        "reporters.s3.enabled" in record.getMessage() for record in caplog.records
    ), caplog.text
    for section in (hub, s3):
        assert (section or {}).get("enabled") is not True, section
        assert _REPOSITORY_CHOSE not in json.dumps(section or {}), section
    # The warnings charge the repository's file the chain came through (the
    # destination step names the region, profile and enabled it replaced,
    # config/reporter_trust.py; the settle step names the scope,
    # config/operator_only_options.py), and what they say is ignored is in
    # fact not what runs (checked above), never the operator's file or the
    # base's value.
    warnings = _security_hub_warnings(caplog)
    assert warnings
    for warning in warnings:
        assert ".ash.yaml" in warning, warning
        assert "operator.yaml" not in warning, warning
        assert _REPOSITORY_CHOSE not in warning, warning


@pytest.mark.parametrize("spelling", ["aws_security_hub", "AWS-Security-Hub"])
@pytest.mark.unit
def test_the_operator_s_file_folds_onto_the_trusted_base_s_spelling(
    tmp_path, monkeypatch, caplog, spelling
):
    """ASH_CONFIG's file turns the reporter on under `aws-security-hub`; the
    operator's --config, outside the tree too, extends the repository's file
    and sets the scope under another spelling of the same section. The two
    are one section, as the chain's own merge folds them: the reporter runs
    with both files' settings, and no warning blames the repository."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    named = tmp_path / "ash-config.yaml"
    named.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        f"  {spelling}:\n"
        "    options:\n"
        "      findings_scope: operator-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is True, section
    options = (section or {}).get("options") or {}
    assert options.get("aws_region") == REGION, options
    assert options.get("findings_scope") == "operator-scope", options
    assert _security_hub_warnings(caplog) == []


@pytest.mark.unit
def test_a_spelling_that_names_another_plugin_does_not_fold(tmp_path, monkeypatch):
    """The fold onto the trusted base's spelling takes only a section the
    reporter would read as its own. `bedrock-summary-repo_rter` folds to the
    same letters as `bedrock-summary-reporter` but is not the Bedrock
    reporter's section (the separator splits the type word the plugin name
    drops), so the operator file's `enabled: false` there does not land on
    the trusted base's section."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporter,
    )

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    named = tmp_path / "ash-config.yaml"
    named.write_text(
        "reporters:\n  bedrock-summary-reporter:\n    enabled: true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n  bedrock-summary-repo_rter:\n    enabled: false\n",
        encoding="utf-8",
    )

    config = resolve_config(config_path=operator, source_dir=checkout)
    section = reporter_section(config, BedrockSummaryReporter)

    assert (section or {}).get("enabled") is True, section


@pytest.mark.unit
def test_the_operator_s_root_wins_over_the_operator_s_own_base(tmp_path, caplog):
    """The operator's --config extends an operator base outside the tree,
    which extends the repository's file. Both operator files set the scope:
    the section the reporter runs with merges them in chain order, so the
    root's value wins and the base's other settings stay."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    base = tmp_path / "operator-base.yaml"
    base.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: base-scope\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {base.as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: root-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is True, section
    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "root-scope", options
    assert options.get("aws_region") == REGION, options
    assert _security_hub_warnings(caplog) == []


@pytest.mark.unit
def test_two_trusted_spellings_keep_a_third_spelling_s_write_its_own(
    tmp_path, monkeypatch, caplog
):
    """ASH_CONFIG's file, outside the tree, writes the section under two
    spellings the configuration folds together; the operator's --config
    extends the repository's file and writes the scope under a third. The
    scope is the operator's own file's write, so the reporter runs with it,
    whatever spelling that file chose, merged over the trusted base's first
    section; the second trusted spelling's region stays out."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    named = tmp_path / "ash-config.yaml"
    named.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "  AWS_Security_Hub:\n"
        "    options:\n"
        "      aws_region: eu-west-1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n  aws_security_hub:\n    options:\n"
        "      findings_scope: operator-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is True, section
    options = (section or {}).get("options") or {}
    assert options.get("aws_region") == REGION, options
    assert options.get("findings_scope") == "operator-scope", options
    assert "eu-west-1" not in json.dumps(section or {}), section


@pytest.mark.unit
def test_a_shared_base_the_operator_reaches_through_its_own_base_runs(tmp_path, caplog):
    """The operator's --config extends two bases in one ``extends`` list: an
    operator base outside the tree, then the repository's file. Both extend
    the same shared file outside the tree. The operator reached the shared
    file through its own base, so what it wrote runs, as when the operator
    names it directly; reaching it through the repository's file too does not
    take that back. The multi-entry list means the chain's tree rebuilds only
    when each entry counts as its own subtree."""
    import os

    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    shared = tmp_path / "shared.yaml"
    shared.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: shared-file-wrote-this\n",
        encoding="utf-8",
    )
    checkout = _checkout_with_config(
        tmp_path,
        "extends: "
        + Path(os.path.relpath(shared, tmp_path / "checkout" / ".ash")).as_posix()
        + "\n",
    )
    op_base = tmp_path / "operator-base.yaml"
    op_base.write_text(f"extends: {shared.as_posix()}\n", encoding="utf-8")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "extends:\n"
        f"  - {op_base.as_posix()}\n"
        f"  - {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "project_name: operator\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is True, section
    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "shared-file-wrote-this", options
    assert options.get("aws_region") == REGION, options


@pytest.mark.unit
def test_a_repository_file_that_names_its_base_twice_still_confines_it(
    tmp_path, caplog
):
    """The repository's file extends the same shared file twice in one
    ``extends`` list. Every occurrence came through the repository's file, so
    nothing the shared file wrote runs, and the warnings charge the
    repository's file: a repeated entry counts as two subtrees, not one."""
    import os

    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    shared = tmp_path / "shared.yaml"
    shared.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        f"      findings_scope: {_REPOSITORY_CHOSE}\n",
        encoding="utf-8",
    )
    rel = Path(os.path.relpath(shared, tmp_path / "checkout" / ".ash")).as_posix()
    checkout = _checkout_with_config(
        tmp_path,
        f"extends:\n  - {rel}\n  - {rel}\n",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "project_name: operator\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is not True, section
    assert _REPOSITORY_CHOSE not in json.dumps(section or {}), section
    # One warning per confinement step that ignored something, each charging
    # the repository's file, never the operator's file or the shared value.
    warnings = _security_hub_warnings(caplog)
    assert warnings
    for warning in warnings:
        assert ".ash.yaml" in warning, warning
        assert "operator.yaml" not in warning, warning
        assert _REPOSITORY_CHOSE not in warning, warning


@pytest.mark.parametrize(
    "op_line,expected_tags",
    [
        pytest.param(
            "  - op: add\n    path: /reporters/aws-security-hub/options/tags/-\n    value: appended\n",
            ["written", "appended"],
            id="append-to-a-held-list",
        ),
        pytest.param(
            "  - op: replace\n    path: /reporters/aws-security-hub/options/tags/0\n    value: replaced\n",
            ["replaced"],
            id="replace-an-index-in-a-held-list",
        ),
        pytest.param(
            "  - op: add\n    path: /reporters/aws-security-hub/options/absent/-\n    value: appended\n",
            ["written"],
            id="append-to-a-list-only-the-repository-wrote",
        ),
    ],
)
@pytest.mark.unit
def test_an_operator_patch_with_an_array_pointer_applies_only_to_a_held_list(
    tmp_path, caplog, op_line, expected_tags
):
    """An operator file's patch op with an array pointer (a final ``-`` or an
    index) applies to the view where the view itself holds the place: the
    list is the operator's own writes, so the reporter runs with the element
    appended or replaced, exactly as the resolved section has it. Where the
    view does not hold the place -- a list only the repository's file wrote
    -- the op is dropped, erring toward the trusted base, and no mapping
    stands in for a list."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "project_name: checkout\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      absent:\n"
        "        - repository-wrote-this\n",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      tags:\n"
        "        - written\n"
        "patch:\n" + op_line,
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert isinstance(options.get("tags"), list), options
    assert options.get("tags") == expected_tags, options
    assert not isinstance(options.get("absent"), dict), options
    if "appended" not in expected_tags:
        assert "appended" not in json.dumps(options), options


@pytest.mark.unit
def test_an_operator_patch_stepping_through_a_held_list_applies(tmp_path, caplog):
    """A patch op whose pointer steps through a list the operator's own file
    wrote (an index mid-path, a key after it) applies to the view as it
    applied to the full document: the element is the operator's own, so the
    reporter runs with the operator's change, and the list is never
    rewritten into mappings keyed by the index."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      tags:\n"
        "        - name: written\n"
        "patch:\n"
        "  - op: replace\n"
        "    path: /reporters/aws-security-hub/options/tags/0/name\n"
        "    value: changed\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert options.get("tags") == [{"name": "changed"}], options


@pytest.mark.unit
def test_an_operator_patch_removing_a_held_list_element_removes_it(tmp_path, caplog):
    """A ``remove`` with an index into a list the operator's own file wrote
    takes the element out of the view, as it did out of the full document:
    the reporter runs without a value the operator removed."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      tags:\n"
        "        - written\n"
        "        - extra\n"
        "patch:\n"
        "  - op: remove\n"
        "    path: /reporters/aws-security-hub/options/tags/1\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert options.get("tags") == ["written"], options
    assert "extra" not in json.dumps(options), options


@pytest.mark.unit
def test_a_middle_index_into_a_list_only_the_repository_wrote_is_dropped(
    tmp_path, caplog
):
    """A patch op whose pointer steps through an index of a list the view
    does not hold (the repository's file wrote it) applies to the full
    document and is dropped from the view: no mapping keyed by the index is
    invented on the way to the place."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "project_name: checkout\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      absent:\n"
        "        - name: repository-wrote-this\n",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/aws-security-hub/options/absent/0/name\n"
        "    value: changed\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert not isinstance(options.get("absent"), dict), options
    assert "changed" not in json.dumps(options), options


@pytest.mark.unit
def test_a_whole_reporters_patch_value_folds_onto_the_trusted_spelling(
    tmp_path, monkeypatch, caplog
):
    """An operator file replaces all of ``/reporters`` with a patch whose
    value spells the section another way than the trusted base does. The
    value's keys fold as a direct write's do, so the operator's disable
    lands on the section the reporter reads -- never beside it, where the
    exact-spelling lookup would read the trusted base's enable and the
    reporter would run against the operator's word."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    named = tmp_path / "ash-config.yaml"
    named.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters\n"
        "    value:\n"
        "      AwsSecurityHub:\n"
        "        enabled: false\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is False, section


@pytest.mark.unit
def test_a_patch_created_section_anchors_the_fold_for_later_files(tmp_path, caplog):
    """The deepest owned base creates the section with a patch op; the root
    file writes it under another spelling. The patch's spelling anchors the
    fold as a direct write's does, so the root's word -- the operator's last
    -- decides, instead of standing beside the patch-created key where the
    exact-spelling lookup would read the base's enable."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path, "project_name: checkout\nreporters: {}\n"
    )
    base = tmp_path / "base.yaml"
    base.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/aws-security-hub\n"
        "    value:\n"
        "      enabled: true\n"
        "      options:\n"
        f"        aws_region: {REGION}\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {base.as_posix()}\n"
        "reporters:\n  AwsSecurityHub:\n    enabled: false\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is False, section


@pytest.mark.unit
def test_a_digit_mapping_key_in_a_patch_lands_on_a_held_mapping(tmp_path, caplog):
    """A pointer segment of digits names a mapping key where the view holds a
    mapping there ("404" under a dict the operator's own file wrote): the op
    applies through jsonpatch, which reads a dict parent's segment as its
    key, so a real digit key is set -- never dropped as if it were a list
    index."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      codes:\n"
        "        catch: kept\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/aws-security-hub/options/codes/404\n"
        "    value: page\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert options.get("codes") == {"catch": "kept", "404": "page"}, options


@pytest.mark.parametrize(
    "written",
    [
        pytest.param("tags: abc", id="a-string"),
        pytest.param("tags: !!binary YWJj", id="bytes-from-a-binary-tag"),
    ],
)
@pytest.mark.unit
def test_a_remove_at_an_index_the_view_holds_a_string_at_is_dropped(
    tmp_path, caplog, written
):
    """A remove whose pointer indexes into a value the operator view holds as
    a scalar: the operator's own file writes the option as text (or YAML
    !!binary bytes), the repository's file writes a list, and later-wins
    gives the full document the list, so the real patch removes its first
    element. The view skips the repository's file and holds the scalar,
    where jsonpatch's delete raises a bare TypeError -- the op drops there
    like any other pointer that does not fit the view, and nothing here
    refuses the configuration. (With the SAME scalar in the full document,
    the real patch's TypeError is the chain's named refusal, so the load
    refuses either way and the view never decides.)"""
    from automated_security_helper.config.resolve_config import resolve_config
    from tests.utils.helpers import mark_git_checkout

    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "reporters:\n  foo:\n    options:\n      tags: [x, y]\n", encoding="utf-8"
    )
    own = tmp_path / "a.yaml"
    own.write_text(
        f"project_name: op\nreporters:\n  foo:\n    options:\n      {written}\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends:\n  - {own.as_posix()}\n  - {repository.as_posix()}\n"
        "patch:\n  - op: remove\n    path: /reporters/foo/options/tags/0\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)

    resolved = config.get_plugin_config(plugin_type="reporter", plugin_name="foo")
    assert ((resolved or {}).get("options") or {}).get("tags") == ["y"], resolved


@pytest.mark.unit
def test_an_operator_s_own_array_op_is_not_blamed_on_the_repository(tmp_path, caplog):
    """The operator appends to its own list through a patch; the repository
    wrote nothing for the section, so the view applies the op and no warning
    names the repository's file."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      tags:\n        - written\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/aws-security-hub/options/tags/-\n"
        "    value: appended\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert options.get("tags") == ["written", "appended"], options
    blamed = [
        record.getMessage()
        for record in caplog.records
        if "Ignoring reporters.aws-security-hub" in record.getMessage()
    ]
    assert not blamed, blamed


@pytest.mark.unit
def test_a_mid_path_dash_step_lands_on_the_written_mapping(tmp_path, caplog):
    """A patch pointer whose dash-spelled step sits in the MIDDLE (a key
    under it follows): the fold applies at every dict step, so a replace at
    options/code-map/kept lands on the written code_map's entry."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      code_map:\n        kept: before\n"
        "patch:\n"
        "  - op: replace\n"
        "    path: /reporters/aws-security-hub/options/code-map/kept\n"
        "    value: after\n",
        encoding="utf-8",
    )

    config = resolve_config(config_path=operator, source_dir=checkout)
    section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert options.get("code_map") == {"kept": "after"}, options
    assert "code-map" not in options, options


@pytest.mark.unit
def test_a_dash_spelled_step_before_an_index_lands_on_the_written_list(tmp_path):
    """A patch pointer that holds an index also matches its DICT steps against
    the view's own spelling: a remove at options/some-list/1 where the
    operator's file writes some_list removes the written list's entry, as
    the full document's patch does -- not dropped as a misfit, which left
    the view holding the operator's UNPATCHED list (an entry the operator
    removed, kept), against "every drop errs toward the trusted base"."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      some_list: [x, y, z]\n"
        "patch:\n"
        "  - op: remove\n"
        "    path: /reporters/aws-security-hub/options/some-list/1\n",
        encoding="utf-8",
    )

    config = resolve_config(config_path=operator, source_dir=checkout)
    section = reporter_section(config, SecurityHubReporter)

    resolved = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )
    assert ((resolved or {}).get("options") or {}).get("some_list") == ["x", "z"]
    options = (section or {}).get("options") or {}
    assert options.get("some_list") == ["x", "z"], options


def _dash_spelled_option_patch(tmp_path):
    """An operator patch replacing options/findings-scope, dash-spelled, over a
    section whose own file wrote findings_scope."""
    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: scope-a\n"
        "patch:\n"
        "  - op: replace\n"
        "    path: /reporters/aws-security-hub/options/findings-scope\n"
        "    value: scope-b\n",
        encoding="utf-8",
    )
    return checkout, operator


@pytest.mark.unit
def test_an_option_segment_spelled_with_a_dash_lands_on_the_written_option(
    tmp_path, caplog
):
    """The full document matches each pointer segment "-" against "_"
    (_normalize_pointer), so the operator view's walk does too: a replace at
    options/findings-scope replaces the written findings_scope in the section
    the reporter runs with, and leaves no second, dash-spelled key beside
    it."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout, operator = _dash_spelled_option_patch(tmp_path)

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    resolved = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )
    assert ((resolved or {}).get("options") or {}).get("findings_scope") == "scope-b"
    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "scope-b", options
    assert "findings-scope" not in options, options


@pytest.mark.unit
def test_the_reporter_model_builds_from_the_view_with_the_patched_scope(
    tmp_path, caplog
):
    """What the reporter is built from: report_phase passes the section to the
    plugin class, whose options model refuses keys it does not declare. The
    view after a dash-spelled option patch builds, with the operator's
    patched scope -- a view holding both spellings would be refused here."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout, operator = _dash_spelled_option_patch(tmp_path)

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    built = SecurityHubReporterConfig.model_validate(section)
    assert built.options.findings_scope == "scope-b", built


@pytest.mark.unit
def test_an_operator_patch_pointer_unescapes_tilde_sequences(tmp_path, caplog):
    """A patch pointer's ``~1`` and ``~0`` are JSON-Pointer escapes for ``/``
    and ``~``: the operator view lands the op at the literal key, the same
    place the full document's patch wrote it."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/aws-security-hub/options/a~1b~0c\n"
        "    value: slashed\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    options = (section or {}).get("options") or {}
    assert options.get("a/b~c") == "slashed", options


@pytest.mark.unit
def test_an_operator_patch_remove_takes_only_what_the_view_holds(tmp_path, caplog):
    """A ``remove`` of a place the operator's own files wrote takes it out of
    the view. One aimed at a place only the repository's file wrote exists on
    the full document, so the real patch applies, and the view -- which never
    held it -- drops the op instead of failing."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "project_name: checkout\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      repo_only: repository-wrote-this\n",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: operator-scope\n"
        "patch:\n"
        "  - op: remove\n"
        "    path: /reporters/aws-security-hub/options/findings_scope\n"
        "  - op: remove\n"
        "    path: /reporters/aws-security-hub/options/repo_only\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is True, section
    options = (section or {}).get("options") or {}
    assert "findings_scope" not in options, options
    assert "repository-wrote-this" not in json.dumps(options), options


@pytest.mark.unit
def test_colliding_spellings_fold_in_chain_order_not_first_appearance(
    tmp_path, monkeypatch, caplog
):
    """ASH_CONFIG's trusted file holds the section, and three operator files
    write it: the deepest base under the trusted spelling (enabled false),
    the middle base under another (enabled true), the root under the trusted
    one again (enabled false). The chain's order decides: the root's file is
    the operator's last word, so the reporter runs with enabled false -- not
    with the middle base's true riding a fold that merged by where each
    spelling first appeared in the chain's merge."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    named = tmp_path / "ash-config.yaml"
    named.write_text(
        f"reporters:\n  aws-security-hub:\n    options:\n      aws_region: {REGION}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    base_a = tmp_path / "base-a.yaml"
    base_a.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n  aws-security-hub:\n    enabled: false\n    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: base-scope\n",
        encoding="utf-8",
    )
    base_b = tmp_path / "base-b.yaml"
    base_b.write_text(
        f"extends: {base_a.as_posix()}\n"
        "reporters:\n  AwsSecurityHub:\n    enabled: true\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {base_b.as_posix()}\n"
        "reporters:\n  aws-security-hub:\n    enabled: false\n    options:\n"
        "      findings_scope: root-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is False, section
    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "root-scope", options
    assert options.get("aws_region") == REGION, options


@pytest.mark.unit
def test_a_null_section_under_another_spelling_takes_the_section_away(tmp_path, caplog):
    """One operator file writes the section and, under another spelling, a
    null section (a key with nothing after it). The null is the file's later
    word for the same section, so the fold takes it as written -- the load
    does not crash on it, and the reporter does not run with the earlier
    spelling's enabled true."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "  AwsSecurityHub:\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is not True, section


@pytest.mark.unit
def test_an_operator_patch_under_another_spelling_folds_onto_the_section(
    tmp_path, caplog
):
    """An operator file writes the section under one spelling and patches an
    option under another. The pointer's section segment folds as a direct
    write does, so the patched option lands in the section the reporter runs
    with instead of standing beside it under its own spelling."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/aws_security_hub/options/findings_scope\n"
        "    value: patched-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is True, section
    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "patched-scope", options


@pytest.mark.unit
def test_an_operator_patch_that_adds_the_reporters_section_runs(tmp_path, caplog):
    """The operator's --config extends the repository's file (which writes
    nothing for the section) and adds the whole ``reporters`` section with a
    ``patch`` op targeting /reporters. The patch is the operator's own file's,
    aimed at this section, so the reporter runs with it, as it does when the
    file writes the section directly."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters\n"
        "    value:\n"
        "      aws-security-hub:\n"
        "        enabled: true\n"
        "        options:\n"
        f"          aws_region: {REGION}\n"
        "          findings_scope: operator-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is True, section
    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "operator-scope", options
    assert options.get("aws_region") == REGION, options
    assert _security_hub_warnings(caplog) == []


@pytest.mark.unit
def test_an_operator_root_patch_sets_an_option_over_its_own_base(tmp_path, caplog):
    """The operator's --config extends an operator base that writes the
    section, and patches one option at /reporters/.../findings_scope. The op
    is the root file's own, so the section the reporter runs with holds the
    patched value over the base's, as a direct write of it would."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    base = tmp_path / "operator-base.yaml"
    base.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: base-scope\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {base.as_posix()}\n"
        "patch:\n"
        "  - op: replace\n"
        "    path: /reporters/aws-security-hub/options/findings_scope\n"
        "    value: root-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is True, section
    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "root-scope", options
    assert options.get("aws_region") == REGION, options
    assert _security_hub_warnings(caplog) == []


@pytest.mark.unit
def test_a_repository_patch_of_the_section_does_not_run(tmp_path, caplog):
    """The repository's file adds the section with its own ``patch`` op. A
    repository file's ops are the repository's choice, so nothing they write
    reaches the section the reporter runs with, and the warnings charge the
    repository's file."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "project_name: checkout\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters\n"
        "    value:\n"
        "      aws-security-hub:\n"
        "        enabled: true\n"
        "        options:\n"
        f"          aws_region: {REGION}\n"
        f"          findings_scope: {_REPOSITORY_CHOSE}\n",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "project_name: operator\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is not True, section
    assert _REPOSITORY_CHOSE not in json.dumps(section or {}), section
    # One warning per confinement step that ignored something, each charging
    # the repository's file, never the operator's file or the patched value.
    warnings = _security_hub_warnings(caplog)
    assert warnings
    for warning in warnings:
        assert ".ash.yaml" in warning, warning
        assert "operator.yaml" not in warning, warning
        assert _REPOSITORY_CHOSE not in warning, warning


@pytest.mark.parametrize("shape", ["empty-list", "single-string"])
@pytest.mark.unit
def test_the_chain_rebuild_counts_an_empty_list_and_a_single_string(
    tmp_path, caplog, shape
):
    """The extends tree is rebuilt from each file's own ``extends`` count, so
    the two counting shapes a mapping can hold besides a filled list are
    named here: a repository file whose ``extends`` is an empty list counts
    zero bases, and one whose ``extends`` is a single string counts one. The
    chain rebuilds either way, so the operator's own write still runs."""
    import os

    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    if shape == "empty-list":
        checkout = _checkout_with_config(tmp_path, "extends: []\n")
    else:
        shared = tmp_path / "shared.yaml"
        shared.write_text(
            "reporters:\n"
            "  aws-security-hub:\n"
            "    options:\n"
            f"      findings_scope: {_REPOSITORY_CHOSE}\n",
            encoding="utf-8",
        )
        rel = Path(os.path.relpath(shared, tmp_path / "checkout" / ".ash")).as_posix()
        checkout = _checkout_with_config(tmp_path, f"extends: {rel}\n")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        "      findings_scope: operator-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert (section or {}).get("enabled") is True, section
    options = (section or {}).get("options") or {}
    assert options.get("findings_scope") == "operator-scope", options
    assert _REPOSITORY_CHOSE not in json.dumps(section or {}), section
    assert not [
        record.getMessage()
        for record in caplog.records
        if "could not be rebuilt" in record.getMessage()
    ]


@pytest.mark.unit
def test_a_chain_that_cannot_be_rebuilt_says_so_and_takes_nothing(tmp_path, caplog):
    """A chain whose tree does not rebuild takes nothing as the operator's
    own -- and says so, naming the file and no value: silently reducing what
    the reporter runs with would hide a drift between this walk and the
    resolution's. The mismatch cannot be produced through a real load, whose
    one read fills *reads* for every chain file, so the walk is handed a
    chain its reads do not hold."""
    from automated_security_helper.config.resolve_config import (
        _operator_chain_occurrences,
    )

    file = tmp_path / "operator.yaml"
    file.write_text("project_name: operator\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        taken = _operator_chain_occurrences([file], [], {}, set())

    assert taken == []
    [warning] = [
        record.getMessage()
        for record in caplog.records
        if "could not be rebuilt" in record.getMessage()
    ]
    assert "operator.yaml" in warning, warning
    assert "operator-scope" not in warning, warning


@pytest.mark.unit
def test_a_rebuild_warning_names_an_environment_chosen_file_as_value(tmp_path, caplog):
    """The file the rebuild warning names can be one an ``extends`` entry chose
    with a value read from the environment -- the drift the warning exists for
    is likeliest exactly there. Such a file is named ``<value>``, as every
    other confinement warning names it, never by its real path."""
    from automated_security_helper.config.resolve_config import (
        _operator_chain_occurrences,
    )

    file = tmp_path / "env-chosen.yaml"
    file.write_text("project_name: env\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        taken = _operator_chain_occurrences([file], [], {}, {file})

    assert taken == []
    [warning] = [
        record.getMessage()
        for record in caplog.records
        if "could not be rebuilt" in record.getMessage()
    ]
    assert "env-chosen" not in warning, warning
    assert "<value>" in warning, warning


@pytest.mark.unit
def test_the_resolve_hands_the_chain_walk_the_environment_chosen_paths(
    tmp_path, monkeypatch, caplog
):
    """resolve_config passes the paths its ``extends`` entries read from the
    environment through to the operator-chain walk, so the rebuild warning
    can name such a file ``<value>``: the walk itself cannot know them, and a
    caller that forgets them is exactly how the real path leaked."""
    from automated_security_helper.config import resolve_config as module

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    base = tmp_path / "env-chosen-base.yaml"
    base.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n  aws-security-hub:\n    enabled: true\n    options:\n"
        f"      aws_region: {REGION}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_TEST_ENV_BASE", str(base))
    operator = tmp_path / "operator.yaml"
    operator.write_text("extends: ${ASH_TEST_ENV_BASE}\n", encoding="utf-8")

    handed: list = []
    real = module._with_operator_chain_reporters

    # The walk takes the count of scanned roots as well (``roots``); the spy
    # accepts what the resolve passes and hands it on unchanged.
    def spying(trusted, chain, repository_files, reads, environment_paths, roots=1):
        handed.append(set(environment_paths))
        return real(
            trusted, chain, repository_files, reads, environment_paths, roots=roots
        )

    monkeypatch.setattr(module, "_with_operator_chain_reporters", spying)
    with caplog.at_level(logging.WARNING):
        module.resolve_config(config_path=operator, source_dir=checkout)

    assert handed, "the operator-chain walk never ran"
    assert any(base in paths or base.resolve() in paths for paths in handed), handed


@pytest.mark.unit
def test_a_rebuild_warning_names_an_environment_chosen_file_by_resolved_path(
    tmp_path, caplog
):
    """The set holds the paths the resolution recorded; the chain can carry the
    same file by another spelling. It is judged by its resolved path too, so a
    link or a relative spelling does not put the real path back in the
    warning."""
    from automated_security_helper.config.resolve_config import (
        _operator_chain_occurrences,
    )

    file = tmp_path / "env-chosen.yaml"
    file.write_text("project_name: env\n", encoding="utf-8")
    spelled = tmp_path / "sub" / ".." / "env-chosen.yaml"

    with caplog.at_level(logging.WARNING):
        taken = _operator_chain_occurrences([spelled], [], {}, {file.resolve()})

    assert taken == []
    [warning] = [
        record.getMessage()
        for record in caplog.records
        if "could not be rebuilt" in record.getMessage()
    ]
    assert "env-chosen" not in warning, warning
    assert "<value>" in warning, warning


@pytest.mark.unit
def test_the_operator_s_file_merges_over_the_trusted_base_for_the_section(
    tmp_path, monkeypatch, caplog
):
    """ASH_CONFIG's file, outside the tree, turns the reporter on and sets its
    region; the operator's --config, outside the tree too, extends the
    repository's file and sets only the scope. The off-host section is the
    operator's configuration: the --config file's writes merged over the
    trusted base's."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    named = tmp_path / "ash-config.yaml"
    named.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(named))
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: operator-scope\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = reporter_section(config, SecurityHubReporter)

    assert section is not None, section
    assert section.get("enabled") is True, section
    options = section.get("options") or {}
    assert options.get("aws_region") == REGION, options
    assert options.get("findings_scope") == "operator-scope", options
    assert _security_hub_warnings(caplog) == []


_SCOPE_FROM_THE_ENVIRONMENT = "operator-scope-read-from-the-environment"


@pytest.mark.parametrize(
    "overrides",
    [[], ["reporters.aws-security-hub.enabled=true"]],
    ids=["no-override", "a-reporters-override"],
)
@pytest.mark.parametrize("option", ["findings_scope", "aws_profile"])
@pytest.mark.unit
def test_a_value_the_reporter_runs_with_from_the_environment_is_redacted(
    tmp_path, monkeypatch, option, overrides
):
    """ASH_CONFIG's file, outside the tree, sets the reporter up and reads one
    of its options from ${VAR}, and the repository's .ash/.ash.yaml is the
    scan's config file. The reporter sends findings off the host, so it runs
    with the operator's section (reporter_section), and the value is one a
    message of the scan can quote: the scan's configuration redacts it, an
    operator-only option or any other, with an override of the reporters
    replayed onto the operator's section or without one."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.utils.error_text import (
        config_environment_values,
    )

    monkeypatch.setenv("ASH_TEST_SH_OPTION", _SCOPE_FROM_THE_ENVIRONMENT)
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      aws_region: {REGION}\n"
        f"      {option}: ${{ASH_TEST_SH_OPTION}}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")

    config = resolve_config(source_dir=checkout, config_overrides=overrides)

    # The control: the reporter runs with the value the variable gave.
    section = reporter_section(config, SecurityHubReporter)
    assert section["options"][option] == _SCOPE_FROM_THE_ENVIRONMENT
    assert _SCOPE_FROM_THE_ENVIRONMENT in config_environment_values(config)


def _recorded_and_shown(config: AshConfig) -> list[dict[str, Any]]:
    """*config* as a results file records it (``ash_config``) and as `ash config
    get` shows it, before the YAML dump."""
    from automated_security_helper.config.environment_record import (
        record_environment_references,
    )

    recorded = json.loads(
        AshAggregatedResults(ash_config=config).model_dump_json(by_alias=True)
    )["ash_config"]
    shown = record_environment_references(
        config.model_dump(
            mode="json", by_alias=True, exclude_defaults=False, exclude_none=False
        ),
        config._displayed_environment_references,
    )
    return [recorded, shown]


_REPOSITORY_SCOPES = {
    "leaves-it-alone": None,
    "sets-it": "someone-elses-repo",
    "writes-the-same-reference": "${ASH_TEST_SH_SCOPE}",
}


@pytest.mark.parametrize("repository", list(_REPOSITORY_SCOPES))
@pytest.mark.unit
def test_an_operator_file_s_scope_read_from_the_environment_is_recorded_as_written(
    tmp_path, monkeypatch, repository
):
    """The operator's file outside the tree extends the repository's
    .ash/.ash.yaml, which names no scope, its own, or the same ${VAR}, and
    writes findings_scope as ${VAR}. The scope is the operator's and is kept, so
    the record of the configuration and what `ash config get` shows hold the
    reference there, as the operator's file wrote it, and not the value the
    variable gave."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_TEST_SH_SCOPE", _SCOPE_FROM_THE_ENVIRONMENT)
    scope = _REPOSITORY_SCOPES[repository]
    checkout = _checkout_with_config(
        tmp_path,
        "project_name: checkout\n"
        if scope is None
        else "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        f"      findings_scope: {scope}\n",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: ${ASH_TEST_SH_SCOPE}\n",
        encoding="utf-8",
    )

    config = resolve_config(config_path=operator, source_dir=checkout)

    # The control: the configuration holds the scope the variable gave.
    section = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )
    assert section["options"]["findings_scope"] == _SCOPE_FROM_THE_ENVIRONMENT
    for view in _recorded_and_shown(config):
        options = view["reporters"]["aws-security-hub"]["options"]
        assert options["findings_scope"] == "${ASH_TEST_SH_SCOPE}", options
        assert _SCOPE_FROM_THE_ENVIRONMENT not in json.dumps(view)


@pytest.mark.unit
def test_the_trusted_base_s_reference_is_recorded_where_its_scope_replaces_the_repository_s(
    tmp_path, monkeypatch
):
    """ASH_CONFIG's file, outside the tree, writes findings_scope as ${VAR},
    and the repository's file writes a scope of its own, which the scan
    ignores. The configuration holds the trusted base's scope, so the record
    and what `ash config get` show hold its reference, not the value the
    variable gave."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv("ASH_TEST_SH_SCOPE", _SCOPE_FROM_THE_ENVIRONMENT)
    monkeypatch.setenv(
        "ASH_CONFIG", str(_operator_file(tmp_path, "${ASH_TEST_SH_SCOPE}"))
    )
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: someone-elses-repo\n",
    )

    config = resolve_config(source_dir=checkout)

    section = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )
    assert section["options"]["findings_scope"] == _SCOPE_FROM_THE_ENVIRONMENT
    for view in _recorded_and_shown(config):
        options = view["reporters"]["aws-security-hub"]["options"]
        assert options["findings_scope"] == "${ASH_TEST_SH_SCOPE}", options
        assert _SCOPE_FROM_THE_ENVIRONMENT not in json.dumps(view)


@pytest.mark.parametrize("kept_by", ["override", "operator-file"])
@pytest.mark.unit
def test_a_trusted_reference_is_not_recorded_where_the_scope_is_kept(
    tmp_path, monkeypatch, kept_by
):
    """ASH_CONFIG's file, outside the tree and so the trusted base, writes
    findings_scope as ${VAR}. The repository's file writes a scope too, and the
    configuration keeps the operator's own instead: an override's, or that of
    the operator's --config outside the tree, which extends the repository's
    file. The operator typed the same text the variable holds, but read neither
    from it, so the record of the configuration and what `ash config get` shows
    hold the text, not the trusted base's reference: loaded again with another
    value in the variable, the record would name another scope."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv("ASH_TEST_SH_SCOPE", _SCOPE_FROM_THE_ENVIRONMENT)
    trusted = _operator_file(tmp_path, "${ASH_TEST_SH_SCOPE}")
    monkeypatch.setenv("ASH_CONFIG", str(trusted))
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: someone-elses-repo\n",
    )
    if kept_by == "override":
        config = resolve_config(
            source_dir=checkout,
            config_overrides=[
                "reporters.aws-security-hub.options.findings_scope="
                + _SCOPE_FROM_THE_ENVIRONMENT
            ],
        )
    else:
        operator = tmp_path / "operator.yaml"
        operator.write_text(
            f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
            "reporters:\n"
            "  aws-security-hub:\n"
            "    options:\n"
            f"      findings_scope: {_SCOPE_FROM_THE_ENVIRONMENT}\n",
            encoding="utf-8",
        )
        config = resolve_config(config_path=operator, source_dir=checkout)

    section = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )
    assert section["options"]["findings_scope"] == _SCOPE_FROM_THE_ENVIRONMENT
    for view in _recorded_and_shown(config):
        options = view["reporters"]["aws-security-hub"]["options"]
        assert options["findings_scope"] == _SCOPE_FROM_THE_ENVIRONMENT, options


@pytest.mark.unit
def test_confinement_returns_the_options_that_took_the_trusted_base_s_value(
    tmp_path, monkeypatch
):
    """A file in the tree writes detect-secrets' limit, findings_scope and
    archive_resolved_findings, and an override writes archive_resolved_findings.
    The confinement returns the limit and the scope, which took the trusted
    base's values, and not the option the override kept: resolve_config takes
    the trusted base's references for those it returns alone."""
    from automated_security_helper.config.operator_only_options import (
        RepositorySettings,
        confine_operator_only_options,
    )
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    override = "reporters.aws-security-hub.options.archive_resolved_findings=true"
    in_tree = tmp_path / "ash.yaml"
    in_tree.write_text(
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      max_worker_output_mib: 7\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: someone-elses-repo\n"
        "      archive_resolved_findings: true\n",
        encoding="utf-8",
    )
    repository = RepositorySettings([tmp_path])
    config = load_config_file_for_run(
        in_tree, confine=repository.confine, config_overrides=[override]
    )[1]

    settled = confine_operator_only_options(
        config,
        AshConfig(),
        [override],
        [in_tree],
        repository=repository,
        checkout_membership=False,
        mixed_membership=False,
        given_root_membership=False,
        undecided_membership=False,
    )

    assert settled == {
        ("scanners", "detect-secrets", "max_worker_output_mib"),
        ("reporters", "aws-security-hub", "findings_scope"),
    }


@pytest.mark.parametrize("kept_by", ["override", "operator-file"])
@pytest.mark.unit
def test_a_repository_reference_is_not_recorded_where_the_scope_is_kept(
    tmp_path, monkeypatch, kept_by
):
    """The repository's file writes findings_scope as ${VAR}, which the scan
    leaves out, and the operator's own scope is kept: an override's, or that of
    the operator's --config outside the tree, which extends the repository's
    file. The operator typed the same text the variable holds. The record and
    what `ash config get` show hold that text, not the repository's reference,
    and the configuration's reads from the environment hold no reference the
    repository's file wrote there."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_TEST_REPO_SCOPE", _SCOPE_FROM_THE_ENVIRONMENT)
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: ${ASH_TEST_REPO_SCOPE}\n",
    )
    if kept_by == "override":
        config = resolve_config(
            source_dir=checkout,
            config_overrides=[
                "reporters.aws-security-hub.options.findings_scope="
                + _SCOPE_FROM_THE_ENVIRONMENT
            ],
        )
    else:
        operator = tmp_path / "operator.yaml"
        operator.write_text(
            f"extends: {(checkout / '.ash' / '.ash.yaml').as_posix()}\n"
            "reporters:\n"
            "  aws-security-hub:\n"
            "    options:\n"
            f"      findings_scope: {_SCOPE_FROM_THE_ENVIRONMENT}\n",
            encoding="utf-8",
        )
        config = resolve_config(config_path=operator, source_dir=checkout)

    section = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )
    assert section["options"]["findings_scope"] == _SCOPE_FROM_THE_ENVIRONMENT
    for view in _recorded_and_shown(config):
        options = view["reporters"]["aws-security-hub"]["options"]
        assert options["findings_scope"] == _SCOPE_FROM_THE_ENVIRONMENT, options
    assert not [
        reference
        for reference in config._environment_references
        if reference.written == "${ASH_TEST_REPO_SCOPE}"
    ]


@pytest.mark.unit
def test_a_reference_from_a_repository_file_that_links_out_of_the_tree_is_not_recorded(
    tmp_path, monkeypatch
):
    """The repository's .ash/.ash.yaml is a link to a file outside the tree,
    which writes findings_scope as ${VAR}; the scan judges the file by the name
    it reached it through and leaves the scope out, and an override keeps the
    operator's, the same text. The reference names the file the link resolves
    to, and is still the repository's: neither the record nor the reads from
    the environment hold it."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_TEST_REPO_SCOPE", _SCOPE_FROM_THE_ENVIRONMENT)
    target = tmp_path / "elsewhere" / "linked.yaml"
    target.parent.mkdir()
    target.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: ${ASH_TEST_REPO_SCOPE}\n",
        encoding="utf-8",
    )
    checkout = tmp_path / "checkout"
    (checkout / ".ash").mkdir(parents=True)
    _symlink_or_skip(checkout / ".ash" / ".ash.yaml", target)

    config = resolve_config(
        source_dir=checkout,
        config_overrides=[
            "reporters.aws-security-hub.options.findings_scope="
            + _SCOPE_FROM_THE_ENVIRONMENT
        ],
    )

    for view in _recorded_and_shown(config):
        options = view["reporters"]["aws-security-hub"]["options"]
        assert options["findings_scope"] == _SCOPE_FROM_THE_ENVIRONMENT, options
    assert not [
        reference
        for reference in config._environment_references
        if reference.written == "${ASH_TEST_REPO_SCOPE}"
    ]


@pytest.mark.unit
def test_an_unrelated_override_does_not_charge_the_repository_with_either(
    tmp_path, caplog
):
    """The repository's file names neither option, and the operator's
    workspace file, the trusted base, sets both. An override of another setting
    makes neither look set by the repository's file: no warning names them."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "project_name: checkout\n")
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: operator-scope\n"
        "      archive_resolved_findings: true\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            source_dir=checkout,
            trusted_config_path=operator,
            config_overrides=[*_OPERATOR_ENABLES, "project_name=renamed"],
        )

    assert config.project_name == "renamed"
    assert _operator_only_warnings(caplog) == []


@pytest.mark.unit
def test_a_repository_section_under_another_spelling_is_confined_too(tmp_path, caplog):
    """get_plugin_config reads AwsSecurityHub as aws-security-hub's section."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  AwsSecurityHub:\n"
        "    options:\n"
        "      findings_scope: someone-elses-repo\n"
        "      archive_resolved_findings: true\n",
    )
    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=checkout)
    options = _reporter_from(config, tmp_path).config.options

    assert options.findings_scope is None
    assert options.archive_resolved_findings is False
    [warning] = _operator_only_warnings(caplog)
    assert "reporters.AwsSecurityHub.options.findings_scope" in warning


def _underscore_overrides() -> list[str]:
    return [
        "reporters.aws_security_hub.enabled=true",
        f"reporters.aws_security_hub.options.aws_region={REGION}",
        "reporters.aws_security_hub.options.findings_scope=op",
        "reporters.aws_security_hub.options.archive_resolved_findings=true",
    ]


@pytest.mark.unit
def test_a_decoy_section_does_not_carry_the_operators_overrides_to_the_payload(
    tmp_path,
):
    """The repository writes its payload under aws-security-hub and an empty
    decoy under aws_security_hub. The operator's overrides, spelled with
    underscores, land in the decoy, because an override takes the exact key
    first, while the scan reads aws-security-hub. An override counts only for the
    section spelling it lands in, so confinement still drops the scope and
    archiving set in the section the scan reads.
    """
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        "      archive_resolved_findings: true\n"
        "      findings_scope: victim\n"
        "  aws_security_hub:\n"
        "    options: {}\n",
    )
    config = resolve_config(
        source_dir=checkout, config_overrides=_underscore_overrides()
    )
    reporter = _reporter_from(config, tmp_path)

    assert reporter.config.options.findings_scope is None
    assert reporter.config.options.archive_resolved_findings is False
    securityhub, stub = _stubbed_client("securityhub")
    queries = _Capture(securityhub, "GetFindings")
    imports = _Capture(securityhub)
    # Refused before Security Hub is called: the Region the operator gave went
    # to the decoy too, and so did findings_scope.
    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            reporter,
            _model([_result()], completed=("bandit",)),
            {"securityhub": securityhub},
        )
    # The refusal names the option that was missing: the type alone would pass
    # for a refusal that came from somewhere else.
    assert "reporters.aws-security-hub.options." in str(raised.value)
    assert queries.requests == []
    assert imports.requests == []


@pytest.mark.unit
def test_a_decoy_section_does_not_shelter_an_underscore_payload_from_ash_report(
    tmp_path,
):
    """The mirror: the payload under aws_security_hub, the decoy under
    aws-security-hub, and hyphenated overrides that land in the decoy.
    `ash report --format AWS-Security-Hub` looks the section up by its reduced
    name, which the last of the two spellings wins."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options: {}\n"
        "  aws_security_hub:\n"
        "    enabled: true\n"
        "    options:\n"
        "      archive_resolved_findings: true\n"
        "      findings_scope: victim\n",
    )
    config = resolve_config(
        source_dir=checkout,
        config_overrides=[
            override.replace("aws_security_hub", "aws-security-hub")
            for override in _underscore_overrides()
        ],
    )
    for name in ("AWS-Security-Hub", "aws_security_hub"):
        section = config.get_plugin_config(plugin_type="reporter", plugin_name=name)
        options = SecurityHubReporterConfig.model_validate(section).options
        if options.findings_scope == "op":
            # The section the operator's overrides wrote.
            assert options.archive_resolved_findings is True
            continue
        assert options.findings_scope is None, name
        assert options.archive_resolved_findings is False, name


@pytest.mark.unit
def test_an_underscore_override_of_the_only_section_is_the_operators(tmp_path):
    """With one section, an override spelled with underscores is applied to it
    (the '-' and '_' spellings are one key), so it is the operator's value."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      archive_resolved_findings: false\n"
        "      findings_scope: victim\n",
    )
    config = resolve_config(
        source_dir=checkout, config_overrides=_underscore_overrides()
    )
    options = _reporter_from(config, tmp_path).config.options

    assert options.findings_scope == "op"
    assert options.archive_resolved_findings is True


_SPACED_OVERRIDES = [
    " reporters.aws-security-hub.options.findings_scope=op",
    " reporters.aws-security-hub.options.archive_resolved_findings=true",
]


@pytest.mark.unit
def test_ash_report_refuses_an_override_key_with_a_space_before_it(
    tmp_path, monkeypatch
):
    """An override key with whitespace before it, such as the operator's
    " reporters.aws-security-hub.options.archive_resolved_findings=true", names no
    option ASH reads: it is refused (exit 3) before any AWS call."""
    import typer

    from automated_security_helper.cli.report import report_command

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: victim\n"
        "      archive_resolved_findings: true\n",
    )
    mark_git_checkout(checkout)
    output = checkout / ".ash" / "ash_output"
    output.mkdir()
    (output / "ash_aggregated_results.json").write_text(
        _model([_result()], completed=("bandit",)).model_dump_json(),
        encoding="utf-8",
    )
    monkeypatch.chdir(checkout)
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))

    with patch.object(securityhub_module.boto3, "Session", session):
        with pytest.raises(typer.Exit) as exc_info:
            report_command(
                report_format="aws-security-hub",
                output_dir=str(output),
                config_overrides=[
                    (
                        "ash_plugin_modules+="
                        "automated_security_helper.plugin_modules.ash_aws_plugins"
                    ),
                    *_OPERATOR_ENABLES,
                    _OPERATOR_SCOPE,
                    _SPACED_OVERRIDES[1],
                ],
            )

    assert exc_info.value.exit_code == 3
    session.assert_not_called()


@pytest.mark.unit
def test_confinement_reads_an_override_key_as_it_was_applied(tmp_path):
    """apply_config_overrides refuses a key with whitespace around it, so a scan
    never hands confinement one. Confinement reads each key exactly as the
    override was applied, not stripped, so a key with whitespace in it does not
    count as the operator setting the options the repository's file wrote: they
    take the trusted base's values."""
    from automated_security_helper.config.operator_only_options import (
        RepositorySettings,
        confine_operator_only_options,
    )

    repository = RepositorySettings([tmp_path])
    in_tree = tmp_path / ".ash.yaml"
    config = AshConfig.model_validate(
        repository.confine(
            in_tree,
            in_tree,
            {
                "project_name": "test",
                "reporters": {
                    "aws-security-hub": {
                        "options": {
                            "findings_scope": "victim",
                            "archive_resolved_findings": True,
                        }
                    }
                },
            },
        )
    )
    trusted = AshConfig.model_validate(
        {
            "project_name": "test",
            "reporters": {
                "aws-security-hub": {
                    "options": {
                        "findings_scope": "operator-scope",
                        "archive_resolved_findings": False,
                    }
                }
            },
        }
    )

    confine_operator_only_options(
        config,
        trusted,
        _SPACED_OVERRIDES,
        [in_tree],
        repository=repository,
        checkout_membership=False,
        mixed_membership=False,
        given_root_membership=False,
        undecided_membership=False,
    )

    section = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )
    assert section["options"] == {
        "findings_scope": "operator-scope",
        "archive_resolved_findings": False,
    }


@pytest.mark.unit
def test_the_warning_takes_an_in_tree_path_as_text_not_markup(tmp_path, caplog):
    """The repository names its own files. A base at .ash/a[/x].yaml held a
    closing Rich tag, and the console handler raised MarkupError out of
    resolve_config, which ended the scan."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(tmp_path, "extends: a[/x].yaml\n")
    base = checkout / ".ash" / "a[" / "x].yaml"
    base.parent.mkdir()
    base.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      archive_resolved_findings: true\n",
        encoding="utf-8",
    )
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=checkout)
        reporter_section(config, SecurityHubReporter)

    # One warning, for the option and the section reporter_section ignores too.
    [record] = [
        r for r in caplog.records if "reporters.aws-security-hub" in r.getMessage()
    ]
    assert ".options.archive_resolved_findings" in record.getMessage()
    assert getattr(record, "markup", True) is False
    assert "a[/x].yaml" in record.getMessage()


def _security_hub_warnings(caplog) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING
        and "reporters.aws-security-hub" in record.getMessage()
    ]


def _resolve_and_select(checkout: Path, caplog) -> Any:
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    with caplog.at_level(logging.WARNING):
        config = resolve_config(
            source_dir=checkout, config_overrides=[*_OPERATOR_ENABLES, _OPERATOR_SCOPE]
        )
        return reporter_section(config, SecurityHubReporter)


@pytest.mark.unit
def test_each_confinement_names_what_it_ignores_from_the_repositorys_section(
    tmp_path, caplog
):
    """The repository's section sets archiving and a profile. The destination
    step (config/reporter_trust.py) replaces the profile and names it; the
    settle step (config/operator_only_options.py) settles the archiving and
    names it. Each names the repository's file, and reporter_section, whose
    operator section the resolved one now lies within, adds nothing."""
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      archive_resolved_findings: true\n"
        "      aws_profile: repository-profile\n",
    )

    section = _resolve_and_select(checkout, caplog)

    warnings = _security_hub_warnings(caplog)
    assert any(
        "reporters.aws-security-hub.options.archive_resolved_findings" in w
        for w in warnings
    ), warnings
    assert any(
        "reporters.aws-security-hub.options.aws_profile" in w for w in warnings
    ), warnings
    assert all(".ash.yaml" in w for w in warnings), warnings
    assert all("repository-profile" not in w for w in warnings), warnings
    assert "aws_profile" not in section["options"]


@pytest.mark.unit
def test_the_options_alone_draw_the_options_warning(tmp_path, caplog):
    """Where the dropped options were the only difference, reporter_section
    finds the operator's section and ignores nothing more, so the warning names
    only the options."""
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      archive_resolved_findings: true\n",
    )

    _resolve_and_select(checkout, caplog)

    [warning] = _security_hub_warnings(caplog)
    assert "options.archive_resolved_findings" in warning
    assert "the rest of" not in warning


@pytest.mark.unit
def test_the_destination_step_names_a_profile_only_the_repository_wrote(
    tmp_path, caplog
):
    """A section that sets no operator-only option but a destination option:
    the destination step (config/reporter_trust.py) replaces the profile and
    names it from the repository's file; reporter_section then finds the
    resolved section within the operator's and adds nothing."""
    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      aws_profile: repository-profile\n",
    )

    section = _resolve_and_select(checkout, caplog)

    [warning] = _security_hub_warnings(caplog)
    assert warning.startswith(
        "Ignoring reporters.aws-security-hub.options.aws_profile from"
    ), warning
    assert ".ash.yaml" in warning, warning
    assert "repository-profile" not in warning, warning
    assert "aws_profile" not in section["options"]


@pytest.mark.unit
def test_a_section_key_with_controls_is_shown_as_escapes(tmp_path, caplog):
    """A key get_plugin_config reads as aws-security-hub's can hold a carriage
    return, an escape and a bell, and the warning shows each one as an escape."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        '  "aws-security-hub\\r\\e]\\a":\n'
        "    options:\n"
        "      archive_resolved_findings: true\n",
    )
    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=checkout)

    [message] = _operator_only_warnings(caplog)
    for control in ("\r", "\x1b", "\x07"):
        assert control not in message
    assert "aws-security-hub\\x0d\\x1b]\\x07" in message
    section = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )
    assert section == {"options": {}}


def _payload_outside(tmp_path: Path) -> Path:
    payload = tmp_path / "elsewhere" / "payload.yaml"
    payload.parent.mkdir()
    payload.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      archive_resolved_findings: true\n"
        "      findings_scope: victim\n",
        encoding="utf-8",
    )
    return payload


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"cannot make a symlink here: {error}")


@pytest.mark.unit
def test_a_discovered_config_that_links_out_of_the_tree_is_confined(tmp_path):
    """The scan root is no git checkout, and its .ash/.ash.yaml is a symlink to
    a file outside it. The file is judged by the in-tree path the scan reached it
    through, not only its resolved path, so its findings_scope and archiving are
    dropped."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "checkout"
    (checkout / ".ash").mkdir(parents=True)
    _symlink_or_skip(checkout / ".ash" / ".ash.yaml", _payload_outside(tmp_path))

    config = resolve_config(
        source_dir=checkout, config_overrides=[*_OPERATOR_ENABLES, _OPERATOR_SCOPE]
    )
    options = _reporter_from(config, tmp_path).config.options

    assert options.findings_scope == "operator-scope"
    assert options.archive_resolved_findings is False


@pytest.mark.unit
def test_a_named_config_that_links_out_of_the_tree_is_confined(tmp_path):
    """The same, for --config naming a path inside the tree."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "checkout"
    (checkout / "ci").mkdir(parents=True)
    _symlink_or_skip(checkout / "ci" / "ash.yaml", _payload_outside(tmp_path))

    config = resolve_config(
        config_path=checkout / "ci" / "ash.yaml",
        source_dir=checkout,
        config_overrides=_OPERATOR_ENABLES,
    )
    options = _reporter_from(config, tmp_path).config.options

    assert options.findings_scope is None
    assert options.archive_resolved_findings is False


@pytest.mark.unit
def test_the_operators_config_outside_the_tree_is_honored(tmp_path):
    """--config naming the outside file itself is the operator's choice."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    config = resolve_config(
        config_path=_payload_outside(tmp_path),
        source_dir=checkout,
        config_overrides=_OPERATOR_ENABLES,
    )
    options = _reporter_from(config, tmp_path).config.options

    assert options.findings_scope == "victim"
    assert options.archive_resolved_findings is True


def _operator_file(tmp_path: Path, scope: str) -> Path:
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir(exist_ok=True)
    operator.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        f"      findings_scope: {scope}\n"
        "      archive_resolved_findings: true\n",
        encoding="utf-8",
    )
    return operator


@pytest.mark.parametrize("operator_source", ["ASH_CONFIG", "workspace default"])
@pytest.mark.unit
def test_the_trusted_bases_value_replaces_the_repositorys(
    tmp_path, monkeypatch, operator_source
):
    """Where the operator's own file outside the tree sets the option (ASH_CONFIG,
    or a workspace's default config), that value replaces the repository's,
    rather than leaving the option unset."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: victim\n"
        "      archive_resolved_findings: false\n",
    )
    operator = _operator_file(tmp_path, "operator-default")
    if operator_source == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        config = resolve_config(source_dir=checkout)
    else:
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        config = resolve_config(source_dir=checkout, trusted_config_path=operator)
    section = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )

    assert section["options"]["findings_scope"] == "operator-default"
    assert section["options"]["archive_resolved_findings"] is True


@pytest.mark.unit
def test_ash_report_judges_the_config_against_the_results_tree(
    tmp_path, monkeypatch, capsys
):
    """`ash report --config <checkout>/.ash/.ash.yaml --output-dir
    <checkout>/.ash/ash_output`, run from outside the checkout. The file is
    judged against the results tree as well as the working directory, so the
    checkout's findings_scope does not reach the reporter."""
    import typer

    from automated_security_helper.cli.report import report_command

    checkout = _checkout_with_config(
        tmp_path,
        "reporters:\n  aws-security-hub:\n    options:\n      findings_scope: victim\n",
    )
    # A checkout: its repository is the tree the results' directory is in.
    mark_git_checkout(checkout)
    output = checkout / ".ash" / "ash_output"
    output.mkdir()
    (output / "ash_aggregated_results.json").write_text(
        _model([_result()], completed=("bandit",)).model_dump_json(),
        encoding="utf-8",
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))

    with patch.object(securityhub_module.boto3, "Session", session):
        with pytest.raises(typer.Exit):
            report_command(
                report_format="aws-security-hub",
                output_dir=str(output),
                config=str(checkout / ".ash" / ".ash.yaml"),
                config_overrides=[
                    (
                        "ash_plugin_modules+="
                        "automated_security_helper.plugin_modules.ash_aws_plugins"
                    ),
                    *_OPERATOR_ENABLES,
                ],
            )

    session.assert_not_called()
    assert "options.findings_scope" in capsys.readouterr().err


_REPOSITORY_OPTIONS = (
    "reporters:\n"
    "  aws-security-hub:\n"
    "    options:\n"
    "      findings_scope: victim\n"
    "      archive_resolved_findings: true\n"
    "      aws_region: us-west-2\n"
)


def _not_in_a_checkout(path: Path) -> Path:
    """*path*, checked to sit in no checkout the product would see, so a
    test's "outside every checkout" layout is one.

    The product's own predicate, not a bare ``.git`` lookup: an empty
    ``.git`` directory a stray mkdir or a transient mount point leaves in a
    shared parent bounds nothing, and a guard stricter than the product
    fails these cells while the product itself answers "no checkout"."""
    from automated_security_helper.config.sandbox_grants import in_a_checkout

    assert not in_a_checkout(path), path
    return path


def _get_config_from_elsewhere(tmp_path, monkeypatch, config: Path) -> dict[str, Any]:
    """get_config of ``config``, a file the operator names, from a working
    directory that does not hold it.

    A path named to get_config is the client's unless it is in a directory
    ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` names, and a client's file that sets the
    Security Hub section is refused outright. These tests are about how a file
    the operator names is shown, so the test's directory is set aside as the
    operator's."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    return mcp_get_config(config_path=str(config))


def _security_hub_options(result: dict[str, Any]) -> dict[str, Any]:
    return result["reporters"]["aws-security-hub"]["options"]


@pytest.mark.parametrize("scope", ["literal", "from-the-environment"])
@pytest.mark.parametrize(
    "layout",
    ["in a checkout", "a link into a checkout", "a link out of one", "a base in one"],
)
@pytest.mark.unit
def test_get_config_marks_the_operator_only_options_a_repository_file_sets(
    tmp_path, monkeypatch, layout, scope
):
    """MCP get_config judges a named file against this session's scan target,
    here the working directory, which does not hold it, so it showed the
    findings_scope and archiving of a file in a checkout as a scan would apply
    them. A scan of that checkout ignores both, so they are shown marked. The
    file counts as the repository's by the name it was given or by its target,
    and so does a base it extends. A scope the file reads from the
    environment is marked by the reference it wrote, never by the value. The
    rest of the section (aws_region) is the operator's too and is confined
    for a file in another checkout, so it is absent rather than shown as
    applied (docs/content/docs/plugins/aws/security-hub-reporter.md, "Options
    only the operator sets")."""
    _not_in_a_checkout(tmp_path)
    repository_options = _REPOSITORY_OPTIONS
    if scope == "from-the-environment":
        monkeypatch.setenv("ASH_TEST_SH_SCOPE", "victim-from-the-environment")
        repository_options = _REPOSITORY_OPTIONS.replace(
            "findings_scope: victim", "findings_scope: ${ASH_TEST_SH_SCOPE}"
        )
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    outside = tmp_path / "outside"
    outside.mkdir()
    if layout == "in a checkout":
        named = _checkout_with_config(tmp_path, repository_options) / ".ash/.ash.yaml"
    elif layout == "a link into a checkout":
        target = _checkout_with_config(tmp_path, repository_options)
        named = outside / "ash.yaml"
        named.symlink_to(target / ".ash" / ".ash.yaml")
    elif layout == "a link out of one":
        target = outside / "real.yaml"
        target.write_text(repository_options, encoding="utf-8")
        named = checkout / ".ash" / ".ash.yaml"
        named.parent.mkdir()
        named.symlink_to(target)
    else:
        nested = outside / "vendored"
        mark_git_checkout(nested)
        (nested / "base.yaml").write_text(repository_options, encoding="utf-8")
        named = outside / "ash.yaml"
        named.write_text("extends: vendored/base.yaml\n", encoding="utf-8")

    result = _get_config_from_elsewhere(tmp_path, monkeypatch, named)
    options = _security_hub_options(result)

    if scope == "literal":
        assert options["findings_scope"] == (
            '<operator only; ignored from this file: "victim">'
        )
    else:
        assert "victim-from-the-environment" not in json.dumps(result), result
        assert options["findings_scope"] == (
            "<operator only; ignored from this file: <from ${ASH_TEST_SH_SCOPE}>>"
        )
    assert options["archive_resolved_findings"] == (
        "<operator only; ignored from this file: true>"
    )
    assert "aws_region" not in options


@pytest.mark.parametrize(
    "layout, inside",
    [
        ("a link into one", True),
        ("a link out of one", True),
        ("through a link in one", True),
        ("a link in one, then ..", True),
        ("neither", False),
    ],
)
@pytest.mark.unit
def test_in_a_checkout_reads_the_name_and_the_target(tmp_path, layout, inside):
    """get_config passes in_a_checkout the resolved chain as well as the name, so
    there each half of the check also has the other behind it; this holds each
    half on its own. The name and the target can both be outside every checkout
    while a link on the way sits in one, and the checkout then chose the file:
    outside/via.yaml -> checkout/hop.yaml -> outside/file.yaml, and
    checkout/lnk/../file.yaml with checkout/lnk -> outside/sub."""
    from automated_security_helper.config.sandbox_grants import in_a_checkout

    _not_in_a_checkout(tmp_path)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    outside = tmp_path / "outside"
    (outside / "sub").mkdir(parents=True)
    (checkout / "file.yaml").write_text("", encoding="utf-8")
    (outside / "file.yaml").write_text("", encoding="utf-8")
    path = {
        "a link into one": outside / "into.yaml",
        "a link out of one": checkout / "out.yaml",
        "through a link in one": outside / "via.yaml",
        "a link in one, then ..": checkout / "lnk" / ".." / "file.yaml",
        "neither": outside / "file.yaml",
    }[layout]
    if layout == "a link into one":
        path.symlink_to(checkout / "file.yaml")
    elif layout == "a link out of one":
        path.symlink_to(outside / "file.yaml")
    elif layout == "through a link in one":
        (checkout / "hop.yaml").symlink_to(outside / "file.yaml")
        path.symlink_to(checkout / "hop.yaml")
    elif layout == "a link in one, then ..":
        (checkout / "lnk").symlink_to(outside / "sub")
        assert path.resolve() == (outside / "file.yaml").resolve()

    assert in_a_checkout(path) is inside


@pytest.mark.unit
def test_get_config_shows_an_operator_file_outside_every_checkout_as_written(
    tmp_path, monkeypatch
):
    """The paired half: a scan that names a file outside every checkout applies
    its options, so get_config shows them unmarked."""
    named = _not_in_a_checkout(tmp_path) / "operator.yaml"
    named.write_text(_REPOSITORY_OPTIONS, encoding="utf-8")

    options = _security_hub_options(
        _get_config_from_elsewhere(tmp_path, monkeypatch, named)
    )

    assert options["findings_scope"] == "victim"
    assert options["archive_resolved_findings"] is True


@pytest.mark.unit
def test_get_config_does_not_judge_a_named_file_by_ash_configs_checkout(
    tmp_path, monkeypatch
):
    """ASH_CONFIG's file is among the files get_config reads, but a named file is
    not merged with it, so that file being in a checkout says nothing about the
    named one's options."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    _not_in_a_checkout(tmp_path)
    ash_config = tmp_path / "operator-checkout" / "ash.yaml"
    mark_git_checkout(ash_config.parent)
    ash_config.write_text("project_name: operator\n", encoding="utf-8")
    named = tmp_path / "operator.yaml"
    named.write_text(_REPOSITORY_OPTIONS, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("ASH_CONFIG", str(ash_config))
    # The operator names the file (see _get_config_from_elsewhere).
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))

    options = _security_hub_options(mcp_get_config(config_path=str(named)))

    assert options["findings_scope"] == "victim"


@pytest.mark.unit
def test_get_config_shows_the_operators_value_where_the_target_holds_the_file(
    tmp_path, monkeypatch
):
    """When this session's target holds the file, resolve_config has already put
    the operator's value in place, which a scan applies, so it is not marked."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    checkout = _checkout_with_config(tmp_path, _REPOSITORY_OPTIONS)
    mark_git_checkout(checkout)
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("ASH_CONFIG", str(_operator_file(tmp_path, "operator-scope")))
    # The operator names the file (see _get_config_from_elsewhere).
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))

    options = _security_hub_options(
        mcp_get_config(config_path=str(checkout / ".ash" / ".ash.yaml"))
    )

    assert options["findings_scope"] == "operator-scope"


@pytest.mark.unit
def test_a_result_with_no_identity_fails_the_reporter_and_sends_nothing(
    tmp_path, monkeypatch
):
    """from_sarif_result always records the identity a finding's id comes from.
    Should a change ever stop it, report() raises the reporter's own error, which
    the report phase records as this reporter's failure, and nothing reaches
    Security Hub. GetCallerIdentity runs before the findings are built."""
    from automated_security_helper.models.flat_vulnerability import (
        FlatVulnerability,
    )

    real = FlatVulnerability.from_sarif_result

    def without_identity(*args: Any, **kwargs: Any) -> FlatVulnerability:
        flat = real(*args, **kwargs)
        flat._identity = None
        return flat

    monkeypatch.setattr(
        FlatVulnerability, "from_sarif_result", staticmethod(without_identity)
    )
    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    queries = _Capture(securityhub, "GetFindings")

    with pytest.raises(SecurityHubImportError, match="no finding identity"):
        _report_with(
            _reporter(tmp_path, archive=True),
            _model([_result()], completed=("bandit",)),
            {"securityhub": securityhub},
        )

    assert imports.requests == []
    assert queries.requests == []


# --------------------------------------------------------------------------- #
# Scan target: findings_scope
# --------------------------------------------------------------------------- #
#
# The target, which the Ids and the archive filter come from, is findings_scope, a
# reporter option the operator sets, not project_name: a repository's own .ash
# config can set project_name, and naming another project there would write into,
# and archive, that project's findings in the operator's account.


@pytest.mark.parametrize("project_name", ["ash-scan", "a-name-of-its-own"])
@pytest.mark.parametrize("unset", [None, "", "   "], ids=["none", "empty", "blank"])
@pytest.mark.unit
def test_an_unset_findings_scope_is_refused_before_any_aws_call(
    tmp_path, unset, project_name
):
    """No fallback to project_name, whether the default or a name of its own."""
    reporter = _reporter(tmp_path, findings_scope=unset, project_name=project_name)
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))

    with patch.object(securityhub_module.boto3, "Session", session):
        with pytest.raises(SecurityHubImportError) as raised:
            reporter.report(
                _model(_many(1), project_name=project_name, completed=("bandit",))
            )

    session.assert_not_called()
    message = str(raised.value)
    assert "reporters.aws-security-hub.options.findings_scope" in message
    assert "\n" not in message


@pytest.mark.unit
def test_an_unset_findings_scope_is_refused_with_no_findings_too(tmp_path):
    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(_reporter(tmp_path, findings_scope=None), _model([]), {})
    assert "findings_scope" in str(raised.value)


@pytest.mark.unit
def test_a_project_name_naming_another_scope_does_not_reach_its_findings(tmp_path):
    """Repository A's config names repository B's project; A keeps its own scope."""
    theirs = _reporter(tmp_path, findings_scope="repo-b", project_name="repo-b")
    ours = _reporter(tmp_path, findings_scope="repo-a", project_name="repo-b")
    model = _model([_result()], project_name="repo-b")

    [their_finding] = theirs.build_asff_findings(
        model, account_id=ACCOUNT, region=REGION
    )
    [our_finding] = ours.build_asff_findings(model, account_id=ACCOUNT, region=REGION)

    assert our_finding["Id"] != their_finding["Id"]
    assert our_finding["ProductFields"]["ash/target"] == "repo-a"
    assert our_finding["Resources"][0]["Id"].startswith("repo-a/")


@pytest.mark.unit
def test_findings_scope_comes_from_this_reporters_config_not_the_results_file(
    tmp_path,
):
    """A results file is data: whoever wrote it would choose whose findings ``ash
    report`` updates. Neither its project_name nor a findings_scope in its
    recorded config is read."""
    model = _model([_result()])
    model.ash_config = AshConfig.model_validate(
        {
            "project_name": "name-the-scan-recorded",
            "reporters": {
                "aws-security-hub": {
                    "options": {"findings_scope": "scope-the-results-file-names"}
                }
            },
        }
    )
    reporter = _reporter(
        tmp_path,
        findings_scope="operator-scope",
        project_name="name-in-the-current-config",
    )

    [finding] = reporter.build_asff_findings(model, account_id=ACCOUNT, region=REGION)

    assert finding["ProductFields"]["ash/target"] == "operator-scope"
    assert finding["Resources"][0]["Id"].startswith("operator-scope/")


@pytest.mark.unit
def test_the_default_project_name_is_no_obstacle_once_findings_scope_is_set(
    tmp_path,
):
    securityhub, stub = _stubbed_client("securityhub")
    capture = _Capture(securityhub)
    stub.add_response("batch_import_findings", _ok(1))

    _report_with(
        _reporter(tmp_path, project_name="ash-scan"),
        _model([_result()], project_name="ash-scan"),
        {"securityhub": securityhub},
    )

    stub.assert_no_pending_responses()
    [sent] = capture.findings
    assert sent["ProductFields"]["ash/target"] == "fixture-project"


@pytest.mark.unit
def test_a_findings_scope_too_long_for_its_product_field_is_refused(tmp_path):
    """ash/target is findings_scope plus a workspace project's key, and a
    ProductFields value is cut at 2048 characters. A cut value no longer equals
    the GetFindings filter, so archiving and CreatedAt would silently stop.

    The options model refuses the value, and so does the generic options base
    the config would otherwise fall back to (it refuses options it does not
    declare), so the reporter is not built at all; a scan refuses the same
    section with exit 3 when it loads the plugins."""
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))
    with patch.object(securityhub_module.boto3, "Session", session):
        with pytest.raises(ValidationError) as raised:
            SecurityHubReporter(
                context=PluginContext(
                    source_dir=tmp_path,
                    output_dir=tmp_path / "out",
                    config=AshConfig(project_name="fixture-project"),
                ),
                config={
                    "enabled": True,
                    "options": {"aws_region": REGION, "findings_scope": "s" * 1025},
                },
            )
    session.assert_not_called()
    assert "findings_scope" in str(raised.value)
    assert "at most 1024 characters" in str(raised.value)


@pytest.mark.unit
def test_findings_scope_from_config_overrides_reaches_the_reporter(tmp_path):
    """The form the docs give: a value with a slash, set on the command line."""
    from automated_security_helper.config.resolve_config import resolve_config

    empty = tmp_path / "empty-checkout"
    empty.mkdir()
    config = resolve_config(
        source_dir=empty,
        config_overrides=[
            "reporters.aws-security-hub.enabled=true",
            "reporters.aws-security-hub.options.aws_region=us-east-1",
            "reporters.aws-security-hub.options.findings_scope=my-org/my-repo",
        ],
    )
    reporter = _reporter_from(config, tmp_path)

    assert isinstance(reporter.config, SecurityHubReporterConfig)
    assert reporter.config.options.findings_scope == "my-org/my-repo"


# --------------------------------------------------------------------------- #
# Identity: fingerprints and occurrences
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_fingerprints_replace_the_line_numbers_in_the_id(tmp_path):
    """An edit above a finding moves its line; its fingerprint does not move."""
    reporter = _reporter(tmp_path)
    fingerprint = {"matchBasedId/v1": "4f1c0e"}
    assert _ids(reporter, [_result(line=9, fingerprints=fingerprint)]) == _ids(
        reporter, [_result(line=40, fingerprints=fingerprint)]
    )
    assert _ids(reporter, [_result(fingerprints=fingerprint)]) != _ids(
        reporter, [_result(fingerprints={"matchBasedId/v1": "77aa01"})]
    )


@pytest.mark.unit
def test_partial_fingerprints_are_used_when_there_are_no_fingerprints(tmp_path):
    reporter = _reporter(tmp_path)
    partial = {"primaryLocationLineHash": "39fa2ee980eb94b0:1"}
    assert _ids(reporter, [_result(line=9, partial_fingerprints=partial)]) == _ids(
        reporter, [_result(line=12, partial_fingerprints=partial)]
    )


@pytest.mark.unit
def test_distinct_findings_on_one_line_are_all_sent(tmp_path):
    """Two secrets on one line are two findings, not one with the other dropped."""
    securityhub, stub = _stubbed_client("securityhub")
    capture = _Capture(securityhub)
    stub.add_response("batch_import_findings", _ok(3))

    document = json.loads(
        _report_with(
            _reporter(tmp_path),
            _model(
                [
                    _result(message="secret one"),
                    _result(message="secret two"),
                    _result(message="secret two", start_column=30),
                ]
            ),
            {"securityhub": securityhub},
        )
    )

    assert len({f["Id"] for f in capture.findings}) == 3
    assert document["duplicates_skipped"] == 0


@pytest.mark.unit
def test_the_occurrence_index_does_not_depend_on_result_order(tmp_path):
    reporter = _reporter(tmp_path)
    first, second = _result(message="secret one"), _result(message="secret two")
    by_message = dict(zip(["one", "two"], _ids(reporter, [first, second]), strict=True))
    reversed_ids = dict(
        zip(["two", "one"], _ids(reporter, [second, first]), strict=True)
    )
    assert by_message == reversed_ids


@pytest.mark.unit
def test_an_earlier_column_newcomer_does_not_take_the_existing_findings_id(tmp_path):
    """A newcomer at column 5 gets an Id of its own, so the finding at column 20
    keeps its Id and its triage state."""
    reporter = _reporter(tmp_path)
    [before] = _ids(reporter, [_result(message="secret one", start_column=20)])
    newcomer, existing = _ids(
        reporter,
        [
            _result(message="secret two", start_column=5),
            _result(message="secret one", start_column=20),
        ],
    )
    assert newcomer != before
    assert newcomer != existing


@pytest.mark.unit
def test_removing_the_first_occurrence_does_not_hand_its_id_to_the_next(tmp_path):
    reporter = _reporter(tmp_path)
    first, _second = _ids(
        reporter,
        [
            _result(message="secret one", start_column=5),
            _result(message="secret two", start_column=20),
        ],
    )
    [survivor] = _ids(reporter, [_result(message="secret two", start_column=20)])
    assert survivor != first


@pytest.mark.unit
def test_occurrence_suffixes_are_by_content(tmp_path):
    """Among findings sharing a key, each one's Id depends on its own column and
    message, so the same pair yields the same two Ids next to any third."""
    reporter = _reporter(tmp_path)
    one = _result(message="secret one", start_column=5)
    two = _result(message="secret two", start_column=20)
    three = _result(message="secret three", start_column=40)
    pair = set(_ids(reporter, [one, two]))
    triple = set(_ids(reporter, [three, two, one]))
    assert pair < triple


@pytest.mark.unit
def test_a_placeholder_fingerprint_counts_as_absent(tmp_path):
    """semgrep 1.180 writes matchBasedId/v1 "requires login" on every result."""
    reporter = _reporter(tmp_path)
    placeholder = {"matchBasedId/v1": "requires login"}
    ids = _ids(
        reporter,
        [
            _result(rule_id="R1", line=3, scanner="semgrep", fingerprints=placeholder),
            _result(rule_id="R1", line=9, scanner="semgrep", fingerprints=placeholder),
        ],
    )
    assert len(set(ids)) == 2
    assert ids == _ids(
        reporter,
        [
            _result(rule_id="R1", line=3, scanner="semgrep"),
            _result(rule_id="R1", line=9, scanner="semgrep"),
        ],
    )


@pytest.mark.unit
def test_a_fingerprint_shared_by_two_locations_counts_as_absent(tmp_path):
    reporter = _reporter(tmp_path)
    shared = {"matchBasedId/v1": "0000aaaa"}
    ids = _ids(
        reporter,
        [_result(line=3, fingerprints=shared), _result(line=9, fingerprints=shared)],
    )
    assert len(set(ids)) == 2
    assert ids == _ids(reporter, [_result(line=3), _result(line=9)])


@pytest.mark.unit
def test_a_fingerprint_in_another_file_or_from_another_scanner_moves_no_id(tmp_path):
    """Counted per scanner, rule, file, package and project, which the key holds:
    fixing the finding in one file does not re-key the one in another that
    carries the same value, and neither does another scanner's finding."""
    reporter = _reporter(tmp_path)
    shared = {"matchBasedId/v1": "0000aaaa"}
    in_a = _result(uri="app/a.py", line=3, fingerprints=shared)
    in_b = _result(uri="app/b.py", line=9, fingerprints=shared)
    other = _result(uri="app/c.py", scanner="semgrep", fingerprints=shared)

    alone = _ids(reporter, [in_a])

    assert _ids(reporter, [in_a, in_b]) == alone + _ids(reporter, [in_b])
    assert _ids(reporter, [in_a, other])[0] == alone[0]


@pytest.mark.unit
def test_fingerprints_win_over_partial_fingerprints(tmp_path):
    reporter = _reporter(tmp_path)
    full = {"matchBasedId/v1": "4f1c0e"}
    base = _ids(
        reporter,
        [_result(fingerprints=full, partial_fingerprints={"lineHash": "a:1"})],
    )
    # Only the partial fingerprint changed: the Id does not.
    assert base == _ids(
        reporter,
        [_result(fingerprints=full, partial_fingerprints={"lineHash": "b:1"})],
    )
    # With the fingerprint a placeholder, the partial fingerprint decides.
    placeholder = {"matchBasedId/v1": "requires login"}
    assert _ids(
        reporter,
        [_result(fingerprints=placeholder, partial_fingerprints={"lineHash": "a:1"})],
    ) != _ids(
        reporter,
        [_result(fingerprints=placeholder, partial_fingerprints={"lineHash": "b:1"})],
    )


@pytest.mark.parametrize(
    "written",
    ["app/../app/app.py", "./app/./app.py"],
)
@pytest.mark.unit
def test_path_spellings_of_one_file_give_one_id(tmp_path, written):
    reporter = _reporter(tmp_path)
    [finding] = reporter.build_asff_findings(
        _model([_result(uri=written)]), account_id=ACCOUNT, region=REGION
    )
    assert finding["ProductFields"]["ash/file"] == "app/app.py"
    assert _ids(reporter, [_result(uri=written)]) == _ids(
        reporter, [_result(uri="app/app.py")]
    )


@pytest.mark.unit
def test_a_backslash_in_a_relative_path_names_another_file(tmp_path):
    """A sanitized relative path's backslash is part of a POSIX file name (a path
    made on Windows has "/" by then), so app\\app.py is not app/app.py. Each
    file's finding gets its own Id, so neither overwrites the other in Security
    Hub."""
    reporter = _reporter(tmp_path)
    [finding] = reporter.build_asff_findings(
        _model([_result(uri="app\\app.py")]), account_id=ACCOUNT, region=REGION
    )
    assert finding["ProductFields"]["ash/file"] == "app\\app.py"
    assert _ids(reporter, [_result(uri="app\\app.py")]) != _ids(
        reporter, [_result(uri="app/app.py")]
    )


@pytest.mark.unit
def test_the_id_is_the_contract_v2_hash_of_target_and_key(tmp_path):
    """Id = "ash/" + sha256(json.dumps([target, key], sort_keys=True))."""
    import hashlib

    reporter = _reporter(tmp_path)
    [finding] = reporter.build_asff_findings(
        _model([_result(line=9)]), account_id=ACCOUNT, region=REGION
    )
    key = {
        "scanner": "bandit",
        "rule": "B602",
        "file": "app/app.py",
        "package": [None, None],
        "project": None,
        "startLine": 9,
        "endLine": 9,
    }
    expected = hashlib.sha256(
        json.dumps(["fixture-project", key], sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert finding["Id"] == "ash/" + expected


# --------------------------------------------------------------------------- #
# account_id from YAML or --config-overrides
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw, expected",
    [
        (123456789012, "123456789012"),
        # An unquoted YAML account id with a leading zero arrives as an int
        # with the zero gone.
        (12345678901, "012345678901"),
        ("123456789012", "123456789012"),
    ],
)
@pytest.mark.unit
def test_an_integer_account_id_is_read_as_twelve_digits(tmp_path, raw, expected):
    reporter = SecurityHubReporter(
        context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            config=AshConfig(project_name="fixture-project"),
        ),
        config={"enabled": True, "options": {"aws_region": REGION, "account_id": raw}},
    )
    # Not the ReporterPluginConfigBase fallback, which has no aws_region at all.
    assert isinstance(reporter.config, SecurityHubReporterConfig)
    assert reporter.config.options.account_id == expected


@pytest.mark.unit
def test_an_account_id_from_config_overrides_reaches_the_reporter(tmp_path):
    from automated_security_helper.config.resolve_config import resolve_config

    empty = tmp_path / "empty-checkout"
    empty.mkdir()
    config = resolve_config(
        source_dir=empty,
        config_overrides=[
            "reporters.aws-security-hub.enabled=true",
            "reporters.aws-security-hub.options.aws_region=us-east-1",
            "reporters.aws-security-hub.options.findings_scope=fixture-project",
            "reporters.aws-security-hub.options.account_id=123456789012",
        ],
    )
    reporter = _reporter_from(config, tmp_path)

    assert isinstance(reporter.config, SecurityHubReporterConfig)
    assert reporter.config.options.account_id == "123456789012"
    assert reporter.config.options.aws_region == "us-east-1"


# --------------------------------------------------------------------------- #
# Content
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_a_fenced_code_block_in_the_message_is_not_sent(tmp_path):
    """FlatVulnerability reads a fenced block in a message as a code snippet."""
    message = (
        "Hardcoded key found\n```\naws_secret = 'FENCED-MARKER-1'\n```\nRemove it.\n"
        "Context:\n```python\nFENCED-MARKER-2"
    )
    [finding] = _reporter(tmp_path).build_asff_findings(
        _model([_result(message=message)]), account_id=ACCOUNT, region=REGION
    )
    payload = json.dumps(finding)
    assert "FENCED-MARKER" not in payload
    assert finding["Description"].startswith("Hardcoded key found")
    assert "Remove it." in finding["Description"]
    assert finding["Title"] == "B602: Hardcoded key found"


@pytest.mark.unit
def test_a_message_that_is_only_a_code_block_still_has_a_description(tmp_path):
    [finding] = _reporter(tmp_path).build_asff_findings(
        _model([_result(message="```\nFENCED-ONLY\n```")]),
        account_id=ACCOUNT,
        region=REGION,
    )
    assert "FENCED-ONLY" not in json.dumps(finding)
    assert finding["Description"].strip()
    assert finding["Title"].strip()


@pytest.mark.parametrize(
    "region, partition",
    [
        ("us-east-1", "aws"),
        ("us-gov-west-1", "aws-us-gov"),
        ("cn-north-1", "aws-cn"),
    ],
)
@pytest.mark.unit
def test_the_product_arn_uses_the_regions_partition(tmp_path, region, partition):
    [finding] = _reporter(tmp_path, region=region).build_asff_findings(
        _model([_result()]), account_id=ACCOUNT, region=region
    )
    assert finding["ProductArn"] == (
        f"arn:{partition}:securityhub:{region}:{ACCOUNT}:product/{ACCOUNT}/default"
    )


# --------------------------------------------------------------------------- #
# Failure paths the first round did not pin
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_a_batch_rejected_entirely_with_invalid_access_stops_the_import(tmp_path):
    """Security Hub answers so for every finding when it is off; do not keep sending."""
    securityhub, stub = _stubbed_client("securityhub")
    capture = _Capture(securityhub)
    stub.add_response(
        "batch_import_findings",
        {
            "FailedCount": 100,
            "SuccessCount": 0,
            "FailedFindings": [
                {"Id": f"id-{n}", "ErrorCode": "InvalidAccess", "ErrorMessage": "x"}
                for n in range(100)
            ],
        },
    )

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path), _model(_many(150)), {"securityhub": securityhub}
        )

    stub.assert_no_pending_responses()
    assert len(capture.requests) == 1
    assert "100 of 150" in str(raised.value)
    assert "Not sent: 50" in str(raised.value)


@pytest.mark.unit
def test_a_request_botocore_refuses_is_not_reported_as_unreachable(
    tmp_path, monkeypatch
):
    """ParamValidationError is raised before anything is sent; it is ASH's defect."""
    original = SecurityHubReporter._to_asff

    def malformed(self, *args, **kwargs):
        finding = original(self, *args, **kwargs)
        finding["Title"] = 5
        return finding

    monkeypatch.setattr(SecurityHubReporter, "_to_asff", malformed)
    securityhub, stub = _stubbed_client("securityhub")
    # Queued so the Stubber is not what refuses the call: botocore's parameter
    # validation runs first and raises before this response could be returned.
    stub.add_response("batch_import_findings", _ok(1))

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path), _model(_many(1)), {"securityhub": securityhub}
        )

    message = str(raised.value)
    assert "could not reach" not in message
    assert "before sending" in message
    assert "report" in message


# --------------------------------------------------------------------------- #
# Archiving findings a later scan no longer reports
# --------------------------------------------------------------------------- #

SCAN_TIME = "2026-01-15T12:00:00.000Z"


def _built(reporter, result: Result) -> dict:
    [finding] = reporter.build_asff_findings(
        _model([result]), account_id=ACCOUNT, region=REGION
    )
    return finding


def _stored(
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


def _archive_run(
    tmp_path, model, stored_findings, *, expected_sent: int, reporter=None
):
    """Run report() against GetFindings returning ``stored_findings``."""
    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    queries = _Capture(securityhub, "GetFindings")
    stub.add_response("get_findings", {"Findings": stored_findings})
    stub.add_response("batch_import_findings", _ok(expected_sent))
    document = json.loads(
        _report_with(
            reporter or _reporter(tmp_path, archive=True),
            model,
            {"securityhub": securityhub},
        )
    )
    stub.assert_no_pending_responses()
    return document, imports, queries


@pytest.mark.unit
def test_archiving_is_off_by_default():
    """Opt-in: what a scan did not report is not always fixed (a scanner that lost
    some targets, a narrower --source-dir, a refused converted tree, new
    ignore_paths or rules), so archiving is the operator's call."""
    assert SecurityHubReporterConfigOptions().archive_resolved_findings is False


@pytest.mark.unit
def test_a_finding_the_scan_no_longer_reports_is_archived(tmp_path):
    reporter = _reporter(tmp_path)
    gone = _stored(_built(reporter, _result(rule_id="B105", line=5)))

    document, imports, queries = _archive_run(
        tmp_path,
        _model([_result()], completed=("bandit",)),
        [gone],
        expected_sent=2,
    )

    # The whole request: an added filter (RecordState ACTIVE, say) would drop
    # the ARCHIVED findings whose CreatedAt must be kept.
    [query] = queries.requests
    assert query == {
        "Filters": {
            "ProductArn": [{"Value": PRODUCT_ARN, "Comparison": "EQUALS"}],
            "ProductFields": [
                {
                    "Key": "ash/target",
                    "Value": "fixture-project",
                    "Comparison": "EQUALS",
                }
            ],
        },
        "MaxResults": 100,
    }
    sent = {finding["Id"]: finding for finding in imports.findings}
    archived = sent[gone["Id"]]
    assert archived["RecordState"] == "ARCHIVED"
    assert archived["UpdatedAt"] == SCAN_TIME
    assert archived["CreatedAt"] == gone["CreatedAt"]
    assert archived["Title"] == gone["Title"]
    assert not any(key.startswith("aws/") for key in archived["ProductFields"])
    for field in ("Workflow", "Region", "ProcessedAt"):
        assert field not in archived
    assert "Normalized" not in archived["Severity"]
    assert document["archived"] == 1
    assert len(sent) == 2


@pytest.mark.unit
def test_every_page_of_existing_findings_is_read(tmp_path):
    reporter = _reporter(tmp_path)
    first = _stored(_built(reporter, _result(rule_id="R1")))
    second = _stored(_built(reporter, _result(rule_id="R2")))
    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    queries = _Capture(securityhub, "GetFindings")
    stub.add_response("get_findings", {"Findings": [first], "NextToken": "page-2"})
    stub.add_response("get_findings", {"Findings": [second]})
    stub.add_response("batch_import_findings", _ok(3))

    _report_with(
        _reporter(tmp_path, archive=True),
        _model([_result()], completed=("bandit",)),
        {"securityhub": securityhub},
    )

    stub.assert_no_pending_responses()
    assert [q.get("NextToken") for q in queries.requests] == [None, "page-2"]
    archived = {f["Id"] for f in imports.findings if f["RecordState"] == "ARCHIVED"}
    assert archived == {first["Id"], second["Id"]}


@pytest.mark.unit
def test_an_existing_finding_keeps_its_created_at(tmp_path):
    reporter = _reporter(tmp_path)
    still_there = _stored(_built(reporter, _result()))

    _document, imports, _queries = _archive_run(
        tmp_path,
        _model([_result()], completed=("bandit",)),
        [still_there],
        expected_sent=1,
    )

    [finding] = imports.findings
    assert finding["Id"] == still_there["Id"]
    assert finding["RecordState"] == "ACTIVE"
    assert finding["CreatedAt"] == still_there["CreatedAt"]
    assert finding["UpdatedAt"] == SCAN_TIME


@pytest.mark.unit
def test_a_suppressed_finding_keeps_its_created_at_too(tmp_path):
    """Archived findings are read as well, or suppression would reset CreatedAt."""
    reporter = _reporter(tmp_path)
    suppressed = _stored(
        _built(reporter, _result(suppressed=True)), record_state="ARCHIVED"
    )

    _document, imports, _queries = _archive_run(
        tmp_path,
        _model([_result(suppressed=True)], completed=("bandit",)),
        [suppressed],
        expected_sent=1,
    )

    [finding] = imports.findings
    assert finding["CreatedAt"] == suppressed["CreatedAt"]


def _scoped_model(rule: str):
    """A model that reports B602 and must not archive the stale B105."""
    model = _model([_result()], completed=("bandit",))
    if rule == "scanner errored":
        model.scanner_results["bandit"].status = ScannerStatus.ERROR
    elif rule == "scanner missing":
        model.scanner_results["bandit"].status = ScannerStatus.MISSING
    elif rule == "scanner skipped":
        model.scanner_results["bandit"].status = ScannerStatus.SKIPPED
    elif rule == "scanner excluded":
        model.scanner_results["bandit"].excluded = True
    elif rule == "scanner dependencies not satisfied":
        model.scanner_results["bandit"].dependencies_satisfied = False
    elif rule == "scanner not in this scan":
        del model.scanner_results["bandit"]
        model.scanner_results["checkov"] = ScannerTargetStatusInfo(
            status=ScannerStatus.PASSED
        )
    elif rule == "one shard of a split scan":
        from automated_security_helper.core.sharding import ShardAssignment

        model.metadata.shard = ShardAssignment(
            shard_index=0, shard_count=2, assigned_scanners=["bandit"]
        )
    elif rule == "changed files only":
        model.metadata.changed_files_only = True
    elif rule == "no changed-files marker":
        del model.metadata.__pydantic_extra__["changed_files_only"]
    elif rule == "a target of the scanner failed":
        # cdk-nag style: 10 templates attempted, 4 failed, rolled up to FAILED.
        # The report carries the scanner's name as a scan writes it: the
        # metrics readers (core/unified_metrics.own_target_reports) read only a
        # report that names its scanner, so one without the name would count
        # as no report and the scanner as having lost no target.
        model.scanner_results["bandit"].status = ScannerStatus.FAILED
        model.additional_reports["bandit"] = {
            "source": {
                "scanner_name": "bandit",
                "target_type": "source",
                "status": "FAILED",
                "targets_attempted": 10,
                "targets_failed": 4,
            }
        }
    return model


@pytest.mark.parametrize(
    "rule",
    [
        "scanner errored",
        "scanner missing",
        "scanner skipped",
        "scanner excluded",
        "scanner dependencies not satisfied",
        "scanner not in this scan",
        "one shard of a split scan",
        "changed files only",
        "no changed-files marker",
        "a target of the scanner failed",
    ],
)
@pytest.mark.unit
def test_archiving_is_limited_to_what_the_scan_looked_at(tmp_path, rule):
    reporter = _reporter(tmp_path)
    stale = _stored(_built(reporter, _result(rule_id="B105", line=5)))

    document, imports, _queries = _archive_run(
        tmp_path, _scoped_model(rule), [stale], expected_sent=1
    )

    assert stale["Id"] not in {f["Id"] for f in imports.findings}
    assert document["archived"] == 0
    if rule in (
        "one shard of a split scan",
        "changed files only",
        "no changed-files marker",
    ):
        # Nothing at all is archived from such a scan, and the receipt says why.
        assert document["archive_skipped"]
        assert document["archive_scanners"] == []


# --------------------------------------------------------------------------- #
# Results that record no scanned directory
# --------------------------------------------------------------------------- #
#
# A scan the legacy ./ash or Invoke-ASH wrapper starts records no scan_source
# (utils/scan_source.py), so with archive_resolved_findings on nothing is ever
# archived. The receipt said why, and nothing else did: an operator who turned
# archiving on saw resolved findings stay ACTIVE with no message at the default
# log level.

_NO_DIRECTORY_NOTICE = "aws-security-hub archives nothing from this run"

#: What a scan under the legacy wrappers sees: the image's ASH_IN_CONTAINER and
#: the wrapper's ASH_ACTUAL_SOURCE_DIR, and no ASH_SCAN_SOURCE.
_WRAPPER_ENVIRON = {"ASH_IN_CONTAINER": "YES", "ASH_ACTUAL_SOURCE_DIR": "/host/src"}


@pytest.fixture
def no_notice_yet():
    """The notice is printed once per process; each test starts before it."""
    securityhub_module.reset_no_scan_source_notice()
    yield
    securityhub_module.reset_no_scan_source_notice()


def _in_a_wrapper_run(monkeypatch) -> None:
    for name, value in _WRAPPER_ENVIRON.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ASH_SCAN_SOURCE", raising=False)


@pytest.mark.unit
def test_a_wrapper_runs_results_say_once_on_stderr_that_nothing_is_archived(
    tmp_path, monkeypatch, capsys, caplog, no_notice_yet
):
    """Once, whatever the log level (the logger is at CRITICAL here), naming the
    wrapper as the reason and what to run instead; and nothing is archived."""
    _in_a_wrapper_run(monkeypatch)
    caplog.set_level(logging.CRITICAL, logger="ash")
    reporter = _reporter(tmp_path, archive=True)
    stale = _stored(_built(reporter, _result(rule_id="B105", line=5)))

    documents = []
    for _ in range(2):
        document, imports, _queries = _archive_run(
            tmp_path,
            _model([_result()], completed=("bandit",), scan_source=None),
            [stale],
            expected_sent=1,
            reporter=reporter,
        )
        documents.append(document)
        assert stale["Id"] not in {f["Id"] for f in imports.findings}
        assert not [f for f in imports.findings if f["RecordState"] == "ARCHIVED"]

    err = capsys.readouterr().err
    assert err.count(_NO_DIRECTORY_NOTICE) == 1, err
    [notice] = [line for line in err.splitlines() if _NO_DIRECTORY_NOTICE in line]
    assert "scan_source" in notice
    assert "./ash" in notice and "Invoke-ASH" in notice
    # The wrapper's own reason, not the list of every possible one.
    assert "without ASH_SCAN_SOURCE" in notice
    assert "ash --mode container" in notice
    # One reason was given, so the advice points at the documented list rather
    # than at "these".
    assert "none of these" not in notice
    assert '"Findings a scan no longer reports"' in notice
    for document in documents:
        assert document["archived"] == 0
        assert "scan_source" in document["archive_skipped"]


@pytest.mark.unit
def test_results_from_elsewhere_with_no_directory_give_the_possible_reasons(
    tmp_path, monkeypatch, capsys, no_notice_yet
):
    """``ash report`` on another host cannot tell which case it was."""
    for name in ("ASH_IN_CONTAINER", "ASH_ACTUAL_SOURCE_DIR", "ASH_SCAN_SOURCE"):
        monkeypatch.delenv(name, raising=False)
    reporter = _reporter(tmp_path, archive=True)

    document, _imports, _queries = _archive_run(
        tmp_path,
        _model([_result()], completed=("bandit",), scan_source=None),
        [],
        expected_sent=1,
        reporter=reporter,
    )

    [notice] = [
        line
        for line in capsys.readouterr().err.splitlines()
        if _NO_DIRECTORY_NOTICE in line
    ]
    assert "without ASH_SCAN_SOURCE" not in notice
    # Every case the reporter page lists as recording no directory.
    for case in (
        "./ash",
        "ASH_ACTUAL_SOURCE_DIR",
        "submodule",
        "nested in another repository",
        "enclosing",
        "not UTF-8",
        "outside a git repository",
        "git on the host refused",
        "label was refused",
        "workspace project",
        "shards",
        "older ASH",
    ):
        assert case in notice, case
        assert case in document["archive_skipped"], case
    assert "ash --mode container" in notice
    # Advice that fits every case, a merge included.
    assert "not inside another one" not in notice


@pytest.mark.parametrize("case", ["archiving off", "directory recorded"])
@pytest.mark.unit
def test_no_notice_when_archiving_is_off_or_the_directory_is_recorded(
    tmp_path, monkeypatch, capsys, no_notice_yet, case
):
    _in_a_wrapper_run(monkeypatch)
    if case == "archiving off":
        securityhub, stub = _stubbed_client("securityhub")
        stub.add_response("batch_import_findings", _ok(1))
        _report_with(
            _reporter(tmp_path),
            _model([_result()], completed=("bandit",), scan_source=None),
            {"securityhub": securityhub},
        )
    else:
        _archive_run(
            tmp_path,
            _model([_result()], completed=("bandit",), scan_source="."),
            [],
            expected_sent=1,
        )

    assert _NO_DIRECTORY_NOTICE not in capsys.readouterr().err


@pytest.mark.parametrize(
    "case",
    [
        "updated by a later scan",
        "updated at the same instant",
        "already archived",
        "another scan target",
        "not an ASH finding",
        "no scanner recorded",
        "another scan scope",
        "no scan scope recorded",
    ],
)
@pytest.mark.unit
def test_archiving_leaves_findings_this_scan_cannot_speak_for(tmp_path, case):
    reporter = _reporter(tmp_path)
    finding = _built(reporter, _result(rule_id="B105", line=5))
    overrides: dict[str, Any] = {}
    if case == "updated by a later scan":
        overrides["updated_at"] = "2026-01-16T00:00:00.000Z"
    elif case == "updated at the same instant":
        overrides["updated_at"] = SCAN_TIME
    elif case == "already archived":
        overrides["record_state"] = "ARCHIVED"
    stale = _stored(finding, **overrides)
    if case == "another scan target":
        stale["ProductFields"]["ash/target"] = "another-repository"
    elif case == "not an ASH finding":
        stale["Id"] = "custom-integration/123"
    elif case == "no scanner recorded":
        del stale["ProductFields"]["ash/scanner"]
    elif case == "another scan scope":
        # The same findings_scope scanned with a narrower --source-dir.
        stale["ProductFields"]["ash/scope"] = "source=services/api;converted=no"
    elif case == "no scan scope recorded":
        del stale["ProductFields"]["ash/scope"]

    document, imports, _queries = _archive_run(
        tmp_path,
        _model([_result()], completed=("bandit",)),
        [stale],
        expected_sent=1,
    )

    assert stale["Id"] not in {f["Id"] for f in imports.findings}
    assert document["archived"] == 0


@pytest.mark.unit
def test_archiving_never_touches_findings_outside_findings_scope(tmp_path):
    """Only this scope is read and archived, even with project_name naming another
    project. GetFindings answers with the other project's finding too, as a
    filter that matched more than it should would: it is still left alone."""
    ours = _reporter(
        tmp_path, findings_scope="repo-a", project_name="repo-b", archive=True
    )
    theirs = _reporter(tmp_path, findings_scope="repo-b", project_name="repo-b")
    our_stale = _stored(_built(ours, _result(rule_id="B105", line=5)))
    their_active = _stored(_built(theirs, _result(rule_id="B108", line=9)))

    document, imports, queries = _archive_run(
        tmp_path,
        _model([_result()], project_name="repo-b", completed=("bandit",)),
        [our_stale, their_active],
        expected_sent=2,
        reporter=ours,
    )

    assert [query["Filters"]["ProductFields"] for query in queries.requests] == [
        [{"Key": "ash/target", "Value": "repo-a", "Comparison": "EQUALS"}]
    ]
    sent = {finding["Id"] for finding in imports.findings}
    assert their_active["Id"] not in sent
    assert document["archived_ids"] == [our_stale["Id"]]


@pytest.mark.unit
def test_a_scope_and_project_never_archive_a_scope_that_reads_the_same(tmp_path):
    """ash/target is "<findings_scope>/<project>", so findings_scope "org" with
    workspace project "repo" reads the same as findings_scope "org/repo" with
    none. That other scope's findings must not be archived."""
    ours = _reporter(tmp_path, findings_scope="org", archive=True)
    theirs = _reporter(tmp_path, findings_scope="org/repo")

    def project_model(results):
        model = _model(results, completed=("bandit",))
        model.metadata.workspace_project = "repo"
        return model

    [our_stale] = ours.build_asff_findings(
        project_model([_result(rule_id="B105", line=5)]),
        account_id=ACCOUNT,
        region=REGION,
    )
    our_stale = _stored(our_stale)
    their_active = _stored(_built(theirs, _result(rule_id="B108", line=9)))
    assert our_stale["ProductFields"]["ash/target"] == "org/repo"
    assert their_active["ProductFields"]["ash/target"] == "org/repo"

    document, imports, _queries = _archive_run(
        tmp_path,
        project_model([_result()]),
        [our_stale, their_active],
        expected_sent=2,
        reporter=ours,
    )

    assert their_active["Id"] not in {f["Id"] for f in imports.findings}
    assert document["archived_ids"] == [our_stale["Id"]]


@pytest.mark.unit
def test_a_stored_finding_missing_a_required_field_is_skipped_with_a_warning(
    tmp_path, caplog
):
    """One malformed stored finding must not fail every later import."""
    reporter = _reporter(tmp_path)
    good = _stored(_built(reporter, _result(rule_id="B105", line=5)))
    malformed = _stored(_built(reporter, _result(rule_id="B108", line=9)))
    # Blank rather than absent: the stubbed GetFindings response is validated
    # against the API shape, which requires Title.
    malformed["Title"] = "   "

    with caplog.at_level(logging.WARNING):
        document, imports, _queries = _archive_run(
            tmp_path,
            _model([_result()], completed=("bandit",)),
            [malformed, good],
            expected_sent=2,
        )

    sent = {f["Id"] for f in imports.findings}
    assert malformed["Id"] not in sent
    assert document["archived_ids"] == [good["Id"]]
    assert any(
        r.levelno == logging.WARNING and malformed["Id"] in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.unit
def test_a_stored_finding_with_a_required_field_absent_is_skipped_too(tmp_path, caplog):
    """Absent, not blank: the test above cannot remove Title, because the stubbed
    GetFindings response is validated against the API shape. Here the archive
    selection runs on its own, so a field can be missing outright, and a check
    that called .strip() on it without testing for a string first would raise
    and fail the whole import."""
    reporter = _reporter(tmp_path)
    good = _stored(_built(reporter, _result(rule_id="B105", line=5)))
    missing = _stored(_built(reporter, _result(rule_id="B108", line=9)))
    missing.pop("Title")

    with caplog.at_level(logging.WARNING):
        records = securityhub_module._archive_records(
            [missing, good],
            current_ids=set(),
            owned={("fixture-project", None)},
            completed=frozenset({"bandit"}),
            scope=good["ProductFields"]["ash/scope"],
            timestamp=SCAN_TIME,
        )

    assert [record["Id"] for record in records] == [good["Id"]]
    assert any(
        r.levelno == logging.WARNING and missing["Id"] in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.unit
def test_a_scan_with_no_findings_archives_what_it_no_longer_finds(tmp_path):
    reporter = _reporter(tmp_path)
    stale = _stored(_built(reporter, _result()))

    document, imports, _queries = _archive_run(
        tmp_path, _model([], completed=("bandit",)), [stale], expected_sent=1
    )

    [archived] = imports.findings
    assert archived["Id"] == stale["Id"]
    assert archived["RecordState"] == "ARCHIVED"
    assert document["imported"] == 1
    assert document["archived"] == 1


@pytest.mark.unit
def test_a_scan_with_no_findings_and_nothing_to_archive_makes_no_call(tmp_path):
    securityhub, stub = _stubbed_client("securityhub")
    document = json.loads(
        _report_with(
            _reporter(tmp_path, account_id=None, archive=True),
            _model([]),
            {"securityhub": securityhub},
            caller=None,
        )
    )
    stub.assert_no_pending_responses()
    assert document["imported"] == 0


@pytest.mark.unit
def test_with_archiving_off_existing_findings_are_not_read(tmp_path):
    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    stub.add_response("batch_import_findings", _ok(1))

    document = json.loads(
        _report_with(
            _reporter(tmp_path, archive=False),
            _model([_result()], completed=("bandit",)),
            {"securityhub": securityhub},
        )
    )

    stub.assert_no_pending_responses()
    [finding] = imports.findings
    assert finding["CreatedAt"] == finding["UpdatedAt"] == SCAN_TIME
    assert document["archived"] == 0
    assert "archive_resolved_findings" in document["archive_skipped"]


@pytest.mark.unit
def test_a_denied_get_findings_still_imports_and_then_fails(tmp_path):
    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    stub.add_client_error(
        "get_findings",
        service_error_code="AccessDeniedException",
        service_message="denied",
        http_status_code=403,
    )
    stub.add_response("batch_import_findings", _ok(1))

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(
            _reporter(tmp_path, archive=True),
            _model([_result()], completed=("bandit",)),
            {"securityhub": securityhub},
        )

    stub.assert_no_pending_responses()
    assert len(imports.findings) == 1
    message = str(raised.value)
    assert "securityhub:GetFindings" in message
    assert "archive_resolved_findings" in message
    assert "imported 1" in message.lower() or "imported: 1" in message.lower()


@pytest.mark.unit
def test_the_archive_reimport_passes_request_validation(tmp_path):
    """The rebuilt archive record is checked by botocore like any other finding."""
    reporter = _reporter(tmp_path)
    gone = _stored(_built(reporter, _result(rule_id="B105", line=5)))
    _document, imports, _queries = _archive_run(
        tmp_path,
        _model([], completed=("bandit",)),
        [gone],
        expected_sent=1,
    )
    report = ParamValidator().validate(
        {"Findings": imports.findings}, _securityhub_validator_shape()
    )
    assert not report.has_errors(), report.generate_report()


# --------------------------------------------------------------------------- #
# Delta review: timestamps, scope, refusals
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value, expected",
    [
        # GetFindings returns this form; Python 3.10's fromisoformat rejects "Z".
        ("2026-01-15T12:00:00.000Z", (2026, 1, 15, 12, 0, 0, 0)),
        ("2026-01-15T12:00:00Z", (2026, 1, 15, 12, 0, 0, 0)),
        ("2026-01-15T12:00:00.1Z", (2026, 1, 15, 12, 0, 0, 100000)),
        ("2026-01-15T12:00:00.123456789Z", (2026, 1, 15, 12, 0, 0, 123456)),
        ("2026-01-15T12:00:00+00:00", (2026, 1, 15, 12, 0, 0, 0)),
        ("2026-01-15T14:00:00.000+02:00", (2026, 1, 15, 12, 0, 0, 0)),
    ],
)
@pytest.mark.unit
def test_security_hub_timestamps_parse_on_every_supported_python(value, expected):
    from datetime import datetime, timezone

    parsed = securityhub_module._parse_timestamp(value)
    assert parsed is not None
    assert parsed.astimezone(timezone.utc) == datetime(*expected, tzinfo=timezone.utc)


def _git_checkout(root: Path) -> Path:
    import subprocess

    root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root


@pytest.mark.integration
def test_the_scope_is_the_one_the_scan_recorded_not_the_reporting_hosts(tmp_path):
    """``ash merge`` on a collector without the checkout, or ``ash report`` on
    another host, cannot see the scanned directory. The scope must still be the
    one the shards recorded, or no stored finding matches it."""
    repo = _git_checkout(tmp_path / "repo")
    narrow = repo / "services" / "api"
    narrow.mkdir(parents=True)
    reporter = _reporter(tmp_path, archive=True)
    # Where this host would look: a directory that is not the scanned one.
    reporter.context.source_dir = narrow
    model = _model([_result()], completed=("bandit",), scan_source=".")
    # The directory the scan target records, which does not exist here.
    model.additional_reports["bandit"] = {
        "source": {
            "target_type": "source",
            "status": "PASSED",
            "target": "/nonexistent/scan-host/checkout",
        }
    }
    stale = _stored(_built(reporter, _result(rule_id="B105", line=5)))
    stale["ProductFields"]["ash/scope"] = "source=.;converted=no"

    [finding] = reporter.build_asff_findings(model, account_id=ACCOUNT, region=REGION)
    document, imports, _queries = _archive_run(
        tmp_path, model, [stale], expected_sent=2, reporter=reporter
    )

    assert finding["ProductFields"]["ash/scope"] == "source=.;converted=no"
    assert document["archived_ids"] == [stale["Id"]]


@pytest.mark.unit
def test_results_that_do_not_record_the_scanned_directory_archive_nothing(tmp_path):
    """Results from an ASH that did not record it: the reporter does not guess
    from the host, it says why nothing was archived."""
    reporter = _reporter(tmp_path, archive=True)
    model = _model([_result()], completed=("bandit",), scan_source=None)
    stale = _stored(_built(reporter, _result(rule_id="B105", line=5)))

    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    stub.add_response("get_findings", {"Findings": [stale]})
    stub.add_response("batch_import_findings", _ok(1))
    document = json.loads(_report_with(reporter, model, {"securityhub": securityhub}))

    assert stale["Id"] not in {f["Id"] for f in imports.findings}
    assert document["archived"] == 0
    assert "scanned directory" in document["archive_skipped"]
    assert all("ash/scope" not in f["ProductFields"] for f in imports.findings)


@pytest.mark.unit
def test_the_scope_says_whether_the_converted_tree_was_scanned(tmp_path):
    reporter = _reporter(tmp_path)
    model = _model([_result()])
    model.additional_reports["bandit"] = {
        "source": {"target_type": "source", "status": "PASSED"},
        "converted": {"target_type": "converted", "status": "PASSED"},
    }
    [finding] = reporter.build_asff_findings(model, account_id=ACCOUNT, region=REGION)
    assert finding["ProductFields"]["ash/scope"].endswith(";converted=yes")


@pytest.mark.unit
def test_a_workspace_results_file_is_refused(tmp_path):
    """Its findings span projects and it records no generated_at, ash_config or
    changed_files_only, so UpdatedAt would be "now" and archive newer findings."""
    from automated_security_helper.models.workspace import (
        WorkspaceProjectResult,
        WorkspaceResults,
    )

    model = _model([_result()], completed=("bandit",))
    model.workspace = WorkspaceResults(
        workspace_file="ws.code-workspace",
        workspace_root="/ws",
        exit_code=0,
        projects=[
            WorkspaceProjectResult(
                project="api",
                relative_path="api",
                display_label="api",
                status="completed",
                output_path="projects/api",
            )
        ],
    )
    session = MagicMock()

    with patch.object(securityhub_module.boto3, "Session", session):
        with pytest.raises(SecurityHubImportError) as raised:
            _reporter(tmp_path, archive=True).report(model)

    session.assert_not_called()
    assert "projects/api/ash_aggregated_results.json" in str(raised.value)


@pytest.mark.unit
def test_report_refuses_when_the_reporter_is_not_enabled(tmp_path):
    """`ash report --format aws-security-hub` builds the reporter whatever its
    `enabled` says; the send path is where that is enforced."""
    reporter = _reporter(tmp_path)
    reporter.config.enabled = False
    session = MagicMock()

    with patch.object(securityhub_module.boto3, "Session", session):
        with pytest.raises(SecurityHubImportError) as raised:
            reporter.report(_model(_many(1)))

    session.assert_not_called()
    assert "reporters.aws-security-hub.enabled" in str(raised.value)


@pytest.mark.unit
def test_an_invalid_option_is_refused_when_the_reporter_is_built(tmp_path):
    """A fallback to ReporterPluginConfigBase after a failed validation, whose enabled
    defaults to True, would let one bad value switch the reporter on. The generic
    options base refuses options it does not declare (PluginOptionsBase), so
    the fallback fails too and no reporter is built; a scan refuses the same
    section with exit 3 when it loads the plugins (plugin_option_check)."""
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))
    with patch.object(securityhub_module.boto3, "Session", session):
        with pytest.raises(ValidationError) as raised:
            SecurityHubReporter(
                context=PluginContext(
                    source_dir=tmp_path,
                    output_dir=tmp_path / "out",
                    config=AshConfig(project_name="fixture-project"),
                ),
                config={
                    "enabled": True,
                    "options": {"aws_region": REGION, "max_retries": "three"},
                },
            )
    session.assert_not_called()
    assert "max_retries" in str(raised.value)


@pytest.mark.unit
def test_a_config_named_for_another_reporter_is_refused_when_the_reporter_is_built(
    tmp_path,
):
    """A section whose `name` is not aws-security-hub is validated by this
    reporter's own config model (config_validated_by_declared_model in
    base/plugin_config.py), never read as ReporterPluginConfigBase, whose
    enabled defaults to True. So no reporter is built, and nothing contacts
    AWS."""
    session = MagicMock(side_effect=AssertionError("AWS was contacted"))
    with patch.object(securityhub_module.boto3, "Session", session):
        with pytest.raises(ValidationError) as raised:
            SecurityHubReporter(
                context=PluginContext(
                    source_dir=tmp_path,
                    output_dir=tmp_path / "out",
                    config=AshConfig(project_name="fixture-project"),
                ),
                config={"enabled": True, "name": "not-security-hub"},
            )
    session.assert_not_called()
    assert "name" in str(raised.value)
    assert "aws-security-hub" in str(raised.value)
