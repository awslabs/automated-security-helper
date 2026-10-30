# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the Security Hub reporter declares, reads, retries, logs and refuses.

Each test failed at the base: an empty AWS_REGION hid AWS_DEFAULT_REGION and a
blank profile from a config file reached boto3.Session as a profile named ""; the
reporter declared three destination options while the trust table lists five;
a ClientError without an Error record left the dependency check as a KeyError
and a throttled DescribeHub dropped the reporter with no retry; results with no
SARIF report archived every stored finding; the GetCallerIdentity failure told
the operator to set account_id, which the call does not depend on; a stderr
that could not be written aborted the import; the findings an earlier batch
rejected were not logged when a later batch raised, and the lines that were
logged carried Security Hub's message unredacted; a stored CreatedAt later than
the import's UpdatedAt was copied onto the finding; a generated_at that does not
parse was replaced with the current time, and once refused, was refused only
after the account lookup; and a scan target longer than a
ProductFields value compared uncut with the cut stored value, so archiving
silently stopped.

No test here calls AWS: the clients are botocore Stubbers over blocked sockets,
or plain stand-ins that answer or raise.
"""

import logging
from typing import Any

import pytest
from botocore.exceptions import ClientError
from pydantic import ValidationError

from automated_security_helper.config.reporter_trust import (
    REPORTER_DESTINATION_OPTIONS,
)
from automated_security_helper.plugin_modules.ash_aws_plugins import (
    security_hub_reporter as securityhub_module,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    MAX_FINDINGS_SCOPE_LENGTH,
    MAX_PRODUCT_FIELD_VALUE_LENGTH,
    SecurityHubImportError,
    SecurityHubReporter,
    SecurityHubReporterConfigOptions,
    _asff_timestamp,
    _keep_created_at,
    reset_no_scan_source_notice,
)
from tests.unit.plugin_modules.ash_aws_plugins.test_security_hub_batch_import import (
    ACCOUNT,
    REGION,
    _FixedClientSession,
    _archive_run,
    _model,
    _report_with,
    _reporter,
    _result,
    _stored,
    _stubbed_client,
    _validate_with,
    isolated_aws_environment,  # noqa: F401  (autouse fixture)
    no_retry_sleep,  # noqa: F401  (autouse fixture)
)

pytestmark = pytest.mark.unit


def _client_error(code: str, status: int, operation: str) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": f"{code} happened"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        operation,
    )


# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #


def test_an_empty_aws_region_does_not_hide_aws_default_region(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.setenv("AWS_PROFILE", "")

    options = SecurityHubReporterConfigOptions()

    assert options.aws_region == "eu-west-1"
    assert options.aws_profile is None


@pytest.mark.parametrize("field", ["aws_region", "aws_profile"])
@pytest.mark.parametrize("value", ["", "  "])
def test_a_blank_value_from_the_config_is_unset(field, value):
    """``aws_profile: "${AWS_PROFILE}"`` with the variable empty, or an empty
    --config-overrides value, arrives through the field, not the environment
    default, and reached boto3.Session as a profile or region named ""."""
    options = SecurityHubReporterConfigOptions(**{field: value})

    assert getattr(options, field) is None


def test_an_all_digit_scope_or_profile_written_as_text_is_kept_as_written():
    options = SecurityHubReporterConfigOptions(
        findings_scope="0755", aws_profile="0123"
    )

    assert options.findings_scope == "0755"
    assert options.aws_profile == "0123"


@pytest.mark.parametrize("field", ["findings_scope", "aws_profile"])
@pytest.mark.parametrize("value", [493, 12345])
def test_an_int_scope_or_profile_is_refused_not_converted(field, value):
    """YAML reads an unquoted 0755 as octal 493: the text the operator wrote is
    not recoverable from the int, so an int is refused (as a configuration
    error) rather than converted into a name they never wrote."""
    with pytest.raises(ValidationError):
        SecurityHubReporterConfigOptions(**{field: value})


def test_a_scope_that_is_not_text_is_still_refused():
    with pytest.raises(ValidationError):
        SecurityHubReporterConfigOptions(findings_scope=["a", "list"])


def test_the_reporter_declares_every_destination_option_the_table_lists():
    """``declared_destination_options`` replaces the table's entry with this
    tuple once the plugin is loaded, so the two must name the same options."""
    assert (
        SecurityHubReporter.destination_options
        == REPORTER_DESTINATION_OPTIONS["aws-security-hub"]
    )
    assert "findings_scope" in SecurityHubReporter.destination_options
    assert "archive_resolved_findings" in SecurityHubReporter.destination_options


# --------------------------------------------------------------------------- #
# The dependency check
# --------------------------------------------------------------------------- #


class _DescribeHubRaises:
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    def describe_hub(self) -> dict:
        self.calls += 1
        raise self.error


class _DescribeHubThrottledOnce:
    def __init__(self) -> None:
        self.calls = 0

    def describe_hub(self) -> dict:
        self.calls += 1
        if self.calls == 1:
            raise _client_error("LimitExceededException", 429, "DescribeHub")
        return {"HubArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default"}


def test_a_client_error_without_an_error_record_fails_the_check_cleanly(
    tmp_path, caplog
):
    """A ClientError carrying no Error record used to leave the handler as a
    KeyError; the check answers False and logs the failure."""
    securityhub = _DescribeHubRaises(ClientError({}, "DescribeHub"))

    with caplog.at_level(logging.ERROR):
        satisfied = _validate_with(_reporter(tmp_path), {"securityhub": securityhub})

    assert satisfied is False
    assert securityhub.calls == 1
    assert "validation failed" in caplog.text, caplog.text


def test_a_throttled_describe_hub_is_retried_on_the_reporters_schedule(tmp_path):
    securityhub = _DescribeHubThrottledOnce()

    satisfied = _validate_with(_reporter(tmp_path), {"securityhub": securityhub})

    assert satisfied is True
    assert securityhub.calls == 2


# --------------------------------------------------------------------------- #
# report()
# --------------------------------------------------------------------------- #


def test_results_with_no_sarif_report_archive_nothing(tmp_path):
    reporter = _reporter(tmp_path, archive=True)
    model = _model([], completed=("bandit",))
    model.sarif = None

    completed, reason = reporter._archive_scope(model)

    assert completed is None
    assert "SARIF" in reason, reason


def test_the_caller_account_failure_does_not_suggest_setting_account_id(tmp_path):
    """GetCallerIdentity is called whether or not account_id is configured."""

    class _Sts:
        def get_caller_identity(self) -> dict:
            raise _client_error("AccessDeniedException", 403, "GetCallerIdentity")

    reporter = _reporter(tmp_path)

    with pytest.raises(SecurityHubImportError) as raised:
        reporter._caller_account(_FixedClientSession({"sts": _Sts()}), REGION)

    message = str(raised.value)
    assert "AccessDeniedException" in message
    assert "account_id" not in message


def test_a_stderr_that_cannot_be_written_does_not_abort_the_import(
    tmp_path, monkeypatch
):
    reset_no_scan_source_notice()

    def _broken_pipe(*_: Any, **__: Any) -> None:
        raise OSError(32, "Broken pipe")

    monkeypatch.setattr(securityhub_module, "echo", _broken_pipe)
    monkeypatch.setattr(
        "automated_security_helper.utils.scan_source.why_no_scan_source",
        lambda source_dir, environ: "The scan recorded no directory.",
    )
    reporter = _reporter(tmp_path, archive=True)

    reporter._notify_no_scan_source()  # must not raise

    reset_no_scan_source_notice()


def test_a_generated_at_that_does_not_parse_refuses_the_import(tmp_path):
    """Replacing it with the current time would overrule every newer scan's
    findings in Security Hub; nothing is sent, and nothing is asked of AWS
    first: with no STS client prepared (``caller=None``), a lookup of the
    account before the refusal would fail the test with a KeyError."""
    with pytest.raises(SecurityHubImportError) as raised:
        _asff_timestamp("yesterday-ish")
    assert "generated_at" in str(raised.value)

    securityhub, stub = _stubbed_client("securityhub")
    with pytest.raises(SecurityHubImportError) as refused:
        _report_with(
            _reporter(tmp_path),
            _model([_result()], generated_at="yesterday-ish"),
            {"securityhub": securityhub},
            caller=None,
        )
    assert "generated_at" in str(refused.value)
    stub.assert_no_pending_responses()


# --------------------------------------------------------------------------- #
# Rejections
# --------------------------------------------------------------------------- #


class _RejectsThenRefuses:
    """The first batch rejects one finding; the second is refused outright."""

    def __init__(self, message: str) -> None:
        self.message = message
        self.calls = 0

    def batch_import_findings(self, Findings: list) -> dict:
        self.calls += 1
        if self.calls == 1:
            return {
                "FailedCount": 1,
                "SuccessCount": len(Findings) - 1,
                "FailedFindings": [
                    {
                        "Id": "ash/rejected-in-the-first-batch",
                        "ErrorCode": "InvalidInput",
                        "ErrorMessage": self.message,
                    }
                ],
            }
        raise _client_error("AccessDeniedException", 403, "BatchImportFindings")


def _findings(count: int) -> list[dict]:
    return [{"Id": f"ash/{n}"} for n in range(count)]


def test_findings_an_earlier_batch_rejected_are_logged_when_a_later_batch_raises(
    tmp_path, caplog
):
    reporter = _reporter(tmp_path)
    client = _RejectsThenRefuses("Finding is malformed")

    with caplog.at_level(logging.ERROR):
        with pytest.raises(SecurityHubImportError) as raised:
            reporter._import(client, _findings(101), account_id=ACCOUNT, region=REGION)

    assert client.calls == 2
    assert "rejected: 1" in str(raised.value)
    assert "ash/rejected-in-the-first-batch" in caplog.text, caplog.text
    assert "Finding is malformed" in caplog.text, caplog.text


def test_a_rejection_line_carries_no_value_the_config_read_from_the_environment(
    tmp_path, caplog
):
    canary = "envcanary-scope-value-for-the-log"
    reporter = _reporter(tmp_path)
    reporter.context.config._environment_values = [canary]
    client = _RejectsThenRefuses(f"Finding names {canary} in its scope")

    with caplog.at_level(logging.ERROR):
        with pytest.raises(SecurityHubImportError):
            reporter._import(client, _findings(1), account_id=ACCOUNT, region=REGION)

    # The control: the line itself was logged.
    assert "ash/rejected-in-the-first-batch" in caplog.text, caplog.text
    assert canary not in caplog.text, caplog.text


# --------------------------------------------------------------------------- #
# Timestamps and the archive comparison
# --------------------------------------------------------------------------- #


def test_a_stored_created_at_later_than_the_import_is_not_copied():
    """An older results file re-reported must not send a finding created after
    it was updated; its own timestamps are kept."""
    finding = {
        "Id": "ash/one",
        "CreatedAt": "2026-01-10T00:00:00.000Z",
        "UpdatedAt": "2026-01-10T00:00:00.000Z",
    }
    newer_than_the_import = {"Id": "ash/one", "CreatedAt": "2026-01-20T00:00:00.000Z"}

    _keep_created_at([finding], [newer_than_the_import])

    assert finding["CreatedAt"] == "2026-01-10T00:00:00.000Z"


def test_a_stored_created_at_before_the_import_is_kept():
    """The control: the documented behavior, an earlier first-seen time kept."""
    finding = {
        "Id": "ash/one",
        "CreatedAt": "2026-01-10T00:00:00.000Z",
        "UpdatedAt": "2026-01-10T00:00:00.000Z",
    }

    _keep_created_at(
        [finding], [{"Id": "ash/one", "CreatedAt": "2026-01-01T00:00:00.000Z"}]
    )

    assert finding["CreatedAt"] == "2026-01-01T00:00:00.000Z"


LONG_SCOPE = "s" * MAX_FINDINGS_SCOPE_LENGTH
LONG_PROJECT = "p" * (MAX_PRODUCT_FIELD_VALUE_LENGTH - MAX_FINDINGS_SCOPE_LENGTH + 100)


def _long_key_model(results):
    model = _model(results, completed=("bandit",))
    model.metadata.workspace_project = LONG_PROJECT
    return model


def test_a_scan_target_longer_than_a_product_field_still_archives(tmp_path):
    """ash/target is cut when stored; the filter and the owner comparison use
    the cut form, so the stored finding is still found and archived."""
    reporter = _reporter(tmp_path, findings_scope=LONG_SCOPE, archive=True)
    [earlier] = reporter.build_asff_findings(
        _long_key_model([_result(rule_id="B105", line=5)]),
        account_id=ACCOUNT,
        region=REGION,
    )
    stored = _stored(earlier)
    assert len(stored["ProductFields"]["ash/target"]) == MAX_PRODUCT_FIELD_VALUE_LENGTH
    assert len(f"{LONG_SCOPE}/{LONG_PROJECT}") > MAX_PRODUCT_FIELD_VALUE_LENGTH

    document, imports, queries = _archive_run(
        tmp_path,
        _long_key_model([_result()]),
        [stored],
        expected_sent=2,
        reporter=reporter,
    )

    [query] = queries.requests
    assert (
        query["Filters"]["ProductFields"][0]["Value"]
        == stored["ProductFields"]["ash/target"]
    )
    assert document["archived"] == 1
    archived = {f["Id"]: f for f in imports.findings}[stored["Id"]]
    assert archived["RecordState"] == "ARCHIVED"


# A directory whose scope string (``source=<dir>;converted=<yes|no>``) is longer
# than a ProductFields value: stored cut, it loses its ``;converted=`` part.
LONG_SOURCE = "d" * (MAX_PRODUCT_FIELD_VALUE_LENGTH - 10)


def _long_source_model(results, *, converted: bool):
    model = _model(results, completed=("bandit",), scan_source=LONG_SOURCE)
    reports = {"source": {"target_type": "source", "status": "PASSED"}}
    if converted:
        reports["converted"] = {"target_type": "converted", "status": "PASSED"}
    model.additional_reports["bandit"] = reports
    return model


def test_a_scope_longer_than_a_product_field_archives_nothing(tmp_path):
    """A converted-tree scan and a plain scan of the same long directory store
    the same cut scope, so neither can tell the other's findings from its own;
    compared cut, the plain scan archived what only the converted tree
    reported. Nothing is archived instead, and the receipt says why."""
    reporter = _reporter(tmp_path, archive=True)
    [from_converted_tree] = reporter.build_asff_findings(
        _long_source_model([_result(rule_id="B105", line=5)], converted=True),
        account_id=ACCOUNT,
        region=REGION,
    )
    [from_plain_scan] = reporter.build_asff_findings(
        _long_source_model([_result()], converted=False),
        account_id=ACCOUNT,
        region=REGION,
    )
    # The mechanism: both stored scopes are the same cut string.
    assert len(from_converted_tree["ProductFields"]["ash/scope"]) == (
        MAX_PRODUCT_FIELD_VALUE_LENGTH
    )
    assert (
        from_converted_tree["ProductFields"]["ash/scope"]
        == from_plain_scan["ProductFields"]["ash/scope"]
    )
    stored = _stored(from_converted_tree)

    document, imports, _queries = _archive_run(
        tmp_path,
        _long_source_model([_result()], converted=False),
        [stored],
        expected_sent=1,
        reporter=reporter,
    )

    assert stored["Id"] not in {f["Id"] for f in imports.findings}
    assert document["archived"] == 0
    assert "scope" in document["archive_skipped"]
    assert str(MAX_PRODUCT_FIELD_VALUE_LENGTH) in document["archive_skipped"]
