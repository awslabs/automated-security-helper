# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import functools
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Callable, Literal, TYPE_CHECKING, overload

import boto3
import botocore.session
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectionError as BotocoreConnectionError,
    HTTPClientError,
    NoCredentialsError,
    ParamValidationError,
)
from pydantic import (
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    MAX_RETRIES,
    MAX_RETRY_DELAY_SECONDS,
    RETRYABLE_EXCEPTIONS,
    blank_is_unset,
    check_retry_delays,
    report_missing_setting,
    retry_with_backoff,
    stripped_or_none,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.finding_identity import (
    identity_keys,
    relative_path,
    relative_to_scan_root,
)
from automated_security_helper.utils.console import echo
from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import _resolve_result_severity

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import Result


# Limits this reporter is built on. Each is quoted from the AWS documentation page
# named beside it; none is from memory.
#
# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html
#   Findings: "Maximum of 100 findings per request." and "Array Members: Minimum
#   number of 1 item. Maximum number of 100 items."
#   "The maximum allowed size for a finding is 240 Kb. An error is returned for any
#   finding larger than 240 Kb." The page states no limit on the request as a whole.
#   Every field below is bounded, so a finding stays far under 240 KB.
MAX_FINDINGS_PER_REQUEST = 100

# Whether this process has printed the notice that results with no scan_source
# archive nothing (_notify_no_scan_source). Once per process is once per `ash`
# command, workspace projects included; a long-lived MCP server prints it for its
# first such scan only, and every receipt still says why in archive_skipped.
_no_scan_source_notice_printed = False
_no_scan_source_notice_lock = threading.Lock()


def reset_no_scan_source_notice() -> None:
    """Forget that the no-scan_source notice was printed (tests)."""
    global _no_scan_source_notice_printed
    with _no_scan_source_notice_lock:
        _no_scan_source_notice_printed = False


# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFinding.html
#   Id, GeneratorId: "Maximum length of 512". Title: "Maximum length of 256".
#   Description: "Maximum length of 1024". ProductFields: "Can contain up to 50
#   key-value pairs. For each key-value pair, the key can contain up to 128
#   characters, and the value can contain up to 2048 characters."
#   SchemaVersion: "The value is 2018-10-08."
MAX_GENERATOR_ID_LENGTH = 512
MAX_TITLE_LENGTH = 256
MAX_DESCRIPTION_LENGTH = 1024
MAX_PRODUCT_FIELD_VALUE_LENGTH = 2048
ASFF_SCHEMA_VERSION = "2018-10-08"

# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Severity.html
#   Original: "Maximum length of 64". Label valid values: INFORMATIONAL | LOW |
#   MEDIUM | HIGH | CRITICAL.
_ASFF_SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFORMATIONAL",
}

# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Resource.html
#   Type: "If the resource does not match any of the provided types, then set Type
#   to Other." Id has no documented length limit; this reporter bounds it at the
#   ProductFields value length so the finding size stays bounded.
_RESOURCE_TYPE = "Other"
MAX_RESOURCE_ID_LENGTH = 2048

# https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html
#   Types: "One or more finding types in the format of namespace/category/classifier".
_TYPE_VULNERABILITY = "Software and Configuration Checks/Vulnerabilities"
_TYPE_CVE = "Software and Configuration Checks/Vulnerabilities/CVE"
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Set on every finding so the Security Hub console and filters name ASH instead of
# the "Personal" / "Default" a custom integration otherwise shows. The ASFF page
# for CompanyName and ProductName: "You cannot update this attribute with
# BatchImportFindings or BatchUpdateFindings. The exception to this is a custom
# integration."
PRODUCT_NAME = "Automated Security Helper"
COMPANY_NAME = "AWS Labs"

# The longest findings_scope accepted. ash/target is findings_scope plus a
# workspace project's key, and a ProductFields value is cut at
# MAX_PRODUCT_FIELD_VALUE_LENGTH; a cut value no longer equals the GetFindings
# filter, so archiving and the kept CreatedAt would silently stop. Half the value
# length leaves the rest for the project key.
MAX_FINDINGS_SCOPE_LENGTH = MAX_PRODUCT_FIELD_VALUE_LENGTH // 2

# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html
#   MaxResults: "Valid Range: Minimum value of 1. Maximum value of 100."
MAX_GET_FINDINGS_RESULTS = 100

# The scanner statuses that mean the scanner looked at everything it was given.
# ERROR, MISSING and SKIPPED scanners did not, so their findings are never archived.
_COMPLETED_STATUSES = {"PASSED", "FAILED"}

# An ISO 8601 timestamp, split so it can be rewritten into the forms
# datetime.fromisoformat accepts on Python 3.10: no "Z", and a fraction of exactly
# 3 or 6 digits. Security Hub returns "2026-01-15T12:00:00.000Z".
_ISO_TIMESTAMP = re.compile(
    r"^(?P<head>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?P<zone>[Zz]|[+-]\d{2}:?\d{2})?$"
)

# A fenced code block in a finding message. FlatVulnerability reads one as the
# finding's code snippet, and snippets are not sent. An unterminated fence runs to
# the end of the message.
_FENCED_BLOCK = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)

# The API's own 500 is InternalException, which the shared list does not carry.
# LimitExceededException, the API's 429, is already in it.
_RETRYABLE_ERRORS = [*RETRYABLE_EXCEPTIONS, "InternalException"]

# Request errors that mean the credentials themselves were refused.
_CREDENTIAL_ERRORS = {
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
    "SignatureDoesNotMatch",
}
_ACCESS_DENIED_ERRORS = {"AccessDenied", "AccessDeniedException"}
_THROTTLING_ERRORS = {
    "LimitExceededException",
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
}

#: How many rejected findings are listed one per log line before the rest are
#: only counted. The exception message carries the counts by error code.
_MAX_LOGGED_FAILURES = 20


class SecurityHubImportError(RuntimeError):
    """Security Hub did not import every finding ASH sent, or ASH could not send.

    Raised rather than returned so that ``ReportPhase`` marks the reporter failed
    and ``ash report`` exits non-zero: a returned document would be written as
    ``reports/ash.aws-security-hub.asff.json`` and reported as a generated report.
    """


class SecurityHubReporterConfigOptions(ReporterOptionsBase):
    # Read from the environment when the options are built, not when this module
    # is imported, so a config built later sees the run's environment.
    # An empty or blank value is unset: AWS_REGION="" or " " does not hide
    # AWS_DEFAULT_REGION, and an empty AWS_PROFILE is no profile.
    aws_region: Annotated[
        str | None,
        Field(
            default_factory=lambda: (
                stripped_or_none(os.environ.get("AWS_REGION"))
                or stripped_or_none(os.environ.get("AWS_DEFAULT_REGION"))
            ),
            description="AWS Region for Security Hub integration",
        ),
    ]
    aws_profile: Annotated[
        str | None,
        Field(
            default_factory=lambda: stripped_or_none(os.environ.get("AWS_PROFILE")),
            description="AWS Profile to use for authentication",
        ),
    ]
    account_id: Annotated[
        str | None,
        Field(
            default=None,
            description=(
                "AWS account ID the findings are imported into. Looked up from the "
                "credentials if not set; when set, it must be the credentials' "
                "account, because Security Hub accepts findings sent with the "
                "account's default product ARN only from the account they name"
            ),
        ),
    ] = None
    max_retries: Annotated[
        int,
        Field(
            le=MAX_RETRIES,
            description=(
                "Maximum number of retries for a throttled or failed "
                "BatchImportFindings request"
            ),
        ),
    ] = 3
    base_delay: Annotated[
        float,
        Field(
            le=MAX_RETRY_DELAY_SECONDS,
            description="Base delay in seconds between retry attempts",
        ),
    ] = 1.0
    max_delay: Annotated[
        float,
        Field(
            le=MAX_RETRY_DELAY_SECONDS,
            description="Maximum delay in seconds between retry attempts",
        ),
    ] = 60.0
    # findings_scope and aws_profile take text only. An all-digit value YAML or
    # --config-overrides hands over as an int is refused rather than converted:
    # the text the operator wrote is not recoverable from the int (YAML reads
    # `0755` as octal 493), so a converted value could name a scope or profile
    # they never wrote. Quote it in the config to keep it text.
    findings_scope: Annotated[
        str | None,
        Field(
            max_length=MAX_FINDINGS_SCOPE_LENGTH,
            description=(
                "Name of the findings this scan owns in Security Hub, unique among "
                "the repositories that import into the same account and Region: "
                "finding Ids are derived from it, and archiving touches only the "
                "findings recorded with it. Required; project_name is not used. Set "
                "it only in the operator's configuration (--config-overrides, or a "
                "config file outside the scanned tree), because it decides which "
                "findings a scan updates and archives"
            ),
        ),
    ] = None
    archive_resolved_findings: Annotated[
        bool,
        Field(
            description=(
                "Archive findings an earlier scan of the same scope imported that "
                "this scan no longer reports, for the scanners that lost no target. "
                "Off by default: a finding a scan did not report is not always "
                "fixed. Needs securityhub:GetFindings, which is also used to keep "
                "each existing finding's CreatedAt. Set it only in the operator's "
                "configuration"
            ),
        ),
    ] = False

    @field_validator("account_id", mode="before")
    @classmethod
    def _account_id_from_int(cls, value: Any) -> Any:
        """An unquoted account id in YAML, or one from --config-overrides, is an int.

        Converted rather than refused, since it names the account the operator
        meant. Account ids are 12 digits, so an int is zero-padded back to the
        leading zero YAML drops.
        """
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return f"{value:012d}"
        return value

    @field_validator("aws_region", "aws_profile", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: Any) -> Any:
        """A blank region or profile is no value (``blank_is_unset``)."""
        return blank_is_unset(value)

    @model_validator(mode="after")
    def _retry_delays_are_bounded(self):
        return check_retry_delays(self)


class SecurityHubReporterConfig(ReporterPluginConfigBase):
    name: Literal["aws-security-hub"] = "aws-security-hub"
    extension: Annotated[
        str,
        Field(
            default="aws-security-hub.asff.json",
            description="File extension for Security Hub ASFF output",
        ),
    ] = "aws-security-hub.asff.json"
    # Off by default: this reporter sends findings to an AWS service with the
    # operator's credentials, so only the operator's config turns it on.
    enabled: Annotated[
        bool,
        Field(
            default=False,
            description=(
                "Whether the Security Hub reporter is enabled. Off by default: "
                "loading ash_aws_plugins for another reporter must not send findings "
                "to Security Hub"
            ),
        ),
    ] = False
    options: Annotated[
        SecurityHubReporterConfigOptions,
        Field(
            default_factory=SecurityHubReporterConfigOptions,
            description="Configuration options for Security Hub reporter",
        ),
    ]


@ash_reporter_plugin
class SecurityHubReporter(ReporterPluginBase[SecurityHubReporterConfig]):
    """Sends security findings to AWS Security Hub in ASFF format.

    Off by default (``enabled: False``): a scan that loads ``ash_aws_plugins`` for
    the S3, CloudWatch Logs or Bedrock reporter must not send its findings, with
    suppressed ones and their justifications, to Security Hub.

    What is sent
    ------------
    Every SARIF result in the model becomes one ASFF finding, imported with
    ``BatchImportFindings`` in requests of at most 100 findings, under the
    account's default product ARN,
    ``arn:<partition>:securityhub:<region>:<account>:product/<account>/default`` --
    the form Security Hub documents for findings a customer imports itself. A
    finding carries the rule, the scanner, the file and line, ASH's severity, and
    the result message with ASH's secret masking applied (bandit B105/B106/B107
    passwords, as in the flat-json and CSV reports) and its fenced code blocks
    removed. No code snippet is sent.

    The returned document, which ``ReportPhase`` writes to
    ``reports/ash.aws-security-hub.asff.json``, is a receipt for the import plus
    the findings exactly as they were sent.

    Finding identity
    ----------------
    Security Hub keys a finding on ``Id`` within the product ARN, so the ``Id``
    decides whether a re-scan updates a finding or adds a second one. It follows
    identity contract v2, shared with ``utils/finding_identity.py``: ``"ash/" +
    sha256(json.dumps([target, key], sort_keys=True))``. The key is what makes
    the finding the same finding from one scan to the next: the scanner, the
    rule, the file (one spelling, relative to the scan root, so a different
    checkout path or a Windows separator does not change it), the package name
    and path for dependency findings, the workspace project, and the result's
    usable SARIF fingerprints -- or, for a result that has none, its start and
    end line plus a content suffix when other results share that key (see
    ``build_asff_findings``). It deliberately leaves out ``report_id`` and
    the scan time, which change on every scan; the message and severity, which a
    newer scanner version may reword or re-rate without the finding being a
    different one; the column, which most scanners do not report; and the package
    version, because upgrading to a release that is still vulnerable does not make
    it a different finding. The account and Region are not in it either: they are
    already in the product ARN, which scopes the ``Id``.

    The scan target is the ``findings_scope`` option, and ``report`` refuses
    before any AWS call when it is unset. It is not ``project_name``: a
    repository's own ``.ash`` config can set that, and naming another project
    there wrote into, and archived, that project's findings in the operator's
    account. Nor does the reporter read it from the config recorded in the
    results file, which is data. Only the operator's configuration sets it and
    ``archive_resolved_findings``: a config file inside the scanned tree cannot
    (``config/operator_only_options.py``), and ``ash merge``, which builds every
    reporter from the shards' recorded config, drops both from that config. The
    ``ash/target`` product field, which ``GetFindings`` filters on, appends a
    workspace project's key when it differs from the target.

    Where the checks live
    ---------------------
    ``validate_plugin_dependencies`` is main's: the Region, ``DescribeHub``, and
    ``GetCallerIdentity`` when ``account_id`` is unset. The checks this reporter
    needs before it sends live at the start of ``report``, before anything is
    read from or written to Security Hub: that the configuration validated and
    the reporter is enabled (``ash report`` builds it whatever ``enabled``
    says), that the results are not a workspace's unified file, the Region, a
    ``findings_scope``, and ``GetCallerIdentity`` with the configured
    ``account_id`` compared against the caller's. ``report`` therefore enforces
    them in a scan and in ``ash report``, which skips the dependency check.

    ``UpdatedAt`` is the scan's ``generated_at``. Security Hub ignores an import
    whose ``UpdatedAt`` is not later than the stored one, so re-reporting an older
    scan with ``ash report`` cannot overwrite a newer one. With archiving on,
    ``CreatedAt`` is kept from Security Hub for a finding that already exists
    there.

    Suppressed findings are sent with ``RecordState: ARCHIVED`` rather than left
    out, so a finding imported before it was suppressed is archived by the next
    scan. ``Workflow`` is not set: Security Hub ignores ``BatchImportFindings``
    updates to it once a finding exists.

    Archiving what a scan no longer reports
    ---------------------------------------
    Opt-in, with ``archive_resolved_findings: true``: a finding a scan did not
    report is not always fixed. The existing findings of the scan target are read
    with ``GetFindings`` and each ACTIVE one this scan did not produce is
    re-imported with ``RecordState: ARCHIVED``, but only from a scanner that
    finished without losing a target, only for a finding of this scan's scope
    (``ash/scope``: the scanned directory within its repository, as the scan
    recorded it, and whether the converted tree was scanned) and of this scan's
    target and workspace project, only when it was last updated before this
    scan, and never from one shard of a split scan or from results that do not
    say ``changed_files_only: false`` or do not record the scanned directory. A
    new ignore_paths entry or ruleset change can still make a finding look
    fixed. See ``_archive_scope``, ``_scan_scope`` and ``_archive_records``.
    Results that record no scanned directory (every scan the legacy wrappers
    start) also print a notice to stderr, once per process
    (``_notify_no_scan_source``).

    Failures
    --------
    Anything short of every finding imported raises
    :class:`SecurityHubImportError` with the counts and what to do: no
    findings_scope, a missing Region, no credentials, an ``account_id`` that is not
    the credentials' account, a request Security Hub refused
    (``InvalidAccess`` when Security Hub is not enabled, ``AccessDenied`` when the
    credentials lack ``securityhub:BatchImportFindings``), throttling that
    outlasted the retries, a request botocore refused before sending it, findings
    Security Hub rejected inside a successful response (``FailedCount`` /
    ``FailedFindings``), or a ``GetFindings`` that failed (raised after the import,
    so the findings still land). Rejected findings are logged by ``Id`` with
    Security Hub's error code and message.

    Workspace mode: per project.

    This reporter has a side effect -- it calls ``BatchImportFindings`` -- so the
    behaviour is not only about document shape. Each project's own scan already
    publishes that project's findings. Invoking it again at workspace level would
    import every finding a second time, and ASFF findings are keyed on ``Id``, so
    the duplicates would either overwrite the per-project imports or land beside
    them depending on how the ids collide. Neither outcome is one an operator
    asked for, and both are silent.

    Per project is also the correct scope for the data: an ASFF finding is
    attributed to one resource in one account, and a workspace's projects are
    independently owned.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT
    # Sends findings to AWS with the host's credentials.
    sends_off_host = True
    # The Region and profile, the account, the archive switch and the findings
    # scope are the operator's: where the findings are sent, and which of them a
    # scan owns, updates and archives. The retry options set how long it keeps
    # calling Security Hub with the operator's credentials. Declared here so
    # the declaration ``ash merge`` and ``ash report`` read
    # (``declared_destination_options``) names them as the trust table does.
    destination_options = (
        "aws_region",
        "aws_profile",
        "account_id",
        "archive_resolved_findings",
        "findings_scope",
        "max_retries",
        "base_delay",
        "max_delay",
    )

    #: Why the configuration given to this reporter was refused, when it was.
    _config_error: str | None = PrivateAttr(default=None)

    def model_post_init(self, context):
        if self.config is None:
            self.config = SecurityHubReporterConfig()
        elif not isinstance(self.config, SecurityHubReporterConfig):
            # The ``config`` field is a union with ReporterPluginConfigBase, so a
            # section that fails SecurityHubReporterConfig and that the base class
            # accepts (a ``name`` other than aws-security-hub) is read as the base
            # class, whose ``enabled`` defaults to True: the reporter would turn
            # itself on with none of its options. It is turned off instead, and
            # report() refuses with the reason. A bad option value (max_retries:
            # three) does not get here: the base refuses options it does not
            # declare, so neither branch accepts the section and it is refused.
            self._config_error = _config_problem(self.config)
            ASH_LOGGER.error(
                "aws-security-hub is disabled because its configuration is "
                f"invalid: {self._config_error}"
            )
            self.config = SecurityHubReporterConfig(enabled=False)
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate reporter configuration and AWS connectivity."""
        self.dependencies_satisfied = False

        if not self.config.options.aws_region:
            report_missing_setting(
                self.config.name, "aws_region", ("AWS_REGION", "AWS_DEFAULT_REGION")
            )
            return self.dependencies_satisfied

        try:
            session = boto3.Session(
                profile_name=self.config.options.aws_profile,
                region_name=self.config.options.aws_region,
            )

            # Test Security Hub connectivity. DescribeHub needs
            # securityhub:DescribeHub, a permission the import itself does not:
            # a principal granted only BatchImportFindings (and GetFindings, to
            # archive) imports with `ash report`, which skips this check, so a
            # scan is not disabled on that one refusal. The refusal is named
            # with its permission; the import's own errors say the rest. Both
            # calls are retried on the reporter's schedule, as the import is: a
            # throttled DescribeHub used to drop the reporter for the scan.
            securityhub_client = session.client("securityhub")
            try:
                self._with_retry(securityhub_client.describe_hub)
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") not in _ACCESS_DENIED_ERRORS:
                    raise
                ASH_LOGGER.warning(
                    "securityhub:DescribeHub was refused for the configured "
                    "credentials, so whether Security Hub is enabled in the "
                    "configured region was not checked; the import itself needs "
                    "securityhub:BatchImportFindings (and securityhub:GetFindings "
                    "when archive_resolved_findings is on) and reports its own "
                    "refusal"
                )

            # Get account ID if not provided
            if not self.config.options.account_id:
                sts_client = session.client("sts")
                identity = self._with_retry(sts_client.get_caller_identity)
                self.config.options.account_id = identity["Account"]

            self.dependencies_satisfied = True
            # The region is named by its option, not its value, which a config
            # file can read from the environment.
            ASH_LOGGER.info(
                "Security Hub reporter validated for the region in its aws_region "
                "option"
            )

        except NoCredentialsError:
            ASH_LOGGER.error("AWS credentials not found for Security Hub reporter")
        except ClientError as e:
            # .get: a ClientError built without an Error record must not leave
            # the handler as a KeyError.
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "InvalidAccessException":
                ASH_LOGGER.error(
                    "Security Hub is not enabled in this region or insufficient permissions"
                )
            else:
                # error_text with the config's environment values: botocore's
                # exceptions name the profile, region or account they were given.
                ASH_LOGGER.error(
                    "AWS Security Hub validation failed: "
                    f"{error_text(e, self._environment_values())}"
                )
        except Exception as e:
            ASH_LOGGER.error(
                "Security Hub reporter validation failed: "
                f"{error_text(e, self._environment_values())}"
            )

        return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str:
        """Import the findings into Security Hub and return the import receipt.

        Raises:
            SecurityHubImportError: when any finding was not imported, or the
                existing findings could not be read for archiving.
        """
        if isinstance(self.config, dict):
            self.config = SecurityHubReporterConfig.model_validate(self.config)
        # Refusals that need no AWS call, in the order an operator would fix them.
        if self._config_error:
            raise SecurityHubImportError(
                "aws-security-hub's configuration is invalid, so the reporter is "
                f"disabled: {self._config_error}. Fix "
                "reporters.aws-security-hub in the ASH configuration."
            )
        if not self.config.enabled:
            raise SecurityHubImportError(_not_enabled_message())
        if getattr(model, "workspace", None) is not None:
            raise SecurityHubImportError(_workspace_results_message(model))
        options = self.config.options
        region = options.aws_region
        if not region:
            raise SecurityHubImportError(_missing_region_message())
        base_key = _target_key(self._scan_target(), _model_project(model))
        # The stored forms: a ProductFields value is cut at
        # MAX_PRODUCT_FIELD_VALUE_LENGTH when a finding is sent, so the
        # GetFindings filter and the ownership and scope comparisons below use
        # the cut forms too. Compared uncut, a long workspace project key or scan
        # path made every comparison miss and archiving silently stopped.
        stored_base_key = _as_stored(base_key)
        stored_project = _as_stored(_model_project(model))

        completed, archive_skipped = self._archive_scope(model)
        if options.archive_resolved_findings and self._scan_scope(model) is None:
            self._notify_no_scan_source()
        elif options.archive_resolved_findings and archive_skipped:
            # The receipt says why too, but nothing an operator reads at the
            # default log level did: resolved findings stayed ACTIVE with no
            # message, as _notify_no_scan_source's docstring records for the
            # case it covers.
            ASH_LOGGER.warning(
                f"aws-security-hub archived nothing from this run: {archive_skipped}"
            )
        result_count = len(model.sarif.get_all_results()) if model.sarif else 0
        if result_count == 0 and completed is None:
            # BatchImportFindings takes at least one finding, and nothing can be
            # archived, so there is nothing to call. Nor is there a reason to
            # look the account up.
            ASH_LOGGER.info("aws-security-hub: no findings to import")
            return self._receipt(
                findings=[],
                account_id=options.account_id,
                region=region,
                imported=0,
                requests=0,
                duplicates=0,
                archived=[],
                archive_skipped=archive_skipped,
                archive_scanners=None,
            )

        # The scan time orders this import against the stored findings; a
        # generated_at that does not parse is refused here, before the account
        # lookup, so that it is not found only once the credentials work. After
        # the return above: a results file with nothing to send needs no scan
        # time, and a file written with archiving off may not record one.
        timestamp = _asff_timestamp(model.metadata.generated_at)
        try:
            session = boto3.Session(
                profile_name=options.aws_profile,
                region_name=region,
            )
            securityhub = session.client("securityhub")
        except BotoCoreError as e:
            # A profile that does not exist is the usual cause.
            raise SecurityHubImportError(
                f"aws-security-hub could not set up an AWS session in {region}: {e}"
            ) from e
        # Every check that needs AWS but changes nothing, before anything is
        # read from or written to Security Hub. Here rather than in
        # validate_plugin_dependencies so that it also holds for `ash report`,
        # which skips that check.
        caller_account = self._caller_account(session, region)
        if options.account_id and options.account_id != caller_account:
            raise SecurityHubImportError(
                _account_mismatch_message(options.account_id, caller_account)
            )
        account_id = caller_account
        product_arn = _product_arn(region, account_id)

        findings, duplicates = _unique_by_id(
            self.build_asff_findings(model, account_id=account_id, region=region)
        )
        if duplicates:
            # The identity key tells every result of a run apart (occurrences
            # and ordinals, utils/finding_identity.identity_keys), so a repeated
            # Id is not two equal results: it is a defect in how the keys were
            # made, and the finding is sent once as Security Hub would process
            # only the first.
            ASH_LOGGER.warning(
                f"aws-security-hub: {duplicates} finding(s) were given an Id an "
                "earlier finding already had, which the identity key is meant to "
                "rule out; each Id was sent once. Please report this as an ASH "
                "defect."
            )

        existing: list[dict[str, Any]] = []
        existing_error: Exception | None = None
        if options.archive_resolved_findings:
            target_keys = {stored_base_key} | {
                f["ProductFields"]["ash/target"] for f in findings
            }
            try:
                existing = self._existing_findings(
                    securityhub, product_arn=product_arn, target_keys=target_keys
                )
            except (ClientError, BotoCoreError) as e:
                existing_error = e
                ASH_LOGGER.error(
                    "aws-security-hub could not read the existing findings "
                    f"(GetFindings): {error_text(e, self._environment_values())}"
                )
            _keep_created_at(findings, existing)

        archived: list[dict[str, Any]] = []
        scope = self._scan_scope(model)
        if completed is not None and scope is not None and existing_error is None:
            archived = _archive_records(
                existing,
                current_ids={f["Id"] for f in findings},
                owned={(stored_base_key, stored_project)}
                | {_owner(f["ProductFields"]) for f in findings},
                completed=completed,
                scope=_as_stored(scope),
                timestamp=timestamp,
            )

        to_send = findings + archived
        imported, requests = (0, 0)
        if to_send:
            imported, requests = self._import(
                securityhub,
                to_send,
                account_id=account_id,
                region=region,
            )
        if existing_error is not None:
            raise SecurityHubImportError(
                _existing_findings_failure_message(
                    existing_error, imported=imported, total=len(to_send)
                )
            )
        # Redacted: the region is configured (the account id comes from STS, but
        # the whole line goes through the same redaction), and ash.log keeps it.
        ASH_LOGGER.info(
            text_without_values(
                f"Imported {imported} finding(s) into Security Hub for account "
                f"{account_id} in {region}, {len(archived)} of them archived as no "
                "longer reported",
                self._environment_values(),
            )
        )
        return self._receipt(
            findings=findings,
            account_id=account_id,
            region=region,
            imported=imported,
            requests=requests,
            duplicates=duplicates,
            archived=archived,
            archive_skipped=archive_skipped,
            archive_scanners=completed,
        )

    def build_asff_findings(
        self, model: "AshAggregatedResults", *, account_id: str, region: str
    ) -> list[dict[str, Any]]:
        """Convert every SARIF result in ``model`` to an ASFF finding.

        One finding per result, in model order. Each finding's ``Id`` follows
        identity contract v2: ``"ash/" + sha256(json.dumps([target, key],
        sort_keys=True))``, where the target is ``findings_scope``
        (``_scan_target``) and the key is the one ``utils/finding_identity``
        defines for the flattened finding id: ``identity_keys`` over every
        result's ``FlatVulnerability.identity``, with each file made relative to
        this scan's source directory first. The rules (fingerprints that identify
        a result instead of its lines, occurrences and ordinals for results that
        share a location) are documented there.
        """
        product_arn = _product_arn(region, account_id)
        timestamp = _asff_timestamp(model.metadata.generated_at)
        target = self._scan_target()
        model_project = _model_project(model)
        scope = self._scan_scope(model)
        source_dir = getattr(self.context, "source_dir", None)

        prepared: list[dict[str, Any]] = []
        for run in (model.sarif.runs if model.sarif else None) or []:
            tool_name = "unknown"
            if run.tool and run.tool.driver and run.tool.driver.name:
                tool_name = run.tool.driver.name
            for result in run.results or []:
                prepared.append(
                    self._prepare(
                        result,
                        tool_name=tool_name,
                        target=target,
                        model_project=model_project,
                        source_dir=source_dir,
                    )
                )

        # One call for the whole model: a fingerprint, an occurrence and an
        # ordinal each depend on the other results.
        keys = identity_keys(
            [entry["identity"] for entry in prepared], default_project=model_project
        )
        return [
            self._to_asff(
                entry,
                key=key,
                target=target,
                scope=scope,
                account_id=account_id,
                product_arn=product_arn,
                timestamp=timestamp,
            )
            for entry, key in zip(prepared, keys)
        ]

    def _prepare(
        self,
        result: "Result",
        *,
        tool_name: str,
        target: str,
        model_project: str | None,
        source_dir: str | Path | None,
    ) -> dict[str, Any]:
        """Everything about one result that its ASFF finding is built from."""
        # FlatVulnerability is the extraction every tabular reporter shares: the
        # location, the scanner name, the suppression, the package identity, the
        # message with secrets masked, and the finding's identity. Its severity is
        # not used: it maps an error-level result with no issue_severity to HIGH,
        # while ASH's severity counts and threshold gate map it to CRITICAL.
        # Security Hub should show the severity the scan summary and exit code
        # counted.
        flat = FlatVulnerability.from_sarif_result(result, tool_name, "UNKNOWN")
        # from_sarif_result always records the identity it took the id from; only
        # an additional_reports entry that carries its plugin's id has none, and
        # those are not SARIF results.
        identity = flat.identity
        if identity is None:
            # The reporter's own error, so the report phase records this
            # reporter's failure rather than a crash.
            raise SecurityHubImportError(
                f"aws-security-hub: the {tool_name} result "
                f"{flat.rule_id or 'unknown'} has no finding identity, so no "
                "finding Id can be derived for it; nothing was sent"
            )
        project = flat.workspace_project or model_project
        return {
            "flat": flat,
            "result": result,
            "scanner": flat.scanner or tool_name,
            "rule_id": flat.rule_id or "unknown",
            # Where the finding is, as the scan root sees it. A converted file's
            # key names it relative to the converted root instead, which is not a
            # path a reader can open.
            "file_path": relative_path(flat.file_path, source_dir),
            "project": project,
            "target_key": _target_key(target, project),
            "identity": relative_to_scan_root(identity, source_dir),
            "message": _without_code_blocks(flat.description or ""),
        }

    def _to_asff(
        self,
        entry: dict[str, Any],
        *,
        key: dict[str, Any],
        target: str,
        scope: str | None,
        account_id: str,
        product_arn: str,
        timestamp: str,
    ) -> dict[str, Any]:
        flat = entry["flat"]
        ash_severity = _resolve_result_severity(entry["result"])
        label = _ASFF_SEVERITY_LABELS.get(ash_severity, "INFORMATIONAL")
        original = ash_severity.upper()

        scanner = entry["scanner"]
        rule_id = entry["rule_id"]
        file_path = entry["file_path"]
        project = entry["project"]
        target_key = entry["target_key"]

        message = entry["message"]
        first_line = next(
            (line.strip() for line in message.splitlines() if line.strip()), ""
        )
        location = file_path or target_key
        if file_path and flat.line_start is not None:
            location = f"{file_path}:{flat.line_start}"
        title = f"{rule_id}: {first_line}" if first_line else rule_id
        description = (
            message if first_line else f"{scanner} reported {rule_id} at {location}"
        )

        types = [_TYPE_CVE if _CVE_PATTERN.search(rule_id) else _TYPE_VULNERABILITY]
        severity = {"Label": label, "Original": original}
        resource_id = f"{target_key}/{file_path}" if file_path else target_key

        product_fields = {
            "ash/target": target_key,
            "ash/scope": scope,
            "ash/scanner": scanner,
            "ash/ruleId": rule_id,
            "ash/severity": original,
            "ash/suppressed": "true" if flat.is_suppressed else "false",
            "ash/file": file_path,
            "ash/startLine": _str_or_none(flat.line_start),
            "ash/endLine": _str_or_none(flat.line_end),
            "ash/workspaceProject": project,
            "ash/suppressionJustification": (
                flat.suppression_justification if flat.is_suppressed else None
            ),
            "ash/packageName": flat.package_name,
            "ash/packageVersion": flat.package_version,
        }

        return {
            "SchemaVersion": ASFF_SCHEMA_VERSION,
            "Id": _finding_id(target, key),
            "ProductArn": product_arn,
            "GeneratorId": _truncate(
                f"ash/{scanner}/{rule_id}", MAX_GENERATOR_ID_LENGTH
            ),
            "AwsAccountId": account_id,
            "Types": types,
            "CreatedAt": timestamp,
            "UpdatedAt": timestamp,
            "Severity": dict(severity),
            "Title": _truncate(title, MAX_TITLE_LENGTH),
            "Description": _truncate(description, MAX_DESCRIPTION_LENGTH),
            "Resources": [
                {
                    "Type": _RESOURCE_TYPE,
                    "Id": _truncate(resource_id, MAX_RESOURCE_ID_LENGTH),
                }
            ],
            # The fields a finding provider updates through FindingProviderFields;
            # see https://docs.aws.amazon.com/securityhub/latest/userguide/finding-update-batchimportfindings.html.
            # The top-level copies are kept because the ASFF required-attributes
            # page lists Severity and Types as required; for an existing finding
            # Security Hub updates them only if nobody changed them with
            # BatchUpdateFindings.
            "FindingProviderFields": {"Severity": dict(severity), "Types": list(types)},
            "ProductFields": {
                key: _truncate(value, MAX_PRODUCT_FIELD_VALUE_LENGTH)
                for key, value in product_fields.items()
                if isinstance(value, str) and value.strip()
            },
            "ProductName": PRODUCT_NAME,
            "CompanyName": COMPANY_NAME,
            "RecordState": "ARCHIVED" if flat.is_suppressed else "ACTIVE",
        }

    def _scan_target(self) -> str:
        """The ``findings_scope`` option, which the Ids and the archive filter follow.

        Read from this reporter's own configuration only: not from
        ``project_name``, which a repository's own config can set, and not from
        the config recorded in the results file, so ``ash report`` imports into
        the scope its operator names. Unset or blank is refused; there is no
        fallback.
        """
        scope = (self.config.options.findings_scope or "").strip()
        if not scope:
            raise SecurityHubImportError(_missing_findings_scope_message())
        return scope

    def _notify_no_scan_source(self) -> None:
        """Say on stderr, once per process, that these results archive nothing.

        archive_resolved_findings is on and the results record no scan_source,
        which every scan the legacy wrappers start does. The receipt's
        archive_skipped says so too, but nothing an operator sees did: resolved
        findings stayed ACTIVE with no message at the default log level. So this
        is printed, not logged, and shows whatever the log level is.
        """
        global _no_scan_source_notice_printed
        with _no_scan_source_notice_lock:
            if _no_scan_source_notice_printed:
                return
            _no_scan_source_notice_printed = True
        from automated_security_helper.utils.process_env import snapshot_environ
        from automated_security_helper.utils.scan_source import why_no_scan_source

        reason = why_no_scan_source(
            getattr(self.context, "source_dir", None) or ".", snapshot_environ()
        )
        notice = (
            "aws-security-hub archives nothing from this run: "
            "archive_resolved_findings is on, but the results record no scanned "
            f"directory (scan_source). {reason} To archive, scan with `ash --mode "
            "container`, or run ASH directly, where none of the cases the "
            "aws-security-hub reporter's documentation lists under "
            '"Findings a scan no longer reports" applies.'
        )
        ASH_LOGGER.debug(notice)
        # Through the console's echo, as is every message ASH prints for a
        # person. It flushes, so the notice reaches stderr before the reporter
        # goes on. A stderr that cannot be written (closed, or a full pipe) is
        # no reason to abort the import: the receipt's archive_skipped and the
        # debug line above still say so.
        try:
            echo(notice, err=True)
        except OSError as e:
            ASH_LOGGER.debug(f"The no-scan_source notice could not be printed: {e}")

    def _archive_scope(
        self, model: "AshAggregatedResults"
    ) -> tuple[frozenset[str] | None, str | None]:
        """The scanners whose resolved findings may be archived, or why none may.

        Archiving reads "not reported" as "fixed", which is true only for what
        the scan looked at in full. So it applies only to scanners that finished
        (PASSED or FAILED, not excluded, dependencies satisfied) without losing a
        single target (``targets_failed`` 0 -- a partial loss like cdk-nag's 4 of
        10 templates rolls up to ERROR, or to FAILED when the evaluated
        templates' findings fail the severity gate, so this counter check is
        what refuses the partial-loss FAILED rows the status check admits; it
        also refuses an older stored result that kept PASSED or FAILED beside
        such counts), and not at all to one shard of a split
        scan, or to results that do not say they are unfiltered: the marker must
        be an explicit ``changed_files_only: false``, which results from an older
        ASH lack. ``_archive_records`` also requires the stored finding's scan
        scope to be this scan's, so results that do not record the scanned
        directory (``metadata.scan_source``) archive nothing either. A new
        ignore_paths entry or a ruleset change can still make a finding look
        fixed; that is why archiving is opt-in.

        Two more things the results record narrow it, and both are read off the
        scanner's own per-target reports through the metrics readers, so a
        scanner with an ``additional_reports`` entry those readers return
        nothing for (an empty entry, a slot holding no mapping, reports filed
        under another scanner's name) is left out as well: its coverage cannot
        be checked. A scanner that reported
        inputs it found and did not scan (``inputs_not_scanned`` on its target
        reports) did not look at everything either, so it is left out; inputs
        ASH itself left out of the scan set (``metadata.inputs_not_scanned``) were
        read by no scanner, so nothing is archived. And when a converter failed
        this run (``converter_results``: a ``failure``, or unsatisfied
        dependencies with inputs to convert) while a scanner scanned the
        converted tree, the converted tree is missing that converter's outputs
        and a converted-tree finding the scan no longer reports is not fixed; a
        stored finding does not say which tree it came from, so nothing is
        archived from such a scan.
        """
        from automated_security_helper.core.unified_metrics import (
            SCAN_SET_OWNER,
            inputs_not_scanned,
            own_target_reports,
            target_counts,
        )

        if not self.config.options.archive_resolved_findings:
            return None, "archive_resolved_findings is false"
        if getattr(model, "sarif", None) is None:
            # No SARIF report is not "zero findings": what the scan reported is
            # unknown, so nothing it did not report can be read as fixed.
            return None, (
                "the results carry no SARIF report, so what the scan reported "
                "cannot be compared with the stored findings"
            )
        if getattr(model.metadata, "shard", None) is not None:
            return None, "the results are one shard of a split scan"
        marker = getattr(model.metadata, "changed_files_only", None)
        if marker is True:
            return None, (
                "the results were filtered to files changed against the base ref"
            )
        if marker is not False:
            return None, (
                "the results do not record whether they were filtered to changed "
                "files (made by an older ASH?)"
            )
        scope = self._scan_scope(model)
        if scope is None:
            from automated_security_helper.utils.scan_source import (
                NO_SCAN_SOURCE_CASES,
            )

            return None, (
                "the results do not record the scanned directory (scan_source), "
                "so their scope cannot be compared. The scan could not tell which "
                f"directory of which repository it scanned: {NO_SCAN_SOURCE_CASES}"
            )
        if len(scope) > MAX_PRODUCT_FIELD_VALUE_LENGTH:
            # A finding stores the scope cut at the field's length, which drops
            # its trailing ";converted=<yes|no>" part (and the end of a long
            # directory), so a converted-tree scan and a plain scan of the same
            # directory would read as the same scope and archive each other's
            # findings. Compared cut, the scope tells scans apart no more;
            # nothing is archived rather than the wrong thing.
            return None, (
                "the scan scope (source=<dir>;converted=<yes|no>) is longer than "
                f"a ProductFields value ({MAX_PRODUCT_FIELD_VALUE_LENGTH} "
                "characters), so the stored findings' scope cannot be compared "
                "with this scan's; shorten the scanned directory's path"
            )
        failed_converters = sorted(
            name
            for name, info in (model.converter_results or {}).items()
            if _converter_lost_inputs(info)
        )
        if failed_converters and scope.endswith("converted=yes"):
            return None, (
                "a converter failed this run "
                f"({', '.join(failed_converters)}), so the converted tree is "
                "missing its outputs and a converted-tree finding the scan no "
                "longer reports cannot be read as fixed"
            )
        not_scanned_by = {owner for owner, _path, _reason in inputs_not_scanned(model)}
        if SCAN_SET_OWNER in not_scanned_by:
            return None, (
                "the scan left inputs out of its scan set (metadata."
                "inputs_not_scanned), so no scanner looked at everything"
            )
        reports = model.additional_reports or {}
        finished = [
            name
            for name, info in (model.scanner_results or {}).items()
            if str(getattr(info.status, "value", info.status)) in _COMPLETED_STATUSES
            and not getattr(info, "excluded", False)
            and getattr(info, "dependencies_satisfied", True)
        ]

        def left_out_because(name: str) -> str | None:
            """Why a finished scanner does not count, or None when it does."""
            # A scanner with an additional_reports entry whose per-target
            # reports the metrics read as nobody's (an empty entry, a slot
            # holding no mapping, reports filed under another scanner's name)
            # has coverage that cannot be checked: the two reads below would
            # see no lost target and no unscanned input in them. Left out
            # rather than trusted.
            if name in reports and not own_target_reports(model, name):
                return "its per-target reports cannot be read"
            if target_counts(model, name)[1] != 0:
                return "lost a target"
            # A scanner that found inputs it did not scan did not look at
            # everything, whatever its status says.
            if name in not_scanned_by:
                return "found inputs it did not scan"
            return None

        reasons = {name: left_out_because(name) for name in finished}
        completed = frozenset(name for name, why in reasons.items() if why is None)
        if not completed:
            left_out = [f"{name} ({why})" for name, why in reasons.items() if why]
            if not left_out:
                return None, "no scanner finished without losing a target"
            return None, (
                "no scanner finished without losing a target or an input it found: "
                + ", ".join(left_out)
            )
        return completed, None

    def _scan_scope(self, model: "AshAggregatedResults") -> str | None:
        """Where this scan looked: ``source=<dir>;converted=<yes|no>``, or None.

        ``<dir>`` is ``metadata.scan_source``, which the scan records while the
        directory exists: the scanned directory relative to its git repository's
        root (``.`` for the root), or its absolute path outside a repository
        (see ``utils/scan_source.py``). Nothing is worked out on this host, so
        ``ash merge`` on a collector without the checkout and ``ash report`` on
        another host give the scan's scope. ``converted`` says whether any
        scanner scanned the converted tree (archives, notebooks), from the
        results' own target records. None when the results do not record the
        directory; such findings carry no ``ash/scope`` and nothing is archived.

        Recorded on every finding as ``ash/scope``; a finding is archived only by
        a scan of the same scope, so a narrower ``--source-dir`` under the same
        findings_scope, or a run whose converted tree was empty, refused or gone
        (the last notebook deleted), archives nothing the other one found. A
        scope longer than a ProductFields value is stored cut, which loses that
        distinction, so ``_archive_scope`` archives nothing for such a scan.
        """
        source = getattr(model.metadata, "scan_source", None)
        if not isinstance(source, str) or not source.strip():
            return None
        converted = any(
            "converted" in report
            for report in (getattr(model, "additional_reports", None) or {}).values()
            if isinstance(report, dict)
        )
        return f"source={source};converted={'yes' if converted else 'no'}"

    def _existing_findings(
        self, client, *, product_arn: str, target_keys: set[str]
    ) -> list[dict[str, Any]]:
        """Every finding stored under this product ARN for these scan targets.

        Both record states are read: the ARCHIVED ones (suppressed findings, and
        earlier archives) are needed to keep their CreatedAt; only ACTIVE ones
        are archive candidates. Filters on one field joined by OR are allowed
        (https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_MapFilter.html),
        but one query per target keeps each filter to a single value.
        """
        found: list[dict[str, Any]] = []
        for target_key in sorted(target_keys):
            token = None
            while True:
                params: dict[str, Any] = {
                    "Filters": {
                        "ProductArn": [{"Value": product_arn, "Comparison": "EQUALS"}],
                        "ProductFields": [
                            {
                                "Key": "ash/target",
                                "Value": target_key,
                                "Comparison": "EQUALS",
                            }
                        ],
                    },
                    "MaxResults": MAX_GET_FINDINGS_RESULTS,
                }
                if token:
                    params["NextToken"] = token
                response = self._with_retry(
                    functools.partial(client.get_findings, **params)
                )
                found.extend(response.get("Findings") or [])
                token = response.get("NextToken")
                if not token:
                    break
        return found

    def _caller_account(self, session, region: str) -> str:
        """The account the credentials belong to, from sts:GetCallerIdentity."""
        try:
            return session.client("sts").get_caller_identity()["Account"]
        except NoCredentialsError as e:
            raise SecurityHubImportError(_no_credentials_message(region)) from e
        except ClientError as e:
            error = e.response.get("Error", {})
            # The call is made whether or not account_id is configured (a
            # configured one is compared with the caller's), so setting it is
            # not a way around this failure and is not suggested.
            raise SecurityHubImportError(
                "aws-security-hub could not determine the AWS account: "
                f"sts:GetCallerIdentity failed with {error.get('Code')}: "
                f"{error.get('Message')}. Check the credentials ASH runs with."
            ) from e
        except BotoCoreError as e:
            raise SecurityHubImportError(
                f"aws-security-hub could not determine the AWS account: {e}"
            ) from e

    def _import(
        self,
        client,
        findings: list[dict[str, Any]],
        *,
        account_id: str,
        region: str,
    ) -> tuple[int, int]:
        """Send ``findings`` in batches. Returns (imported, requests) or raises."""
        total = len(findings)
        imported = 0
        requests = 0
        rejected: list[dict[str, Any]] = []
        rejected_count = 0
        not_sent = 0

        for start in range(0, total, MAX_FINDINGS_PER_REQUEST):
            batch = findings[start : start + MAX_FINDINGS_PER_REQUEST]
            try:
                response = self._with_retry(
                    functools.partial(client.batch_import_findings, Findings=batch)
                )
            except (ClientError, BotoCoreError) as e:
                # Stop: the failures that reach here (no credentials, refused
                # credentials, access denied, Security Hub off, throttling that
                # outlasted the retries, a request botocore refused) would fail
                # every later batch the same way. The findings an earlier batch
                # rejected are logged first; the raise used to skip them.
                self._log_rejections(rejected)
                raise SecurityHubImportError(
                    _request_failure_message(
                        e,
                        imported=imported,
                        total=total,
                        not_sent=total - start,
                        rejected=rejected_count,
                        account_id=account_id,
                        region=region,
                        max_retries=self.config.options.max_retries,
                    )
                ) from e
            requests += 1
            failed = list(response.get("FailedFindings") or [])
            imported += int(response.get("SuccessCount", len(batch) - len(failed)))
            rejected_count += int(response.get("FailedCount", len(failed)))
            rejected.extend(failed)
            if (
                failed
                and len(failed) == len(batch)
                and all(f.get("ErrorCode") == "InvalidAccess" for f in failed)
            ):
                # Security Hub answers this way for every finding when it is not
                # enabled in the account and Region; the next batch would too.
                not_sent = total - (start + len(batch))
                break

        if rejected_count or not_sent:
            self._log_rejections(rejected)
            raise SecurityHubImportError(
                _rejection_message(
                    rejected,
                    rejected_count=rejected_count,
                    imported=imported,
                    total=total,
                    not_sent=not_sent,
                    account_id=account_id,
                    region=region,
                )
            )
        return imported, requests

    def _log_rejections(self, rejected: list[dict[str, Any]]) -> None:
        """One ERROR line per rejected finding, up to ``_MAX_LOGGED_FAILURES``.

        Security Hub's ErrorMessage can quote the finding it refused, and a
        finding carries configured values (the scope, a path), so the line is
        redacted with the config's environment values as the reporter's other
        lines are.
        """
        if not rejected:
            return
        values = self._environment_values()
        for failure in rejected[:_MAX_LOGGED_FAILURES]:
            ASH_LOGGER.error(
                text_without_values(
                    f"Security Hub rejected finding {failure.get('Id')}: "
                    f"{failure.get('ErrorCode')}: {failure.get('ErrorMessage')}",
                    values,
                )
            )
        if len(rejected) > _MAX_LOGGED_FAILURES:
            ASH_LOGGER.error(
                f"... and {len(rejected) - _MAX_LOGGED_FAILURES} more rejected "
                "finding(s)"
            )

    def _with_retry(self, call: Callable[[], Any]) -> Any:
        """``call()``, retried on the configured schedule when throttled.

        The decorator is applied to a closure at call time, as in
        ``S3Reporter._put_object_with_retry``, so it reads this reporter's options
        rather than the module defaults.

        Throttling is the case this exists for. The API reference gives
        BatchImportFindings "RateLimit of 10 requests per second. BurstLimit of 30
        requests per second" and GetFindings "RateLimit of 3 requests per second.
        BurstLimit of 6 requests per second"
        (https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#throttling-limits),
        and a throttled request fails with LimitExceededException (HTTP 429).
        """
        options = self.config.options

        @retry_with_backoff(
            max_retries=options.max_retries,
            base_delay=options.base_delay,
            max_delay=options.max_delay,
            retryable_exceptions=_RETRYABLE_ERRORS,
        )
        def attempt():
            return call()

        return attempt()

    def _receipt(
        self,
        *,
        findings: list[dict[str, Any]],
        account_id: str | None,
        region: str,
        imported: int,
        requests: int,
        duplicates: int,
        archived: list[dict[str, Any]],
        archive_skipped: str | None,
        archive_scanners: frozenset[str] | None,
    ) -> str:
        """The document ReportPhase writes to reports/ash.aws-security-hub.asff.json."""
        return json.dumps(
            {
                "product_arn": _product_arn(region, account_id) if account_id else None,
                "aws_account_id": account_id,
                "region": region,
                "imported": imported,
                "requests": requests,
                "duplicates_skipped": duplicates,
                "archived": len(archived),
                "archived_ids": [record["Id"] for record in archived],
                "archive_scanners": sorted(archive_scanners)
                if archive_scanners
                else [],
                "archive_skipped": archive_skipped,
                "findings": findings,
            },
            indent=2,
        )


def _account_mismatch_message(configured: str, caller: str) -> str:
    return (
        f"aws-security-hub: account_id is {configured}, but the credentials belong "
        f"to account {caller}. Security Hub accepts findings sent with an "
        "account's default product ARN only from that account. Use credentials "
        f"for account {configured}, or remove account_id to import into {caller}."
    )


def _not_enabled_message() -> str:
    return (
        "aws-security-hub is not enabled, so it imports nothing. Set "
        "reporters.aws-security-hub.enabled: true in the ASH configuration, or "
        "pass --config-overrides 'reporters.aws-security-hub.enabled=true'."
    )


def _workspace_results_message(model: "AshAggregatedResults") -> str:
    projects = [
        f"{getattr(project, 'output_path', None) or 'projects/' + str(project.project)}"
        "/ash_aggregated_results.json"
        for project in (getattr(model.workspace, "projects", None) or [])
    ]
    listed = (
        ", ".join(projects)
        if projects
        else "projects/<key>/ash_aggregated_results.json"
    )
    return (
        "aws-security-hub imports one project's results at a time, and these are a "
        "workspace's unified results, which record no scan time, configuration or "
        "changed-files marker of their own. Run ash report with --output-dir set "
        "to a project's directory under the workspace output, so it reads that "
        f"project's results: {listed}."
    )


def _config_problem(config: Any) -> str:
    """Why ``config`` does not validate as a SecurityHubReporterConfig."""
    data = config.model_dump() if hasattr(config, "model_dump") else config
    try:
        SecurityHubReporterConfig.model_validate(data)
    except ValidationError as e:
        return "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in e.errors()
        )
    return f"it was read as {type(config).__name__}"


def _missing_region_message() -> str:
    return (
        "aws-security-hub needs an AWS Region: set "
        "reporters.aws-security-hub.options.aws_region, or AWS_REGION or "
        "AWS_DEFAULT_REGION before ASH starts."
    )


def _no_credentials_message(region: str) -> str:
    return (
        "aws-security-hub found no AWS credentials. Provide credentials for the "
        f"account whose Security Hub in {region} should receive the findings: "
        "environment variables, a profile (reporters.aws-security-hub.options."
        "aws_profile or AWS_PROFILE), or an instance or task role."
    )


def _request_failure_message(
    error: Exception,
    *,
    imported: int,
    total: int,
    not_sent: int,
    rejected: int,
    account_id: str,
    region: str,
    max_retries: int,
) -> str:
    progress = (
        f"Security Hub imported {imported} of {total} findings before the failure; "
        f"not sent: {not_sent}"
    )
    if rejected:
        progress += f"; rejected: {rejected}"
    progress += "."

    if isinstance(error, NoCredentialsError):
        return f"{_no_credentials_message(region)} {progress}"
    if isinstance(error, ParamValidationError):
        return (
            "botocore rejected the BatchImportFindings request before sending it: "
            f"{error}. That is a defect in ASH's ASFF conversion; please report it "
            f"with this message. {progress}"
        )
    if isinstance(error, (BotocoreConnectionError, HTTPClientError)):
        return (
            f"BatchImportFindings could not reach Security Hub in {region}: "
            f"{error}. {progress}"
        )
    if not isinstance(error, ClientError):
        return f"BatchImportFindings failed in {region}: {error}. {progress}"

    details = error.response.get("Error", {})
    code = details.get("Code")
    cause = f"BatchImportFindings failed with {code}: {details.get('Message')}."
    if code == "InvalidAccessException":
        hint = (
            f"Security Hub is not enabled for account {account_id} in {region}, or "
            "the account may not import findings. Enable it with "
            f"'aws securityhub enable-security-hub --region {region}' and grant "
            "securityhub:BatchImportFindings."
        )
    elif code in _ACCESS_DENIED_ERRORS:
        hint = (
            "The credentials may not call securityhub:BatchImportFindings. Grant "
            "that action to the role or user ASH runs as."
        )
    elif code in _THROTTLING_ERRORS:
        hint = (
            "Security Hub throttled the import, or a limit was exceeded, and the "
            f"request still failed after {max_retries} retries. Retry later, or "
            "raise reporters.aws-security-hub.options.max_retries or base_delay."
        )
    elif code == "InvalidInputException":
        hint = (
            "Security Hub refused the request as invalid. That is a defect in "
            "ASH's ASFF conversion; please report it with this message."
        )
    elif code in _CREDENTIAL_ERRORS:
        hint = "The credentials were refused; refresh or replace them."
    else:
        hint = ""
    return " ".join(part for part in (cause, hint, progress) if part)


def _rejection_message(
    rejected: list[dict[str, Any]],
    *,
    rejected_count: int,
    imported: int,
    total: int,
    not_sent: int,
    account_id: str,
    region: str,
) -> str:
    codes: dict[str, int] = {}
    for failure in rejected:
        code = str(failure.get("ErrorCode") or "unknown")
        codes[code] = codes.get(code, 0) + 1
    by_code = ", ".join(f"{code}: {count}" for code, count in sorted(codes.items()))

    parts = [
        f"Security Hub rejected {rejected_count} of {total} findings"
        + (f" ({by_code})" if by_code else "")
        + f"; imported: {imported}."
    ]
    if not_sent:
        parts.append(f"Not sent: {not_sent}.")
    if "InvalidAccess" in codes:
        parts.append(
            "Security Hub rejects every finding with InvalidAccess when it is not "
            f"enabled for account {account_id} in {region}: enable it with "
            f"'aws securityhub enable-security-hub --region {region}', and check "
            f"that the credentials belong to account {account_id}."
        )
    if any(code in _ACCESS_DENIED_ERRORS for code in codes):
        parts.append("Grant securityhub:BatchImportFindings to the caller.")
    if "InvalidInput" in codes:
        parts.append(
            "InvalidInput means ASH built a finding Security Hub does not accept; "
            "please report it with the logged error message."
        )
    parts.append("Each rejected finding is logged with its Id and error.")
    return " ".join(parts)


def _existing_findings_failure_message(
    error: Exception, *, imported: int, total: int
) -> str:
    if isinstance(error, ClientError):
        details = error.response.get("Error", {})
        cause = f"{details.get('Code')}: {details.get('Message')}"
    else:
        cause = str(error)
    return (
        f"Security Hub imported {imported} of {total} findings, but ASH could not "
        f"read the findings already there (GetFindings failed with {cause}), so "
        "no finding this scan no longer reports was archived and existing "
        "findings did not keep their CreatedAt. Grant securityhub:GetFindings, or "
        "set reporters.aws-security-hub.options.archive_resolved_findings to "
        "false."
    )


def _missing_findings_scope_message() -> str:
    return (
        "aws-security-hub needs reporters.aws-security-hub.options.findings_scope "
        "set to a name unique to this repository among those importing into the "
        "same account and Region; finding Ids and archiving follow it. Set it in "
        "the operator's configuration: --config-overrides "
        "'reporters.aws-security-hub.options.findings_scope=<name>', or a config "
        "file outside the scanned tree."
    )


def _converter_lost_inputs(info: Any) -> bool:
    """Whether a converter's recorded row says the converted tree lacks its
    outputs: it raised (``failure``), or its dependencies were unavailable while
    it had inputs to convert (``candidate_inputs`` not 0; None counts, as the
    completeness gate counts it). An excluded converter never ran by intent."""
    if getattr(info, "excluded", False):
        return False
    if getattr(info, "failure", None):
        return True
    if getattr(info, "dependencies_satisfied", True):
        return False
    return getattr(info, "candidate_inputs", None) != 0


def _target_key(target: str, project: str | None) -> str:
    """The scan target, with a workspace project's key when it adds anything."""
    return target if not project or project == target else f"{target}/{project}"


def _owner(product_fields: dict[str, Any]) -> tuple[Any, Any]:
    """``(ash/target, ash/workspaceProject)`` of a finding; the project is None
    when the finding has none, as ``_to_asff`` leaves the field out then."""
    return (
        product_fields.get("ash/target"),
        product_fields.get("ash/workspaceProject"),
    )


def _model_project(model: "AshAggregatedResults") -> str | None:
    project = getattr(model.metadata, "workspace_project", None)
    return project if isinstance(project, str) and project.strip() else None


def _without_code_blocks(message: str) -> str:
    """``message`` with every fenced code block removed."""
    stripped = _FENCED_BLOCK.sub("", message)
    return re.sub(r"\n{3,}", "\n\n", stripped).strip()


def _parse_timestamp(value: Any) -> datetime | None:
    """An ISO 8601 timestamp as an aware datetime, on every supported Python.

    Python 3.10's ``datetime.fromisoformat`` accepts neither a trailing ``Z`` nor
    a fraction of other than 3 or 6 digits, and GetFindings returns
    ``2026-01-15T12:00:00.000Z``. Both are rewritten first: ``Z`` to ``+00:00``,
    and the fraction padded or cut to 6 digits.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    match = _ISO_TIMESTAMP.match(text)
    if match:
        text = match["head"]
        if match["fraction"]:
            text += "." + (match["fraction"] + "000000")[:6]
        zone = match["zone"]
        if zone in ("Z", "z"):
            zone = "+00:00"
        elif zone and ":" not in zone:
            zone = f"{zone[:3]}:{zone[3:]}"
        text += zone or ""
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _keep_created_at(
    findings: list[dict[str, Any]], existing: list[dict[str, Any]]
) -> None:
    """Give each finding that already exists in Security Hub its stored CreatedAt.

    Upon creation "the CreatedAt and UpdatedAt timestamps must be the same", and
    afterwards CreatedAt records when the issue was first imported
    (https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html).
    """
    created = {
        stored["Id"]: stored["CreatedAt"]
        for stored in existing
        if isinstance(stored.get("Id"), str)
        and isinstance(stored.get("CreatedAt"), str)
    }
    for finding in findings:
        if finding["Id"] not in created:
            continue
        # Not when the stored CreatedAt is later than this import's UpdatedAt:
        # an older results file re-reported with `ash report` would then send a
        # finding created after it was updated. Its own timestamps are kept.
        kept = _parse_timestamp(created[finding["Id"]])
        updated = _parse_timestamp(finding.get("UpdatedAt"))
        if kept is not None and updated is not None and kept > updated:
            continue
        finding["CreatedAt"] = created[finding["Id"]]


def _archive_records(
    existing: list[dict[str, Any]],
    *,
    current_ids: set[str],
    owned: set[tuple[Any, Any]],
    completed: frozenset[str],
    scope: str,
    timestamp: str,
) -> list[dict[str, Any]]:
    """Re-imports, with RecordState ARCHIVED, of findings this scan no longer reports.

    Only a stored finding this scan can speak for: an ACTIVE ``ash/`` finding of
    this scan scope whose ``(ash/target, ash/workspaceProject)`` pair is one this
    scan owns (see ``_owner``), from a scanner that lost no target in this scan,
    last updated before this scan. A finding updated at or after this scan's
    time was written by a later scan, which this one must not overrule.

    The pair, not ``ash/target`` alone: ``ash/target`` is
    ``<findings_scope>/<project>``, so findings_scope ``org`` with workspace
    project ``repo`` reads the same as findings_scope ``org/repo`` with none, and
    would have archived that scope's findings.

    A later scan that reports the finding again sends it with RecordState ACTIVE,
    which reactivates it: "RecordState is intended for finding providers, and can
    be updated only by using the BatchImportFindings operation" and "If the record
    state changes from ARCHIVED to ACTIVE, and the workflow status of the finding
    is NOTIFIED or RESOLVED, Security Hub CSPM automatically changes the workflow
    status to NEW."
    (https://docs.aws.amazon.com/securityhub/latest/userguide/asff-top-level-attributes.html#asff-recordstate)
    """
    scan_time = _parse_timestamp(timestamp)
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for stored in existing:
        finding_id = stored.get("Id")
        if not isinstance(finding_id, str) or not finding_id.startswith("ash/"):
            continue
        if finding_id in current_ids or finding_id in seen:
            continue
        if stored.get("RecordState") != "ACTIVE":
            continue
        fields = stored.get("ProductFields") or {}
        if _owner(fields) not in owned:
            continue
        if fields.get("ash/scanner") not in completed:
            continue
        if fields.get("ash/scope") != scope:
            # Another source directory, or the converted tree scanned in one run
            # and not the other: this scan did not look where that one did.
            continue
        updated = _parse_timestamp(stored.get("UpdatedAt"))
        if updated is None or scan_time is None or updated >= scan_time:
            continue
        record = _archive_record(stored, timestamp)
        if record is None:
            ASH_LOGGER.warning(
                f"aws-security-hub: stored finding {finding_id} lacks a required "
                "field, so it was not archived"
            )
            continue
        seen.add(finding_id)
        records.append(record)
    return records


def _archive_record(stored: dict[str, Any], timestamp: str) -> dict[str, Any] | None:
    """``stored`` as a provider re-import: the fields ASH sends, and nothing else.

    Security Hub's own fields (Region, ProcessedAt, Workflow, the ``aws/``
    ProductFields) are left out: "The aws/ prefix represents a reserved namespace
    for AWS products and services only and must not be submitted with findings
    from third-party integrations."
    (https://docs.aws.amazon.com/securityhub/latest/userguide/asff-top-level-attributes.html#asff-productfields)
    """
    provider = stored.get("FindingProviderFields") or {}
    stored_severity = provider.get("Severity") or stored.get("Severity") or {}
    severity = {
        key: stored_severity[key]
        for key in ("Label", "Original")
        if isinstance(stored_severity.get(key), str) and stored_severity[key].strip()
    }
    severity.setdefault("Label", "INFORMATIONAL")
    types = list(provider.get("Types") or stored.get("Types") or [_TYPE_VULNERABILITY])
    resources = [
        {"Type": resource.get("Type") or _RESOURCE_TYPE, "Id": resource["Id"]}
        for resource in stored.get("Resources") or []
        if isinstance(resource.get("Id"), str) and resource["Id"].strip()
    ]
    record = {
        "SchemaVersion": stored.get("SchemaVersion") or ASFF_SCHEMA_VERSION,
        "Id": stored.get("Id"),
        "ProductArn": stored.get("ProductArn"),
        "GeneratorId": stored.get("GeneratorId"),
        "AwsAccountId": stored.get("AwsAccountId"),
        "Types": types,
        "CreatedAt": stored.get("CreatedAt"),
        "UpdatedAt": timestamp,
        "Severity": dict(severity),
        "Title": stored.get("Title"),
        "Description": stored.get("Description"),
        "Resources": resources,
        "FindingProviderFields": {"Severity": dict(severity), "Types": list(types)},
        "ProductFields": {
            key: value
            for key, value in (stored.get("ProductFields") or {}).items()
            if not key.startswith("aws/")
        },
        "ProductName": PRODUCT_NAME,
        "CompanyName": COMPANY_NAME,
        "RecordState": "ARCHIVED",
    }
    required = (
        "Id",
        "ProductArn",
        "GeneratorId",
        "AwsAccountId",
        "CreatedAt",
        "Title",
        "Description",
    )
    if not resources or not all(
        isinstance(record[key], str) and record[key].strip() for key in required
    ):
        return None
    return record


def _unique_by_id(
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Drop findings whose Id an earlier one has; return (kept, dropped count).

    Security Hub's guidance for custom products: "If the custom product sends
    multiple findings with the same finding ID, Security Hub CSPM only processes
    the first finding."
    (https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-providers.html)
    Doing the same here keeps the counts in the receipt honest.
    """
    seen: set[str] = set()
    kept: list[dict[str, Any]] = []
    for finding in findings:
        if finding["Id"] in seen:
            continue
        seen.add(finding["Id"])
        kept.append(finding)
    return kept, len(findings) - len(kept)


def _finding_id(target: str, key: dict[str, Any]) -> str:
    """``ash/<sha256>`` of the scan target and the identity key; 68 characters.

    Identity contract v2: ``"ash/" + sha256(json.dumps([target, key],
    sort_keys=True))``, the hash the Security Hub reporter takes over the key
    ``utils/finding_identity.py`` defines.
    """
    canonical = json.dumps([target, key], sort_keys=True)
    return "ash/" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@functools.lru_cache(maxsize=None)
def _partition(region: str) -> str:
    """The AWS partition for ``region``, from botocore's bundled endpoint data."""
    try:
        return botocore.session.get_session().get_partition_for_region(region)
    except BotoCoreError:
        return "aws"


def _product_arn(region: str, account_id: str) -> str:
    """The account's default product ARN, for findings it imports itself.

    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-providers.html:
    "This product ARN has the following format:
    arn:aws:securityhub:<region>:<account-id>:product/<account-id>/default".
    """
    return (
        f"arn:{_partition(region)}:securityhub:{region}:{account_id}:"
        f"product/{account_id}/default"
    )


def _asff_timestamp(value: str | None) -> str:
    """``value`` as ``YYYY-MM-DDTHH:MM:SS.mmmZ``, a form the API reference lists.

    https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps
    """
    moment = _parse_timestamp(value) if value else None
    if moment is None:
        # Refused rather than replaced with the current time: now is later than
        # any stored UpdatedAt, so an import stamped with it would overrule the
        # findings of every newer scan and archive what they reported.
        # ReportMetadata always sets generated_at, so this is reached only for
        # a hand-edited or foreign results file.
        raise SecurityHubImportError(
            f"aws-security-hub: the results' generated_at {value!r} is not an "
            "ISO 8601 timestamp, so the scan time that orders this import "
            "against the findings already in Security Hub is unknown; nothing "
            "was sent. Set metadata.generated_at in the results file to the "
            "time of the scan."
        )
    return (
        moment.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _str_or_none(value: int | None) -> str | None:
    return None if value is None else str(value)


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


@overload
def _as_stored(value: str) -> str: ...


@overload
def _as_stored(value: None) -> None: ...


@overload
def _as_stored(value: str | None) -> str | None: ...


def _as_stored(value: str | None) -> str | None:
    """``value`` as a ProductFields value is stored: cut at the field's length.

    For the comparisons with stored findings (the ``ash/target`` filter, the
    owner pair, ``ash/scope``), which have to use the form ``_to_asff`` sent.
    """
    return None if value is None else _truncate(value, MAX_PRODUCT_FIELD_VALUE_LENGTH)
