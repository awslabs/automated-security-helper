# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal, Optional, TYPE_CHECKING, Tuple

import boto3
from pydantic import Field, model_validator

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
    write_report_file,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.report_yaml import report_yaml
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    MAX_RETRIES,
    MAX_RETRY_DELAY_SECONDS,
    check_retry_delays,
    report_missing_setting,
    retry_with_backoff,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class S3ReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        Optional[str],
        Field(
            default_factory=lambda: os.environ.get(
                "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", None)
            ),
            pattern=r"(af|il|ap|ca|eu|me|sa|us|cn|us-gov|us-iso|us-isob)-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)-\d{1}",
            description="AWS region to use for S3 operations",
        ),
    ]
    aws_profile: Annotated[
        Optional[str],
        Field(
            default_factory=lambda: os.environ.get("AWS_PROFILE", None),
            description="AWS profile to use for authentication",
        ),
    ]
    bucket_name: Annotated[
        Optional[str],
        Field(
            default_factory=lambda: os.environ.get("ASH_S3_BUCKET_NAME", None),
            description="Name of the S3 bucket to store reports",
        ),
    ]
    key_prefix: Annotated[
        str,
        Field(
            description="Prefix for S3 object keys",
        ),
    ] = "ash-reports/"
    file_format: Annotated[
        Literal["json", "yaml"],
        Field(
            description="Format to use for the report file",
        ),
    ] = "json"
    # Retry configuration
    max_retries: Annotated[
        int,
        Field(
            le=MAX_RETRIES,
            description="Maximum number of retry attempts for S3 operations",
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

    @model_validator(mode="after")
    def _retry_delays_are_bounded(self):
        return check_retry_delays(self)


class S3ReporterConfig(ReporterPluginConfigBase):
    name: Literal["s3"] = "s3"
    extension: str = "s3.json"
    # Off by default: this reporter sends findings to an AWS service with the
    # operator's credentials, so only the operator's config turns it on.
    enabled: bool = False
    # A factory, so the environment defaults are read when the config is built.
    options: Annotated[
        S3ReporterConfigOptions, Field(default_factory=S3ReporterConfigOptions)
    ]


@ash_reporter_plugin
class S3Reporter(ReporterPluginBase[S3ReporterConfig]):
    """Formats results and uploads to an S3 bucket.

    Workspace mode: per project. The RFC's reporter table did not rule on this
    one, so the reasoning is recorded here.

    Same shape of argument as ``cloudwatch_logs_reporter``: a delivery mechanism
    rather than a format, with a side effect -- ``PutObject``. Each project's own
    scan already uploads its own object, and a workspace-level invocation would
    add an N+1st object holding the lossy ``scanner_results`` rollup and an
    ``ash_config`` belonging to no project.

    The object key needs care for this ruling to hold.

    The key is ``f"{key_prefix}[{project}/]ash-report-{timestamp}.{ext}"``, as
    documented in ``docs/plugins/aws/s3-reporter.md``. ``timestamp`` used to be
    read only from ``model.metadata.summary_stats.start``, and that field is
    **not set yet** when a reporter runs: ``ScanExecutionEngine.execute_phases``
    assigns it in a ``finally`` block that runs *after* ``ReportPhase``. So every
    scan uploaded to the literal key ``ash-report-None.json``, and every run
    overwrote the one before it.

    The timestamp is now ``metadata.generated_at``, which ``ReportMetadata``
    always sets (to the second, in UTC) when the results model is built, and
    which nothing reassigns afterwards. Because it is stored in
    ``ash_aggregated_results.json``, re-reporting a finished scan with
    ``ash report --format s3`` computes the same key the scan did and replaces
    that object rather than minting a second one. ``summary_stats.start`` is only
    a fallback: preferring it would give the scan and a later ``ash report`` two
    different keys, since it is unset during the first and set in the second.
    Moving when ``summary_stats.start`` is assigned was rejected: more than this
    reporter reads it.

    Two projects in one workspace can still share a second, and ``PutObject``
    overwrites silently, so the project segment stays: without it N-1 projects'
    reports could vanish with no message.

    ``report()`` returns a JSON receipt -- bucket, key, URL, format and the path of
    the local copy -- which ``ReportPhase`` writes to ``reports/ash.s3.json``. It
    used to return the bare ``s3://`` URL, so a file named ``.json`` held text
    that is not JSON, and an upload failure wrote the error message there as if
    it were the report. A failed upload now returns ``None``, which ``ReportPhase``
    reports as a reporter that produced nothing. The uploaded content itself is
    kept locally at ``reports/s3-report.{ext}``, as the docs describe.

    The project is read from ``metadata.workspace_project`` rather than from
    ``model.workspace``, because a project inside a workspace is scanned as a
    complete single-project run and its own model's ``workspace`` is ``None`` --
    a project does not know it is in a workspace.
    ``ASHScanOrchestrator._apply_metadata`` is what puts the project there.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT
    # Sends findings to AWS with the host's credentials.
    sends_off_host = True
    destination_options = (
        "aws_region",
        "aws_profile",
        "bucket_name",
        "key_prefix",
        # How long it keeps calling S3 with the operator's credentials.
        "max_retries",
        "base_delay",
        "max_delay",
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = S3ReporterConfig()
        return super().model_post_init(context)

    def companion_file_names(self) -> Tuple[str, ...]:
        """The local copy of the uploaded content, ``s3-report.<json|yaml>``."""
        return (self._local_copy_name(),)

    def _local_copy_name(self) -> str:
        config = self.config
        if isinstance(config, dict):
            config = S3ReporterConfig.model_validate(config)
        file_extension = "json" if config.options.file_format == "json" else "yaml"
        return f"s3-report.{file_extension}"

    def validate_plugin_dependencies(self) -> bool:
        """Validate reporter configuration and requirements."""
        self.dependencies_satisfied = False
        missing = False
        if self.config.options.aws_region is None:
            report_missing_setting(
                self.config.name, "aws_region", ("AWS_REGION", "AWS_DEFAULT_REGION")
            )
            missing = True
        if self.config.options.bucket_name is None:
            report_missing_setting(
                self.config.name, "bucket_name", ("ASH_S3_BUCKET_NAME",)
            )
            missing = True
        if missing:
            return self.dependencies_satisfied
        try:
            session = boto3.Session(
                profile_name=self.config.options.aws_profile,
                region_name=self.config.options.aws_region,
            )
            sts_client = session.client("sts")
            caller_id = sts_client.get_caller_identity()

            # Check if S3 bucket exists and is accessible
            s3_client = session.client("s3")
            s3_client.head_bucket(Bucket=self.config.options.bucket_name)

            self.dependencies_satisfied = "Account" in caller_id
        except Exception as e:
            # error_text with the config's environment values: botocore's
            # exceptions name the profile, bucket or region they were given.
            self._plugin_log(
                "Error when validating S3 access: "
                f"{error_text(e, self._environment_values())}",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )
        return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str | None:
        """Upload the results to S3 and return a JSON receipt, or None on failure."""
        if isinstance(self.config, dict):
            self.config = S3ReporterConfig.model_validate(self.config)

        # Create a key for the S3 object. generated_at is set when the model is
        # built and is the same during the scan and in a later `ash report`;
        # summary_stats.start is unset during a scan. See the class docstring.
        # The project segment keeps workspace projects apart.
        timestamp = (
            model.metadata.generated_at
            or model.metadata.summary_stats.start
            or datetime.now(timezone.utc).isoformat(timespec="seconds")
        )
        file_extension = "json" if self.config.options.file_format == "json" else "yaml"
        project = getattr(model.metadata, "workspace_project", None)
        project_segment = f"{project}/" if isinstance(project, str) and project else ""
        s3_key = (
            f"{self.config.options.key_prefix}{project_segment}"
            f"ash-report-{timestamp}.{file_extension}"
        )

        # Format the results based on the specified format
        if self.config.options.file_format == "json":
            output_dict = model.to_simple_dict()
            output_content = json.dumps(output_dict, default=str, indent=2)
        else:
            output_dict = model.to_simple_dict()
            # utils/report_yaml.py: no line of it is a CI workflow command, whatever
            # a refused input's name or a finding's text holds.
            output_content = report_yaml(output_dict, default_flow_style=False)

        # Create a session with the specified profile and region
        session = boto3.Session(
            profile_name=self.config.options.aws_profile,
            region_name=self.config.options.aws_region,
        )
        s3_client = session.client("s3")

        try:
            # Upload the content to S3 with retry logic
            self._put_object_with_retry(
                s3_client,
                Bucket=self.config.options.bucket_name,
                Key=s3_key,
                Body=output_content,
                ContentType=(
                    "application/json"
                    if file_extension == "json"
                    else "application/yaml"
                ),
            )

            s3_url = f"s3://{self.config.options.bucket_name}/{s3_key}"
            # Redacted: the bucket and key prefix are configured, a configured
            # option can come from the environment, and ash.log keeps this line.
            ASH_LOGGER.info(
                text_without_values(
                    f"Successfully uploaded report to {s3_url}",
                    self._environment_values(),
                )
            )

            # The documented local copy of the uploaded content.
            reports_dir = Path(self.context.output_dir) / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            local_copy = write_report_file(
                reports_dir, self._local_copy_name(), output_content
            )

            # What ReportPhase writes to reports/ash.s3.json: a receipt for the
            # upload, as JSON so the file matches its extension.
            return json.dumps(
                {
                    "url": s3_url,
                    "bucket": self.config.options.bucket_name,
                    "key": s3_key,
                    "file_format": self.config.options.file_format,
                    "local_copy": local_copy.as_posix() if local_copy else None,
                },
                indent=2,
            )
        except Exception as e:
            error_msg = (
                "Error uploading to S3 after retries: "
                f"{error_text(e, self._environment_values())}"
            )
            self._plugin_log(
                error_msg,
                level=logging.ERROR,
                append_to_stream="stderr",
            )
            # None, not the message: ReportPhase reports a None result as a
            # reporter that produced nothing, and writes no ash.s3.json. Returning
            # the message used to write it into that file as if it were a report.
            return None

    def _put_object_with_retry(self, s3_client, **kwargs):
        """Put object to S3, retrying on the schedule this reporter was configured with.

        The decorator used to be applied to this method directly, with no
        arguments. That is valid -- every parameter of ``retry_with_backoff`` has
        a default -- but it is applied when the class body executes, where there
        is no ``self``, so it could only ever use the module defaults of
        max_retries=3, base_delay=1.0, max_delay=60.0. This reporter's
        ``max_retries``, ``base_delay`` and ``max_delay`` options were the only
        three in the file that nothing read: declared, documented to users, and
        inert. Setting max_retries=10 changed nothing.

        Applying the decorator to a closure instead, the way
        ``CloudWatchLogsReporter._create_log_stream_with_retry`` already does,
        defers it to call time when ``self.config`` exists. The method name and
        signature are unchanged, so the existing ``patch.object`` in
        test_project_attribution keeps working.
        """

        @retry_with_backoff(
            max_retries=self.config.options.max_retries,
            base_delay=self.config.options.base_delay,
            max_delay=self.config.options.max_delay,
        )
        def put_object():
            return s3_client.put_object(**kwargs)

        return put_object()
