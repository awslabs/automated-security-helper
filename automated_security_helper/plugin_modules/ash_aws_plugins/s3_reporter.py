# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal, Optional, TYPE_CHECKING, Tuple

import boto3
import botocore.exceptions
from pydantic import BaseModel, Field, field_validator, model_validator

from automated_security_helper.base.options import ReporterOptionsBase, _warn_once
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
    AWS_REGION_PATTERN,
    MAX_RETRIES,
    MAX_RETRY_DELAY_SECONDS,
    blank_is_unset,
    check_retry_delays,
    reporter_client_config,
    retry_with_backoff,
    settings_missing,
    stripped_or_none,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class S3ReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        Optional[str],
        Field(
            # An empty or blank value is unset: AWS_REGION="" or " " does not
            # hide AWS_DEFAULT_REGION, and an empty region is named as the
            # missing setting rather than refused by the pattern or sent to AWS.
            default_factory=lambda: (
                stripped_or_none(os.environ.get("AWS_REGION"))
                or stripped_or_none(os.environ.get("AWS_DEFAULT_REGION"))
            ),
            # The three AWS reporters share one pattern (aws_utils), so a region
            # one accepts is never a configuration error for another.
            pattern=AWS_REGION_PATTERN,
            description="AWS region to use for S3 operations",
        ),
    ]
    aws_profile: Annotated[
        Optional[str],
        Field(
            # An empty or blank AWS_PROFILE is no profile, not a profile named
            # "" or " ".
            default_factory=lambda: stripped_or_none(os.environ.get("AWS_PROFILE")),
            description="AWS profile to use for authentication",
        ),
    ]
    bucket_name: Annotated[
        Optional[str],
        Field(
            # An empty or blank value is unset, so it is named as missing
            # instead of reaching PutObject as an empty bucket name.
            default_factory=lambda: stripped_or_none(
                os.environ.get("ASH_S3_BUCKET_NAME")
            ),
            description="Name of the S3 bucket to store reports",
        ),
    ]
    key_prefix: Annotated[
        str,
        Field(
            description=(
                "Prefix for S3 object keys, used as written: the object name "
                "follows it directly, so end it with '/' to place the report in a "
                "directory. A prefix that does not end in '/' is warned about "
                "once per run"
            ),
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

    @field_validator("aws_region", "aws_profile", "bucket_name", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: Any) -> Any:
        """A blank region, profile or bucket is no value (``blank_is_unset``)."""
        return blank_is_unset(value)

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
    documented in ``docs/content/plugins/aws.md``, where ``key_prefix`` is the
    option as written: a prefix such as ``scans/repo-`` writes
    ``scans/repo-ash-report-...``, the name it has always had, so the
    notifications, lifecycle rules and queries an operator matches against the
    object names keep matching. A prefix that does not end in ``/`` is warned
    about once per run, because the name runs on from it. ``timestamp`` used to be
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
        if self._settings_missing():
            return self.dependencies_satisfied
        try:
            session = boto3.Session(
                profile_name=self.config.options.aws_profile,
                region_name=self.config.options.aws_region,
            )
            sts_client = session.client("sts")
            caller_id = sts_client.get_caller_identity()

            # Check that the S3 bucket can be reached. HeadBucket needs
            # s3:ListBucket, which the documented write-only policy
            # (s3:PutObject alone) does not grant: without it S3 answers 403
            # whether or not the bucket exists, so a 403 says only that the
            # check could not be made. The upload is still tried, and a bucket
            # that turns out to be missing fails there (report() then returns
            # None). A 404, which S3 gives a principal that may list, and any
            # other failure leave the dependency unsatisfied here.
            s3_client = session.client("s3")
            try:
                s3_client.head_bucket(Bucket=self.config.options.bucket_name)
            except botocore.exceptions.ClientError as e:
                status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
                code = e.response.get("Error", {}).get("Code")
                if status != 403 and code not in ("403", "Forbidden", "AccessDenied"):
                    raise
                ASH_LOGGER.debug(
                    "HeadBucket on the bucket the bucket_name option names was "
                    "refused (s3:ListBucket is not granted), so whether the "
                    "bucket exists was not checked; the upload is tried with "
                    "s3:PutObject alone and reports its own failure"
                )

            self.dependencies_satisfied = "Account" in caller_id
        except Exception as e:
            # error_text with the config's environment values: botocore's
            # exceptions name the profile, bucket or region they were given.
            # At ERROR, like report_missing_setting: the report phase leaves
            # the reporter out on False, so under --quiet a WARNING was the
            # only word of why an enabled upload did not happen, and --quiet
            # hid it.
            self._plugin_log(
                "Error when validating S3 access: "
                f"{error_text(e, self._environment_values())}",
                level=logging.ERROR,
                target_type="source",
                append_to_stream="stderr",
            )
        return self.dependencies_satisfied

    def _settings_missing(self) -> bool:
        """Name each required setting that is unset or empty; True when one is.

        The options model maps a blank value to None (``_blank_is_unset``), from
        the environment or a config file alike; ``not`` rather than ``is None``
        keeps an empty name out of PutObject should one ever get through.
        """
        return settings_missing(
            self.config.name,
            self.config.options,
            (
                ("aws_region", ("AWS_REGION", "AWS_DEFAULT_REGION")),
                ("bucket_name", ("ASH_S3_BUCKET_NAME",)),
            ),
        )

    def report(self, model: "AshAggregatedResults") -> str | None:
        """Upload the results to S3 and return a JSON receipt, or None on failure.

        ``ash report`` never calls ``validate_plugin_dependencies``, so the
        settings are checked here too: an unset bucket used to reach PutObject
        and come back as a botocore parameter error.
        """
        if isinstance(self.config, dict):
            self.config = S3ReporterConfig.model_validate(self.config)
        if self._settings_missing():
            return None
        if isinstance(getattr(model, "workspace", None), BaseModel):
            # A workspace's unified results: each project's own scan already
            # uploaded its object (the class docstring says why the rollup is
            # not uploaded), and `ash report` on the workspace output
            # directory is the one path that reaches here with them.
            self._plugin_log(
                "s3 uploads one project's results at a time, and these are a "
                "workspace's unified results, which each project's own scan "
                "already uploaded. Run ash report with --output-dir set to a "
                "project's directory under the workspace output.",
                level=logging.ERROR,
                append_to_stream="stderr",
            )
            return None

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
        # The prefix is used as written, so the object name stays the one an
        # operator's notifications, lifecycle rules and queries already match. A
        # prefix that does not end in "/" runs on into the file name, which may be
        # meant ("scans/repo-"), so it is named once per run and left alone. The
        # warning does not quote it: a configured option can come from the
        # environment, and the warning goes to the console and ash.log.
        key_prefix = self.config.options.key_prefix
        if key_prefix and not key_prefix.endswith("/"):
            _warn_once(
                "reporters.s3.options.key_prefix",
                key_prefix,
                "The s3 reporter's key_prefix does not end in '/', so the object "
                "name runs on from it: <key_prefix>ash-report-<time>.<extension>. "
                "End the prefix with '/' to place the report in a directory.",
            )
        s3_key = f"{key_prefix}{project_segment}ash-report-{timestamp}.{file_extension}"

        # Format the results based on the specified format. to_simple_dict()
        # carries the metadata, the configuration record and the scanner
        # results, but no findings (the CloudWatch Logs reporter shares it
        # because PutLogEvents caps an event at 1 MB); the uploaded file is
        # documented to hold the findings, and S3 has no such cap, so the SARIF
        # report goes with it. Dumped in JSON mode, so the YAML form holds plain
        # scalars and no Python-only tag (an enum member used to be written as a
        # !!python/object/apply tag yaml.safe_load cannot read).
        output_dict = model.to_simple_dict()
        if model.sarif is not None:
            output_dict["sarif"] = model.sarif.model_dump(
                by_alias=True, exclude_none=True, mode="json"
            )
        output_dict = json.loads(json.dumps(output_dict, default=str))
        if self.config.options.file_format == "json":
            output_content = json.dumps(output_dict, indent=2)
        else:
            # utils/report_yaml.py: no line of it is a CI workflow command, whatever
            # a refused input's name or a finding's text holds.
            output_content = report_yaml(output_dict, default_flow_style=False)

        # Create a session with the specified profile and region
        session = boto3.Session(
            profile_name=self.config.options.aws_profile,
            region_name=self.config.options.aws_region,
        )
        # The upload repeats a failure itself (retry_with_backoff), so the client
        # makes one attempt per call.
        s3_client = session.client("s3", config=reporter_client_config())

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

        # The documented local copy of the uploaded content. Outside the upload's
        # handler: a failure here (a read-only reports directory, say) used to
        # be logged as a failed upload and turned the receipt of an upload that
        # succeeded into None.
        local_copy = None
        try:
            reports_dir = Path(self.context.output_dir) / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            local_copy = write_report_file(
                reports_dir, self._local_copy_name(), output_content
            )
        except Exception as e:
            self._plugin_log(
                "The report was uploaded to S3, but its local copy could not be "
                f"written: {error_text(e, self._environment_values())}",
                level=logging.WARNING,
                append_to_stream="stderr",
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
