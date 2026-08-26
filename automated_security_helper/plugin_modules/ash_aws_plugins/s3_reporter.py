# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
from pathlib import Path
from typing import Annotated, Literal, Optional, TYPE_CHECKING

import boto3
from pydantic import Field
import yaml

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
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
            description="Maximum number of retry attempts for S3 operations",
        ),
    ] = 3
    base_delay: Annotated[
        float,
        Field(
            description="Base delay in seconds between retry attempts",
        ),
    ] = 1.0
    max_delay: Annotated[
        float,
        Field(
            description="Maximum delay in seconds between retry attempts",
        ),
    ] = 60.0


class S3ReporterConfig(ReporterPluginConfigBase):
    name: Literal["s3"] = "s3"
    extension: str = "s3.json"
    enabled: bool = True
    options: S3ReporterConfigOptions = S3ReporterConfigOptions()


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

    The object key needs care for this ruling to hold, and the reason is worse
    than a race.

    The key is ``f"{key_prefix}ash-report-{timestamp}.{ext}"`` with ``timestamp``
    taken from ``model.metadata.summary_stats.start``. That field is **not set
    yet** when a reporter runs: ``ScanExecutionEngine.execute_phases`` assigns it
    in a ``finally`` block (``execution_engine.py`` around line 547) that runs
    *after* ``ReportPhase`` (around line 492). So every reporter observes ``None``,
    and the key every scan computes is literally ``ash-report-None.json``.

    Verified rather than reasoned about, by probing ``ReportPhase._execute_phase``
    during a real scan: ``start`` is ``None`` there and
    ``'2026-08-26T00:38:09+00:00'`` once the scan returns -- a second-granular
    string, so even if it were available in time it would not separate concurrent
    projects reliably.

    Consequences, in order of how much they matter here:

    * All N projects in a workspace compute the same key and overwrite each other.
      ``PutObject`` overwrites silently, so N-1 projects' reports vanish with no
      message -- a false negative with extra steps, in the feature this PR
      completes. The project segment below closes this, which is the part this
      ruling owns.
    * Every *run* of a single-directory scan also overwrites the previous one,
      because the key is a constant. That is a pre-existing defect orthogonal to
      workspace mode, and it is deliberately **not** fixed here.

      Not deferred for convenience: both behaviours are defensible and either
      choice breaks someone. A constant key loses every run but the last. A
      varying key breaks anyone treating that object as a stable "latest report"
      pointer, and accumulates objects indefinitely for anyone without a
      lifecycle policy. That is a product decision about a customer-facing AWS
      integration, and it belongs to whoever owns that integration rather than to
      a workspace-mode change.

      Also deliberately not fixed by making the timestamp available earlier:
      ``summary_stats.start`` is read by more than this reporter, so moving when
      it is assigned has a much wider blast radius than the key does.

      ``tests/unit/workspace/test_project_attribution.py::TestS3KeysCannotCollideAcrossProjects::test_the_start_timestamp_is_unset_when_a_reporter_runs``
      pins the premise, so if the timestamp ever does become available the
      assumption fails loudly rather than silently producing a different key.

    The project is read from ``metadata.workspace_project`` rather than from
    ``model.workspace``, because a project inside a workspace is scanned as a
    complete single-project run and its own model's ``workspace`` is ``None`` --
    a project does not know it is in a workspace.
    ``ASHScanOrchestrator._apply_metadata`` is what puts the project there.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = S3ReporterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate reporter configuration and requirements."""
        self.dependencies_satisfied = False
        if (
            self.config.options.aws_region is None
            or self.config.options.bucket_name is None
        ):
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
            self._plugin_log(
                f"Error when validating S3 access: {e}",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )
        return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model and upload to S3 bucket."""
        if isinstance(self.config, dict):
            self.config = S3ReporterConfig.model_validate(self.config)

        # Create a key for the S3 object.
        #
        # `timestamp` is None here in every real scan -- summary_stats.start is
        # assigned after the report phase, not before it -- so without the
        # project segment every project in a workspace computes the identical key
        # and PutObject silently overwrites all but the last. See the class
        # docstring for the verification and for why the single-project key is
        # left exactly as it is.
        timestamp = model.metadata.summary_stats.start
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
            output_content = yaml.dump(output_dict, default_flow_style=False)

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
            ASH_LOGGER.info(f"Successfully uploaded report to {s3_url}")

            # Also write to local file if needed
            output_path = (
                Path(self.context.output_dir)
                / "reports"
                / f"s3-report.{file_extension}"
            )
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output_content)

            return s3_url
        except Exception as e:
            error_msg = f"Error uploading to S3 after retries: {str(e)}"
            self._plugin_log(
                error_msg,
                level=logging.ERROR,
                append_to_stream="stderr",
            )
            return error_msg

    @retry_with_backoff()
    def _put_object_with_retry(self, s3_client, **kwargs):
        """Put object to S3 with retry logic."""
        return s3_client.put_object(**kwargs)
