# Reporter Plugins

Reporter plugins generate reports from scan results in various formats. They transform the ASH aggregated results model into human-readable or machine-readable formats.

> For detailed visual diagrams of reporter plugin architecture and workflow, see [Reporter Plugin Diagrams](reporter-plugins-diagrams.md).

## Reporter Plugin Interface

Reporter plugins must implement the `ReporterPluginBase` interface:

```python
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


@ash_reporter_plugin
class MyReporter(ReporterPluginBase):
    """My custom reporter implementation"""

    def report(self, model):
        """Generate a report from the model"""
        # Your code here
```

## Reporter Plugin Configuration

Define a configuration class for your reporter:

```python
from typing import Literal
from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase


class MyReporterConfigOptions(ReporterOptionsBase):
    include_details: bool = Field(default=True, description="Include detailed findings")
    max_findings: int = Field(
        default=100, description="Maximum number of findings to include"
    )


class MyReporterConfig(ReporterPluginConfigBase):
    name: Literal["my-reporter"] = "my-reporter"
    extension: str = "my-report.txt"
    enabled: bool = True
    options: MyReporterConfigOptions = MyReporterConfigOptions()
```

## Reporter Plugin Example

Here's a complete example of a custom reporter plugin based on the S3Reporter in your codebase:

```python
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal, Optional, TYPE_CHECKING

import boto3
from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


class S3ReporterConfigOptions(ReporterOptionsBase):
    aws_region: Annotated[
        str | None,
        Field(
            pattern=r"(af|il|ap|ca|eu|me|sa|us|cn|us-gov|us-iso|us-isob)-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)-\d{1}"
        ),
    ] = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", None))
    aws_profile: Optional[str] = os.environ.get("AWS_PROFILE", None)
    bucket_name: str | None = os.environ.get("ASH_S3_BUCKET_NAME", None)
    key_prefix: str = "ash-reports/"
    file_format: Literal["json", "yaml"] = "json"


class S3ReporterConfig(ReporterPluginConfigBase):
    name: Literal["s3"] = "s3"
    extension: str = "s3.json"
    enabled: bool = True
    options: S3ReporterConfigOptions = S3ReporterConfigOptions()


@ash_reporter_plugin
class S3Reporter(ReporterPluginBase[S3ReporterConfig]):
    """Formats results and uploads to an S3 bucket."""

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

    def report(self, model: "AshAggregatedResults") -> str | None:
        """Upload the results to S3 and return the URL, or None on failure."""
        if isinstance(self.config, dict):
            self.config = S3ReporterConfig.model_validate(self.config)

        # Create a key for the S3 object from the time the results were generated
        timestamp = model.metadata.generated_at or datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )
        file_extension = "json" if self.config.options.file_format == "json" else "yaml"
        s3_key = (
            f"{self.config.options.key_prefix}ash-report-{timestamp}.{file_extension}"
        )

        # Format the results based on the specified format
        if self.config.options.file_format == "json":
            output_dict = model.to_simple_dict()
            output_content = json.dumps(output_dict, default=str, indent=2)
        else:
            import yaml

            output_dict = model.to_simple_dict()
            output_content = yaml.dump(output_dict, default_flow_style=False)

        # Create a session with the specified profile and region
        session = boto3.Session(
            profile_name=self.config.options.aws_profile,
            region_name=self.config.options.aws_region,
        )
        s3_client = session.client("s3")

        try:
            # Upload the content to S3
            s3_client.put_object(
                Bucket=self.config.options.bucket_name,
                Key=s3_key,
                Body=output_content,
                ContentType="application/json"
                if file_extension == "json"
                else "application/yaml",
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
            error_msg = f"Error uploading to S3: {str(e)}"
            self._plugin_log(
                error_msg,
                level=logging.ERROR,
                append_to_stream="stderr",
            )
            # None, not the message: ASH treats a None result as a reporter that
            # produced nothing and writes no report file for it. A returned
            # message would be written into that file as if it were the report.
            return None
```

## Simple Reporter Plugin Example

Here's a simpler example of a custom reporter plugin:

```python
from pathlib import Path
from typing import Literal

from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class SimpleReporterConfigOptions(ReporterOptionsBase):
    include_details: bool = Field(default=True, description="Include detailed findings")
    max_findings: int = Field(
        default=100, description="Maximum number of findings to include"
    )
    output_file: str = Field(
        default="simple-report.txt", description="Output file name"
    )


class SimpleReporterConfig(ReporterPluginConfigBase):
    name: Literal["simple"] = "simple"
    extension: str = "simple.txt"
    enabled: bool = True
    options: SimpleReporterConfigOptions = SimpleReporterConfigOptions()


@ash_reporter_plugin
class SimpleReporter(ReporterPluginBase[SimpleReporterConfig]):
    """Generates a simple text report."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = SimpleReporterConfig()
        return super().model_post_init(context)

    def report(self, model):
        """Generate a simple text report."""
        # Create the report content
        content = []
        content.append("# Security Scan Report")
        content.append("")
        stats = model.metadata.summary_stats
        content.append(f"Project: {model.metadata.project_name}")
        content.append(f"Scan Time: {model.metadata.generated_at}")
        content.append("")
        content.append("## Summary")
        content.append("")
        content.append(f"Total Findings: {stats.total}")
        content.append(f"Critical: {stats.severity_counts.critical}")
        content.append(f"High: {stats.severity_counts.high}")
        content.append(f"Medium: {stats.severity_counts.medium}")
        content.append(f"Low: {stats.severity_counts.low}")
        content.append(f"Info: {stats.severity_counts.info}")
        content.append("")

        # Add detailed findings if configured
        if self.config.options.include_details:
            content.append("## Detailed Findings")
            content.append("")

            # Get flat vulnerabilities
            vulnerabilities = model.to_flat_vulnerabilities()

            # Limit the number of findings
            max_findings = min(len(vulnerabilities), self.config.options.max_findings)

            for i, vuln in enumerate(vulnerabilities[:max_findings]):
                content.append(f"### Finding {i + 1}")
                content.append(f"Title: {vuln.title}")
                content.append(f"Severity: {vuln.severity}")
                content.append(f"File: {vuln.file_path}")
                content.append(f"Line: {vuln.line_start}")
                content.append(f"Description: {vuln.description}")
                content.append("")

        # Write the report to a file
        report_text = "\n".join(content)
        output_path = (
            Path(self.context.output_dir) / "reports" / self.config.options.output_file
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        return report_text
```

## Reporter Plugin Best Practices

1. **Handle Configuration**: Use Pydantic models for configuration
2. **Validate Dependencies**: Implement the `validate_plugin_dependencies` method to check dependencies
3. **Error Handling**: Use try/except blocks and provide meaningful error messages
4. **Output to Files**: Write reports to the `reports` directory. Return the report and ASH writes it to
   `ash.<extension>`; write any other file there with `write_report_file` and return its name from
   `companion_file_names()`, so that a link already at that name stops the run before any reporter writes
5. **Return Content**: Return the report content as a string, or `None` when the report could not be produced (ASH then writes no file for it)
6. **Use Model Methods**: Use the model's helper methods like `to_simple_dict()` and `to_flat_vulnerabilities()`

## Reporter Plugin Configuration in ASH

Configure your reporter in the ASH configuration file:

```yaml
# ASH config file (.ashrc.yaml in a new project)
reporters:
  simple:
    enabled: true
    options:
      include_details: true
      max_findings: 50
      output_file: custom-report.txt
```

## Declaring destination options

A reporter that sends findings somewhere, or writes them to a path its options
name, declares those options in `destination_options`:

```python
from typing import ClassVar, Tuple


@ash_reporter_plugin
class WebhookReporter(ReporterPluginBase[WebhookReporterConfig]):
    destination_options: ClassVar[Tuple[str, ...]] = ("webhook_url", "api_token")
```

List every option that chooses where findings are sent or written, or which
credentials send them: an endpoint, a region, an account, a bucket, a profile, a
token, an output path. Name each as its field in the options model. An alias of
the field is covered as well. The default is `()`.

When the config was built from a file inside the scanned tree (a discovered
`.ash/.ash.yaml`, a `--config` inside the tree, an `extends` base, or
`ASH_CONFIG`), or from a file an MCP client delivered, ASH takes these options from
the trusted base instead: the defaults, an operator config outside the tree, and
`--config-overrides`. A value such a file set is replaced, under any spelling of the
reporter's section that ASH reads as this reporter's, and one warning names each
option it ignored. The reporter's other options still apply from the file. ASH
does this once it has imported your plugin module and before it builds any
reporter, in a scan and in `ash report`. The built-in AWS reporters declare theirs
the same way; see [Settings a repository's config cannot choose](../configuration-guide.md#settings-a-repositorys-config-cannot-choose).

A reporter that declares any destination option sends findings somewhere, so
whether it runs is the operator's choice too, in both directions. Its `enabled`
comes from the trusted base, or from the default of your config model's `enabled`
when the trusted base sets none: such a file's `enabled: true` or `enabled: false`
is replaced with a warning where it differs, and leaving the section out leaves the
reporter as the trusted base has it. A reporter that declares no destination
options writes only local files, and its `enabled` applies from the file.

Under the MCP server, a delivered file that sets a declared option is scanned with
the server's value rather than refused, because the server checks the file against
`denied_paths` before it imports your plugin module. To have such a file refused,
add the option to the profile's `global_settings.mcp.runtime_overrides.denied_paths`,
for example `/reporters/webhook/options/webhook_url`.

## Testing Reporter Plugins

Create unit tests for your reporter:

```python
import pytest
from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.models.asharp_model import AshAggregatedResults
from my_ash_plugins.reporters import SimpleReporter


def test_simple_reporter():
    # Create a plugin context
    context = PluginContext(
        source_dir=Path("test_data"), output_dir=Path("test_output")
    )

    # Create reporter instance
    reporter = SimpleReporter(context=context)

    # Create a model; the project name is part of its metadata
    model = AshAggregatedResults()
    model.metadata.project_name = "test-project"

    # Generate the report
    report = reporter.report(model)

    # Assert report content
    assert "Security Scan Report" in report
    assert "test-project" in report
```