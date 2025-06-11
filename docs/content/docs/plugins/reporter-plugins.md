# Reporter Plugins

Reporter plugins generate reports from scan results in various formats. They transform the ASH aggregated results model into human-readable or machine-readable formats.

## Reporter Plugin Interface

Reporter plugins must implement the `ReporterPluginBase` interface:

```python
from automated_security_helper.base.reporter_plugin import ReporterPluginBase, ReporterPluginConfigBase
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

class MyReporterConfig(ReporterPluginConfigBase):
    name: Literal["my-reporter"] = "my-reporter"
    extension: str = "my-report.txt"
    enabled: bool = True

    class Options:
        include_details: bool = Field(default=True, description="Include detailed findings")
        max_findings: int = Field(default=100, description="Maximum number of findings to include")
```

## Reporter Plugin Example

Here's a complete example of a custom reporter plugin based on the S3Reporter in your codebase:

```python
import json
import os
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

    def validate(self) -> bool:
        """Validate reporter configuration and requirements."""
        self.dependencies_satisfied = False
        if self.config.options.aws_region is None or self.config.options.bucket_name is None:
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
                level="WARNING",
                target_type="source",
                append_to_stream="stderr",
            )
        finally:
            return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model and upload to S3 bucket."""
        if isinstance(self.config, dict):
            self.config = S3ReporterConfig.model_validate(self.config)

        # Create a unique key for the S3 object
        timestamp = model.scan_metadata.scan_time.strftime("%Y%m%d-%H%M%S")
        file_extension = "json" if self.config.options.file_format == "json" else "yaml"
        s3_key = f"{self.config.options.key_prefix}ash-report-{timestamp}.{file_extension}"

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
                ContentType="application/json" if file_extension == "json" else "application/yaml"
            )

            s3_url = f"s3://{self.config.options.bucket_name}/{s3_key}"
            ASH_LOGGER.info(f"Successfully uploaded report to {s3_url}")

            # Also write to local file if needed
            output_path = Path(self.context.output_dir) / "reports" / f"s3-report.{file_extension}"
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output_content)

            return s3_url
        except Exception as e:
            error_msg = f"Error uploading to S3: {str(e)}"
            self._plugin_log(
                error_msg,
                level="ERROR",
                append_to_stream="stderr",
            )
            return error_msg
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
    max_findings: int = Field(default=100, description="Maximum number of findings to include")
    output_file: str = Field(default="simple-report.txt", description="Output file name")

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
        content.append(f"Project: {model.project_name}")
        content.append(f"Scan Time: {model.scan_metadata.scan_time}")
        content.append("")
        content.append("## Summary")
        content.append("")
        content.append(f"Total Findings: {model.summary_stats.total_findings}")
        content.append(f"Critical: {model.summary_stats.critical_count}")
        content.append(f"High: {model.summary_stats.high_count}")
        content.append(f"Medium: {model.summary_stats.medium_count}")
        content.append(f"Low: {model.summary_stats.low_count}")
        content.append(f"Info: {model.summary_stats.info_count}")
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
                content.append(f"### Finding {i+1}")
                content.append(f"Title: {vuln.title}")
                content.append(f"Severity: {vuln.severity}")
                content.append(f"File: {vuln.file_path}")
                content.append(f"Line: {vuln.line_number}")
                content.append(f"Description: {vuln.description}")
                content.append("")

        # Write the report to a file
        report_text = "\n".join(content)
        output_path = Path(self.context.output_dir) / "reports" / self.config.options.output_file
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        return report_text
```

## Reporter Plugin Best Practices

1. **Handle Configuration**: Use Pydantic models for configuration
2. **Validate Dependencies**: Implement the `validate` method to check dependencies
3. **Error Handling**: Use try/except blocks and provide meaningful error messages
4. **Output to Files**: Write reports to the `reports` directory
5. **Return Content**: Return the report content as a string
6. **Use Model Methods**: Use the model's helper methods like `to_simple_dict()` and `to_flat_vulnerabilities()`

## Reporter Plugin Configuration in ASH

Configure your reporter in the ASH configuration file:

```yaml
# .ash/.ash.yaml
reporters:
  simple:
    enabled: true
    options:
      include_details: true
      max_findings: 50
      output_file: custom-report.txt
```

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
        source_dir=Path("test_data"),
        output_dir=Path("test_output")
    )

    # Create reporter instance
    reporter = SimpleReporter(context=context)

    # Create a mock model
    model = AshAggregatedResults(
        project_name="test-project",
        # Add other required fields
    )

    # Generate the report
    report = reporter.report(model)

    # Assert report content
    assert "Security Scan Report" in report
    assert "test-project" in report
```