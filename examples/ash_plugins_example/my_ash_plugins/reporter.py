# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Example reporter plugin for ASH."""

from typing import Annotated, Literal

from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class ExampleReporterConfigOptions(ReporterOptionsBase):
    title: str = Field(
        default="ASH example report",
        description="Heading written at the top of the report",
    )


class ExampleReporterConfig(ReporterPluginConfigBase):
    """Configuration for the example reporter."""

    name: Literal["my-example-reporter"] = "my-example-reporter"
    # ASH writes the string report() returns to reports/ash.<extension>.
    extension: str = "example.md"
    enabled: bool = True
    options: Annotated[
        ExampleReporterConfigOptions,
        Field(description="Configure my-example-reporter"),
    ] = ExampleReporterConfigOptions()


@ash_reporter_plugin
class ExampleReporter(ReporterPluginBase[ExampleReporterConfig]):
    """Lists every finding in the aggregated SARIF as a Markdown bullet."""

    def model_post_init(self, context):
        # Do not assign to self.context here. The context is one object shared by
        # every plugin in the run, so repointing work_dir would move where the
        # converted files the scanners were given are looked for.
        if self.config is None:
            self.config = ExampleReporterConfig()
        return super().model_post_init(context)

    def report(self, model: AshAggregatedResults) -> str:
        """Return the report text.

        Return the content rather than writing a file: ASH writes it to
        ``reports/ash.<extension>`` under the output directory.
        """
        self._pre_report()

        lines = [f"# {self.config.options.title}", ""]
        runs = model.sarif.runs if model.sarif and model.sarif.runs else []
        results = [result for run in runs for result in (run.results or [])]
        lines.append(f"{len(results)} findings")
        lines.append("")
        for result in results:
            where = "unknown location"
            if result.locations and result.locations[0].physicalLocation:
                physical = result.locations[0].physicalLocation.root
                uri = (
                    physical.artifactLocation.uri if physical.artifactLocation else None
                )
                line = physical.region.startLine if physical.region else None
                where = f"{uri}:{line}" if line else f"{uri}"
            text = result.message.root.text if result.message else ""
            lines.append(f"- {result.ruleId} at {where}: {text}")

        self._post_report()
        return "\n".join(lines) + "\n"
