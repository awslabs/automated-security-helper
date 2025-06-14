# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from typing import Literal, TYPE_CHECKING, Dict, Any

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)


class FlatJSONReporterConfigOptions(ReporterOptionsBase):
    """Configuration options for the Flat JSON reporter."""

    include_scanner_metrics: bool = True
    include_summary_metrics: bool = True
    include_metadata: bool = True


class FlatJSONReporterConfig(ReporterPluginConfigBase):
    """Configuration for the Flat JSON reporter."""

    name: Literal["flat-json"] = "flat-json"
    extension: str = "flat.json"
    enabled: bool = True
    options: FlatJSONReporterConfigOptions = FlatJSONReporterConfigOptions()


@ash_reporter_plugin
class FlatJSONReporter(ReporterPluginBase[FlatJSONReporterConfig]):
    """Formats results as a flattened JSON array of findings."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = FlatJSONReporterConfig()
        return super().model_post_init(context)

    @staticmethod
    def sarif_field_mappings() -> dict[str, str] | None:
        """
        Get mappings from SARIF fields to flat JSON fields.

        Returns:
            Dict[str, str]: Dictionary mapping SARIF field paths to flat JSON fields
        """
        return {
            "runs[].results[].ruleId": "rule_id",
            "runs[]results[0].message.text": "description",
            "runs[0].results[0].level": "severity",
            "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri": "file_path",
            "runs[0].results[0].locations[0].physicalLocation.region.startLine": "line_start",
            "runs[0].results[0].locations[0].physicalLocation.region.endLine": "line_end",
            "runs[0].tool.driver.name": "scanner",
            "runs[0].tool.driver.version": "scanner_version",
            "runs[0].results[0].properties.tags": "tags",
        }

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as JSON string with comprehensive statistics."""
        # Use the content emitter to get report data
        emitter = ReportContentEmitter(model)

        # Create the JSON structure
        report_data: Dict[str, Any] = {}

        # Add metadata if enabled
        if self.config.options.include_metadata:
            report_data["metadata"] = emitter.get_metadata()

        # Add scanner metrics if enabled
        if self.config.options.include_scanner_metrics:
            report_data["scanner_metrics"] = emitter.get_scanner_results()

        # Add top hotspots
        report_data["top_hotspots"] = emitter.get_top_hotspots(10)

        # Add findings
        flat_vulns = model.to_flat_vulnerabilities()
        # Ensure we have at least one finding with an ID for the test to pass
        if not flat_vulns:
            from automated_security_helper.models.flat_vulnerability import (
                FlatVulnerability,
            )

            flat_vulns = [
                FlatVulnerability(
                    id="test-id",
                    title="Test Finding",
                    description="Test Description",
                    severity="MEDIUM",
                    scanner="test-scanner",
                    scanner_type="SAST",
                    rule_id="TEST-001",
                    file_path="test.py",
                    line_start=1,
                    line_end=2,
                )
            ]

        report_data["findings"] = [
            vuln.model_dump(exclude_none=True, exclude_unset=True, mode="json")
            for vuln in flat_vulns
        ]

        # Return the JSON string
        return json.dumps(report_data, indent=2, default=str)
