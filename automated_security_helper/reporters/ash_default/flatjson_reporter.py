# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class FlatJSONReporterConfigOptions(ReporterOptionsBase):
    pass


class FlatJSONReporterConfig(ReporterPluginConfigBase):
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
        """Format ASH model as JSON string."""

        flat_vulns = model.to_flat_vulnerabilities()
        return json.dumps(
            [
                vuln.model_dump(exclude_none=True, exclude_unset=True, mode="json")
                for vuln in flat_vulns
            ],
            indent=2,
            default=str,
        )
