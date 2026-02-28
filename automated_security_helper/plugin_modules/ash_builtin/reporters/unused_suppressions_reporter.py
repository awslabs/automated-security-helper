# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporter for identifying unused suppressions."""

import json
from typing import Literal, TYPE_CHECKING, Dict, Any, List

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.models.core import AshSuppression


class UnusedSuppressionsReporterConfigOptions(ReporterOptionsBase):
    """Configuration options for the Unused Suppressions reporter."""

    output_format: str = "json"  # "json" or "markdown"


class UnusedSuppressionsReporterConfig(ReporterPluginConfigBase):
    """Configuration for the Unused Suppressions reporter."""

    name: Literal["unused-suppressions"] = "unused-suppressions"
    extension: str = "unused-suppressions.json"
    enabled: bool = True
    options: UnusedSuppressionsReporterConfigOptions = (
        UnusedSuppressionsReporterConfigOptions()
    )


@ash_reporter_plugin
class UnusedSuppressionsReporter(ReporterPluginBase[UnusedSuppressionsReporterConfig]):
    """Identifies and reports suppressions that were not applied to any findings."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = UnusedSuppressionsReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Generate a report of unused suppressions."""
        # Ensure config is properly typed if it was passed as a dictionary
        if isinstance(self.config, dict):
            self.config = UnusedSuppressionsReporterConfig.model_validate(self.config)

        # Get all configured suppressions
        all_suppressions = (
            self.context.config.global_settings.suppressions
            if self.context.config.global_settings.suppressions
            else []
        )

        # Get used suppressions from the model
        used_suppressions = getattr(model, "used_suppressions", set())

        # Identify unused suppressions
        unused_suppressions = []
        for suppression in all_suppressions:
            # Create a unique identifier for the suppression
            suppression_id = self._get_suppression_id(suppression)
            if suppression_id not in used_suppressions:
                unused_suppressions.append(suppression)

        # Build the report data
        report_data: Dict[str, Any] = {
            "summary": {
                "total_suppressions": len(all_suppressions),
                "used_suppressions": len(used_suppressions),
                "unused_suppressions": len(unused_suppressions),
            },
            "unused_suppressions": [
                self._suppression_to_dict(s) for s in unused_suppressions
            ],
        }

        # Return in requested format
        output_format = getattr(self.config.options, "output_format", "json")
        if output_format == "markdown":
            return self._generate_markdown_report(report_data, unused_suppressions)
        else:
            return json.dumps(report_data, indent=2, default=str)

    @staticmethod
    def _get_suppression_id(suppression: AshSuppression) -> str:
        """Generate a unique identifier for a suppression rule."""
        # If line_start is specified but line_end is not, use line_start for both
        line_end_val = (
            suppression.line_end
            if suppression.line_end is not None
            else suppression.line_start
        )

        parts = [
            suppression.path,
            suppression.rule_id or "*",
            str(suppression.line_start) if suppression.line_start is not None else "*",
            str(line_end_val) if line_end_val is not None else "*",
        ]
        return "|".join(parts)

    @staticmethod
    def _suppression_to_dict(suppression: AshSuppression) -> Dict[str, Any]:
        """Convert a suppression to a dictionary for JSON serialization."""
        return {
            "path": suppression.path,
            "rule_id": suppression.rule_id,
            "line_start": suppression.line_start,
            "line_end": suppression.line_end,
            "reason": suppression.reason,
            "expiration": suppression.expiration,
        }

    @staticmethod
    def _generate_markdown_report(
        report_data: Dict[str, Any], unused_suppressions: List[AshSuppression]
    ) -> str:
        """Generate a human-readable markdown report."""
        lines = []

        # Title
        lines.append("# Unused Suppressions Report")
        lines.append("")

        # Summary
        summary = report_data["summary"]
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total Suppressions**: {summary['total_suppressions']}")
        lines.append(f"- **Used Suppressions**: {summary['used_suppressions']}")
        lines.append(f"- **Unused Suppressions**: {summary['unused_suppressions']}")
        lines.append("")

        # Status indicator
        if summary["unused_suppressions"] == 0:
            lines.append("✅ **All suppressions are being used!**")
            lines.append("")
        else:
            percentage = (
                (summary["unused_suppressions"] / summary["total_suppressions"] * 100)
                if summary["total_suppressions"] > 0
                else 0
            )
            lines.append(f"⚠️  **{percentage:.1f}% of suppressions are unused**")
            lines.append("")

        # Unused suppressions details
        if unused_suppressions:
            lines.append("## Unused Suppressions")
            lines.append("")
            lines.append(
                "The following suppressions are configured but not currently matching any findings:"
            )
            lines.append("")

            for i, suppression in enumerate(unused_suppressions, 1):
                lines.append(f"### {i}. {suppression.path}")
                lines.append("")
                lines.append(f"- **Rule ID**: `{suppression.rule_id or 'Any'}`")

                if suppression.line_start is not None:
                    if (
                        suppression.line_end is not None
                        and suppression.line_end != suppression.line_start
                    ):
                        lines.append(
                            f"- **Lines**: {suppression.line_start}-{suppression.line_end}"
                        )
                    else:
                        lines.append(f"- **Line**: {suppression.line_start}")
                else:
                    lines.append("- **Lines**: Any")

                lines.append(f"- **Reason**: {suppression.reason}")

                if suppression.expiration:
                    lines.append(f"- **Expiration**: {suppression.expiration}")

                lines.append("")

            # Recommendations
            lines.append("## Recommendations")
            lines.append("")
            lines.append("Review each unused suppression and consider:")
            lines.append("")
            lines.append(
                "1. **File no longer exists**: Remove the suppression from your configuration"
            )
            lines.append(
                "2. **Finding was fixed**: Remove the suppression as it's no longer needed"
            )
            lines.append(
                "3. **Path/rule/line mismatch**: Update the suppression to match the current code"
            )
            lines.append(
                "4. **Still needed**: Verify the suppression is correctly configured"
            )
            lines.append("")
        else:
            lines.append("## Details")
            lines.append("")
            lines.append(
                "No unused suppressions found. All configured suppressions are actively being applied to findings."
            )
            lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*This report was generated by ASH (Automated Security Helper)*")
        lines.append("")

        return "\n".join(lines)
