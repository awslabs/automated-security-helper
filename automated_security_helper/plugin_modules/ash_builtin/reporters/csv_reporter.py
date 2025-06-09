import csv
from io import StringIO
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin


class CSVReporterConfigOptions(ReporterOptionsBase):
    pass


class CSVReporterConfig(ReporterPluginConfigBase):
    name: Literal["csv"] = "csv"
    extension: str = "csv"
    enabled: bool = True
    options: CSVReporterConfigOptions = CSVReporterConfigOptions()


@ash_reporter_plugin
class CsvReporter(ReporterPluginBase[CSVReporterConfig]):
    """Formats results as CSV."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CSVReporterConfig()
        return super().model_post_init(context)

    @staticmethod
    def sarif_field_mappings() -> dict[str, str] | None:
        """
        Get mappings from SARIF fields to CSV column headers.

        Returns:
            Dict[str, str]: Dictionary mapping SARIF field paths to CSV column headers
        """
        return {
            "runs[].results[].ruleId": "Rule ID",
            "runs[].results[].message.text": "Description",
            "runs[].results[].level": "Severity",
            "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "File Path",
            "runs[].results[]locations[].physicalLocation.region.startLine": "Line Start",
            "runs[].results[]locations[].physicalLocation.region.endLine": "Line End",
            "runs[].tool.driver.name": "Scanner",
        }

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as CSV string."""

        output = StringIO()
        writer = csv.writer(output)

        # Get flattened vulnerabilities
        flat_vulns = [
            item.model_dump(
                exclude_defaults=False,
                exclude_none=False,
                exclude_unset=False,
            )
            for item in model.to_flat_vulnerabilities()
        ]

        if not flat_vulns:
            # If no vulnerabilities, return a header-only CSV
            writer.writerow(
                [
                    "ID",
                    "Title",
                    "Description",
                    "Severity",
                    "Scanner",
                    "Scanner Type",
                    "Rule ID",
                    "File Path",
                    "Line Start",
                    "Line End",
                    "CVE ID",
                    "CWE ID",
                    "Fix Available",
                    "Is Suppressed",
                    "Suppression Kind",
                    "Suppression Justification",
                    "Detected At",
                    "Tags",
                    "Properties",
                    "References",
                ]
            )
            return output.getvalue()

        # Get all field names from the first vulnerability
        fields = list(flat_vulns[0].keys())

        # Write header row
        writer.writerow(fields)

        # Write data rows
        for vuln in flat_vulns:
            row = []
            for field in fields:
                value = vuln[field]
                row.append(value if value is not None else "")
            writer.writerow(row)

        return output.getvalue()
