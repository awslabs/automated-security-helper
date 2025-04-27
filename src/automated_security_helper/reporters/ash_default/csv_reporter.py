import csv
from io import StringIO
from typing import Any, Literal
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)


class CSVReporterConfigOptions(ReporterOptionsBase):
    pass


class CSVReporterConfig(ReporterPluginConfigBase):
    name: Literal["csv"] = "csv"
    extension: str = "csv"
    enabled: bool = True
    options: CSVReporterConfigOptions = CSVReporterConfigOptions()


class CSVReporter(ReporterPluginBase[CSVReporterConfig]):
    """Formats results as CSV."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = CSVReporterConfig()
        return super().model_post_init(context)

    def report(self, model: Any) -> str:
        """Format ASH model as CSV string."""
        from automated_security_helper.models.asharp_model import ASHARPModel

        if not isinstance(model, ASHARPModel):
            raise ValueError(f"{self.__class__.__name__} only supports ASHARPModel")

        output = StringIO()
        writer = csv.writer(output)

        # Get flattened vulnerabilities
        flat_vulns = model.to_flat_vulnerabilities()

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
                    "Detected At",
                    "Tags",
                    "Properties",
                    "References",
                ]
            )
            return output.getvalue()

        # Get all field names from the first vulnerability
        fields = list(flat_vulns[0].__class__.model_fields.keys())

        # Write header row
        writer.writerow(fields)

        # Write data rows
        for vuln in flat_vulns:
            row = []
            for field in fields:
                value = getattr(vuln, field)
                row.append(value if value is not None else "")
            writer.writerow(row)

        return output.getvalue()
