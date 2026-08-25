import csv
from io import StringIO
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.models.workspace import is_workspace_scan
from automated_security_helper.plugins.decorators import ash_reporter_plugin

#: The workspace-mode column header. First rather than appended, because a
#: spreadsheet consumer sorts and filters on the leftmost columns and the project
#: is the coarsest grouping a workspace report has.
PROJECT_COLUMN = "workspace_project"


class CSVReporterConfigOptions(ReporterOptionsBase):
    pass


class CSVReporterConfig(ReporterPluginConfigBase):
    name: Literal["csv"] = "csv"
    extension: str = "csv"
    enabled: bool = True
    options: CSVReporterConfigOptions = CSVReporterConfigOptions()


@ash_reporter_plugin
class CsvReporter(ReporterPluginBase[CSVReporterConfig]):
    """Formats results as CSV.

    Workspace mode: one merged artefact with a leading ``workspace_project``
    column. A row is one finding either way, so N projects are N groups of rows
    rather than a different document -- which is exactly what a spreadsheet or a
    ``pandas.read_csv`` consumer wants.

    The column is emitted only when the model is a workspace scan. Emitting it
    unconditionally would add an always-empty column to every single-directory
    CSV, and a consumer that indexes by column *position* rather than by header
    would silently read the wrong field from then on.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

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
            "runs[].results[].locations[].physicalLocation.region.startLine": "Line Start",
            "runs[].results[].locations[].physicalLocation.region.endLine": "Line End",
            "runs[].tool.driver.name": "Scanner",
        }

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as CSV string."""

        output = StringIO()
        writer = csv.writer(output)

        # Whether to emit the project column at all. Read off the workspace block
        # rather than off the findings: a workspace whose projects all came back
        # clean has no findings to inspect, and its header must still declare the
        # column so a consumer's parser does not change shape run to run.
        is_workspace = is_workspace_scan(model)

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
            writer.writerow(self._header(is_workspace))
            return output.getvalue()

        # Get all field names from the first vulnerability
        fields = list(flat_vulns[0].keys())
        if not is_workspace:
            # Dropped rather than never added, so that a single-directory CSV is
            # byte-identical to what it has always been. Leaving an always-empty
            # column in would shift every following column, and a consumer that
            # reads by position rather than by header would silently read the
            # wrong field from then on.
            fields = [field for field in fields if field != PROJECT_COLUMN]
        else:
            # Leading, because a spreadsheet or pandas consumer groups and sorts
            # on the first columns and the project is the coarsest grouping a
            # workspace report has.
            fields = [PROJECT_COLUMN] + [
                field for field in fields if field != PROJECT_COLUMN
            ]

        # Write header row
        writer.writerow(fields)

        # Write data rows
        for vuln in flat_vulns:
            row = []
            for field in fields:
                # .get rather than [], because the header is assembled from the
                # first finding's keys plus the project column. A later finding
                # missing a key -- or a project column added to the header of a
                # scan whose findings predate it -- would otherwise raise a
                # KeyError and lose the whole report rather than one cell.
                value = vuln.get(field)
                row.append(value if value is not None else "")
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def _header(is_workspace: bool) -> list[str]:
        """The header for a scan with no findings at all.

        Derived from ``FlatVulnerability``'s own field order rather than written
        out, so the empty form and the populated form cannot drift apart. The
        hardcoded list this replaced had already drifted: it spelled the columns
        in title case ("Rule ID") while the populated form emitted field names
        ("rule_id"), so a consumer parsing by header name worked against one form
        and not the other depending on whether the scan found anything.
        """
        from automated_security_helper.models.flat_vulnerability import (
            FlatVulnerability,
        )

        fields = list(FlatVulnerability.model_fields)
        if not is_workspace:
            return [field for field in fields if field != PROJECT_COLUMN]
        return [PROJECT_COLUMN] + [field for field in fields if field != PROJECT_COLUMN]
