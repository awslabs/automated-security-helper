import csv
from collections.abc import Sequence
from io import StringIO
from typing import Any, Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.models.workspace import SkippedProject, is_workspace_scan
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_skipped_rows import (
    skipped_project_detail,
    skipped_projects,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin

#: The workspace-mode column header. First rather than appended, because a
#: spreadsheet consumer sorts and filters on the leftmost columns and the project
#: is the coarsest grouping a workspace report has.
PROJECT_COLUMN = "workspace_project"

#: Qualifies what a row IS. Second, directly after the project, so the two columns
#: a workspace consumer groups and filters on sit together at the left edge.
#: Workspace-only, for the same reason ``PROJECT_COLUMN`` is -- see the class
#: docstring. Named on the module so a consumer's schema and a test can both refer
#: to it without spelling the string twice.
ROW_TYPE_COLUMN = "workspace_row_type"

#: The row is a finding, as every row in this format has always been.
FINDING_ROW_TYPE = "finding"

#: The row stands for a project that was never scanned, not for a finding. See
#: ``workspace_skipped_rows`` for why such a row is emitted at all.
SKIPPED_PROJECT_ROW_TYPE = "skipped-project"

#: The prefix on a project row's ``id``. A consumer that keys rows by ``id`` needs
#: one, and prefixing it makes the value self-describing rather than a plausible
#: finding identifier. Deterministic, so the same skip on a re-run is the same row.
SKIPPED_PROJECT_ID_PREFIX = "ash-workspace-skipped-project:"


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

    A skipped project has no findings and so would have no rows at all, which
    reads exactly like a project that came back clean. Workspace mode therefore
    also emits one row per skipped project, qualified by a second workspace-only
    column, ``workspace_row_type``: ``finding`` for every ordinary row and
    ``skipped-project`` for these. Both values are explicit so the filter can be
    written either way round, and the project row's ``severity`` cell is left blank
    so a consumer that groups by severity and never reads the row type still does
    not acquire a phantom finding. ``workspace_skipped_rows`` carries the full
    argument, including why the same problem is solved differently in junitxml and
    ocsf.
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

        # The skipped projects, read before the early return below so that a
        # workspace whose scanned projects all came back clean still discloses
        # them. Appending these after that return would have made the
        # finding-less workspace -- the case where the artefact otherwise says
        # nothing at all -- the one case where the disclosure was lost.
        skipped = skipped_projects(model)

        if not flat_vulns:
            # No findings: the header alone, plus any project rows.
            fields = self._header(is_workspace)
            writer.writerow(fields)
            for entry in skipped:
                writer.writerow(self._skipped_project_row(fields, entry))
            return output.getvalue()

        # Get all field names from the first vulnerability
        fields = self._order(list(flat_vulns[0].keys()), is_workspace)

        # Write header row
        writer.writerow(fields)

        # Write data rows
        for vuln in flat_vulns:
            row = []
            for field in fields:
                if field == ROW_TYPE_COLUMN:
                    # Stated rather than left blank. A blank cell is ambiguous
                    # with a value the producer failed to write, so a consumer
                    # cannot tell "this is a finding" from "something went wrong
                    # here" -- and the filter would have to be a negation, which
                    # silently admits any future row type nobody taught it about.
                    row.append(FINDING_ROW_TYPE)
                    continue
                # .get rather than [], because the header is assembled from the
                # first finding's keys plus the project column. A later finding
                # missing a key -- or a project column added to the header of a
                # scan whose findings predate it -- would otherwise raise a
                # KeyError and lose the whole report rather than one cell.
                value = vuln.get(field)
                row.append(value if value is not None else "")
            writer.writerow(row)

        for entry in skipped:
            writer.writerow(self._skipped_project_row(fields, entry))

        return output.getvalue()

    @staticmethod
    def _order(fields: list[str], is_workspace: bool) -> list[str]:
        """*fields* with the workspace columns dropped or moved to the front.

        Shared by the populated and header-only paths so the two cannot disagree
        about column ORDER, while each keeps deriving the column SET from its own
        source -- ``flat_vulns[0].keys()`` for one and
        ``FlatVulnerability.model_fields`` for the other. Folding the sources
        together as well would have removed the drift
        ``test_the_header_only_form_matches_the_populated_header`` exists to catch,
        leaving a test that compares a function's output with itself.
        """
        if not is_workspace:
            # Dropped rather than never added, so that a single-directory CSV is
            # byte-identical to what it has always been. Leaving an always-empty
            # column in would shift every following column, and a consumer that
            # reads by position rather than by header would silently read the
            # wrong field from then on.
            return [
                field
                for field in fields
                if field not in (PROJECT_COLUMN, ROW_TYPE_COLUMN)
            ]
        # Leading, because a spreadsheet or pandas consumer groups and sorts
        # on the first columns and the project is the coarsest grouping a
        # workspace report has.
        return [PROJECT_COLUMN, ROW_TYPE_COLUMN] + [
            field for field in fields if field not in (PROJECT_COLUMN, ROW_TYPE_COLUMN)
        ]

    @staticmethod
    def _skipped_project_row(
        fields: Sequence[str], entry: SkippedProject
    ) -> list[object]:
        """One row standing for a project that was never scanned.

        Every cell not listed here is blank, and that is the point: ``severity``
        in particular, so a consumer that buckets by severity and never reads
        ``workspace_row_type`` gets no phantom INFO finding. ``scanner`` is blank
        for the same reason -- no scanner ran, and naming one would attribute the
        row to a tool that never saw the project.

        Built against *fields* rather than written as a fixed tuple so the row
        follows the header wherever the header goes; a column added to
        ``FlatVulnerability`` widens both together instead of shifting this row
        out of alignment with it.
        """
        values: dict[str, Any] = {
            PROJECT_COLUMN: entry.project,
            ROW_TYPE_COLUMN: SKIPPED_PROJECT_ROW_TYPE,
            "id": f"{SKIPPED_PROJECT_ID_PREFIX}{entry.project}",
            "title": f"Project '{entry.project}' was not scanned",
            "description": skipped_project_detail(entry),
        }
        return [values.get(field, "") for field in fields]

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

        return CsvReporter._order(list(FlatVulnerability.model_fields), is_workspace)
