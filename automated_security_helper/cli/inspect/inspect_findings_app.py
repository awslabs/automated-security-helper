import typer
from pathlib import Path
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Footer, Header, Static, Select, TextArea
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.binding import Binding

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.utils.log import ASH_LOGGER


class FindingDetailScreen(Screen):
    """Screen for displaying detailed information about a finding."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("q", "app.pop_screen", "Back"),
    ]

    def __init__(self, finding):
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with ScrollableContainer(id="finding_details"):
            yield Static(f"# {self.finding['rule_id']}", classes="title")
            yield Static(
                f"**Severity:** {self.finding['severity']}",
                classes=f"severity-{self.finding['severity']}",
            )
            yield Static(f"**Scanner:** {self.finding['scanner']}")
            yield Static(f"**File:** {self.finding['file']}")
            yield Static(f"**Line:** {self.finding['line']}")

            yield Static("## Message")
            yield Static(self.finding["message"])

            yield Static("## Code")

            # Check if TextArea is available in this version of Textual
            try:
                if self.finding.get("code_snippet"):
                    # Debug output to see what's in the code snippet
                    yield Static(
                        f"Debug - Code snippet length: {len(self.finding.get('code_snippet', ''))}"
                    )

                    # Use TextArea if available
                    code_area = TextArea.code_editor(
                        self.finding.get("code_snippet", "# No code snippet available"),
                        language="python",
                        read_only=True,
                    )
                    yield code_area
                else:
                    yield Static("No code snippet available", classes="notice")
            except (ImportError, TypeError, AttributeError) as e:
                # Fallback to Static widget if TextArea is not available
                if self.finding.get("code_snippet"):
                    yield Static(
                        self.finding.get("code_snippet", "No code snippet available"),
                        classes="code",
                    )
                else:
                    yield Static("No code snippet available", classes="notice")

                # Show error for debugging
                yield Static(f"TextArea widget error: {str(e)}", classes="error")

            if self.finding.get("suppressed"):
                yield Static("## Suppression")
                yield Static(
                    f"This finding is suppressed. Reason: {self.finding.get('suppression_reason', 'Not specified')}"
                )

        yield Footer()


class FindingsExplorerApp(App):
    """Interactive findings explorer application."""

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("f", "toggle_filters", "Toggle Filters"),
        Binding("j", "next_finding", "Next Finding"),
        Binding("k", "previous_finding", "Previous Finding"),
        Binding("v", "view_selected", "View Selected"),
    ]

    CSS = """
    .findings-table {
        height: 70%;
        border: solid rgb(51, 51, 51);
    }

    .filters {
        height: 3;
        margin: 1 0;
    }

    #finding_details {
        height: auto;
        padding: 1;
    }

    #code_snippet {
        min-height: 10;
        max-height: 20;
        margin: 1 0;
        border: solid rgb(40, 100, 40);
        background: rgb(30, 30, 30);
        color: rgb(235, 235, 235);
        padding: 1;
    }

    .notice {
        color: rgb(150, 150, 150);
        text-style: italic;
    }

    .code {
        background: rgb(30, 30, 30);
        color: rgb(235, 235, 235);
        border: solid rgb(40, 40, 40);
        padding: 1;
    }

    .error {
        color: rgb(255, 85, 85);
        background: rgb(40, 0, 0);
        padding: 1;
        border: solid rgb(100, 0, 0);
    }

    .title {
        text-style: bold;
        color: rgb(97, 175, 239);
    }

    .severity-critical {
        color: rgb(255, 85, 85);
        text-style: bold;
    }

    .severity-high {
        color: rgb(255, 85, 85);
    }

    .severity-medium {
        color: rgb(241, 250, 140);
    }

    .severity-low {
        color: rgb(80, 250, 123);
    }

    .severity-info {
        color: rgb(139, 233, 253);
    }

    .suppressed {
        text-style: strike;
        color: rgb(100, 100, 100);
    }
    """

    def __init__(self, findings, title="ASH Security Findings"):
        super().__init__()
        self.title = title
        self.findings = findings
        self.filtered_findings = findings
        self.current_filter = "all"
        self.current_sort = "severity"
        self.show_filters = True

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal(id="filters_container", classes="filters"):
            yield Static("Filter by:", classes="label")
            yield Select(
                [("All", "all")]
                + [
                    (f"Severity: {sev}", f"severity:{sev}")
                    for sev in ["critical", "high", "medium", "low", "info"]
                ]
                + [
                    (f"Scanner: {scanner}", f"scanner:{scanner}")
                    for scanner in self._get_unique_scanners()
                ]
                + [
                    ("Suppressed", "suppressed"),
                    ("Not Suppressed", "not_suppressed"),
                ],
                value="all",
                id="filter_select",
            )
            yield Static("Sort by:", classes="label")
            yield Select(
                [("Severity", "severity"), ("File", "file"), ("Scanner", "scanner")],
                value="severity",
                id="sort_select",
            )

        yield DataTable(id="findings_table", classes="findings-table")
        yield Static(
            f"Total findings: {len(self.findings)} | Showing: {len(self.filtered_findings)}",
            id="status_bar",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Set up the table when the app is mounted."""
        table = self.query_one("#findings_table", DataTable)
        table.add_columns("ID", "Severity", "Scanner", "File", "Line", "Message")
        self._populate_table()

    def _populate_table(self) -> None:
        """Populate the table with findings."""
        table = self.query_one("#findings_table", DataTable)
        table.clear()

        # Apply filtering and sorting
        self._apply_filters()
        self._apply_sorting()

        # Update status bar
        status_bar = self.query_one("#status_bar", Static)
        status_bar.update(
            f"Total findings: {len(self.findings)} | Showing: {len(self.filtered_findings)}"
        )

        # Add rows to the table
        for i, finding in enumerate(self.filtered_findings):
            table.add_row(
                str(i + 1),
                finding["severity"],
                finding["scanner"],
                finding["file"] or "N/A",
                str(finding.get("line", "N/A")),
                (
                    finding["message"][:50] + "..."
                    if len(finding["message"]) > 50
                    else finding["message"]
                ),
                key=i,  # Use index as row key
            )

    def action_next_finding(self) -> None:
        """Select the next finding in the table."""
        table = self.query_one("#findings_table", DataTable)
        if table.row_count > 0:
            # Get current cursor position or default to 0
            current_row = table.cursor_row if table.cursor_row is not None else 0
            next_row = min(current_row + 1, table.row_count - 1)
            table.move_cursor(row=next_row)

            # Update status bar with selected finding info
            if 0 <= next_row < len(self.filtered_findings):
                finding = self.filtered_findings[next_row]
                status_bar = self.query_one("#status_bar", Static)
                status_bar.update(
                    f"Selected: {finding['rule_id']} - Press 'v' to view details"
                )

    def action_previous_finding(self) -> None:
        """Select the previous finding in the table."""
        table = self.query_one("#findings_table", DataTable)
        if table.row_count > 0:
            # Get current cursor position or default to 0
            current_row = table.cursor_row if table.cursor_row is not None else 0
            prev_row = max(current_row - 1, 0)
            table.move_cursor(row=prev_row)

            # Update status bar with selected finding info
            if 0 <= prev_row < len(self.filtered_findings):
                finding = self.filtered_findings[prev_row]
                status_bar = self.query_one("#status_bar", Static)
                status_bar.update(
                    f"Selected: {finding['rule_id']} - Press 'v' to view details"
                )

    def action_view_selected(self) -> None:
        """View the currently selected finding."""
        table = self.query_one("#findings_table", DataTable)
        if table.row_count > 0 and table.cursor_row is not None:
            finding_idx = table.cursor_row
            if 0 <= finding_idx < len(self.filtered_findings):
                finding = self.filtered_findings[finding_idx]

                # Debug output
                ASH_LOGGER.debug(
                    f"Selected finding: {finding.get('rule_id')} - {finding.get('scanner')}"
                )
                ASH_LOGGER.debug(
                    f"File: {finding.get('file')}, Line: {finding.get('line')}"
                )
                ASH_LOGGER.debug(
                    f"Has code snippet: {bool(finding.get('code_snippet'))}"
                )

                # Try to extract code snippet if not already present
                if (
                    not finding.get("code_snippet")
                    and finding.get("file")
                    and finding.get("line")
                ):
                    try:
                        file_path = Path(finding["file"])
                        ASH_LOGGER.debug(
                            f"Looking for file: {file_path}, exists: {file_path.exists()}"
                        )

                        if file_path.exists():
                            with open(file_path, mode="r", encoding="utf-8") as f:
                                lines = f.readlines()

                            # Get line number (adjust for 0-based indexing)
                            line_num = int(finding["line"]) - 1

                            # Get context (5 lines before and after)
                            start_line = max(0, line_num - 5)
                            end_line = min(len(lines), line_num + 6)

                            # Extract the snippet with line numbers
                            snippet_lines = []
                            for i in range(start_line, end_line):
                                prefix = "→ " if i == line_num else "  "
                                snippet_lines.append(f"{prefix}{i + 1}: {lines[i]}")

                            finding["code_snippet"] = "".join(snippet_lines)
                            ASH_LOGGER.debug(
                                f"Extracted code snippet of length: {len(finding['code_snippet'])}"
                            )
                        else:
                            ASH_LOGGER.debug(f"File not found: {file_path}")
                    except Exception as e:
                        ASH_LOGGER.debug(f"Failed to extract code snippet: {e}")

                self.push_screen(FindingDetailScreen(finding))

    def on_data_table_row_selected(self, event) -> None:
        """Handle row selection in the findings table."""
        finding_idx = event.row_key.value
        finding = self.filtered_findings[finding_idx]

        # Debug output
        ASH_LOGGER.debug(
            f"Selected finding: {finding.get('rule_id')} - {finding.get('scanner')}"
        )
        ASH_LOGGER.debug(f"File: {finding.get('file')}, Line: {finding.get('line')}")
        ASH_LOGGER.debug(f"Has code snippet: {bool(finding.get('code_snippet'))}")

        # Try to extract code snippet if not already present
        if (
            not finding.get("code_snippet")
            and finding.get("file")
            and finding.get("line")
        ):
            try:
                file_path = Path(finding["file"])
                ASH_LOGGER.debug(
                    f"Looking for file: {file_path}, exists: {file_path.exists()}"
                )

                if file_path.exists():
                    with open(file_path, mode="r", encoding="utf-8") as f:
                        lines = f.readlines()

                    # Get line number (adjust for 0-based indexing)
                    line_num = int(finding["line"]) - 1

                    # Get context (5 lines before and after)
                    start_line = max(0, line_num - 5)
                    end_line = min(len(lines), line_num + 6)

                    # Extract the snippet with line numbers
                    snippet_lines = []
                    for i in range(start_line, end_line):
                        prefix = "→ " if i == line_num else "  "
                        snippet_lines.append(f"{prefix}{i + 1}: {lines[i]}")

                    finding["code_snippet"] = "".join(snippet_lines)
                    ASH_LOGGER.debug(
                        f"Extracted code snippet of length: {len(finding['code_snippet'])}"
                    )
                else:
                    ASH_LOGGER.debug(f"File not found: {file_path}")
            except Exception as e:
                ASH_LOGGER.debug(f"Failed to extract code snippet: {e}")

        self.push_screen(FindingDetailScreen(finding))

    def on_select_changed(self, event) -> None:
        """Handle changes to filter or sort selects."""
        if event.select.id == "filter_select":
            self.current_filter = event.value
        elif event.select.id == "sort_select":
            self.current_sort = event.value
        self._populate_table()

    def action_toggle_filters(self) -> None:
        """Toggle the visibility of filters."""
        self.show_filters = not self.show_filters
        filters = self.query_one("#filters_container")
        filters.display = not self.show_filters

    def _apply_filters(self) -> None:
        """Apply filters to the findings."""
        if self.current_filter == "all":
            self.filtered_findings = self.findings
            return

        if self.current_filter == "suppressed":
            self.filtered_findings = [f for f in self.findings if f.get("suppressed")]
            return

        if self.current_filter == "not_suppressed":
            self.filtered_findings = [
                f for f in self.findings if not f.get("suppressed")
            ]
            return

        if ":" in self.current_filter:
            filter_type, filter_value = self.current_filter.split(":", 1)

            if filter_type == "severity":
                self.filtered_findings = [
                    f for f in self.findings if f["severity"] == filter_value
                ]
            elif filter_type == "scanner":
                self.filtered_findings = [
                    f for f in self.findings if f["scanner"] == filter_value
                ]
        else:
            self.filtered_findings = self.findings

    def _apply_sorting(self) -> None:
        """Sort the filtered findings."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        if self.current_sort == "severity":
            self.filtered_findings.sort(
                key=lambda f: severity_order.get(f["severity"], 5)
            )
        elif self.current_sort == "file":
            self.filtered_findings.sort(key=lambda f: f.get("file", ""))
        elif self.current_sort == "scanner":
            self.filtered_findings.sort(key=lambda f: f.get("scanner", ""))

    def _get_unique_scanners(self) -> list:
        """Get a list of unique scanner names."""
        return sorted(set(f["scanner"] for f in self.findings if "scanner" in f))


def extract_findings(model):
    """Extract findings from the ASHARPModel."""
    findings = []

    # Extract findings from SARIF reports
    if model.sarif and model.sarif.runs:
        for run in model.sarif.runs:
            if run.results:
                result: Result
                for result in run.results:
                    # Extract basic info
                    finding = {
                        "id": result.ruleIndex or -1,
                        "rule_id": result.ruleId,
                        "message": result.message.root.text
                        if result.message.root
                        else "",
                        "level": result.level,
                        "kind": result.kind,
                        "severity": map_level_to_severity(result.level),
                        "scanner": result.properties.model_dump(by_alias=True)
                        .get("scanner_details", {})
                        .get("tool_name", "unknown"),
                        "suppressed": (
                            bool(result.suppressions)
                            if hasattr(result, "suppressions") and result.suppressions
                            else False
                        ),
                    }

                    # Extract suppression reason if available
                    if (
                        finding["suppressed"]
                        and hasattr(result, "suppressions")
                        and result.suppressions
                    ):
                        finding["suppression_reason"] = (
                            result.suppressions[0].justification
                            if hasattr(result.suppressions[0], "justification")
                            else "Not specified"
                        )

                    # Extract location info
                    if result.locations:
                        for location in result.locations:
                            if (
                                location.physicalLocation
                                and location.physicalLocation.root.artifactLocation
                            ):
                                finding["file"] = (
                                    location.physicalLocation.root.artifactLocation.uri
                                )
                                if location.physicalLocation.root.region:
                                    finding["line"] = (
                                        location.physicalLocation.root.region.startLine
                                    )
                                    finding["column"] = (
                                        location.physicalLocation.root.region.startColumn
                                    )

                                    # Extract code snippet if available in SARIF
                                    if location.physicalLocation.root.region.snippet:
                                        finding["code_snippet"] = (
                                            location.physicalLocation.root.region.snippet.text
                                        )
                                break

                    # If no snippet was found in locations, try to extract from codeFlows if available
                    if not finding.get("code_snippet") and hasattr(result, "codeFlows"):
                        for codeFlow in result.codeFlows:
                            if hasattr(codeFlow, "threadFlows"):
                                for threadFlow in codeFlow.threadFlows:
                                    if hasattr(threadFlow, "locations"):
                                        for loc in threadFlow.locations:
                                            if (
                                                hasattr(loc, "location")
                                                and hasattr(
                                                    loc.location, "physicalLocation"
                                                )
                                                and hasattr(
                                                    loc.location.physicalLocation,
                                                    "region",
                                                )
                                                and hasattr(
                                                    loc.location.physicalLocation.region,
                                                    "snippet",
                                                )
                                                and hasattr(
                                                    loc.location.physicalLocation.region.snippet,
                                                    "text",
                                                )
                                            ):
                                                finding["code_snippet"] = (
                                                    loc.location.physicalLocation.region.snippet.text
                                                )
                                                break

                    findings.append(finding)

    return findings


def map_level_to_severity(level):
    """Map SARIF level to severity."""
    if level == "error":
        return "high"
    elif level == "warning":
        return "medium"
    elif level == "note":
        return "low"
    else:
        return "info"


def findings_command(
    output_dir: Path = typer.Option(
        Path.cwd().joinpath(".ash", "ash_output"),
        help="Path to the output directory containing an ASH Aggregated Results JSON report file to analyze.",
    ),
    report_file: str = typer.Option(
        "ash_aggregated_results.json",
        help="Name of the report file to analyze. Defaults to 'ash_aggregated_results.json'.",
    ),
):
    """Interactively explore security findings."""
    # Try to load the model from the output directory
    try:
        report_file_actual = Path(output_dir).joinpath(report_file)
        model = ASHARPModel.load_model(Path(report_file_actual))
        if model is None:
            typer.echo(
                "No model or report file available. Please run a scan first or provide a report file."
            )
            return

        # Extract findings from the model
        findings = extract_findings(model)

        if not findings:
            typer.echo("No findings to display.")
            return

        # Launch the Textual app
        app = FindingsExplorerApp(findings)
        app.run()
    except Exception as e:
        typer.secho(f"Error loading model or report: {e}", fg="red")
        return
