import typer
from pathlib import Path
from textual.app import App, ComposeResult
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Static,
    Select,
    Input,
    Markdown,
    Label,
)
from textual.containers import (
    HorizontalGroup,
    ScrollableContainer,
    Container,
    VerticalGroup,
)
from textual.screen import Screen
from textual.binding import Binding

from automated_security_helper.models.asharp_model import AshAggregatedResults
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
        snippet_path = Path(self.finding["file"])
        file_ext = (
            snippet_path.suffix.lstrip(".")
            if snippet_path.suffix != ""
            else snippet_path.name
            if self.finding["file"]
            else None
        )
        if file_ext == "yml":
            file_ext = "yaml"
        yield Header(show_clock=True)

        with ScrollableContainer(id="finding_details"):
            md_text = f"""
#  {self.finding["rule_id"]}

## Metadata

| Key | Value |
|-----|-------|
|Severity|{self.finding["severity"]}|
|Scanner|{self.finding["scanner"]}|
|File|{self.finding["file"]}|
|Line|{self.finding["line"]}|

## Message

{self.finding["message"]}
"""
            if self.finding.get("suppressed"):
                md_text += f"\n\n## Suppression\n\n**This finding is suppressed.** Suppression justification:\n\n> {self.finding.get('suppression_reason', 'Not specified')}"
            # yield Static(f"# {self.finding['rule_id']}", classes="title")
            # yield Static(
            #     f"**Severity:** {self.finding['severity']}",
            #     classes=f"severity-{self.finding['severity']}",
            # )
            # yield Static(f"**Scanner:** {self.finding['scanner']}")
            # yield Static(f"**File:** {self.finding['file']}")
            # yield Static(f"**Line:** {self.finding['line']}")

            # yield Static("## Message")
            # yield Static(self.finding["message"])

            # yield Static("## Code")

            # Check if TextArea is available in this version of Textual
            try:
                if self.finding.get("code_snippet"):
                    # Debug output to see what's in the code snippet
                    # yield Static(
                    #     f"Debug - Code snippet length: {len(self.finding.get('code_snippet', ''))}"
                    # )

                    md_text += f"""\n\n## Code

```{file_ext}
{self.finding.get("code_snippet")}
```
"""
                    # # Use TextArea if available
                    # code_area = TextArea.code_editor(
                    #     self.finding.get("code_snippet", "# No code snippet available"),
                    #     language="python",
                    #     read_only=True,
                    # )
                    # yield code_area
                # else:
                #     yield Static("No code snippet available", classes="notice")
            except (ImportError, TypeError, AttributeError) as e:
                # Fallback to Static widget if TextArea is not available
                if self.finding.get("code_snippet"):
                    md_text += f"""\n\n## Code

```{Path(self.finding["file"]).name.split["."][-1]}
{self.finding.get("code_snippet")}
```
"""
                    # yield Static(
                    #     self.finding.get("code_snippet", "No code snippet available"),
                    #     classes="code",
                    # )
                # else:
                #     yield Static("No code snippet available", classes="notice")

                # Show error for debugging
                yield Static(f"TextArea widget error: {str(e)}", classes="error")
            finally:
                yield Markdown(md_text)
                yield Footer()


class FindingsExplorerApp(App):
    """Interactive findings explorer application."""

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("f", "toggle_filters", "Toggle Filters"),
        Binding("j", "next_finding", "Next Finding"),
        Binding("k", "previous_finding", "Previous Finding"),
        Binding("v", "view_selected", "View Selected"),
        Binding("s", "toggle_search", "Search"),
        Binding("/", "toggle_search", "Search"),
        Binding("escape", "exit_search", "Exit Search"),
        Binding("h", "toggle_suppressed", "Toggle Suppressed"),
    ]

    CSS = """
    .findings-table {
        height: 80%;
        border: solid rgb(51, 51, 51);
    }

    .filters {
        height: auto;
        margin: 1 0;
        display: none;  /* Hidden by default */
        background: rgb(30, 30, 30);
        border: solid rgb(60, 60, 60);
        padding: 1;
    }

    .filters-visible {
        display: block !important;
    }

    /* Ensure Select widgets are visible */
    Select {
        width: 30;
        height: 3;
        background: rgb(40, 40, 40);
        color: rgb(235, 235, 235);
        border: solid rgb(60, 60, 60);
        margin: 1 2;
    }

    /* Style for labels in the filter panel */
    .label {
        padding: 1;
        color: rgb(200, 200, 200);
    }

    .search-bar {
        height: 3;
        margin: 1 0;
        background: rgb(30, 30, 30);
        color: rgb(235, 235, 235);
        border: solid rgb(60, 60, 60);
        display: none;  /* Hidden by default */
    }

    .search-bar-visible {
        display: block;
    }

    #search_input {
        width: 100%;
        background: rgb(30, 30, 30);
        color: rgb(235, 235, 235);
        border: solid rgb(60, 60, 60);
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
        background: rgb(40, 40, 40);
    }
    """

    def __init__(self, findings, title="ASH Security Findings"):
        super().__init__()
        self.title = title
        self.findings = findings
        self.filtered_findings = findings
        self.current_filter = "all"
        self.current_sort = "severity"
        self.show_filters = False  # Hide filters by default
        self.search_mode = False
        self.search_query = ""
        self.sort_reverse = False
        self.sort_column = "Severity"
        self.show_suppressed = False  # Hide suppressed findings by default

    def _get_unique_scanners(self) -> list:
        """Get a list of unique scanner names."""
        return sorted(set(f["scanner"] for f in self.findings if "scanner" in f))

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        # Filter container (hidden by default)
        with HorizontalGroup(id="filters_container", classes="filters"):
            with VerticalGroup():
                yield Label("Severity")
                yield Select(
                    name="Severity",
                    options=[
                        ("All", "all"),
                        ("Critical", "severity:critical"),
                        ("High", "severity:high"),
                        ("Medium", "severity:medium"),
                        ("Low", "severity:low"),
                        ("Info", "severity:info"),
                    ],
                    value="all",
                    id="severity_select",
                    prompt="Select severity",
                )

            with VerticalGroup():
                yield Label("Scanner")
                yield Select(
                    name="Scanner",
                    options=[("All", "all")]
                    + [
                        (scanner, f"scanner:{scanner}")
                        for scanner in self._get_unique_scanners()
                    ],
                    value="all",
                    id="scanner_select",
                    prompt="Select scanner",
                )

            with VerticalGroup():
                yield Label("Show")
                yield Select(
                    name="Show",
                    options=[
                        ("All findings", "all"),
                        ("Only active", "not_suppressed"),
                        ("Only suppressed", "suppressed"),
                    ],
                    value="all" if self.show_suppressed else "not_suppressed",
                    id="suppressed_select",
                    prompt="Filter suppressed",
                )

        # Search bar (hidden by default)
        with Container(id="search_container", classes="search-bar"):
            yield Static("Search:", classes="label")
            yield Input(
                placeholder="Type to search... (ESC to exit search)", id="search_input"
            )

        yield DataTable(id="findings_table", classes="findings-table")
        yield Static(
            f"Total findings: {len(self.findings)} | Showing: {len(self.filtered_findings)} | Press s or / to search | f to toggle filters | h to toggle suppressed",
            id="status_bar",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Set up the table when the app is mounted."""
        table = self.query_one("#findings_table", DataTable)
        table.add_columns(
            "ID", "Rule ID", "Severity", "Scanner", "File", "Line", "Message"
        )

        # Enable sorting on columns
        table.cursor_type = "row"
        table.can_focus = True

        self._populate_table()

    def _populate_table(self) -> None:
        """Populate the table with findings."""
        table = self.query_one("#findings_table", DataTable)
        table.clear()

        # Apply filtering and sorting
        self._apply_filters()
        self._apply_search()
        self._apply_sorting()

        # Update status bar
        status_bar = self.query_one("#status_bar", Static)
        if self.search_mode:
            status_bar.update(
                f"SEARCH MODE: {len(self.filtered_findings)} results for '{self.search_query}' | Press ESC to exit"
            )
        else:
            suppressed_status = "showing" if self.show_suppressed else "hiding"
            status_bar.update(
                f"Total: {len(self.findings)} | Showing: {len(self.filtered_findings)} | {suppressed_status.capitalize()} suppressed | s=search | f=filters | h=toggle suppressed"
            )

        # Add rows to the table
        for i, finding in enumerate(self.filtered_findings):
            # For suppressed findings, we'll use a different approach
            # Instead of applying style after adding, we'll use different CSS classes
            # in the cell content

            if finding.get("suppressed"):
                # For suppressed findings, wrap content in spans with suppressed class
                table.add_row(
                    str(i + 1),
                    f"[suppressed]{finding.get('rule_id', 'N/A')}[/suppressed]",
                    f"[suppressed]{finding['severity']}[/suppressed]",
                    f"[suppressed]{finding['scanner']}[/suppressed]",
                    f"[suppressed]{finding['file'] or 'N/A'}[/suppressed]",
                    f"[suppressed]{str(finding.get('line', 'N/A'))}[/suppressed]",
                    f"[suppressed]{finding['message']}[/suppressed]",
                    key=i,
                )
            else:
                # For normal findings, add row as usual
                table.add_row(
                    str(i + 1),
                    finding.get("rule_id", "N/A"),
                    finding["severity"],
                    finding["scanner"],
                    finding["file"] or "N/A",
                    str(finding.get("line", "N/A")),
                    finding["message"],
                    key=i,
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

    def action_toggle_suppressed(self) -> None:
        """Toggle showing/hiding suppressed findings."""
        self.show_suppressed = not self.show_suppressed

        # Update the suppressed select widget if it exists
        try:
            suppressed_select = self.query_one("#suppressed_select")
            suppressed_select.value = (
                "all" if self.show_suppressed else "not_suppressed"
            )
        except Exception:
            pass

        self._populate_table()

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
        if event.select.id == "severity_select":
            self.current_filter = event.value
            self._populate_table()
        elif event.select.id == "scanner_select":
            self.current_filter = event.value
            self._populate_table()
        elif event.select.id == "suppressed_select":
            if event.value == "all":
                self.show_suppressed = True
            elif event.value == "not_suppressed":
                self.show_suppressed = False
            elif event.value == "suppressed":
                self.show_suppressed = True
                self.current_filter = "suppressed"
            self._populate_table()

    def action_toggle_filters(self) -> None:
        """Toggle the visibility of filters."""
        self.show_filters = not self.show_filters
        filters = self.query_one("#filters_container")

        if self.show_filters:
            filters.add_class("filters-visible")

            # Update status bar
            status_bar = self.query_one("#status_bar", Static)
            status_bar.update("Filters visible | Press 'f' to hide filters")
        else:
            filters.remove_class("filters-visible")

            # Update status bar
            self._populate_table()  # This will update the status bar

    def action_toggle_search(self) -> None:
        """Toggle search mode."""
        self.search_mode = not self.search_mode
        search_container = self.query_one("#search_container")

        if self.search_mode:
            # Show search bar and focus it
            search_container.remove_class("search-bar")
            search_container.add_class("search-bar-visible")
            search_input = self.query_one("#search_input", Input)
            search_input.focus()

            # Update status bar
            status_bar = self.query_one("#status_bar", Static)
            status_bar.update("SEARCH MODE: Type to filter | Press ESC to exit search")
        else:
            # Hide search bar and clear search
            search_container.remove_class("search-bar-visible")
            search_container.add_class("search-bar")
            self.search_query = ""
            self._populate_table()

            # Return focus to table
            table = self.query_one("#findings_table", DataTable)
            table.focus()

    def action_exit_search(self) -> None:
        """Exit search mode."""
        if self.search_mode:
            self.search_mode = False
            search_container = self.query_one("#search_container")
            search_container.remove_class("search-bar-visible")
            search_container.add_class("search-bar")

            # Clear search if ESC is pressed
            self.search_query = ""
            self._populate_table()

            # Return focus to table
            table = self.query_one("#findings_table", DataTable)
            table.focus()

    def _apply_filters(self) -> None:
        """Apply filters to the findings."""
        # First, filter by suppressed status
        if not self.show_suppressed:
            self.filtered_findings = [
                f for f in self.findings if not f.get("suppressed")
            ]
        else:
            self.filtered_findings = self.findings

        # Then apply other filters
        if self.current_filter == "all":
            return

        if self.current_filter == "suppressed":
            self.filtered_findings = [
                f for f in self.filtered_findings if f.get("suppressed")
            ]
            return

        if self.current_filter == "not_suppressed":
            self.filtered_findings = [
                f for f in self.filtered_findings if not f.get("suppressed")
            ]
            return

        if ":" in self.current_filter:
            filter_type, filter_value = self.current_filter.split(":", 1)

            if filter_type == "severity":
                self.filtered_findings = [
                    f for f in self.filtered_findings if f["severity"] == filter_value
                ]
            elif filter_type == "scanner":
                self.filtered_findings = [
                    f for f in self.filtered_findings if f["scanner"] == filter_value
                ]

    def _apply_sorting(self) -> None:
        """Sort the filtered findings."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        if self.current_sort == "severity":
            self.filtered_findings.sort(
                key=lambda f: severity_order.get(f["severity"], 5),
                reverse=self.sort_reverse,
            )
        elif self.current_sort == "file":
            self.filtered_findings.sort(
                key=lambda f: f.get("file", ""), reverse=self.sort_reverse
            )
        elif self.current_sort == "scanner":
            self.filtered_findings.sort(
                key=lambda f: f.get("scanner", ""), reverse=self.sort_reverse
            )
        elif self.current_sort == "line":
            self.filtered_findings.sort(
                key=lambda f: (
                    int(f.get("line", 0))
                    if f.get("line") and str(f.get("line")).isdigit()
                    else 0
                ),
                reverse=self.sort_reverse,
            )
        elif self.current_sort == "message":
            self.filtered_findings.sort(
                key=lambda f: f.get("message", ""), reverse=self.sort_reverse
            )
        elif self.current_sort == "rule_id":
            self.filtered_findings.sort(
                key=lambda f: f.get("rule_id", ""), reverse=self.sort_reverse
            )

    def _apply_search(self) -> None:
        """Apply search filter to the findings."""
        if not self.search_query:
            return

        search_term = self.search_query.lower()
        self.filtered_findings = [
            f
            for f in self.filtered_findings
            if (
                search_term in f.get("message", "").lower()
                or search_term in f.get("rule_id", "").lower()
                or search_term in f.get("file", "").lower()
                or search_term in f.get("scanner", "").lower()
                or search_term in str(f.get("line", "")).lower()
            )
        ]

    def on_input_changed(self, event) -> None:
        """Handle changes to the search input."""
        if event.input.id == "search_input":
            self.search_query = event.value
            self._populate_table()

    def on_data_table_header_selected(self, event) -> None:
        """Handle column header selection for sorting."""
        # In Textual 3.2.0, the event already contains the label
        # Convert the Text object to a string
        column_name = str(event.label)

        # Toggle sort direction if clicking the same column
        if self.sort_column == column_name:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column_name
            self.sort_reverse = False

        # Map column name to sort key
        column_to_sort = {
            "Severity": "severity",
            "Scanner": "scanner",
            "File": "file",
            "Line": "line",
            "Message": "message",
            "Rule ID": "rule_id",
        }.get(column_name, "severity")

        self.current_sort = column_to_sort
        self._populate_table()


def extract_findings(model):
    """Extract findings from the AshAggregatedResults."""
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
                        "message": (
                            result.message.root.text if result.message.root else ""
                        ),
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
        model = AshAggregatedResults.load_model(Path(report_file_actual))
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
