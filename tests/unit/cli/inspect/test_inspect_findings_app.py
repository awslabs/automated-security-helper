"""Unit tests for the inspect findings TUI application.

Tests focus on business logic methods: initialization, filtering, sorting,
searching, action handlers, and the extract_findings utility function.
Textual rendering internals are not tested.
"""

import pytest
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
    FindingDetailScreen,
    extract_findings,
    map_level_to_severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_findings():
    """A representative set of findings for filter/sort/search tests."""
    return [
        {
            "id": 1,
            "rule_id": "B101",
            "message": "Use of exec detected",
            "level": "error",
            "severity": "high",
            "scanner": "bandit",
            "file": "/src/app.py",
            "line": 10,
            "suppressed": False,
        },
        {
            "id": 2,
            "rule_id": "B102",
            "message": "Hardcoded password",
            "level": "warning",
            "severity": "medium",
            "scanner": "bandit",
            "file": "/src/config.py",
            "line": 25,
            "suppressed": False,
        },
        {
            "id": 3,
            "rule_id": "CVE-2023-001",
            "message": "Vulnerable dependency",
            "level": "error",
            "severity": "critical",
            "scanner": "trivy",
            "file": "/requirements.txt",
            "line": 3,
            "suppressed": True,
            "suppression_reason": "Accepted risk",
        },
        {
            "id": 4,
            "rule_id": "INFO-001",
            "message": "Informational note",
            "level": "note",
            "severity": "info",
            "scanner": "trivy",
            "file": "/Dockerfile",
            "line": 1,
            "suppressed": False,
        },
        {
            "id": 5,
            "rule_id": "LOW-001",
            "message": "Minor issue found",
            "level": "note",
            "severity": "low",
            "scanner": "cfn-nag",
            "file": "/template.yaml",
            "line": 42,
            "suppressed": False,
        },
    ]


@pytest.fixture
def app(sample_findings):
    """Create a FindingsExplorerApp without running it."""
    return FindingsExplorerApp(sample_findings)


@pytest.fixture
def empty_app():
    """App with no findings."""
    return FindingsExplorerApp([])


@pytest.fixture
def finding_detail():
    """A single finding dict for the detail screen."""
    return {
        "rule_id": "B101",
        "severity": "high",
        "scanner": "bandit",
        "file": "/src/app.py",
        "line": 10,
        "message": "Use of exec detected",
        "code_snippet": "exec(user_input)",
    }


# ---------------------------------------------------------------------------
# App initialization
# ---------------------------------------------------------------------------


class TestAppInitialization:
    def test_default_state(self, app, sample_findings):
        assert app.findings == sample_findings
        assert app.filtered_findings == sample_findings
        assert app.current_filter == "all"
        assert app.current_sort == "severity"
        assert app.show_filters is False
        assert app.search_mode is False
        assert app.search_query == ""
        assert app.sort_reverse is False
        assert app.show_suppressed is False

    def test_custom_title(self, sample_findings):
        custom = FindingsExplorerApp(sample_findings, title="Custom Title")
        assert custom.title == "Custom Title"

    def test_empty_findings(self, empty_app):
        assert empty_app.findings == []
        assert empty_app.filtered_findings == []

    def test_get_unique_scanners(self, app):
        scanners = app._get_unique_scanners()
        assert scanners == ["bandit", "cfn-nag", "trivy"]

    def test_get_unique_scanners_empty(self, empty_app):
        assert empty_app._get_unique_scanners() == []


# ---------------------------------------------------------------------------
# Filtering logic
# ---------------------------------------------------------------------------


class TestFiltering:
    def test_filter_all_no_suppressed(self, app):
        """Default: show_suppressed=False, current_filter='all'."""
        app._apply_filters()
        # Should exclude the one suppressed finding
        assert len(app.filtered_findings) == 4
        assert all(not f.get("suppressed") for f in app.filtered_findings)

    def test_filter_all_with_suppressed(self, app):
        app.show_suppressed = True
        app._apply_filters()
        assert len(app.filtered_findings) == 5

    def test_filter_by_severity(self, app):
        app.show_suppressed = True
        app.current_filter = "severity:high"
        app._apply_filters()
        assert all(f["severity"] == "high" for f in app.filtered_findings)
        assert len(app.filtered_findings) == 1

    def test_filter_by_severity_critical(self, app):
        app.show_suppressed = True
        app.current_filter = "severity:critical"
        app._apply_filters()
        assert len(app.filtered_findings) == 1
        assert app.filtered_findings[0]["rule_id"] == "CVE-2023-001"

    def test_filter_by_scanner(self, app):
        app.show_suppressed = True
        app.current_filter = "scanner:bandit"
        app._apply_filters()
        assert all(f["scanner"] == "bandit" for f in app.filtered_findings)
        assert len(app.filtered_findings) == 2

    def test_filter_suppressed_only(self, app):
        app.show_suppressed = True
        app.current_filter = "suppressed"
        app._apply_filters()
        assert all(f.get("suppressed") for f in app.filtered_findings)
        assert len(app.filtered_findings) == 1

    def test_filter_not_suppressed(self, app):
        app.show_suppressed = True
        app.current_filter = "not_suppressed"
        app._apply_filters()
        assert all(not f.get("suppressed") for f in app.filtered_findings)
        assert len(app.filtered_findings) == 4

    def test_filter_nonexistent_scanner(self, app):
        app.show_suppressed = True
        app.current_filter = "scanner:nonexistent"
        app._apply_filters()
        assert len(app.filtered_findings) == 0


# ---------------------------------------------------------------------------
# Sorting logic
# ---------------------------------------------------------------------------


class TestSorting:
    def test_sort_by_severity_default(self, app):
        app.show_suppressed = True
        app.filtered_findings = list(app.findings)
        app._apply_sorting()
        severities = [f["severity"] for f in app.filtered_findings]
        assert severities[0] == "critical"
        assert severities[-1] == "info"

    def test_sort_by_severity_reversed(self, app):
        app.show_suppressed = True
        app.filtered_findings = list(app.findings)
        app.sort_reverse = True
        app._apply_sorting()
        severities = [f["severity"] for f in app.filtered_findings]
        assert severities[-1] == "critical"
        assert severities[0] == "info"

    def test_sort_by_file(self, app):
        app.filtered_findings = list(app.findings)
        app.current_sort = "file"
        app._apply_sorting()
        files = [f["file"] for f in app.filtered_findings]
        assert files == sorted(files)

    def test_sort_by_scanner(self, app):
        app.filtered_findings = list(app.findings)
        app.current_sort = "scanner"
        app._apply_sorting()
        scanners = [f["scanner"] for f in app.filtered_findings]
        assert scanners == sorted(scanners)

    def test_sort_by_line(self, app):
        app.filtered_findings = list(app.findings)
        app.current_sort = "line"
        app._apply_sorting()
        lines = [int(f["line"]) for f in app.filtered_findings]
        assert lines == sorted(lines)

    def test_sort_by_message(self, app):
        app.filtered_findings = list(app.findings)
        app.current_sort = "message"
        app._apply_sorting()
        messages = [f["message"] for f in app.filtered_findings]
        assert messages == sorted(messages)

    def test_sort_by_rule_id(self, app):
        app.filtered_findings = list(app.findings)
        app.current_sort = "rule_id"
        app._apply_sorting()
        rule_ids = [f["rule_id"] for f in app.filtered_findings]
        assert rule_ids == sorted(rule_ids)

    def test_sort_with_missing_line(self):
        findings = [
            {"severity": "high", "line": None, "scanner": "x", "file": "a"},
            {"severity": "low", "line": "5", "scanner": "x", "file": "b"},
        ]
        test_app = FindingsExplorerApp(findings)
        test_app.filtered_findings = list(findings)
        test_app.current_sort = "line"
        test_app._apply_sorting()
        # Should not raise; None lines treated as 0
        assert True


# ---------------------------------------------------------------------------
# Search logic
# ---------------------------------------------------------------------------


class TestSearch:
    def test_search_empty_query(self, app):
        app.filtered_findings = list(app.findings)
        app.search_query = ""
        app._apply_search()
        assert len(app.filtered_findings) == 5

    def test_search_by_message(self, app):
        app.filtered_findings = list(app.findings)
        app.search_query = "exec"
        app._apply_search()
        assert len(app.filtered_findings) == 1
        assert app.filtered_findings[0]["rule_id"] == "B101"

    def test_search_by_rule_id(self, app):
        app.filtered_findings = list(app.findings)
        app.search_query = "cve"
        app._apply_search()
        assert len(app.filtered_findings) == 1
        assert app.filtered_findings[0]["rule_id"] == "CVE-2023-001"

    def test_search_by_file(self, app):
        app.filtered_findings = list(app.findings)
        app.search_query = "dockerfile"
        app._apply_search()
        assert len(app.filtered_findings) == 1

    def test_search_by_scanner(self, app):
        app.filtered_findings = list(app.findings)
        app.search_query = "cfn-nag"
        app._apply_search()
        assert len(app.filtered_findings) == 1

    def test_search_by_line_number(self, app):
        app.filtered_findings = list(app.findings)
        app.search_query = "42"
        app._apply_search()
        assert len(app.filtered_findings) == 1
        assert app.filtered_findings[0]["line"] == 42

    def test_search_case_insensitive(self, app):
        app.filtered_findings = list(app.findings)
        app.search_query = "HARDCODED"
        app._apply_search()
        assert len(app.filtered_findings) == 1
        assert app.filtered_findings[0]["rule_id"] == "B102"

    def test_search_no_results(self, app):
        app.filtered_findings = list(app.findings)
        app.search_query = "zzzznonexistent"
        app._apply_search()
        assert len(app.filtered_findings) == 0


# ---------------------------------------------------------------------------
# Action handlers (mocked Textual widgets)
# ---------------------------------------------------------------------------


class TestActionHandlers:
    def test_toggle_suppressed(self, app):
        """action_toggle_suppressed flips the flag and attempts UI update."""
        assert app.show_suppressed is False

        # Mock query_one so _populate_table doesn't fail on missing widgets
        app.query_one = MagicMock(side_effect=Exception("no widget"))
        app._populate_table = MagicMock()

        app.action_toggle_suppressed()
        assert app.show_suppressed is True
        app._populate_table.assert_called_once()

    def test_toggle_suppressed_twice(self, app):
        app.query_one = MagicMock(side_effect=Exception("no widget"))
        app._populate_table = MagicMock()

        app.action_toggle_suppressed()
        app.action_toggle_suppressed()
        assert app.show_suppressed is False

    def test_toggle_filters(self, app):
        mock_filters = MagicMock()
        mock_status = MagicMock()

        def query_side_effect(selector, *args, **kwargs):
            if selector == "#filters_container":
                return mock_filters
            if selector == "#status_bar":
                return mock_status
            raise Exception("unexpected")  # nosec B110

        app.query_one = query_side_effect
        app._populate_table = MagicMock()

        # First toggle: show
        app.action_toggle_filters()
        assert app.show_filters is True
        mock_filters.add_class.assert_called_with("filters-visible")

    def test_toggle_filters_hide(self, app):
        mock_filters = MagicMock()
        app.show_filters = True
        app._populate_table = MagicMock()

        def query_side_effect(selector, *args, **kwargs):
            if selector == "#filters_container":
                return mock_filters
            raise MagicMock()

        app.query_one = query_side_effect

        app.action_toggle_filters()
        assert app.show_filters is False
        mock_filters.remove_class.assert_called_with("filters-visible")

    def test_toggle_search_on(self, app):
        mock_container = MagicMock()
        mock_input = MagicMock()
        mock_status = MagicMock()

        def query_side_effect(selector, *args):
            if selector == "#search_container":
                return mock_container
            if selector == "#search_input":
                return mock_input
            if selector == "#status_bar":
                return mock_status
            raise Exception("unexpected")  # nosec B110

        app.query_one = query_side_effect

        app.action_toggle_search()
        assert app.search_mode is True
        mock_container.add_class.assert_called_with("search-bar-visible")
        mock_input.focus.assert_called_once()

    def test_toggle_search_off(self, app):
        app.search_mode = True
        app.search_query = "something"
        mock_container = MagicMock()
        mock_table = MagicMock()

        def query_side_effect(selector, *args):
            if selector == "#search_container":
                return mock_container
            if "#findings_table" in str(selector):
                return mock_table
            return MagicMock()

        app.query_one = query_side_effect
        app._populate_table = MagicMock()

        app.action_toggle_search()
        assert app.search_mode is False
        assert app.search_query == ""
        app._populate_table.assert_called_once()

    def test_exit_search_when_active(self, app):
        app.search_mode = True
        app.search_query = "test"
        mock_container = MagicMock()
        mock_table = MagicMock()

        def query_side_effect(selector, *args):
            if selector == "#search_container":
                return mock_container
            if "#findings_table" in str(selector):
                return mock_table
            return MagicMock()

        app.query_one = query_side_effect
        app._populate_table = MagicMock()

        app.action_exit_search()
        assert app.search_mode is False
        assert app.search_query == ""

    def test_exit_search_when_inactive(self, app):
        """exit_search is a no-op when not in search mode."""
        app.search_mode = False
        app.action_exit_search()
        assert app.search_mode is False


# ---------------------------------------------------------------------------
# on_select_changed handler
# ---------------------------------------------------------------------------


class TestSelectChanged:
    def _make_event(self, select_id, value):
        event = MagicMock()
        event.select = MagicMock()
        event.select.id = select_id
        event.value = value
        return event

    def test_severity_select(self, app):
        app._populate_table = MagicMock()
        event = self._make_event("severity_select", "severity:high")
        app.on_select_changed(event)
        assert app.current_filter == "severity:high"
        app._populate_table.assert_called_once()

    def test_scanner_select(self, app):
        app._populate_table = MagicMock()
        event = self._make_event("scanner_select", "scanner:trivy")
        app.on_select_changed(event)
        assert app.current_filter == "scanner:trivy"
        app._populate_table.assert_called_once()

    def test_suppressed_select_all(self, app):
        app._populate_table = MagicMock()
        event = self._make_event("suppressed_select", "all")
        app.on_select_changed(event)
        assert app.show_suppressed is True

    def test_suppressed_select_not_suppressed(self, app):
        app.show_suppressed = True
        app._populate_table = MagicMock()
        event = self._make_event("suppressed_select", "not_suppressed")
        app.on_select_changed(event)
        assert app.show_suppressed is False

    def test_suppressed_select_suppressed_only(self, app):
        app._populate_table = MagicMock()
        event = self._make_event("suppressed_select", "suppressed")
        app.on_select_changed(event)
        assert app.show_suppressed is True
        assert app.current_filter == "suppressed"


# ---------------------------------------------------------------------------
# Header sort handler
# ---------------------------------------------------------------------------


class TestHeaderSort:
    def _make_header_event(self, label):
        event = MagicMock()
        event.label = label
        return event

    def test_sort_by_column(self, app):
        app._populate_table = MagicMock()
        event = self._make_header_event("File")
        app.on_data_table_header_selected(event)
        assert app.current_sort == "file"
        assert app.sort_reverse is False

    def test_sort_same_column_toggles_direction(self, app):
        app._populate_table = MagicMock()
        app.sort_column = "Severity"
        event = self._make_header_event("Severity")
        app.on_data_table_header_selected(event)
        assert app.sort_reverse is True

    def test_sort_unknown_column_defaults_to_severity(self, app):
        app._populate_table = MagicMock()
        event = self._make_header_event("UnknownCol")
        app.on_data_table_header_selected(event)
        assert app.current_sort == "severity"


# ---------------------------------------------------------------------------
# FindingDetailScreen
# ---------------------------------------------------------------------------


class TestFindingDetailScreen:
    def test_init_stores_finding(self, finding_detail):
        screen = FindingDetailScreen(finding_detail)
        assert screen.finding == finding_detail

    def test_bindings_include_escape(self, finding_detail):
        screen = FindingDetailScreen(finding_detail)
        binding_keys = [b.key for b in screen.BINDINGS]
        assert "escape" in binding_keys
        assert "q" in binding_keys

    def test_file_extension_yml_normalized(self):
        finding = {
            "rule_id": "R1",
            "severity": "low",
            "scanner": "test",
            "file": "/path/to/config.yml",
            "line": 1,
            "message": "test",
        }
        screen = FindingDetailScreen(finding)
        # Compose would use file_ext = "yaml" for .yml files
        # We verify the logic by checking the path suffix handling
        snippet_path = Path(finding["file"])
        file_ext = snippet_path.suffix.lstrip(".")
        if file_ext == "yml":
            file_ext = "yaml"
        assert file_ext == "yaml"

    def test_file_no_extension_uses_name(self):
        finding = {
            "rule_id": "R1",
            "severity": "low",
            "scanner": "test",
            "file": "Dockerfile",
            "line": 1,
            "message": "test",
        }
        screen = FindingDetailScreen(finding)
        snippet_path = Path(finding["file"])
        file_ext = (
            snippet_path.suffix.lstrip(".")
            if snippet_path.suffix != ""
            else snippet_path.name
            if finding["file"]
            else None
        )
        assert file_ext == "Dockerfile"


# ---------------------------------------------------------------------------
# map_level_to_severity
# ---------------------------------------------------------------------------


class TestMapLevelToSeverity:
    def test_error_maps_to_high(self):
        assert map_level_to_severity("error") == "high"

    def test_warning_maps_to_medium(self):
        assert map_level_to_severity("warning") == "medium"

    def test_note_maps_to_low(self):
        assert map_level_to_severity("note") == "low"

    def test_unknown_maps_to_info(self):
        assert map_level_to_severity("unknown") == "info"

    def test_none_maps_to_info(self):
        assert map_level_to_severity(None) == "info"


# ---------------------------------------------------------------------------
# extract_findings
# ---------------------------------------------------------------------------


class TestExtractFindings:
    def test_empty_model(self):
        model = MagicMock()
        model.sarif = None
        result = extract_findings(model)
        assert result == []

    def test_no_runs(self):
        model = MagicMock()
        model.sarif = MagicMock()
        model.sarif.runs = []
        result = extract_findings(model)
        assert result == []

    def test_run_with_no_results(self):
        model = MagicMock()
        run = MagicMock()
        run.results = None
        model.sarif = MagicMock()
        model.sarif.runs = [run]
        result = extract_findings(model)
        assert result == []

    def test_basic_finding_extraction(self):
        model = MagicMock()
        run = MagicMock()

        # Build a mock result
        result_obj = MagicMock()
        result_obj.ruleIndex = 1
        result_obj.ruleId = "B101"
        result_obj.message.root.text = "Use of exec"
        result_obj.message.root = MagicMock(text="Use of exec")
        result_obj.level = "error"
        result_obj.kind = "fail"
        result_obj.properties.model_dump.return_value = {
            "scanner_details": {"tool_name": "bandit"}
        }
        result_obj.suppressions = None
        result_obj.locations = []
        result_obj.codeFlows = []

        run.results = [result_obj]
        model.sarif = MagicMock()
        model.sarif.runs = [run]

        findings = extract_findings(model)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "B101"
        assert findings[0]["severity"] == "high"
        assert findings[0]["scanner"] == "bandit"
        assert findings[0]["message"] == "Use of exec"

    def test_finding_with_location(self):
        model = MagicMock()
        run = MagicMock()

        result_obj = MagicMock()
        result_obj.ruleIndex = 0
        result_obj.ruleId = "R1"
        result_obj.message.root = MagicMock(text="msg")
        result_obj.level = "warning"
        result_obj.kind = "fail"
        result_obj.properties.model_dump.return_value = {
            "scanner_details": {"tool_name": "scanner1"}
        }
        result_obj.suppressions = None

        # Location mock
        location = MagicMock()
        physical = MagicMock()
        physical.root.artifactLocation.uri = "/src/file.py"
        physical.root.region.startLine = 15
        physical.root.region.startColumn = 4
        physical.root.region.snippet = None
        location.physicalLocation = physical
        result_obj.locations = [location]
        result_obj.codeFlows = []

        run.results = [result_obj]
        model.sarif = MagicMock()
        model.sarif.runs = [run]

        findings = extract_findings(model)
        assert findings[0]["file"] == "/src/file.py"
        assert findings[0]["line"] == 15
        assert findings[0]["column"] == 4

    def test_finding_with_suppression(self):
        model = MagicMock()
        run = MagicMock()

        result_obj = MagicMock()
        result_obj.ruleIndex = 0
        result_obj.ruleId = "R2"
        result_obj.message.root = MagicMock(text="suppressed finding")
        result_obj.level = "error"
        result_obj.kind = "fail"
        result_obj.properties.model_dump.return_value = {
            "scanner_details": {"tool_name": "s1"}
        }

        # Suppression
        suppression = MagicMock()
        suppression.justification = "Risk accepted"
        result_obj.suppressions = [suppression]
        result_obj.locations = []
        result_obj.codeFlows = []

        run.results = [result_obj]
        model.sarif = MagicMock()
        model.sarif.runs = [run]

        findings = extract_findings(model)
        assert findings[0]["suppressed"] is True
        assert findings[0]["suppression_reason"] == "Risk accepted"

    def test_finding_with_code_snippet_in_region(self):
        model = MagicMock()
        run = MagicMock()

        result_obj = MagicMock()
        result_obj.ruleIndex = 0
        result_obj.ruleId = "R3"
        result_obj.message.root = MagicMock(text="has snippet")
        result_obj.level = "note"
        result_obj.kind = "fail"
        result_obj.properties.model_dump.return_value = {
            "scanner_details": {"tool_name": "s2"}
        }
        result_obj.suppressions = None

        # Location with snippet
        location = MagicMock()
        physical = MagicMock()
        physical.root.artifactLocation.uri = "/a.py"
        physical.root.region.startLine = 5
        physical.root.region.startColumn = 1
        snippet_mock = MagicMock()
        snippet_mock.text = "exec(input())"
        physical.root.region.snippet = snippet_mock
        location.physicalLocation = physical
        result_obj.locations = [location]
        result_obj.codeFlows = []

        run.results = [result_obj]
        model.sarif = MagicMock()
        model.sarif.runs = [run]

        findings = extract_findings(model)
        assert findings[0]["code_snippet"] == "exec(input())"


# ---------------------------------------------------------------------------
# findings_command error path
# ---------------------------------------------------------------------------


class TestFindingsCommand:
    @patch("automated_security_helper.cli.inspect.inspect_findings_app.AshAggregatedResults")
    @patch("typer.secho")
    def test_command_handles_load_error(self, mock_secho, mock_model_cls):
        from automated_security_helper.cli.inspect.inspect_findings_app import findings_command

        mock_model_cls.load_model.side_effect = FileNotFoundError("not found")

        # Call through typer callback simulation
        findings_command(output_dir=Path("/nonexistent"), report_file="report.json")
        mock_secho.assert_called_once()
        call_args = mock_secho.call_args
        assert "Error loading model or report" in call_args[0][0]

    @patch("automated_security_helper.cli.inspect.inspect_findings_app.AshAggregatedResults")
    @patch("typer.echo")
    def test_command_handles_none_model(self, mock_echo, mock_model_cls):
        from automated_security_helper.cli.inspect.inspect_findings_app import findings_command

        mock_model_cls.load_model.return_value = None

        findings_command(output_dir=Path("/tmp"), report_file="report.json")
        mock_echo.assert_called_once()
        assert "No model" in mock_echo.call_args[0][0]

    @patch("automated_security_helper.cli.inspect.inspect_findings_app.AshAggregatedResults")
    @patch("automated_security_helper.cli.inspect.inspect_findings_app.extract_findings")
    @patch("typer.echo")
    def test_command_handles_no_findings(self, mock_echo, mock_extract, mock_model_cls):
        from automated_security_helper.cli.inspect.inspect_findings_app import findings_command

        mock_model_cls.load_model.return_value = MagicMock()
        mock_extract.return_value = []

        findings_command(output_dir=Path("/tmp"), report_file="report.json")
        mock_echo.assert_called_once()
        assert "No findings" in mock_echo.call_args[0][0]


# ---------------------------------------------------------------------------
# Code snippet extraction in action_view_selected
# ---------------------------------------------------------------------------


class TestCodeSnippetExtraction:
    def test_view_selected_extracts_snippet_from_file(self, app, tmp_path):
        """action_view_selected reads surrounding lines from the file."""
        # Create a temporary source file
        src_file = tmp_path / "code.py"
        lines = [f"line {i}\n" for i in range(1, 20)]
        src_file.write_text("".join(lines))

        # Set up a finding pointing at that file, line 10
        finding = {
            "rule_id": "TEST",
            "severity": "high",
            "scanner": "test",
            "file": str(src_file),
            "line": 10,
            "message": "test issue",
        }
        app.findings = [finding]
        app.filtered_findings = [finding]

        # Mock the Textual widgets
        mock_table = MagicMock()
        mock_table.row_count = 1
        mock_table.cursor_row = 0

        app.query_one = MagicMock(return_value=mock_table)
        app.push_screen = MagicMock()

        app.action_view_selected()

        # The finding should now have a code_snippet
        assert finding.get("code_snippet") is not None
        assert "line 10" in finding["code_snippet"]
        # The arrow marker should point to line 10
        assert "→ " in finding["code_snippet"]
        app.push_screen.assert_called_once()

    def test_view_selected_missing_file(self, app):
        """action_view_selected gracefully handles missing files."""
        finding = {
            "rule_id": "TEST",
            "severity": "high",
            "scanner": "test",
            "file": "/nonexistent/path/file.py",
            "line": 5,
            "message": "test",
        }
        app.findings = [finding]
        app.filtered_findings = [finding]

        mock_table = MagicMock()
        mock_table.row_count = 1
        mock_table.cursor_row = 0

        app.query_one = MagicMock(return_value=mock_table)
        app.push_screen = MagicMock()

        # Should not raise
        app.action_view_selected()
        # No snippet extracted for missing file
        assert finding.get("code_snippet") is None
        app.push_screen.assert_called_once()

    def test_view_selected_no_rows(self, app):
        """action_view_selected is a no-op if no rows."""
        mock_table = MagicMock()
        mock_table.row_count = 0

        app.query_one = MagicMock(return_value=mock_table)
        app.push_screen = MagicMock()

        app.action_view_selected()
        app.push_screen.assert_not_called()

    def test_view_selected_cursor_none(self, app):
        """action_view_selected is a no-op if cursor is None."""
        mock_table = MagicMock()
        mock_table.row_count = 1
        mock_table.cursor_row = None

        app.query_one = MagicMock(return_value=mock_table)
        app.push_screen = MagicMock()

        app.action_view_selected()
        app.push_screen.assert_not_called()


# ---------------------------------------------------------------------------
# on_input_changed
# ---------------------------------------------------------------------------


class TestInputChanged:
    def test_search_input_updates_query(self, app):
        app._populate_table = MagicMock()
        event = MagicMock()
        event.input = MagicMock()
        event.input.id = "search_input"
        event.value = "test query"

        app.on_input_changed(event)
        assert app.search_query == "test query"
        app._populate_table.assert_called_once()

    def test_other_input_ignored(self, app):
        app._populate_table = MagicMock()
        event = MagicMock()
        event.input = MagicMock()
        event.input.id = "other_input"
        event.value = "ignored"

        app.on_input_changed(event)
        assert app.search_query == ""
        app._populate_table.assert_not_called()
