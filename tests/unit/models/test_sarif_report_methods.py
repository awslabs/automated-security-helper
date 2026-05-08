"""Tests for self-contained methods on the SarifReport model."""

from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    PhysicalLocation,
    PhysicalLocation2,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
    Message,
)


def _make_run(driver_name: str, result_uris: list[str] | None = None) -> Run:
    """Build a minimal Run with a tool driver and optional result URIs."""
    results = None
    if result_uris is not None:
        results = []
        for uri in result_uris:
            results.append(
                Result(
                    message=Message(text="finding"),
                    locations=[
                        Location(
                            physicalLocation=PhysicalLocation(
                                root=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(uri=uri),
                                )
                            )
                        )
                    ],
                )
            )
    return Run(
        tool=Tool(driver=ToolComponent(name=driver_name)),
        results=results,
    )


def _make_report(*runs: Run) -> SarifReport:
    return SarifReport(runs=list(runs))


# ---------------------------------------------------------------------------
# get_all_results()
# ---------------------------------------------------------------------------


class TestGetAllResults:
    def test_empty_report_returns_empty_list(self):
        report = SarifReport()
        # Explicitly clear runs to simulate the "no runs" case
        report.runs = []
        assert report.get_all_results() == []

    def test_runs_none_returns_empty_list(self):
        report = SarifReport()
        report.runs = None  # type: ignore[assignment]
        assert report.get_all_results() == []

    def test_single_run_with_three_results(self):
        report = _make_report(
            _make_run("bandit", ["a.py", "b.py", "c.py"]),
        )
        results = report.get_all_results()
        assert len(results) == 3

    def test_multiple_runs_concatenated(self):
        report = _make_report(
            _make_run("bandit", ["a.py", "b.py"]),
            _make_run("semgrep", ["c.py"]),
            _make_run("checkov", ["d.py", "e.py", "f.py"]),
        )
        results = report.get_all_results()
        assert len(results) == 6

    def test_run_with_results_none_is_skipped(self):
        report = _make_report(
            _make_run("bandit", ["a.py"]),
            _make_run("semgrep", None),
            _make_run("checkov", ["c.py"]),
        )
        results = report.get_all_results()
        assert len(results) == 2


# ---------------------------------------------------------------------------
# get_scanner_names()
# ---------------------------------------------------------------------------


class TestGetScannerNames:
    def test_single_run_returns_single_name(self):
        report = _make_report(_make_run("bandit", []))
        assert report.get_scanner_names() == ["bandit"]

    def test_multiple_runs_returns_sorted_unique(self):
        report = _make_report(
            _make_run("semgrep", []),
            _make_run("bandit", []),
            _make_run("checkov", []),
            _make_run("bandit", []),  # duplicate
        )
        assert report.get_scanner_names() == ["bandit", "checkov", "semgrep"]

    def test_empty_report_returns_empty(self):
        report = SarifReport()
        report.runs = []
        assert report.get_scanner_names() == []

    def test_runs_none_returns_empty(self):
        report = SarifReport()
        report.runs = None  # type: ignore[assignment]
        assert report.get_scanner_names() == []


# ---------------------------------------------------------------------------
# filter_results_by_files()
# ---------------------------------------------------------------------------


class TestFilterResultsByFiles:
    def test_keeps_results_with_matching_paths(self):
        report = _make_report(
            _make_run("bandit", ["src/keep.py", "src/drop.py"]),
        )
        report.filter_results_by_files({"src/keep.py"}, source_dir="/tmp/src")
        kept = report.get_all_results()
        assert len(kept) == 1
        uri = kept[0].locations[0].physicalLocation.root.artifactLocation.uri
        assert uri == "src/keep.py"

    def test_removes_results_with_non_matching_paths(self):
        report = _make_report(
            _make_run("bandit", ["src/a.py", "src/b.py"]),
        )
        report.filter_results_by_files(set(), source_dir="/tmp/src")
        assert report.get_all_results() == []

    def test_handles_file_uri_prefix(self):
        report = _make_report(
            _make_run("bandit", ["file:///tmp/src/src/keep.py"]),
        )
        report.filter_results_by_files({"src/keep.py"}, source_dir="/tmp/src")
        kept = report.get_all_results()
        assert len(kept) == 1

    def test_handles_absolute_paths_relative_to_source_dir(self):
        report = _make_report(
            _make_run("bandit", ["/tmp/src/src/keep.py", "/tmp/src/src/drop.py"]),
        )
        report.filter_results_by_files({"src/keep.py"}, source_dir="/tmp/src")
        kept = report.get_all_results()
        assert len(kept) == 1
        uri = kept[0].locations[0].physicalLocation.root.artifactLocation.uri
        assert uri == "/tmp/src/src/keep.py"

    def test_result_with_no_locations_is_kept(self):
        """Results without locations cannot be filtered — keep them."""
        run = Run(
            tool=Tool(driver=ToolComponent(name="bandit")),
            results=[Result(message=Message(text="no-loc"))],
        )
        report = _make_report(run)
        report.filter_results_by_files({"anything.py"}, source_dir="/tmp/src")
        assert len(report.get_all_results()) == 1

    def test_empty_report_is_noop(self):
        report = SarifReport()
        report.runs = []
        report.filter_results_by_files({"a.py"}, source_dir="/tmp/src")
        assert report.runs == []

    def test_runs_none_is_noop(self):
        report = SarifReport()
        report.runs = None  # type: ignore[assignment]
        # Must not raise
        report.filter_results_by_files({"a.py"}, source_dir="/tmp/src")
