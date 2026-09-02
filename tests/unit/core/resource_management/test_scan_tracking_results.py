#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for scan_tracking's file-reading and result-assembly paths.

scan_tracking derives scan state from what is on disk rather than from events,
so its untested surface was mostly the disk shapes that are not the happy one:
a scanner directory holding a stray file, an aggregated results file that is
half-written, a results document whose scanner_results is the wrong type.

Every fixture here is a real file under tmp_path. These functions branch on
Path.exists(), Path.is_dir() and json.loads, so a mocked filesystem would be
testing the mock; and each function also has a "caller passed None" branch that
resolves against the process working directory, which only monkeypatch.chdir can
exercise honestly.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    create_scan_progress_from_files,
    find_scanner_result_files,
    get_scan_progress_info,
    get_scan_results,
    get_scan_results_with_error_handling,
    get_scanner_progress,
    parse_aggregated_results,
    parse_scanner_result_file,
    resolve_output_directory,
    summarize_scanner_statuses,
    validate_output_directory,
)
from automated_security_helper.utils.log import ASHLogger

_MODULE = "automated_security_helper.core.resource_management.scan_tracking"
_RESULTS_FILE = "ash_aggregated_results.json"


def _aggregated_doc(**extra):
    """A results document that AshAggregatedResults accepts."""
    doc = {
        "scanner_results": {
            "bandit": {
                "status": "PASSED",
                "finding_count": 2,
                "severity_counts": {
                    "critical": 0,
                    "high": 1,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                    "suppressed": 0,
                },
            }
        }
    }
    doc.update(extra)
    return doc


def _write_results(output_dir: Path, doc) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / _RESULTS_FILE
    path.write_text(json.dumps(doc) if not isinstance(doc, str) else doc)
    return path


def _write_scanner_result(output_dir: Path, scanner: str, target: str, doc) -> Path:
    target_dir = output_dir / "scanners" / scanner / target
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / "ASH.ScanResults.json"
    path.write_text(json.dumps(doc))
    return path


class TestFindScannerResultFiles:
    def test_stray_files_beside_scanner_directories_are_ignored(self, tmp_path):
        """Only directories are walked, at both the scanner and target levels."""
        out = tmp_path / "ash_output"
        _write_scanner_result(out, "bandit", "source", {"scanner_name": "bandit"})
        (out / "scanners" / "README.txt").write_text("not a scanner")
        (out / "scanners" / "bandit" / "notes.txt").write_text("not a target")

        found = find_scanner_result_files(out)

        assert set(found) == {"bandit"}
        assert set(found["bandit"]) == {"source"}

    def test_a_target_directory_without_a_result_file_is_omitted(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_scanner_result(out, "bandit", "source", {"scanner_name": "bandit"})
        (out / "scanners" / "bandit" / "converted").mkdir()

        found = find_scanner_result_files(out)

        assert set(found["bandit"]) == {"source"}

    def test_a_missing_scanners_directory_yields_nothing(self, tmp_path):
        assert find_scanner_result_files(tmp_path / "ash_output") == {}


class TestGetScannerProgress:
    def test_an_unparseable_result_file_is_warned_about_and_skipped(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_scanner_result(out, "bandit", "source", {"scanner_name": "bandit"})

        with (
            patch(
                f"{_MODULE}.parse_scanner_result_file",
                side_effect=ValueError("truncated file"),
            ),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            progress = get_scanner_progress(out)

        assert progress["bandit"]["findings"] == []
        assert progress["bandit"]["targets_completed"] == ["source"]
        warning = logger.warning.call_args[0][0]
        assert (
            "Failed to parse result file for scanner bandit, target source" in warning
        )
        assert "truncated file" in warning

    def test_findings_from_each_target_are_accumulated(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_scanner_result(out, "bandit", "source", {"findings": [{"id": "a"}]})
        _write_scanner_result(out, "bandit", "converted", {"findings": [{"id": "b"}]})

        progress = get_scanner_progress(out)

        assert progress["bandit"]["targets_count"] == 2
        assert sorted(f["id"] for f in progress["bandit"]["findings"]) == ["a", "b"]


class TestParseScannerResultFile:
    def test_defaults_to_the_aggregated_results_file_under_cwd(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        with patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger:
            assert parse_scanner_result_file(None) == []

        expected = tmp_path / ".ash" / "ash_output" / _RESULTS_FILE
        assert str(expected) in logger.warning.call_args[0][0]

    def test_a_metadata_only_file_yields_no_findings(self, tmp_path):
        path = tmp_path / "ASH.ScanResults.json"
        path.write_text(json.dumps({"scanner_name": "bandit", "status": "PASSED"}))

        assert parse_scanner_result_file(path) == []

    def test_an_unrecognized_structure_is_warned_about(self, tmp_path):
        path = tmp_path / "ASH.ScanResults.json"
        path.write_text(json.dumps({"something": "else"}))

        with patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger:
            assert parse_scanner_result_file(path) == []

        assert "Unexpected result file structure" in logger.warning.call_args[0][0]


class TestSummarizeScannerStatuses:
    def test_a_missing_results_file_yields_empty_collections(self, tmp_path):
        assert summarize_scanner_statuses(tmp_path) == {
            "scanner_statuses": {},
            "skipped_scanners": [],
        }

    def test_a_half_written_file_yields_empty_collections(self, tmp_path):
        _write_results(tmp_path, '{"scanner_results": {"bandit"')

        assert summarize_scanner_statuses(tmp_path)["scanner_statuses"] == {}

    def test_a_document_that_is_not_an_object_yields_empty_collections(self, tmp_path):
        _write_results(tmp_path, ["not", "an", "object"])

        assert summarize_scanner_statuses(tmp_path) == {
            "scanner_statuses": {},
            "skipped_scanners": [],
        }

    def test_scanner_results_of_the_wrong_type_yields_empty_collections(self, tmp_path):
        _write_results(tmp_path, {"scanner_results": ["bandit", "semgrep"]})

        assert summarize_scanner_statuses(tmp_path) == {
            "scanner_statuses": {},
            "skipped_scanners": [],
        }

    @pytest.mark.parametrize(
        "info, expected_reason",
        [
            (
                {"status": "MISSING", "dependencies_satisfied": False},
                "missing_dependencies",
            ),
            (
                {"status": "SKIPPED", "dependencies_satisfied": True, "excluded": True},
                "excluded_by_configuration",
            ),
            (
                {
                    "status": "SKIPPED",
                    "dependencies_satisfied": True,
                    "excluded": False,
                },
                "skipped",
            ),
        ],
    )
    def test_each_skip_reason_is_reported_distinctly(
        self, tmp_path, info, expected_reason
    ):
        """The reason is the whole point: a missing tool is not a config exclusion."""
        _write_results(tmp_path, {"scanner_results": {"grype": info}})

        summary = summarize_scanner_statuses(tmp_path)

        assert summary["skipped_scanners"] == [
            {
                "scanner": "grype",
                "status": info["status"],
                "reason": expected_reason,
            }
        ]

    def test_a_scanner_that_ran_is_not_reported_as_skipped(self, tmp_path):
        _write_results(
            tmp_path,
            {"scanner_results": {"bandit": {"status": "FAILED"}}},
        )

        summary = summarize_scanner_statuses(tmp_path)

        assert summary["skipped_scanners"] == []
        assert summary["scanner_statuses"]["bandit"]["status"] == "FAILED"


class TestParseAggregatedResults:
    def test_defaults_to_the_ash_output_directory_under_cwd(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        with pytest.raises(MCPResourceError) as excinfo:
            parse_aggregated_results(None)

        expected = tmp_path / ".ash" / "ash_output" / _RESULTS_FILE
        assert str(expected) in str(excinfo.value)
        assert excinfo.value.context["error_category"] == "file_not_found"

    def test_a_malformed_file_propagates_the_format_error_with_the_output_dir(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_results(out, "{ not json")

        with pytest.raises(MCPResourceError) as excinfo:
            parse_aggregated_results(out)

        assert excinfo.value.context["error_category"] == "invalid_format"
        assert excinfo.value.context["output_dir"] == str(out)


class TestCreateScanProgressFromFiles:
    def test_defaults_to_the_ash_output_directory_under_cwd(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        progress = create_scan_progress_from_files("scan-1", None)

        assert progress.scan_id == "scan-1"
        assert progress.status == "in_progress"
        assert progress.total_scanners == 0

    def test_sarif_results_become_findings_attributed_to_their_tool(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_results(
            out,
            {
                "sarif": {
                    "runs": [
                        {
                            "tool": {"driver": {"name": "bandit"}},
                            "results": [
                                {"ruleId": "B105", "level": "error"},
                                {"ruleId": "B303", "level": "warning"},
                            ],
                        }
                    ]
                },
                # No severity_counts, so the findings drive the counts.
                "scanner_results": {"bandit": {"status": "PASSED"}},
            },
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.status == "completed"
        assert progress.total_scanners == 1
        source = progress.scanners["bandit"]["source"]
        assert source.finding_count == 2
        assert progress.total_findings == 2
        # SARIF "level" values (error/warning/note) are carried through as the
        # finding severity, but extract_findings_summary only counts
        # critical/high/medium/low/info/suppressed. So a SARIF-derived finding
        # counts toward finding_count and toward nothing in severity_counts.
        # Pinned as current behavior, not endorsed as correct.
        assert set(source.severity_counts) == {
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "suppressed",
        }
        assert sum(source.severity_counts.values()) == 0

    def test_severity_counts_on_the_scanner_take_precedence_over_findings(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_results(out, _aggregated_doc())

        progress = create_scan_progress_from_files("scan-1", out)

        source = progress.scanners["bandit"]["source"]
        assert source.severity_counts["high"] == 1
        assert source.severity_counts["medium"] == 1
        assert source.finding_count == 2

    def test_scanner_severity_counts_are_used_when_sarif_is_absent(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_results(out, _aggregated_doc())

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.severity_counts["high"] == 1
        assert progress.status == "completed"

    def test_a_malformed_aggregated_file_marks_the_scan_failed(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_results(out, "{ not json")

        with patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger:
            progress = create_scan_progress_from_files("scan-1", out)

        assert progress.status == "failed"
        assert "Error parsing aggregated results" in logger.error.call_args[0][0]

    def test_an_incomplete_scan_reads_the_per_scanner_files(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_scanner_result(
            out, "bandit", "source", {"findings": [{"severity": "HIGH"}]}
        )

        progress = create_scan_progress_from_files("scan-1", out)

        assert progress.status == "in_progress"
        assert progress.scanners["bandit"]["source"].finding_count == 1
        assert progress.severity_counts["high"] == 1

    def test_a_per_scanner_file_that_cannot_be_parsed_is_warned_about_and_skipped(
        self, tmp_path
    ):
        out = tmp_path / "ash_output"
        _write_scanner_result(out, "bandit", "source", {"findings": []})

        with (
            patch(
                f"{_MODULE}.parse_scanner_result_file",
                side_effect=ValueError("truncated file"),
            ),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            progress = create_scan_progress_from_files("scan-1", out)

        assert progress.total_scanners == 0
        warning = logger.warning.call_args[0][0]
        assert "Error parsing result file for scanner bandit, target source" in warning


class TestGetScanProgressInfo:
    def test_defaults_to_the_ash_output_directory_under_cwd(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        info = get_scan_progress_info(None)

        assert info["status"] == "in_progress"
        assert info["is_complete"] is False
        assert info["scanners_completed"] == []

    def test_completed_scan_reports_sarif_findings_and_scanner_names(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_results(
            out,
            {
                "sarif": {
                    "runs": [
                        {"results": [{"ruleId": "B105", "severity": "HIGH"}]},
                        {"results": [{"ruleId": "B303", "severity": "LOW"}]},
                    ]
                },
                "scanner_results": {"bandit": {"status": "PASSED"}},
            },
        )

        info = get_scan_progress_info(out)

        assert info["status"] == "completed"
        assert info["findings_count"] == 2
        assert info["scanners_completed"] == ["bandit"]
        # No metadata.summary_stats, so the summary is derived from the findings.
        assert info["findings_summary"]["high"] == 1
        assert info["findings_summary"]["low"] == 1

    def test_summary_stats_in_metadata_are_used_verbatim(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_results(
            out,
            {
                "metadata": {
                    "summary_stats": {"critical": 7},
                    "generated_at": "2024-05-05T00:00:00",
                },
                "scanner_results": {"bandit": {"status": "PASSED"}},
            },
        )

        info = get_scan_progress_info(out)

        assert info["findings_summary"] == {"critical": 7}
        assert info["completion_time"] == "2024-05-05T00:00:00"

    def test_a_malformed_aggregated_file_is_reported_as_an_error_status(self, tmp_path):
        out = tmp_path / "ash_output"
        _write_results(out, "{ not json")

        info = get_scan_progress_info(out)

        assert info["status"] == "error"
        assert info["is_complete"] is True
        assert info["context"]["error_category"] == "invalid_format"


class TestValidateOutputDirectory:
    def test_a_missing_directory_is_invalid(self, tmp_path):
        is_valid, error = validate_output_directory(tmp_path / "absent")

        assert is_valid is False
        assert "Directory not found" in error

    def test_a_directory_with_neither_scanners_nor_results_is_invalid(self, tmp_path):
        is_valid, error = validate_output_directory(tmp_path)

        assert is_valid is False
        assert "missing 'scanners' directory and no aggregated results" in error

    def test_a_directory_with_only_aggregated_results_is_valid(self, tmp_path):
        _write_results(tmp_path, _aggregated_doc())

        assert validate_output_directory(tmp_path) == (True, None)

    def test_a_directory_with_only_a_scanners_tree_is_valid(self, tmp_path):
        (tmp_path / "scanners").mkdir()

        assert validate_output_directory(tmp_path) == (True, None)


class TestGetScanResults:
    def test_defaults_to_the_ash_output_directory_under_cwd(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        with pytest.raises(MCPResourceError) as excinfo:
            get_scan_results(None)

        assert "Directory not found" in str(excinfo.value)

    def test_an_incomplete_scan_raises_with_the_incomplete_category(self, tmp_path):
        with pytest.raises(MCPResourceError) as excinfo:
            get_scan_results(tmp_path)

        assert excinfo.value.context["error_category"] == "scan_incomplete"
        assert "Wait for the scan to complete" in excinfo.value.context["suggestions"]

    def test_a_completed_scan_reports_only_scanners_that_ran(self, tmp_path):
        doc = _aggregated_doc()
        doc["scanner_results"]["grype"] = {"status": "MISSING", "finding_count": 0}
        doc["scanner_results"]["semgrep"] = {"status": "FAILED", "finding_count": 1}
        _write_results(tmp_path, doc)

        results = get_scan_results(tmp_path)

        assert results["status"] == "completed"
        assert results["is_complete"] is True
        # MISSING never ran, so it is not a completed scanner; FAILED did run.
        assert results["total_scanners"] == 2
        assert results["scan_id"].startswith("scan-")
        assert "bandit" in results["raw_results"]["scanner_results"]

    def test_summary_stats_are_surfaced_as_actionable_findings(self, tmp_path):
        doc = _aggregated_doc(
            metadata={
                "summary_stats": {"actionable": 3},
                "generated_at": "2024-05-05T00:00:00",
            }
        )
        _write_results(tmp_path, doc)

        results = get_scan_results(tmp_path)

        assert results["actionable_findings"] == 3
        assert results["completion_time"] == "2024-05-05T00:00:00"

    def test_a_malformed_file_reraises_with_the_scan_id_stamped_on(self, tmp_path):
        _write_results(tmp_path, "{ not json")

        with pytest.raises(MCPResourceError) as excinfo:
            get_scan_results(tmp_path)

        assert excinfo.value.context["error_category"] == "invalid_format"
        # scan_id is added by get_scan_results' own handler. output_dir is NOT
        # asserted here: parse_aggregated_results already sets it on the way up,
        # so an assertion on it would pass without get_scan_results' handler
        # running at all. The next test covers that stamping directly.
        assert excinfo.value.context["scan_id"] is None

    def test_an_error_raised_without_context_gets_both_keys_stamped_on(self, tmp_path):
        """The re-raise handler fills in only the keys that are missing.

        Reached with an MCPResourceError carrying an empty context, because every
        error that arrives here through the normal path has already had output_dir
        set by parse_aggregated_results -- so the `if "output_dir" not in
        e.context` branch is only observable with a bare error.
        """
        _write_results(tmp_path, _aggregated_doc())

        with patch(
            f"{_MODULE}.AshAggregatedResults",
            side_effect=MCPResourceError("model rejected the document", context={}),
        ):
            with pytest.raises(MCPResourceError) as excinfo:
                get_scan_results(tmp_path)

        assert excinfo.value.context["scan_id"] is None
        assert excinfo.value.context["output_dir"] == str(tmp_path)
        assert "model rejected the document" in str(excinfo.value)

    def test_a_document_the_model_rejects_becomes_an_unexpected_error(self, tmp_path):
        """scanner_results is typed as a mapping; a list fails model construction."""
        _write_results(tmp_path, {"scanner_results": ["bandit"]})

        with pytest.raises(MCPResourceError) as excinfo:
            get_scan_results(tmp_path)

        assert excinfo.value.context["error_category"] == "unexpected_error"
        assert "Unexpected error retrieving scan results" in str(excinfo.value)
        assert excinfo.value.context["output_dir"] == str(tmp_path)


class TestResolveOutputDirectory:
    def test_an_absolute_output_dir_wins_over_the_source_dir(self, tmp_path):
        resolved = resolve_output_directory(
            source_dir=str(tmp_path / "src"), output_dir=str(tmp_path / "out")
        )

        assert resolved == tmp_path / "out"

    def test_a_relative_output_dir_is_resolved_under_an_absolute_source_dir(
        self, tmp_path
    ):
        resolved = resolve_output_directory(
            source_dir=str(tmp_path / "src"), output_dir="build/out"
        )

        assert resolved == tmp_path / "src" / "build" / "out"

    def test_both_relative_resolve_under_the_working_directory(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        resolved = resolve_output_directory(source_dir="src", output_dir="build/out")

        assert resolved == tmp_path / "src" / "build" / "out"

    def test_an_absolute_source_dir_alone_gets_the_default_output_tree(self, tmp_path):
        resolved = resolve_output_directory(source_dir=str(tmp_path / "src"))

        assert resolved == tmp_path / "src" / ".ash" / "ash_output"

    def test_a_relative_source_dir_alone_resolves_under_the_working_directory(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        resolved = resolve_output_directory(source_dir="src")

        assert resolved == tmp_path / "src" / ".ash" / "ash_output"

    def test_a_relative_output_dir_alone_resolves_under_the_working_directory(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        resolved = resolve_output_directory(output_dir="build/out")

        assert resolved == tmp_path / "build" / "out"

    def test_neither_argument_gets_the_default_output_tree_under_cwd(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)

        assert resolve_output_directory() == tmp_path / ".ash" / "ash_output"


class TestGetScanResultsWithErrorHandling:
    def test_a_missing_directory_becomes_an_error_response(self, tmp_path):
        result = get_scan_results_with_error_handling(tmp_path / "absent")

        assert result["success"] is False
        assert result["operation"] == "get_scan_results"
        assert "Check that the output directory exists" in result["suggestions"]

    def test_an_incomplete_scan_becomes_an_error_response(self, tmp_path):
        result = get_scan_results_with_error_handling(tmp_path)

        assert result["success"] is False
        assert result["error_category"] == "scan_incomplete"
        assert "is not complete" in result["error"]
        assert "Wait for the scan to complete" in result["suggestions"]

    def test_a_completed_scan_returns_the_results_unchanged(self, tmp_path):
        _write_results(tmp_path, _aggregated_doc())

        result = get_scan_results_with_error_handling(tmp_path)

        assert result["status"] == "completed"
        assert result["is_complete"] is True
        assert "success" not in result

    def test_a_resource_error_becomes_an_error_response(self, tmp_path):
        _write_results(tmp_path, "{ not json")

        result = get_scan_results_with_error_handling(tmp_path)

        assert result["success"] is False
        assert result["operation"] == "get_scan_results"
        assert result["error_category"] == "invalid_format"

    def test_an_unexpected_error_is_typed_and_logged(self, tmp_path):
        _write_results(tmp_path, _aggregated_doc())

        with (
            patch(
                f"{_MODULE}.get_scan_results", side_effect=RuntimeError("model blew up")
            ),
            patch(f"{_MODULE}._logger", MagicMock(spec=ASHLogger)) as logger,
        ):
            result = get_scan_results_with_error_handling(tmp_path)

        assert result["success"] is False
        assert result["error_category"] == "unexpected_error"
        assert result["context"]["error_type"] == "RuntimeError"
        assert result["context"]["output_dir"] == str(tmp_path)
        assert "cwd" in result["context"]
        assert "Unexpected error getting scan results" in logger.error.call_args[0][0]
