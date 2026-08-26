# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that never ran must not read as one that ran and found nothing.

Why this file exists
--------------------
`get_scan_progress` over MCP reported scanners skipped for missing dependencies
as indistinguishable from clean ones, so a consumer could not tell "scanned, no
findings" from "never ran". For a security tool that difference is the whole
answer.

Where the information was lost
------------------------------
Not in the core. scan_phase.py records the truth:

    aggregated_results.scanner_results[display_name] = ScannerStatusInfo(
        status=ScannerStatus.MISSING, dependencies_satisfied=False, ...
    )

The MCP layer then rebuilt its own view by globbing
`scanners/*/*/ASH.ScanResults.json`. A scanner that never ran writes no such
file, so it simply fell out of the map, and the surrounding counts made the
remaining ones look like the complete set. The fix reads the authoritative
statuses instead of re-deriving them from what happens to be on disk.

Why a standalone helper
-----------------------
This logic lives here rather than in cli/mcp_server.py because that module
imports the MCP SDK at module scope, so a test of it cannot run without the SDK
installed. Keeping the policy in a plain function makes it testable on its own
and leaves the tool as transport.
"""

import json
from pathlib import Path

from automated_security_helper.core.resource_management.scan_tracking import (
    summarize_scanner_statuses,
)


def _write_results(output_dir: Path, scanner_results: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ash_aggregated_results.json").write_text(
        json.dumps({"scanner_results": scanner_results}), encoding="utf-8"
    )


class TestSkippedScannersAreDistinguishable:
    def test_missing_dependencies_is_reported_with_a_reason(self, tmp_path):
        """The reported case: semgrep and syft skipped for missing dependencies."""
        _write_results(
            tmp_path,
            {
                "bandit": {"status": "PASSED", "dependencies_satisfied": True},
                "semgrep": {"status": "MISSING", "dependencies_satisfied": False},
                "syft": {"status": "MISSING", "dependencies_satisfied": False},
            },
        )

        summary = summarize_scanner_statuses(tmp_path)

        skipped = {entry["scanner"]: entry for entry in summary["skipped_scanners"]}
        assert set(skipped) == {"semgrep", "syft"}
        assert skipped["semgrep"]["reason"] == "missing_dependencies"
        assert skipped["semgrep"]["status"] == "MISSING"

    def test_a_clean_scanner_is_not_listed_as_skipped(self, tmp_path):
        """The distinction the issue is about: PASSED with no findings is not skipped."""
        _write_results(
            tmp_path, {"bandit": {"status": "PASSED", "dependencies_satisfied": True}}
        )

        summary = summarize_scanner_statuses(tmp_path)

        assert summary["skipped_scanners"] == []
        assert summary["scanner_statuses"]["bandit"]["status"] == "PASSED"

    def test_excluded_scanner_reports_a_different_reason(self, tmp_path):
        """Excluded by config is a user decision, not a broken environment.

        Both land in skipped_scanners, but conflating the reasons would tell a
        user to install something they deliberately turned off.
        """
        _write_results(
            tmp_path,
            {
                "checkov": {
                    "status": "SKIPPED",
                    "excluded": True,
                    "dependencies_satisfied": True,
                }
            },
        )

        summary = summarize_scanner_statuses(tmp_path)

        assert summary["skipped_scanners"][0]["reason"] == "excluded_by_configuration"

    def test_failed_and_error_are_not_reported_as_skipped(self, tmp_path):
        """A scanner that ran and failed did run. It belongs in neither bucket."""
        _write_results(
            tmp_path,
            {
                "grype": {"status": "FAILED", "dependencies_satisfied": True},
                "opengrep": {"status": "ERROR", "dependencies_satisfied": True},
            },
        )

        summary = summarize_scanner_statuses(tmp_path)

        assert summary["skipped_scanners"] == []
        assert summary["scanner_statuses"]["grype"]["status"] == "FAILED"
        assert summary["scanner_statuses"]["opengrep"]["status"] == "ERROR"

    def test_every_scanner_appears_in_scanner_statuses(self, tmp_path):
        """Including the ones that never ran.

        This is the assertion that fails against a map built by globbing result
        files, since a scanner that never ran leaves none behind.
        """
        _write_results(
            tmp_path,
            {
                "bandit": {"status": "PASSED", "dependencies_satisfied": True},
                "semgrep": {"status": "MISSING", "dependencies_satisfied": False},
            },
        )

        summary = summarize_scanner_statuses(tmp_path)

        assert set(summary["scanner_statuses"]) == {"bandit", "semgrep"}


class TestDegradesQuietly:
    def test_absent_results_file_yields_empty_summary(self, tmp_path):
        """Mid-scan there is no aggregated file yet.

        get_scan_progress is polled while the scan runs, so this is the common
        case rather than an error, and it must not raise.
        """
        summary = summarize_scanner_statuses(tmp_path)

        assert summary == {"scanner_statuses": {}, "skipped_scanners": []}

    def test_malformed_results_file_yields_empty_summary(self, tmp_path):
        """A partially written file must not break a progress poll."""
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / "ash_aggregated_results.json").write_text(
            '{"scanner_results": {', encoding="utf-8"
        )

        summary = summarize_scanner_statuses(tmp_path)

        assert summary == {"scanner_statuses": {}, "skipped_scanners": []}

    def test_non_mapping_scanner_entry_is_ignored(self, tmp_path):
        """Defensive: scanner_results is user-adjacent data by the time we read it."""
        _write_results(
            tmp_path,
            {
                "bandit": {"status": "PASSED", "dependencies_satisfied": True},
                "weird": "not-a-mapping",
            },
        )

        summary = summarize_scanner_statuses(tmp_path)

        assert set(summary["scanner_statuses"]) == {"bandit"}
