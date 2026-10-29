# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The registry's directory comparison and its handling of a stopping runner.

Five mechanisms, each pinned against the behavior it replaced:

* ``_canonical_directory`` caught OSError only. ``Path.resolve`` raises
  RuntimeError for a symlink loop on Python 3.10 to 3.12, and the comparison ran
  over every entry at each registration, so one historical entry whose directory
  had since become a loop made every later ``register_scan`` raise.
* The directory an entry occupies was re-resolved from its raw string at every
  lookup, so a symlink retargeted after the scan started moved the entry to the
  link's new target: a second scan of the real directory was admitted and an
  unrelated directory was refused.
* ``cleanup_scan`` deleted an entry whose runner was still stopping, which let
  ``register_scan`` admit a second scan of the directory into the window the
  runner still writes in.
* ``check_scan_progress`` of an ended scan read the output directory, which a
  later scan of the same directory now writes, and reported that scan's files
  as the old scan's.
* The coverage re-assessment of a finished entry closed without coverage ran
  with no guard on every poll, so a results set that made it raise failed every
  progress call for that scan from then on.
"""

import json
import os
from datetime import timedelta
from unittest.mock import patch

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    _canonical_directory,
)

pytestmark = pytest.mark.unit

_MODULE = "automated_security_helper.core.resource_management.scan_registry"


def _register(registry, directory, output=None):
    output = output if output is not None else directory / ".ash" / "ash_output"
    return registry.register_scan(
        directory_path=str(directory), output_directory=str(output)
    )


def _results_document(scanner_name):
    return {
        "metadata": {"generated_at": "2024-01-01T00:00:00", "summary_stats": {}},
        "scanner_results": {
            scanner_name: {
                "status": "PASSED",
                "finding_count": 1,
                "severity_counts": {"high": 1},
            }
        },
    }


class TestCanonicalDirectorySurvivesAnUnresolvablePath:
    def test_a_symlink_loop_falls_back_to_the_raw_path(self, tmp_path):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        loop = tmp_path / "loop"
        try:
            loop.symlink_to(loop)
        except (OSError, NotImplementedError):
            pytest.skip("this platform refuses a self-referencing link")

        # Python 3.10-3.12 raise RuntimeError here; 3.13 resolves as far as it
        # can without raising. Neither may escape, and the path keeps its name.
        assert _canonical_directory(str(loop)).name == "loop"

    def test_a_nul_byte_falls_back_to_the_raw_path(self, tmp_path):
        bad = str(tmp_path / "pro\x00j")

        assert str(_canonical_directory(bad)) == bad

    def test_one_looping_historical_entry_does_not_break_registration(self, tmp_path):
        """The high finding end to end: register, retarget, register again."""
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        registry = ScanRegistry()
        target = tmp_path / "target"
        target.mkdir()
        link = tmp_path / "link"
        link.symlink_to(target)
        first = _register(registry, link)
        registry.update_scan_status(first, MCScanStatus.COMPLETED)

        # The directory of the historical entry becomes a loop.
        link.unlink()
        try:
            link.symlink_to(link)
        except (OSError, NotImplementedError):
            pytest.skip("this platform refuses a self-referencing link")
        other = tmp_path / "other"
        other.mkdir()

        second = _register(registry, other)

        assert second != first
        assert registry.get_scan_count() == 2


class TestDirectoryOccupancyIsFixedAtRegistration:
    def test_a_retargeted_link_does_not_move_the_scan(self, tmp_path):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        registry = ScanRegistry()
        real = tmp_path / "real"
        real.mkdir()
        unrelated = tmp_path / "unrelated"
        unrelated.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        first = _register(registry, link)

        # After the scan started, the link is pointed somewhere else.
        link.unlink()
        link.symlink_to(unrelated)

        # The real directory is still being scanned: a second scan is refused.
        with pytest.raises(MCPResourceError) as excinfo:
            _register(registry, real)
        assert "already has an active scan" in str(excinfo.value)
        assert excinfo.value.context["scan_id"] == first

        # The unrelated directory the link now names is not: it registers.
        second = _register(registry, unrelated)
        assert second != first

    def test_the_lookup_by_directory_follows_the_registered_target(self, tmp_path):
        if not hasattr(os, "symlink"):
            pytest.skip("symlinks are not available on this platform")
        registry = ScanRegistry()
        real = tmp_path / "real"
        real.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        first = _register(registry, link)
        link.unlink()
        link.symlink_to(elsewhere)

        assert registry.get_scan_by_directory(str(real)).scan_id == first
        assert registry.get_scan_by_directory(str(elsewhere)) is None


class TestCleanupKeepsAStoppingRunner:
    def test_a_cancelled_scan_whose_runner_runs_is_kept(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        scan_id = _register(registry, project)
        entry = registry.get_scan(scan_id)
        entry.has_runner = True
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.cancel_scan(scan_id)

        assert registry.cleanup_scan(scan_id) is False
        assert registry.get_scan(scan_id) is entry
        # And so a second scan of the directory is still refused.
        with pytest.raises(MCPResourceError) as excinfo:
            _register(registry, project)
        assert "still stopping" in str(excinfo.value)

        entry.runner_done.set()

        assert registry.cleanup_scan(scan_id) is True
        assert registry.get_scan(scan_id) is None

    def test_a_scan_without_a_runner_is_removed_as_before(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        scan_id = _register(registry, project)

        assert registry.cleanup_scan(scan_id) is True

    def test_cleanup_completed_scans_keeps_a_stopping_runner(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        scan_id = _register(registry, project)
        entry = registry.get_scan(scan_id)
        entry.has_runner = True
        registry.update_scan_status(scan_id, MCScanStatus.CANCELLED)
        entry.end_time = entry.end_time - timedelta(days=2)

        assert registry.cleanup_completed_scans(max_age_hours=1) == 0
        entry.runner_done.set()
        assert registry.cleanup_completed_scans(max_age_hours=1) == 1

    def test_occupants_of_directory_names_the_other_scans(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        first = _register(registry, project)
        registry.update_scan_status(first, MCScanStatus.COMPLETED)
        second = _register(registry, project)

        assert registry.occupants_of_directory(str(project)) == [second]
        assert (
            registry.occupants_of_directory(str(project), except_scan_id=second) == []
        )
        assert registry.occupants_of_directory(str(project) + os.sep) == [second]


class TestProgressOfASupersededScanReadsNoFiles:
    def test_a_later_scans_files_are_not_reported_as_the_old_scans(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        # The old scan's results are on disk...
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        before = registry.check_scan_progress(old)
        assert "bandit" in before["scanners"]

        # ...until a later scan of the directory takes the output tree over.
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.RUNNING)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("semgrep")), encoding="utf-8"
        )

        after = registry.check_scan_progress(old)

        assert after["scan_id"] == old
        assert after["status"] == "completed"
        assert after["scanners"] == {}
        assert after["total_scanners"] == 0
        assert after["skipped_scanners"] == []
        assert registry.get_scan(old).status is MCScanStatus.COMPLETED
        # The later scan still reads its own files.
        assert "semgrep" in registry.check_scan_progress(new)["scanners"]

    def test_a_running_scan_is_not_superseded_by_an_older_one(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        old = _register(registry, project, output)
        registry.update_scan_status(old, MCScanStatus.COMPLETED)
        new = _register(registry, project, output)
        registry.update_scan_status(new, MCScanStatus.RUNNING)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("semgrep")), encoding="utf-8"
        )

        assert "semgrep" in registry.check_scan_progress(new)["scanners"]


class TestAReadOnlyPollDoesNotRecloseACompletedScan:
    """A COMPLETED entry whose results file later reads as unusable used to be
    turned FAILED, with a new end_time, by every progress poll: the "failed"
    file status was applied to any entry but RUNNING, FAILED, CANCELLED and
    INCOMPLETE. Only an entry no runner owns (PENDING) takes its status from
    the file; a finished scan keeps its status and reports the file problem."""

    def test_a_completed_entry_keeps_its_status_and_reports_the_file(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
        entry = registry.get_scan(scan_id)
        closed_at = entry.end_time
        results_file = output / "ash_aggregated_results.json"
        results_file.write_text("{ not json", encoding="utf-8")

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "completed"
        assert progress["is_complete"] is True
        assert progress["error_message"]
        assert str(results_file) in progress["error_message"]
        assert entry.status is MCScanStatus.COMPLETED
        assert entry.end_time == closed_at
        assert entry.error_message is None

    def test_a_pending_entry_still_takes_the_failure_from_the_file(self, tmp_path):
        """The case the file-decides rule exists for, preserved."""
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        (output / "ash_aggregated_results.json").write_text(
            "{ not json", encoding="utf-8"
        )

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "failed"
        assert registry.get_scan(scan_id).status is MCScanStatus.FAILED


class TestCoverageAssessmentFailureDoesNotFailTheProgressCall:
    def test_a_raising_assessment_leaves_coverage_unknown(self, tmp_path):
        registry = ScanRegistry()
        project = tmp_path / "proj"
        project.mkdir()
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scan_id = _register(registry, project, output)
        (output / "ash_aggregated_results.json").write_text(
            json.dumps(_results_document("bandit")), encoding="utf-8"
        )
        # Closed without coverage, as a caller using update_scan_status does.
        registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)

        with patch(
            f"{_MODULE}.assess_coverage", side_effect=KeyError("rule without id")
        ):
            progress = registry.check_scan_progress(scan_id)
            again = registry.check_scan_progress(scan_id)

        assert progress["success"] is True
        assert progress["status"] == "completed"
        assert progress["coverage_complete"] is None
        assert again["success"] is True
