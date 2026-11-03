# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The registry's lookups agree with its admission rule, and a claim cannot reopen a scan.

Each test is pinned against the behavior it replaced:

* ``_empty_coverage`` lacked ``could_not_stop``, so a progress response's key set
  depended on whether a runner had recorded coverage.
* ``get_scan_by_directory`` matched active entries only and ignored the session,
  so a directory register_scan refused (a stopping runner) read as free, and
  another session's scan, id included, was returned.
* ``register_scan`` compared source directories only, so two scans of different
  directories naming one output directory wrote one tree; and its refusal told a
  session that did not own the occupying scan that it was "stopping".
* ``update_scan_status`` applied RUNNING over a cancelled or closed entry, so the
  runner's claim undid a cancel that landed before it; ``mark_running`` kept the
  old end time, error and coverage; PENDING returned True while changing nothing.
* ``finish_scan`` accepted INCOMPLETE with a coverage payload that named no gap.
* ``cancel_scan`` raised on a PermissionError from os.kill before marking the
  entry cancelled, so its cancel event was never set.
* ``check_scan_progress`` raised for an ended scan whose output directory was
  gone, closed a PENDING entry a runner had claimed from the previous scan's
  results file (and, once that was fixed, still reported that file's scanners
  and counts under the claimed entry's id), and recorded a file-derived failure
  message without the environment-value redaction every other closing message
  gets.
* ``get_scan_statistics`` did not exist; three separate reads could disagree.
"""

import errno
import json
import os
from pathlib import Path

import pytest

from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    _empty_coverage,
)

pytestmark = pytest.mark.unit

SECRET = "a-value-read-from-the-environment"


def _project(tmp_path: Path, name: str) -> Path:
    project = tmp_path / name
    project.mkdir(parents=True, exist_ok=True)
    return project


def _register(registry, project: Path, output=None, **kw) -> str:
    output = output if output is not None else project / ".ash" / "ash_output"
    return registry.register_scan(
        directory_path=str(project), output_directory=str(output), **kw
    )


def _write_results(output: Path, scanner="bandit", finding_count=0) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "ash_aggregated_results.json").write_text(
        json.dumps(
            {
                "metadata": {
                    "generated_at": "2024-01-01T00:00:00",
                    "summary_stats": {},
                },
                "scanner_results": {
                    scanner: {"status": "PASSED", "finding_count": finding_count}
                },
            }
        ),
        encoding="utf-8",
    )


class TestCoverageKeysAreStable:
    def test_empty_coverage_carries_could_not_stop(self):
        assert _empty_coverage()["could_not_stop"] == []

    def test_a_running_scan_reports_the_same_coverage_keys_as_a_finished_one(
        self, tmp_path
    ):
        registry = ScanRegistry()
        project = _project(tmp_path, "proj")
        (project / ".ash" / "ash_output").mkdir(parents=True)
        scan_id = _register(registry, project)
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        progress = registry.check_scan_progress(scan_id)

        assert progress["could_not_stop"] == []


class TestGetScanByDirectoryAgreesWithRegisterScan:
    def test_a_stopping_scan_still_occupies_its_directory(self, tmp_path):
        registry = ScanRegistry()
        project = _project(tmp_path, "proj")
        scan_id = _register(registry, project)
        entry = registry.get_scan(scan_id)
        entry.has_runner = True
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.cancel_scan(scan_id)

        with pytest.raises(MCPResourceError):
            _register(registry, project)
        found = registry.get_scan_by_directory(str(project))

        assert found is not None
        assert found.scan_id == scan_id

    def test_the_lookup_is_session_scoped_when_asked(self, tmp_path):
        registry = ScanRegistry()
        project = _project(tmp_path, "proj")
        scan_id = _register(registry, project, session_id="owner")

        assert registry.get_scan_by_directory(str(project), session_id="other") is None
        owned = registry.get_scan_by_directory(str(project), session_id="owner")
        assert owned is not None and owned.scan_id == scan_id
        assert registry.get_scan_by_directory(str(project)) is not None


class TestRegisterScanRefusals:
    def test_two_directories_cannot_share_an_output_directory(self, tmp_path):
        registry = ScanRegistry()
        shared = tmp_path / "shared-output"
        _register(registry, _project(tmp_path, "a"), output=shared)

        with pytest.raises(MCPResourceError) as excinfo:
            _register(registry, _project(tmp_path, "b"), output=shared)

        assert "Output directory" in str(excinfo.value)
        assert excinfo.value.context["error_category"] == "resource_exhausted"

    def test_another_session_is_not_told_the_scan_is_stopping(self, tmp_path):
        registry = ScanRegistry()
        project = _project(tmp_path, "proj")
        scan_id = _register(registry, project, session_id="owner")
        registry.get_scan(scan_id).has_runner = True
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.cancel_scan(scan_id)

        with pytest.raises(MCPResourceError) as other:
            _register(registry, project, session_id="other")
        with pytest.raises(MCPResourceError) as owner:
            _register(registry, project, session_id="owner")

        assert "stopping" not in str(other.value)
        assert "scan_id" not in other.value.context
        assert "stopping (cancelled)" in str(owner.value)


class TestARunnerClaimCannotReopenAnEndedScan:
    def test_running_over_a_cancelled_entry_is_refused(self, tmp_path):
        registry = ScanRegistry()
        scan_id = _register(registry, _project(tmp_path, "proj"))
        registry.cancel_scan(scan_id)

        assert registry.update_scan_status(scan_id, MCScanStatus.RUNNING) is False
        assert registry.get_scan(scan_id).status is MCScanStatus.CANCELLED

    def test_pending_is_not_a_status_to_move_to(self, tmp_path):
        registry = ScanRegistry()
        scan_id = _register(registry, _project(tmp_path, "proj"))

        with pytest.raises(ValueError):
            registry.update_scan_status(scan_id, MCScanStatus.PENDING)

    def test_an_entry_closed_from_a_file_is_reopened_clean(self, tmp_path):
        registry = ScanRegistry()
        project = _project(tmp_path, "proj")
        output = project / ".ash" / "ash_output"
        _write_results(output)
        scan_id = _register(registry, project)
        # No runner has claimed it: the previous scan's file closes it.
        registry.check_scan_progress(scan_id)
        entry = registry.get_scan(scan_id)
        assert entry.status in (MCScanStatus.COMPLETED, MCScanStatus.INCOMPLETE)

        assert registry.update_scan_status(scan_id, MCScanStatus.RUNNING) is True

        assert entry.status is MCScanStatus.RUNNING
        assert entry.end_time is None
        assert entry.coverage is None
        assert entry.error_message is None

    def test_an_entry_a_runner_claimed_is_not_closed_from_the_previous_file(
        self, tmp_path
    ):
        registry = ScanRegistry()
        project = _project(tmp_path, "proj")
        output = project / ".ash" / "ash_output"
        _write_results(output)
        scan_id = _register(registry, project)
        registry.get_scan(scan_id).has_runner = True

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "pending"
        assert progress["is_complete"] is False
        assert registry.get_scan(scan_id).status is MCScanStatus.PENDING

    def test_a_claimed_entry_does_not_report_the_previous_scans_results(self, tmp_path):
        """The claimed entry's status was already its own (the test above). Its
        scanners, counts and scanner statuses were still read from the output
        tree, which holds the previous scan's files until the runner writes, so
        the response carried the previous scan's results under the new id."""
        registry = ScanRegistry()
        project = _project(tmp_path, "proj")
        _write_results(project / ".ash" / "ash_output", "semgrep", finding_count=3)
        scan_id = _register(registry, project)
        registry.get_scan(scan_id).has_runner = True

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "pending"
        assert progress["scanners"] == {}
        assert progress["total_scanners"] == 0
        assert progress["total_findings"] == 0
        assert progress["skipped_scanners"] == []
        # Not the restore marker's case: the tree holds a leftover, not a
        # put-back, and the key keeps that meaning.
        assert progress["output_holds_previous_results"] is False
        assert registry.get_scan(scan_id).status is MCScanStatus.PENDING

    def test_an_entry_no_runner_claimed_still_reads_the_file(self, tmp_path):
        registry = ScanRegistry()
        project = _project(tmp_path, "proj")
        _write_results(project / ".ash" / "ash_output", "semgrep", finding_count=3)
        scan_id = _register(registry, project)

        progress = registry.check_scan_progress(scan_id)

        assert "semgrep" in progress["scanners"]
        assert progress["total_scanners"] == 1
        assert registry.get_scan(scan_id).closed_from_file is True


class TestFinishScanIncompleteNeedsAGap:
    def test_a_gapless_coverage_payload_is_refused(self, tmp_path):
        registry = ScanRegistry()
        scan_id = _register(registry, _project(tmp_path, "proj"))
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

        with pytest.raises(ValueError):
            registry.finish_scan(
                scan_id, MCScanStatus.INCOMPLETE, coverage=_empty_coverage()
            )

        assert registry.get_scan(scan_id).status is MCScanStatus.RUNNING


class TestCancelScanWhenTheSignalIsRefused:
    def test_a_refused_signal_still_cancels_the_scan(self, tmp_path, monkeypatch):
        registry = ScanRegistry()
        scan_id = _register(registry, _project(tmp_path, "proj"))
        entry = registry.get_scan(scan_id)
        entry.mark_running(process_id=424242)

        def refused(pid, sig):
            raise PermissionError(errno.EPERM, "Operation not permitted")

        monkeypatch.setattr(os, "kill", refused)

        assert registry.cancel_scan(scan_id) is True
        assert entry.status is MCScanStatus.CANCELLED
        assert entry.cancel_event.is_set()
        assert any("Permission denied" in warning for warning in entry.warnings)


class TestCheckScanProgressWithoutAnOutputDirectory:
    def test_an_ended_scan_whose_directory_is_gone_reports_its_status(self, tmp_path):
        registry = ScanRegistry()
        project = _project(tmp_path, "proj")
        scan_id = _register(registry, project)
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.finish_scan(scan_id, MCScanStatus.FAILED, "crashed before writing")

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == "failed"
        assert progress["error_message"] == "crashed before writing"
        assert progress["is_complete"] is True
        assert progress["scanners"] == {}

    def test_a_file_derived_failure_is_redacted_with_the_registered_values(
        self, tmp_path
    ):
        registry = ScanRegistry()
        project = _project(tmp_path, SECRET)
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        (output / "ash_aggregated_results.json").write_text("{ not json", "utf-8")
        scan_id = _register(registry, project, environment_values=(SECRET,))

        progress = registry.check_scan_progress(scan_id)

        entry = registry.get_scan(scan_id)
        assert entry.status is MCScanStatus.FAILED
        assert entry.error_message
        assert SECRET not in entry.error_message
        assert progress["status"] == "failed"

    def test_a_file_derived_message_on_an_ended_scan_is_redacted_too(self, tmp_path):
        """Red at the base: an entry a runner closed COMPLETED is not re-closed
        when its results file later reads as unusable; the response carried the
        file's own message instead, unredacted, the one path that skipped the
        redaction every applied message gets. The file's text names the results
        path, which here carries the value."""
        registry = ScanRegistry()
        project = _project(tmp_path, SECRET)
        output = project / ".ash" / "ash_output"
        output.mkdir(parents=True)
        (output / "ash_aggregated_results.json").write_text("{ not json", "utf-8")
        scan_id = _register(registry, project, environment_values=(SECRET,))
        registry.update_scan_status(scan_id, MCScanStatus.RUNNING)
        registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)

        progress = registry.check_scan_progress(scan_id)

        assert registry.get_scan(scan_id).status is MCScanStatus.COMPLETED
        assert progress["results_available"] is False
        assert progress["error_message"], "the unusable file is reported"
        assert "ash_aggregated_results.json" in progress["error_message"]
        # The message names the path, so the directories above the file are in it
        # too; with one of them present and the value absent, the value was in the
        # path and was removed, and not never there.
        assert "ash_output" in progress["error_message"]
        assert SECRET not in progress["error_message"]


class TestScanStatisticsAreOneRead:
    def test_the_counts_agree_and_follow_the_session(self, tmp_path):
        registry = ScanRegistry()
        a = _register(registry, _project(tmp_path, "a"), session_id="s1")
        _register(registry, _project(tmp_path, "b"), session_id="s2")
        registry.update_scan_status(a, MCScanStatus.RUNNING)

        everyone = registry.get_scan_statistics()
        only_s1 = registry.get_scan_statistics(session_id="s1")

        assert everyone["total_scans"] == 2
        assert everyone["active_scans"] == 2
        assert sum(everyone["status_counts"].values()) == everyone["total_scans"]
        assert only_s1 == {
            "total_scans": 1,
            "active_scans": 1,
            "status_counts": {**{s.value: 0 for s in MCScanStatus}, "running": 1},
        }
