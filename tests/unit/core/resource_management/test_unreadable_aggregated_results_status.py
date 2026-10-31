# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results file that cannot be read as results must not read as a clean scan.

WHY THIS EXISTS
---------------
``ash_aggregated_results.json`` is both the scan's completion signal and the document
``get_scan_progress`` builds its per-scanner section from. ``check_scan_progress``
marked the registry entry ``completed`` as soon as the file *existed*, and the
response's ``status`` is the entry's. So a file that existed and did not parse, or
parsed into something that is not a results document, came back as
``status: completed`` with ``scanners: {}``: a client told the scan finished, having
examined nothing.

The atomic write in utils/atomic_write.py removed the concurrent rewrite as one cause
of that. It did nothing for a file that is corrupt on disk, truncated by a full disk,
or the wrong shape. What the poll answers depends on who owns the entry's lifecycle:

* An entry no runner owns (PENDING) takes its status from the file: an unreadable one
  reports ``failed`` with ``error_message`` naming the file and what was wrong with it,
  and the entry is closed FAILED.
* An entry a runner closed as COMPLETED keeps the runner's word. A read-only poll does
  not rewrite it. The response says what the file cannot give: ``results_available`` is
  False, ``coverage_complete`` is None, the scanners are empty, and ``error_message``
  names the file. ``status`` stays ``completed`` because the scan did end; a client
  decides whether there is anything to read from ``results_available``, not from
  ``status`` alone. (That ``completed`` plus ``results_available`` False is a state the
  published tool reference describes differently is a documentation row, not settled
  here.)

WHAT IS DELIBERATELY NOT A FAILURE
----------------------------------
Two states look like "no results" and are not errors:

* The file does not exist yet, or no longer exists, and the entry was closed as
  completed by whoever ran the scan. The registry entry is the authority on the scan's
  lifecycle there; a workspace closes project entries this way. Pinned below so the
  fix cannot turn it into a failure.
* The file is a JSON object carrying neither ``scanner_results`` nor ``sarif``. That
  is not hypothetical corruption: it is what the SCAN phase writes before the REPORT
  phase runs, measured on a real local scan as
  ``{"name": ..., "description": ..., "ash_config": {}}``, because ``save_model``
  dumps with ``exclude_unset`` and the scan fills ``scanner_results`` in place. While
  the scan is still running that is "not finished yet", so it reports the entry's own
  active status and ``is_complete: False``. Once the entry is closed as completed, the
  same document means the scan ended without final results: the status stays
  ``completed`` and ``results_available`` is False with the file named in
  ``error_message``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
    get_scan_registry,
)

pytestmark = pytest.mark.unit

RESULTS_FILE = "ash_aggregated_results.json"

VALID_DOCUMENT: Dict[str, Any] = {
    "scanner_results": {
        "bandit": {"status": "PASSED", "finding_count": 0, "severity_counts": {}},
        "semgrep": {"status": "PASSED", "finding_count": 0, "severity_counts": {}},
    },
}

# What a truncating write, or a disk that filled mid-write, leaves behind.
TRUNCATED = {
    "empty": "",
    "half_a_document": json.dumps(VALID_DOCUMENT)[
        : len(json.dumps(VALID_DOCUMENT)) // 2
    ],
    "missing_the_closing_brace": json.dumps(VALID_DOCUMENT)[:-1],
}

# Valid JSON that is not a results document, each labeled with the text the error
# must carry so a client can tell which way it is wrong.
SCHEMA_INVALID = {
    "top_level_array": ("[]", "JSON object"),
    "top_level_string": ('"results"', "JSON object"),
    "scanner_results_is_a_list": (
        json.dumps({"scanner_results": ["bandit"]}),
        "scanner_results must be a dictionary",
    ),
    "scanner_entry_is_not_an_object": (
        json.dumps({"scanner_results": {"bandit": 5}}),
        "bandit",
    ),
    "sarif_is_not_an_object": (
        json.dumps({"sarif": "x"}),
        "SARIF data must be a dictionary",
    ),
    "sarif_runs_is_not_a_list": (
        json.dumps({"sarif": {"runs": "x"}}),
        "SARIF 'runs' must be a list",
    ),
}

# What the SCAN phase writes before the REPORT phase, as measured on a real scan.
SCAN_PHASE_DOCUMENT = json.dumps(
    {
        "name": "ASH Scan",
        "description": "Aggregated security scan results",
        "ash_config": {},
    }
)


def _register(registry: ScanRegistry, tmp_path: Path, content: str | None) -> tuple:
    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    if content is not None:
        (output_dir / RESULTS_FILE).write_text(content, encoding="utf-8")
    scan_id = registry.register_scan(
        directory_path=str(tmp_path), output_directory=str(output_dir)
    )
    return scan_id, output_dir


def _assert_reported_as_failed(progress: Dict[str, Any], output_dir: Path) -> None:
    assert progress["status"] != "completed", (
        "A results file that is not a readable results document was reported as a "
        f"completed scan with scanners={progress['scanners']!r}."
    )
    assert progress["status"] == "failed"
    assert progress["is_complete"] is True, (
        "A failed read is terminal; a client polling on is_complete would otherwise "
        "poll until it timed out."
    )
    message = progress["error_message"]
    assert message, "The failure carries no error_message, so a client cannot say why."
    assert str(output_dir / RESULTS_FILE) in message, (
        f"The error does not name the results file: {message!r}"
    )


def test_a_readable_results_file_reports_completed_with_its_scanners(tmp_path):
    """Control: the fixture can produce a completed scan, so a failure below is real."""
    registry = ScanRegistry()
    scan_id, _ = _register(registry, tmp_path, json.dumps(VALID_DOCUMENT))

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == "completed"
    assert progress["error_message"] is None
    assert set(progress["scanners"]) == {"bandit", "semgrep"}


@pytest.mark.parametrize("content", TRUNCATED.values(), ids=TRUNCATED.keys())
def test_a_truncated_results_file_is_a_failure_naming_the_file(tmp_path, content):
    registry = ScanRegistry()
    scan_id, output_dir = _register(registry, tmp_path, content)

    progress = registry.check_scan_progress(scan_id)

    _assert_reported_as_failed(progress, output_dir)
    assert "Invalid JSON" in progress["error_message"]
    assert registry.get_scan(scan_id).status is MCScanStatus.FAILED, (
        "The registry entry still says otherwise, so list_active_scans and the status "
        "counts would disagree with this response."
    )


@pytest.mark.parametrize(
    "content,reason", SCHEMA_INVALID.values(), ids=SCHEMA_INVALID.keys()
)
def test_a_schema_invalid_results_file_is_a_failure_naming_the_file(
    tmp_path, content, reason
):
    registry = ScanRegistry()
    scan_id, output_dir = _register(registry, tmp_path, content)

    progress = registry.check_scan_progress(scan_id)

    _assert_reported_as_failed(progress, output_dir)
    assert reason in progress["error_message"]
    assert registry.get_scan(scan_id).status is MCScanStatus.FAILED


def test_the_published_tool_reports_the_failure_too(tmp_path):
    """The tool clients call, not only the registry method underneath it."""
    from automated_security_helper.cli.mcp_server import get_scan_progress

    scan_id, output_dir = _register(get_scan_registry(), tmp_path, TRUNCATED["empty"])

    progress = asyncio.run(
        get_scan_progress(ctx=MagicMock(spec=Context), scan_id=scan_id)
    )

    _assert_reported_as_failed(progress, output_dir)


def test_a_failure_does_not_overwrite_the_reason_the_scan_already_failed(tmp_path):
    registry = ScanRegistry()
    scan_id, output_dir = _register(registry, tmp_path, TRUNCATED["empty"])
    registry.update_scan_status(scan_id, MCScanStatus.FAILED, "scanner crashed")

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == "failed"
    assert progress["error_message"] == "scanner crashed"


def test_the_scan_phase_document_reads_as_still_running(tmp_path):
    """Written before the REPORT phase. Not finished, and not an error either."""
    registry = ScanRegistry()
    scan_id, _ = _register(registry, tmp_path, SCAN_PHASE_DOCUMENT)
    registry.update_scan_status(scan_id, MCScanStatus.RUNNING)

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == "running"
    assert progress["is_complete"] is False
    assert progress["error_message"] is None


def test_the_scan_phase_document_after_the_scan_ended_reports_no_results(tmp_path):
    """The scan returned, and the final rewrite that adds scanner_results never came.

    The runner's word stands: the entry was closed COMPLETED, so the poll's status
    is "completed" and is_complete is True, and a read-only poll does not re-close
    the entry as FAILED (it used to, while an unreadable file kept the entry, so the
    two unusable-file shapes answered differently). What the file read found is
    reported beside the status: results_available is False, and error_message
    names the file and the missing scanner_results, so a client that would read
    the results is told there are none to read.
    """
    registry = ScanRegistry()
    scan_id, output_dir = _register(registry, tmp_path, SCAN_PHASE_DOCUMENT)
    registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == "completed"
    assert progress["is_complete"] is True
    assert progress["results_available"] is False
    message = progress["error_message"]
    assert message, "The poll carries no error_message, so a client cannot say why."
    assert str(output_dir / RESULTS_FILE) in message, message
    assert "scanner_results" in message, message
    assert progress["scanners"] == {}
    # Read-only: the entry keeps the status its runner gave it.
    assert registry.get_scan(scan_id).status is MCScanStatus.COMPLETED


def _assert_the_completed_entry_was_left_alone(
    registry: ScanRegistry, scan_id: str, progress: Dict[str, Any], output_dir: Path
) -> None:
    assert progress["status"] == "completed"
    assert progress["is_complete"] is True
    assert progress["results_available"] is False
    assert progress["coverage_complete"] is None
    assert progress["scanners"] == {}
    assert str(output_dir / RESULTS_FILE) in progress["error_message"]
    entry = registry.get_scan(scan_id)
    assert entry.status is MCScanStatus.COMPLETED
    assert entry.error_message is None, (
        "A read-only poll wrote its finding into the entry, so every later poll "
        "and list_active_scans would report it as the scan's own reason."
    )


@pytest.mark.parametrize("content", TRUNCATED.values(), ids=TRUNCATED.keys())
def test_a_truncated_file_under_a_completed_entry_is_reported_not_rewritten(
    tmp_path, content
):
    """The runner closed the entry as completed; the poll reports the file.

    The same file under an entry no runner owns closes it FAILED (above). Here the
    entry keeps its status, its end time and an empty reason, and the response
    carries the finding: results_available False beside status completed.
    """
    registry = ScanRegistry()
    scan_id, output_dir = _register(registry, tmp_path, content)
    registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
    end_time = registry.get_scan(scan_id).end_time

    progress = registry.check_scan_progress(scan_id)

    _assert_the_completed_entry_was_left_alone(registry, scan_id, progress, output_dir)
    assert "Invalid JSON" in progress["error_message"]
    assert registry.get_scan(scan_id).end_time == end_time


@pytest.mark.parametrize(
    "content,reason", SCHEMA_INVALID.values(), ids=SCHEMA_INVALID.keys()
)
def test_a_schema_invalid_file_under_a_completed_entry_is_reported_not_rewritten(
    tmp_path, content, reason
):
    registry = ScanRegistry()
    scan_id, output_dir = _register(registry, tmp_path, content)
    registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)
    end_time = registry.get_scan(scan_id).end_time

    progress = registry.check_scan_progress(scan_id)

    _assert_the_completed_entry_was_left_alone(registry, scan_id, progress, output_dir)
    assert reason in progress["error_message"]
    assert registry.get_scan(scan_id).end_time == end_time


def test_an_entry_closed_as_completed_without_a_results_file_stays_completed(tmp_path):
    """The case the registry-over-file override exists for, preserved.

    A workspace closes a project's entry as completed when the run returned and nothing
    says the project did not; the entry, not the file, owns the lifecycle there.
    """
    registry = ScanRegistry()
    scan_id, _ = _register(registry, tmp_path, None)
    registry.update_scan_status(scan_id, MCScanStatus.COMPLETED)

    progress = registry.check_scan_progress(scan_id)

    assert progress["status"] == "completed"
    assert progress["is_complete"] is True
    assert progress["error_message"] is None
