#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two MCP producers set ``success`` on the success path.

Why this file exists
--------------------
``success`` is the key every MCP consumer branches on, and until this change
only ``create_error_response`` ever set it -- always to ``False``. Neither
producer set it on the path where the call worked:

* ``ScanRegistry.check_scan_progress`` returned a sixteen-key literal.
* ``scan_tracking.get_scan_results`` returned a nine-key literal.

``mcp_server.get_scan_progress`` guards on ``not progress_info.get("success")``
and ``mcp_server.get_scan_results`` on ``"error" in results or not
results.get("success")``. With the key absent both guards are true on *both*
branches, so neither was a guard: each was an unconditional return, and every
line after it was dead. ``summarize_scanner_statuses`` -- the repair for the
"a scanner that never ran looks like one that found nothing" confusion -- sat
in that dead region, so ``skipped_scanners`` never reached a client.

Absent and ``False`` are the same thing to a ``.get("success")`` caller and
different things to a schema validator, so every assertion here is ``is True``
or ``is False`` on the key itself rather than a truthiness test. A test written
as ``assert result.get("success")`` would have passed on a payload that omitted
the key entirely once any other repair happened to add it.

Two neighbouring defects in the same subsystem are pinned here as well, because
both are reached through ``check_scan_progress`` and both make an incomplete
scan read as a clean one:

``scanner_info['status']`` was never read
    ``create_scan_progress_from_files`` passed the literal
    ``MCScannerStatus.COMPLETED`` for every scanner in ``scanner_results`` and
    then called ``mark_completed()`` on it, so an aggregated file recording
    semgrep MISSING and grype ERROR reported ``completed_scanners`` 3 of 3 with
    all three statuses ``'completed'``.

A half-written results file counted as completion
    ``check_scan_completion`` only tests that ``ash_aggregated_results.json``
    exists. A truncated file therefore marked the registry entry COMPLETED, and
    the status-forcing block then overwrote the failed ``ScanProgress`` with
    ``'completed'`` -- yielding a finished scan, ``is_complete`` true, no error
    message and zero scanners.

For a security tool all three failures share one shape: something that measured
nothing reads as something that found nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    get_scan_results_with_error_handling,
)

#: The closed set of statuses ``core/enums.ScannerStatus`` defines, mapped to the
#: ``MCScannerStatus`` value each one must produce. Written out here rather than
#: imported so a change to the mapping has to be made in two places on purpose.
EXPECTED_MAPPING = {
    "PASSED": "completed",
    "FAILED": "failed",
    "ERROR": "failed",
    "MISSING": "skipped",
    "SKIPPED": "skipped",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scan_dirs(root: Path) -> tuple[Path, Path]:
    """Build a source tree and its output directory under *root*.

    Both must exist: ``register_scan`` and ``check_scan_progress`` each run
    ``validate_directory_path``, which requires the directory to be there.
    """
    source = root / "proj"
    source.mkdir(parents=True, exist_ok=True)
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    return source, output


def _write_aggregated(output_dir: Path, scanner_results: Dict[str, Any]) -> None:
    (output_dir / "ash_aggregated_results.json").write_text(
        json.dumps(
            {
                "metadata": {"summary_stats": {"actionable": 0}},
                "scanner_results": scanner_results,
            }
        ),
        encoding="utf-8",
    )


def _scanner(status: str, **extra: Any) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "status": status,
        "finding_count": 0,
        "severity_counts": {},
    }
    entry.update(extra)
    return entry


def _progress(root: Path, scanner_results: Dict[str, Any]) -> Dict[str, Any]:
    """Register a scan over a freshly written aggregated file and poll it.

    A private ``ScanRegistry`` rather than ``get_scan_registry()``: the global
    instance is shared process-wide and refuses a second active scan on a
    directory that already has one, which would make these tests
    order-dependent.
    """
    source, output = _scan_dirs(root)
    _write_aggregated(output, scanner_results)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source),
        output_directory=str(output),
    )
    return registry.check_scan_progress(scan_id)


# ---------------------------------------------------------------------------
# 1. The key is present, and present as a boolean
# ---------------------------------------------------------------------------


class TestTheSuccessKeyIsSetOnTheSuccessPath:
    def test_check_scan_progress_sets_success_true(self, tmp_path):
        progress = _progress(tmp_path, {"bandit": _scanner("PASSED")})

        assert progress["success"] is True

    def test_get_scan_results_sets_success_true(self, tmp_path):
        _, output = _scan_dirs(tmp_path)
        _write_aggregated(output, {"bandit": _scanner("PASSED")})

        results = get_scan_results_with_error_handling(output)

        assert results["success"] is True

    @pytest.mark.asyncio
    async def test_a_failed_poll_still_sets_success_false(self, tmp_path):
        """The negative control: ``False`` and absent must stay distinguishable.

        Without this, "set success to True unconditionally at the top of the
        response builder" satisfies both tests above while destroying the signal
        the key carries. ``scan_management.check_scan_progress`` converts the
        registry's raise into ``create_error_response``, which is the only path
        that has ever set the key.
        """
        from automated_security_helper.core.resource_management.scan_management import (
            check_scan_progress,
        )

        response = await check_scan_progress("scan-that-was-never-registered")

        assert response["success"] is False
        assert "error" in response


# ---------------------------------------------------------------------------
# 2. The per-scanner status is read, not asserted
# ---------------------------------------------------------------------------


class TestScannerStatusIsMappedFromTheDocument:
    @pytest.mark.parametrize("reported,expected", sorted(EXPECTED_MAPPING.items()))
    def test_each_reported_status_maps_to_its_own_value(
        self, tmp_path, reported, expected
    ):
        """One case per member of the closed ``ScannerStatus`` set.

        Parametrized rather than written as a single multi-scanner document so
        that a mapping which collapses two inputs onto one output fails on the
        specific pair rather than on an aggregate count.
        """
        progress = _progress(tmp_path, {"bandit": _scanner(reported)})

        assert progress["scanners"]["bandit"]["source"]["status"] == expected

    def test_completed_scanners_counts_only_the_ones_that_ran_clean(self, tmp_path):
        """3 of 3 was the reported figure for one clean scanner out of three."""
        progress = _progress(
            tmp_path,
            {
                "bandit": _scanner("PASSED"),
                "semgrep": _scanner("MISSING", dependencies_satisfied=False),
                "grype": _scanner("ERROR"),
            },
        )

        assert progress["total_scanners"] == 3
        assert progress["completed_scanners"] == 1

    def test_the_skipped_scanners_list_reaches_the_response(self, tmp_path):
        """A caller of the registry must be able to tell "never ran" from "clean".

        ``mcp_server.get_scan_progress`` recomputes this from the same source,
        but it is not the only consumer: ``mcp_get_scan_progress`` and
        ``scan_management.check_scan_progress`` both return this payload
        directly.
        """
        progress = _progress(
            tmp_path,
            {
                "bandit": _scanner("PASSED"),
                "semgrep": _scanner("MISSING", dependencies_satisfied=False),
            },
        )

        assert progress["skipped_scanners"] == [
            {
                "scanner": "semgrep",
                "status": "MISSING",
                "reason": "missing_dependencies",
            }
        ]

    def test_a_clean_scan_lists_nothing_as_skipped(self, tmp_path):
        """Positive control: the list is derived, not always populated."""
        progress = _progress(tmp_path, {"bandit": _scanner("PASSED")})

        assert progress["skipped_scanners"] == []


# ---------------------------------------------------------------------------
# 3. An unparseable document is not a completed scan
# ---------------------------------------------------------------------------


class TestAnUnparseableDocumentDoesNotComplete:
    def _truncated(self, tmp_path) -> Dict[str, Any]:
        source, output = _scan_dirs(tmp_path)
        # The shape a poll sees when it lands midway through the writer: the
        # file exists, so check_scan_completion() says the scan finished.
        (output / "ash_aggregated_results.json").write_text(
            '{"metadata": {"summ', encoding="utf-8"
        )
        registry = ScanRegistry()
        scan_id = registry.register_scan(
            directory_path=str(source),
            output_directory=str(output),
        )
        progress = registry.check_scan_progress(scan_id)
        self.entry_status = registry.get_scan(scan_id).status
        return progress

    def test_a_truncated_results_file_surfaces_as_failed(self, tmp_path):
        progress = self._truncated(tmp_path)

        assert progress["status"] == MCScanStatus.FAILED.value

    def test_the_registry_entry_is_not_marked_completed(self, tmp_path):
        """The entry itself, not only the response, must stop saying completed.

        A later poll reads ``entry.status``, so leaving the entry COMPLETED
        would make the first poll honest and every subsequent one wrong.
        """
        self._truncated(tmp_path)

        assert self.entry_status is MCScanStatus.FAILED

    def test_the_parse_error_reaches_error_message(self, tmp_path):
        """``error_message`` was None, which is what made this silent.

        Asserting on the substring the JSON decoder produces rather than on
        "some string is present": a generic placeholder would leave the operator
        with a failed scan and no way to tell a truncated file from a permission
        error.
        """
        progress = self._truncated(tmp_path)

        assert progress["error_message"] is not None
        assert "Invalid JSON" in progress["error_message"]

    def test_zero_scanners_is_not_reported_as_a_finished_scan(self, tmp_path):
        """The false negative this defect produced, stated directly."""
        progress = self._truncated(tmp_path)

        assert progress["total_scanners"] == 0
        assert not (progress["status"] == "completed" and progress["is_complete"])

    def test_a_parseable_document_still_completes(self, tmp_path):
        """Positive control: the gate rejects unparseable files, not all files.

        Without this, "never mark completed" passes every test above.
        """
        progress = _progress(tmp_path, {"bandit": _scanner("PASSED")})

        assert progress["status"] == MCScanStatus.COMPLETED.value
        assert progress["is_complete"] is True
        assert progress["error_message"] is None

    def test_an_empty_but_valid_document_still_completes(self, tmp_path):
        """``{}`` parses, so it is not this defect and must not change.

        An empty results document reporting a completed scan with zero scanners
        is a separate defect, handled by ``validate_result_structure`` on the
        results path. Gating on "the parser accepted the document" and not on
        "the scan produced scanners" keeps the two apart.
        """
        source, output = _scan_dirs(tmp_path)
        (output / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
        registry = ScanRegistry()
        scan_id = registry.register_scan(
            directory_path=str(source),
            output_directory=str(output),
        )

        progress = registry.check_scan_progress(scan_id)

        assert progress["status"] == MCScanStatus.COMPLETED.value
        assert progress["success"] is True
