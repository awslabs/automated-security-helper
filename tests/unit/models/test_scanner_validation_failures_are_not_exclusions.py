# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that failed is reported as failed, by the status and the checkpoint.

Two readings hid a failure behind a clean-looking scan. A registered scanner
whose construction failed carries a ``failure_reason``; the enablement pass then
labels it "disabled" (it is neither enabled, excluded nor missing a dependency),
and the status derivation read "disabled" as an exclusion, so the completeness
pass backfilled it SKIPPED with ``excluded`` True. And the execution-completion
checkpoint listed a queued scanner that never completed among its missing
scanners without recording a discrepancy, so ``has_issues()`` stayed False and
the scan phase logged that completion validation passed.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def manager():
    context = MagicMock()
    context.config = MagicMock()
    return ScannerValidationManager(context)


def test_a_disabled_label_over_a_recorded_failure_reads_as_failed(manager):
    """Red before the fix: status "excluded", excluded True."""
    manager.update_scanner_state(
        "bandit",
        registration_status="registered",
        queued_for_execution=False,
        execution_completed=False,
        failure_reason="construction raised: no such binary",
    )
    manager.validate_scanner_enablement(enabled_scanners=[], excluded_scanners=[])
    assert manager.scanner_states["bandit"].enablement_status == "disabled"

    status = manager.determine_scanner_status_from_execution_data("bandit")

    assert status["status"] == "failed"
    assert status["excluded"] is False
    assert status["failure_reason"] == "construction raised: no such binary"


def test_a_disabled_scanner_with_no_failure_is_still_excluded(manager):
    """Control: the disabled reading itself is unchanged."""
    manager.update_scanner_state(
        "checkov", enablement_status="disabled", enablement_reason="Scanner disabled"
    )

    status = manager.determine_scanner_status_from_execution_data("checkov")

    assert status["status"] == "excluded"
    assert status["excluded"] is True


def test_a_queued_scanner_that_did_not_complete_is_a_recorded_discrepancy(manager):
    """Red before the fix: has_issues() False with one missing scanner."""
    manager.update_scanner_state("bandit", queued_for_execution=True)
    manager.update_scanner_state("checkov", queued_for_execution=True)

    checkpoint = manager.validate_execution_completion(["bandit"])

    assert checkpoint.get_missing_scanners() == ["checkov"]
    assert checkpoint.has_issues() is True
    assert any("checkov" in line for line in checkpoint.discrepancies)
    report = manager.report_execution_discrepancies(checkpoint)
    assert report["has_discrepancies"] is True
    assert report["missing_count"] == 1


def test_every_queued_scanner_completing_records_no_discrepancy(manager):
    """Control: a complete run keeps a clean checkpoint."""
    manager.update_scanner_state("bandit", queued_for_execution=True)

    checkpoint = manager.validate_execution_completion(["bandit"])

    assert checkpoint.has_issues() is False
    assert checkpoint.discrepancies == []
