# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An enabled scanner with no queued task is a recorded discrepancy.

``validate_task_queue`` listed an enabled scanner that was never queued among the
checkpoint's missing scanners without recording a discrepancy, so ``has_issues()``
stayed False and the checkpoint read as clean. ``handle_queue_validation_errors``
already records the failure reason whatever ``has_issues()`` says; the checkpoint
now says so too, as the execution-completion checkpoint does for a scanner that
did not complete.
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


def test_an_enabled_scanner_with_no_task_is_a_recorded_discrepancy(manager):
    """Red before the fix: has_issues() False with one missing scanner."""
    manager.update_scanner_state("bandit", enablement_status="enabled")
    manager.update_scanner_state("semgrep", enablement_status="enabled")

    checkpoint = manager.validate_task_queue([("semgrep", object())])

    assert checkpoint.get_missing_scanners() == ["bandit"]
    assert checkpoint.has_issues() is True
    assert any("bandit" in line for line in checkpoint.discrepancies)


def test_every_enabled_scanner_queued_records_no_discrepancy(manager):
    """Control: a full queue keeps a clean checkpoint."""
    manager.update_scanner_state("bandit", enablement_status="enabled")

    checkpoint = manager.validate_task_queue([("bandit", object())])

    assert checkpoint.has_issues() is False
    assert checkpoint.discrepancies == []
