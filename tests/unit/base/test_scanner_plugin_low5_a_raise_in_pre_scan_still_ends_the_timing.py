# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A raise in ``_pre_scan`` leaves the target with an end time.

``scan`` clears the instance's timing for the target, ``_pre_scan`` starts it and
then does the work that can raise (the results directory, the dependency
check), and that call sits before the ``try`` whose handler sets the end. A
raise there left ``end_time`` None, so the executor paired this target's start
with no end, or with the previous target's. The end is now set when the call
raises, and the error still propagates as it did.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _populated_target, _scanner

pytestmark = pytest.mark.unit


def test_a_raise_from_the_dependency_check_ends_the_target_s_timing(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))

    with patch.object(
        type(scanner),
        "validate_plugin_dependencies",
        side_effect=RuntimeError("the check broke"),
    ):
        with pytest.raises(RuntimeError, match="the check broke"):
            scanner.scan(target=_populated_target(tmp_path), target_type="source")

    assert scanner.start_time is not None
    assert scanner.end_time is not None
    assert scanner.end_time >= scanner.start_time


def test_a_raise_from_the_whole_pre_scan_ends_the_timing_too(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))

    with patch.object(
        type(scanner), "_pre_scan", side_effect=RuntimeError("setup broke")
    ):
        with pytest.raises(RuntimeError, match="setup broke"):
            scanner.scan(target=_populated_target(tmp_path), target_type="source")

    assert scanner.end_time is not None


def test_a_pre_scan_that_returns_leaves_the_timing_to_the_rest_of_the_scan(tmp_path):
    scanner = _scanner(_context(tmp_path, ()), deps_ok=False)

    assert (
        scanner.scan(target=_populated_target(tmp_path), target_type="source") is False
    )

    # The refusal path ends the timing through _post_scan, as before.
    assert scanner.start_time is not None
    assert scanner.end_time is not None
    assert scanner.end_time >= scanner.start_time
