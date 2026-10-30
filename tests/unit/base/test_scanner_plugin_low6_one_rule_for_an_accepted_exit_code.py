# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One rule says whether an exit code is an accepted one.

``_exit_code_accepted`` grades the scanner's current code and ``_worse_exit_code``
ranks two codes when several runs fold into one. They state the same rule, and
each carried its own copy of it: a scanner that changed one left the other
grading by the old rule, so the fold ranked by one set of accepted codes and the
grade read another. ``_code_is_accepted`` is the rule, with an optional set of
codes, and ``_exit_code_accepted`` applies it to ``exit_code``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.subprocess_utils import SPAWN_FAILURE_RETURNCODE
from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


def _scanner_holding(tmp_path, monkeypatch, accepted, code):
    scanner = _scanner(_context(tmp_path, ()))
    monkeypatch.setattr(type(scanner), "success_exit_codes", set(accepted))
    scanner.exit_code = code
    return scanner


def test_the_rule_takes_the_codes_it_is_given(tmp_path, monkeypatch):
    scanner = _scanner_holding(tmp_path, monkeypatch, {0, 1}, 0)

    assert scanner._code_is_accepted(7) is False
    assert scanner._code_is_accepted(7, {7}) is True
    assert scanner._code_is_accepted(1, {7}) is False


def test_the_rule_refuses_the_spawn_failure_code_even_when_it_is_listed(
    tmp_path, monkeypatch
):
    scanner = _scanner_holding(tmp_path, monkeypatch, {0, SPAWN_FAILURE_RETURNCODE}, 0)

    assert scanner._code_is_accepted(SPAWN_FAILURE_RETURNCODE) is False
    assert (
        scanner._code_is_accepted(SPAWN_FAILURE_RETURNCODE, {SPAWN_FAILURE_RETURNCODE})
        is False
    )


def test_the_rule_does_not_accept_a_missing_code(tmp_path, monkeypatch):
    scanner = _scanner_holding(tmp_path, monkeypatch, {0, 1}, None)

    assert scanner._code_is_accepted(None) is False
    assert scanner._exit_code_accepted() is False


def test_the_current_codes_grade_is_the_rules_answer_for_it(tmp_path, monkeypatch):
    scanner = _scanner_holding(tmp_path, monkeypatch, {0, 2}, 2)

    assert scanner._exit_code_accepted() is True
    assert scanner._exit_code_accepted({0}) is False
    scanner.exit_code = 1
    assert scanner._exit_code_accepted() is False
    assert scanner._exit_code_accepted({1}) is True


def test_a_scanner_that_changes_the_rule_changes_the_grade_and_the_fold(
    tmp_path, monkeypatch
):
    scanner = _scanner_holding(tmp_path, monkeypatch, {0, 1}, 1)
    assert scanner._exit_code_accepted() is True

    def _only_zero_and_two(self, code, success_codes=None):
        return code in (0, 2)

    monkeypatch.setattr(type(scanner), "_code_is_accepted", _only_zero_and_two)

    # The grade follows the rule: 1 is no longer accepted.
    assert scanner._exit_code_accepted() is False
    # So does the fold: an error code of 1 outranks an accepted 2, though the
    # class's own success_exit_codes still list 1.
    assert scanner._worse_exit_code(2, 1) == 1
    assert scanner._worse_exit_code(1, 2) == 1
