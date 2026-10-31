# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner's accumulated exit code ranks an error code above an accepted one.

``worse_exit_code`` keeps the larger of two codes, which is the worse one only
while the accepted codes are the small ones. For a scanner whose accepted set is
``{0, 2}`` (grype) an error code of 1 from one run was hidden behind an accepted
2 from another, and the accumulated code then read as a completed scan. The
accumulator now folds codes through a hook, ``_worse_exit_code``: the base
keeps the larger code, and ``ScannerPluginBase`` ranks a code outside
``success_exit_codes`` above an accepted one. The module function is unchanged.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_base import PluginBase, worse_exit_code
from automated_security_helper.utils.subprocess_utils import SPAWN_FAILURE_RETURNCODE
from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

RUN_FUNCTION = (
    "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
)


def _accepting(tmp_path, monkeypatch, codes):
    """A scanner whose class accepts exactly ``codes``."""
    scanner = _scanner(_context(tmp_path, ()))
    monkeypatch.setattr(type(scanner), "success_exit_codes", set(codes))
    return scanner


def _ran(scanner, *codes):
    for code in codes:
        scanner._process_command_response({"returncode": code})
    return scanner.exit_code


def test_the_base_hook_keeps_the_larger_code(tmp_path):
    scanner = _scanner(_context(tmp_path, ()))

    assert PluginBase._worse_exit_code(scanner, 1, 2) == 2
    assert PluginBase._worse_exit_code(scanner, 2, 1) == 2
    assert PluginBase._worse_exit_code(scanner, None, 3) == 3


def test_an_error_code_below_an_accepted_one_is_kept(tmp_path, monkeypatch):
    scanner = _accepting(tmp_path, monkeypatch, {0, 2})

    assert _ran(scanner, 2, 1) == 1


def test_an_error_code_met_first_is_kept_over_a_later_accepted_one(
    tmp_path, monkeypatch
):
    scanner = _accepting(tmp_path, monkeypatch, {0, 2})

    assert _ran(scanner, 1, 2) == 1


def test_two_accepted_codes_keep_the_larger(tmp_path, monkeypatch):
    scanner = _accepting(tmp_path, monkeypatch, {0, 2})

    assert _ran(scanner, 2, 0) == 2


def test_two_error_codes_keep_the_larger(tmp_path, monkeypatch):
    scanner = _accepting(tmp_path, monkeypatch, {0, 2})

    assert _ran(scanner, 1, 3) == 3
    assert _ran(scanner, 1) == 3


def test_the_spawn_failure_code_is_an_error_even_when_listed(tmp_path, monkeypatch):
    scanner = _accepting(tmp_path, monkeypatch, {0, SPAWN_FAILURE_RETURNCODE})

    assert scanner._worse_exit_code(SPAWN_FAILURE_RETURNCODE, 5) == (
        SPAWN_FAILURE_RETURNCODE
    )
    assert scanner._worse_exit_code(5, SPAWN_FAILURE_RETURNCODE) == (
        SPAWN_FAILURE_RETURNCODE
    )


def test_a_missing_code_a_zero_and_a_signal_death_rank_as_the_module_function_does(
    tmp_path, monkeypatch
):
    scanner = _accepting(tmp_path, monkeypatch, {0, 2})

    for current, new in [(None, 2), (None, 1), (0, 2), (0, 1), (2, -9), (-9, 1)]:
        assert scanner._worse_exit_code(current, new) == worse_exit_code(
            current, new
        ), (current, new)


def test_the_module_function_still_keeps_the_larger_code():
    assert worse_exit_code(2, 1) == 2
    assert worse_exit_code(1, 2) == 2
    assert worse_exit_code(None, 1) == 1


def test_the_handler_after_a_run_folds_through_the_hook(tmp_path, monkeypatch):
    """A run whose response ASH then failed to handle folds its code the same way."""
    context = _context(tmp_path, ())
    scanner = _scanner(context)
    monkeypatch.setattr(type(scanner), "success_exit_codes", {0, 2})
    scanner.use_uv_tool = False
    scanner.exit_code = 2

    def _raise(_response):
        raise RuntimeError("could not record the response")

    with (
        patch.object(type(scanner), "_process_command_response", side_effect=_raise),
        patch(
            RUN_FUNCTION,
            return_value={"returncode": 1, "stdout": "", "stderr": ""},
        ),
    ):
        scanner._run_subprocess(["stub-tool"], results_dir=context.output_dir)

    assert scanner.exit_code == 1, scanner.exit_code


def test_the_handler_after_a_spawn_failure_folds_through_the_hook(
    tmp_path, monkeypatch
):
    context = _context(tmp_path, ())
    scanner = _scanner(context)
    monkeypatch.setattr(type(scanner), "success_exit_codes", {0, 200})
    scanner.use_uv_tool = False
    scanner.exit_code = 200

    def _raise(_response):
        raise RuntimeError("could not record the response")

    with (
        patch.object(type(scanner), "_process_command_response", side_effect=_raise),
        patch(RUN_FUNCTION, side_effect=OSError("no such tool")),
    ):
        scanner._run_subprocess(["stub-tool"], results_dir=context.output_dir)

    assert scanner.exit_code == SPAWN_FAILURE_RETURNCODE, scanner.exit_code


def test_a_hook_that_raises_does_not_lose_the_code(tmp_path, monkeypatch):
    scanner = _scanner(_context(tmp_path, ()))

    def _raises(self, current, new):
        raise RuntimeError("hook broke")

    monkeypatch.setattr(type(scanner), "_worse_exit_code", _raises)

    assert _ran(scanner, 3) == 3


def test_a_hook_that_answers_no_code_does_not_lose_the_code(tmp_path, monkeypatch):
    scanner = _scanner(_context(tmp_path, ()))
    monkeypatch.setattr(
        type(scanner), "_worse_exit_code", lambda self, current, new: None
    )

    assert _ran(scanner, 3) == 3
