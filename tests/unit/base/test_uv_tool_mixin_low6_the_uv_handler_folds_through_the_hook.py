# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A uv run's handler folds its exit code through the plugin's own ranking.

``_uv_response`` handles the response of a uv run. When handling it raises, the
handler folds the run's code into the plugin's ``exit_code`` itself, because the
normal path's fold (``_process_command_response``) raised or never ran. The
normal path folds through the plugin's ``_worse_exit_code`` hook, which ranks a
code outside ``success_exit_codes`` above an accepted one. The handler used the
default ranking, the larger code, so a scanner that accepts ``{0, 2}`` and met an
error code of 1 after an accepted 2 kept the 2, and the error was gone for good:
``_run_subprocess`` folds the copy it gets again, ``hook(2, 2) == 2``.
``test_plugin_base_low2_worse_exit_code_ranks_by_the_accepted_set`` holds the same
two cases for the direct run's handler.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.utils.subprocess_utils import SPAWN_FAILURE_RETURNCODE
from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


def _raise(_response):
    raise RuntimeError("could not record the response")


def _handled(tmp_path, monkeypatch, accepted, held, returncode):
    """The scanner's ``exit_code`` after its uv response failed to be handled.

    The scanner accepts exactly ``accepted`` and holds ``held`` from an earlier
    run; the uv run returned ``returncode``.
    """
    scanner = _scanner(_context(tmp_path, ()))
    monkeypatch.setattr(type(scanner), "success_exit_codes", set(accepted))
    scanner.use_uv_tool = True
    scanner.exit_code = held
    result = SimpleNamespace(stdout="", stderr="", returncode=returncode)

    with patch.object(type(scanner), "_process_command_response", side_effect=_raise):
        response = scanner._uv_response(result, None)

    assert response["returncode"] == returncode, response
    return scanner.exit_code


def test_an_error_code_after_an_accepted_one_is_kept_by_the_uv_handler(
    tmp_path, monkeypatch
):
    code = _handled(tmp_path, monkeypatch, {0, 2}, held=2, returncode=1)

    assert code == 1, code


def test_the_spawn_failure_code_after_an_accepted_one_is_kept_by_the_uv_handler(
    tmp_path, monkeypatch
):
    code = _handled(
        tmp_path, monkeypatch, {0, 200}, held=200, returncode=SPAWN_FAILURE_RETURNCODE
    )

    assert code == SPAWN_FAILURE_RETURNCODE, code


def test_two_accepted_codes_keep_the_larger_in_the_uv_handler(tmp_path, monkeypatch):
    """The control: the hook ranks only across the accepted line."""
    code = _handled(tmp_path, monkeypatch, {0, 2}, held=0, returncode=2)

    assert code == 2, code
