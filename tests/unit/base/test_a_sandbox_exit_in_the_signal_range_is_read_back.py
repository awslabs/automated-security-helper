# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A sandboxed tool's exit of 129..192 is read back as the likely signal.

bwrap and firejail report a tool's death by a signal as their own exit code,
``128 + N``, where a direct child would give the negative code. A plan that
declares this puts ``sandbox_signal_exits`` on the run's response, and
``_process_command_response`` then keeps the run's cause as the signal, worded
by ``inferred_signal_death_message``. The range is exactly 129..192: 128, 193
and 255 stay the tool's own answer, and a response without the declaration
(landlock, sandbox off) is never read back. The exit code is kept as it is.

No sandbox is needed: the declaration is data on the response.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.utils.sandbox.backends import SpawnPlan
from automated_security_helper.utils.subprocess_utils import (
    inferred_signal_death_message,
)

pytestmark = pytest.mark.unit


def _host():
    host = SimpleNamespace(
        command="tool",
        exit_code=0,
        output=[],
        errors=[],
        _scan_kept_flag=None,
        _values_to_redact=lambda: (),
        context=SimpleNamespace(config=SimpleNamespace(_environment_values=())),
    )
    host._process_command_response = PluginBase._process_command_response.__get__(host)
    return host


def _run(returncode, declared=True):
    host = _host()
    response = {"stdout": "", "stderr": "", "returncode": returncode}
    if declared:
        response["sandbox_signal_exits"] = True
    host._process_command_response(response)
    return host


@pytest.mark.parametrize(
    "code",
    [129, 137, 192],
)
def test_a_declared_exit_in_the_range_is_kept_as_the_likely_signal(code):
    host = _run(code)

    assert host._scan_kept_flag == (
        "signaled",
        inferred_signal_death_message(code - 128, code),
    )
    assert "likely" in host._scan_kept_flag[1]
    assert str(code) in host._scan_kept_flag[1]
    assert host.exit_code == code


@pytest.mark.parametrize("code", [0, 1, 128, 193, 255])
def test_a_declared_exit_outside_the_range_stays_the_tools_own_answer(code):
    host = _run(code)

    assert host._scan_kept_flag is None
    assert host.exit_code == code


@pytest.mark.parametrize("code", [129, 137, 192])
def test_an_exit_in_the_range_with_no_declaration_is_not_read_back(code):
    host = _run(code, declared=False)

    assert host._scan_kept_flag is None
    assert host.exit_code == code


@pytest.mark.parametrize("code", [129, 137, 192])
def test_a_count_exit_plugin_opts_out_of_the_read_back(code):
    host = _host()
    host.tool_exit_code_is_a_count = True
    host._process_command_response(
        {
            "stdout": "",
            "stderr": "",
            "returncode": code,
            "sandbox_signal_exits": True,
        }
    )

    assert host._scan_kept_flag is None
    assert host.exit_code == code


def test_a_plugin_that_does_not_declare_a_count_is_still_read_back():
    host = _host()
    host.tool_exit_code_is_a_count = False
    host._process_command_response(
        {
            "stdout": "",
            "stderr": "",
            "returncode": 137,
            "sandbox_signal_exits": True,
        }
    )

    assert host._scan_kept_flag == (
        "signaled",
        inferred_signal_death_message(9, 137),
    )
    assert host.exit_code == 137


def test_a_post_run_error_response_is_not_read_back():
    host = _host()

    host._process_command_response(
        {
            "stdout": "",
            "stderr": "",
            "returncode": 137,
            "sandbox_signal_exits": True,
            "post_run_error": True,
            "error": "ASH could not record the output",
        }
    )

    assert host._scan_kept_flag is None


def test_the_declaration_defaults_off_and_is_set_by_the_plans_that_make_it():
    assert SpawnPlan(argv=[], env={}).signal_deaths_as_exit_codes is False
    assert (
        SpawnPlan(
            argv=[], env={}, signal_deaths_as_exit_codes=True
        ).signal_deaths_as_exit_codes
        is True
    )
