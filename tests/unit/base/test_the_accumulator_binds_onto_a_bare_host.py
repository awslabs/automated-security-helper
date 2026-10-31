# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_process_command_response`` works bound onto a host with only the accumulator fields.

The method is a documented extension seam, and the uv mixin's tests drive the
real accumulator through a stub plugin that carries ``output``, ``errors``,
``exit_code``, ``command`` and ``context`` and nothing else of PluginBase. The
host below has those, plus the two members the method still reads without a
default: ``_values_to_redact`` (read for the values to redact) and
``_scan_kept_flag`` (read on the exit-code step). It has no ``use_uv_tool``,
which the method reads with a default of false. The
processed-response mark and the records hook are PluginBase members, so a hard
read of either made the bound method raise on such a host, and the uv response
path kept that raise as the response's error with no stderr line recorded.
Both are read through getattr, like the uv inputs hook beside them.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_base import PluginBase

pytestmark = pytest.mark.unit


def _bare_host(values):
    # The accumulator fields the mixin's stub carries, its values hook (the
    # mixin's reads the context's environment values), and the one state field
    # the seam has always read on its exit-code step (`_scan_kept_flag`, None
    # on a fresh plugin). Nothing else of PluginBase is present.
    host = SimpleNamespace(
        command="bandit",
        exit_code=0,
        output=[],
        errors=[],
        _scan_kept_flag=None,
        _values_to_redact=lambda: tuple(values),
        context=SimpleNamespace(config=SimpleNamespace(_environment_values=values)),
    )
    host._process_command_response = PluginBase._process_command_response.__get__(host)
    return host


def test_a_bare_host_records_both_streams():
    host = _bare_host([])

    host._process_command_response(
        {"stdout": "tool line one", "stderr": "tool err one", "returncode": 1}
    )

    assert "tool line one" in " ".join(host.output), host.output
    assert "tool err one" in " ".join(host.errors), host.errors
    assert host.exit_code == 1


def test_a_bare_host_still_redacts_the_recorded_stderr():
    canary = "ENVCANARY-bare-77421"
    host = _bare_host([canary])

    host._process_command_response(
        {
            "stdout": "",
            "stderr": f"error: you require bandit=={canary}",
            "returncode": 1,
        }
    )

    assert host.errors, "no stderr line reached errors"
    assert all(canary not in line for line in host.errors), host.errors
