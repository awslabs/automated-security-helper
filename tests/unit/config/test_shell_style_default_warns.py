# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reference written with the shell's ``${VAR:-default}`` form gets a warning.

ASH reads ``${VAR:default}``: everything after the colon is the default. A
file that writes the shell's ``:-`` gets a default that starts with ``-``,
which reads like a working fallback until the variable is unset. The value is
unchanged (it is what ASH's syntax says); the warning names the variable and
the form, not the default, which is the file's own text.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import resolve_env_references

pytestmark = pytest.mark.unit

DEFAULT = "fallback-text-7f3e"


def _warnings(reference: str) -> tuple:
    with patch("automated_security_helper.config.ash_config.ASH_LOGGER") as log:
        value = resolve_env_references(reference)
    return value, [str(call.args[0]) for call in log.warning.call_args_list]


def _shell_form(warnings: list) -> list:
    return [warning for warning in warnings if "':-'" in warning]


def test_an_unset_variable_with_the_shell_form_warns(monkeypatch):
    monkeypatch.delenv("ASH_PROBE_UNSET", raising=False)
    value, warnings = _warnings(f"${{ASH_PROBE_UNSET:-{DEFAULT}}}")
    # The control: the value is what ASH's syntax gives.
    assert value == f"-{DEFAULT}"
    shell = _shell_form(warnings)
    assert len(shell) == 1, warnings
    assert "ASH_PROBE_UNSET" in shell[0]
    assert DEFAULT not in shell[0], "the warning quotes the default"


def test_a_set_variable_with_the_shell_form_warns_too(monkeypatch):
    """The default is unused now, and wrong the day the variable is unset."""
    monkeypatch.setenv("ASH_PROBE_SET", "value-x")
    value, warnings = _warnings(f"${{ASH_PROBE_SET:-{DEFAULT}}}")
    assert value == "value-x"
    shell = _shell_form(warnings)
    assert len(shell) == 1, warnings
    assert DEFAULT not in shell[0], "the warning quotes the default"


def test_a_default_in_ash_s_form_does_not_warn_about_it(monkeypatch):
    monkeypatch.delenv("ASH_PROBE_UNSET", raising=False)
    value, warnings = _warnings(f"${{ASH_PROBE_UNSET:{DEFAULT}}}")
    assert value == DEFAULT
    assert _shell_form(warnings) == [], warnings
