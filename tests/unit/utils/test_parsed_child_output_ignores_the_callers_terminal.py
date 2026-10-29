# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A child whose human-readable output ASH reads gets none of the caller's
terminal settings.

uv lays its text out at the caller's COLUMNS and colors it under FORCE_COLOR or
CLICOLOR_FORCE even into a pipe; NO_COLOR stops the color (measured with uv 0.13).
A marker ASH matches in that text ("No solution found when resolving") then came
back split across lines or wrapped in escape codes. So such a child runs with
``environ_for_parsed_output``: the caller's display variables removed and
NO_COLOR set. The matches also read the text with its line breaks flowed into
spaces, for a tool that wraps whatever it is told.
"""

from __future__ import annotations

import subprocess

import pytest

from automated_security_helper.utils import process_env

pytestmark = pytest.mark.unit

DISPLAY = {
    "COLUMNS": "20",
    "LINES": "5",
    "FORCE_COLOR": "1",
    "CLICOLOR_FORCE": "1",
    "TTY_COMPATIBLE": "1",
    "TTY_INTERACTIVE": "1",
}


def test_a_parsed_child_gets_no_display_variable_and_no_color():
    given = {"PATH": "/opt/tools/bin", "UV_OFFLINE": "1", **DISPLAY}

    env = process_env.environ_for_parsed_output(given)

    assert sorted(set(env) & set(DISPLAY)) == []
    assert env["NO_COLOR"] == "1"
    assert (env["PATH"], env["UV_OFFLINE"]) == ("/opt/tools/bin", "1")
    assert "COLUMNS" in given, "the mapping given is left as it was"


def test_with_no_mapping_it_starts_from_the_environment(monkeypatch):
    monkeypatch.setenv("ASH_PARSED_OUTPUT_PROBE", "kept")
    for name, value in DISPLAY.items():
        monkeypatch.setenv(name, value)

    env = process_env.environ_for_parsed_output()

    kept = env.get("ASH_PARSED_OUTPUT_PROBE")
    assert kept == "kept"
    assert sorted(set(env) & set(DISPLAY)) == []
    assert env["NO_COLOR"] == "1"


#: The resolver error ``uv tool run --offline`` printed at COLUMNS=20 (uv 0.13),
#: its first lines verbatim.
_WRAPPED_RESOLVE_FAILURE = (
    "error: No solution\n"
    "       found when\n"
    "       resolving\n"
    "       tool\n"
    "       dependencies\n"
    "  cause: Because\n"
)


#: The first lines ``uv tool run --offline`` printed into a pipe under
#: FORCE_COLOR=1 (uv 0.12.22), verbatim. The scan's own uv run keeps the caller's
#: environment, so its stderr can arrive like this.
_COLORED_RESOLVE_FAILURE = (
    "\x1b[1m\x1b[31merror\x1b[39m\x1b[0m\x1b[1m:\x1b[0m No solution found when "
    "resolving tool dependencies\n"
    "  \x1b[1m\x1b[31mcause\x1b[39m\x1b[0m\x1b[1m:\x1b[0m Because bandit was not "
    "found in the cache and you require bandit==1.8.6, we can conclude that your "
    "requirements are unsatisfiable.\n"
)


def _offline_scanner():
    from automated_security_helper.base.uv_tool_mixin import UVToolMixin

    class _Scanner(UVToolMixin):
        command = "bandit"

        def __init__(self):
            self.errors = []
            self.logged = []

        def _is_offline_mode(self):
            return True

        def _uv_from_spec(self):
            return "bandit==1.8.6"

        def _plugin_log(self, *msg, **kwargs):
            self.logged.append(" ".join(msg))

    return _Scanner()


def test_a_wrapped_offline_resolve_failure_is_still_explained():
    scanner = _offline_scanner()
    scanner._explain_offline_resolve_failure(
        {"returncode": 1, "stderr": _WRAPPED_RESOLVE_FAILURE}, None
    )

    assert len(scanner.errors) == 1, scanner.errors
    assert scanner.errors[0].startswith(
        "Offline mode: uv could not resolve 'bandit==1.8.6'"
    ), scanner.errors[0]


def test_a_colored_offline_resolve_failure_is_quoted_without_its_escapes():
    """The message quotes what uv said as text: color codes in it would be shown
    as escapes on a terminal and written into the reports."""
    scanner = _offline_scanner()
    scanner._explain_offline_resolve_failure(
        {"returncode": 1, "stderr": _COLORED_RESOLVE_FAILURE}, None
    )

    assert len(scanner.errors) == 1, scanner.errors
    message = scanner.errors[0]
    assert "\x1b" not in message, repr(message)
    quoted = (
        "uv said: error: No solution found when resolving tool dependencies\n"
        "  cause: Because bandit was not found in the cache"
    )
    assert quoted in message, repr(message)
    assert scanner.logged == [message]


def test_a_wrapped_dry_run_failure_is_still_unsatisfied(monkeypatch):
    """The dry run's verdict reads uv's text with its line breaks flowed into
    spaces, whatever width the text came at."""
    from automated_security_helper.utils import pre_installed_tool

    def spawn(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", _WRAPPED_RESOLVE_FAILURE)

    monkeypatch.setattr(pre_installed_tool, "spawn_run", spawn)

    status, _ = pre_installed_tool._dry_run("/opt/uv/bin/uv", "/opt/py/bin/python", "x")

    assert status == "unsatisfied"


@pytest.mark.parametrize(
    "site",
    ["list_available_tools", "get_tool_version", "_run_uv_cache", "dry_run"],
)
def test_each_uv_call_whose_output_is_read_gets_that_environment(monkeypatch, site):
    """Every uv call whose text ASH parses spawns with environ_for_parsed_output's
    mapping: the caller's display variables gone and NO_COLOR set."""
    from automated_security_helper.utils import pre_installed_tool, uv_tool_runner

    for name, value in DISPLAY.items():
        monkeypatch.setenv(name, value)
    seen = []

    def spawn(argv, **kwargs):
        env = kwargs.get("env") or {}
        seen.append((sorted(set(env) & set(DISPLAY)), env.get("NO_COLOR")))
        return subprocess.CompletedProcess(argv, 0, "uv 0.13.0\n", "")

    monkeypatch.setattr(uv_tool_runner, "spawn_run", spawn)
    monkeypatch.setattr(pre_installed_tool, "spawn_run", spawn)
    runner = uv_tool_runner.UVToolRunner(uv_executable="/opt/uv/bin/uv")
    runner._uv_available_cache = True

    if site == "list_available_tools":
        runner.list_available_tools()
    elif site == "get_tool_version":
        runner.get_tool_version("bandit", refresh=True)
    elif site == "_run_uv_cache":
        runner._run_uv_cache("dir", timeout=30, check=False)
    else:
        pre_installed_tool._dry_run("/opt/uv/bin/uv", "/opt/py/bin/python", "x")

    assert seen == [([], "1")]
