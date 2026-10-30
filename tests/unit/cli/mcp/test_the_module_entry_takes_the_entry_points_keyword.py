# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``python -m automated_security_helper.cli.mcp_server`` hands the entry point a
callable that takes the keyword the entry point passes.

``run_module_app`` runs the app it is given as click's ``main`` is run, with
``standalone_mode=False``, so that a usage error and a command's exit code come
back to it instead of ending the process inside click. The command modules hand
it a Typer app, which takes that keyword. This module runs the root app's ``mcp``
command instead, through a callable of its own; a callable that took no keyword
made every module start fail with a TypeError before any startup check ran, and
the server's refusals (an unknown ASH_MCP_TRANSPORT, an ASH_CONFIG that names no
file) came out as a traceback with exit 1 instead of their message and code.

These run the module's callable in this process, with the root app replaced by
a recorder, so the contract between the two modules is pinned without a child
process; the subprocess tests of the two refusals measure the whole path.
"""

import sys
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.cli import entrypoint, mcp_server

#: In-process, the root app replaced by a recorder, no child started: the unit tier.
pytestmark = pytest.mark.unit


@pytest.fixture
def root_app(monkeypatch) -> List[Tuple[List[str], Dict[str, Any]]]:
    """The root app replaced by a recorder that answers with exit code 7."""
    calls: List[Tuple[List[str], Dict[str, Any]]] = []

    def record(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return 7

    monkeypatch.setattr("automated_security_helper.cli.main.app", record)
    monkeypatch.setattr(sys, "argv", ["mcp_server", "--transport", "http"])
    return calls


def test_the_callable_runs_the_mcp_command_with_this_processs_arguments(
    root_app,
) -> None:
    """The root app is called with ``mcp`` in front of the process's arguments,
    and the keyword the entry point passes reaches it unchanged."""
    result = mcp_server._run_as_the_mcp_command(standalone_mode=False)

    assert result == 7
    assert root_app == [
        (["mcp", "--transport", "http"], {"standalone_mode": False}),
    ]


def test_the_entry_point_exits_with_the_code_the_command_returned(root_app) -> None:
    """Run as ``__main__`` runs it, through the public ``run_module_app``, the
    callable's answer becomes the process's exit code, as a command's
    ``typer.Exit`` does: the failure path around the runner passes a
    ``SystemExit`` through unchanged."""
    with pytest.raises(SystemExit) as stopped:
        entrypoint.run_module_app(mcp_server._run_as_the_mcp_command)

    assert stopped.value.code == 7
    assert len(root_app) == 1


def test_the_public_entry_hands_the_callable_to_the_module_runner_unchanged(
    monkeypatch,
) -> None:
    """What ties the two: ``run_module_app`` runs the callable it is given
    through ``_run_module_app``, the same object, once, so the keyword contract
    the tests below pin on the runner is the contract ``python -m`` meets."""
    handed = []
    monkeypatch.setattr(entrypoint, "_run_module_app", handed.append)

    def marker(**kwargs):
        return 0

    entrypoint.run_module_app(marker)

    assert handed == [marker]


def test_a_callable_that_takes_no_keyword_is_what_the_entry_point_refuses() -> None:
    """The shape the module used to hand over: the runner's call reaches it
    with a keyword it does not take, so the TypeError is raised before any
    startup check runs. Pinned on the runner itself, so the contract is named,
    not just avoided; under ``run_module_app`` the failure path would report
    it and exit 1, which is the process-level symptom, not the contract."""
    with pytest.raises(TypeError, match="standalone_mode"):
        entrypoint._run_module_app(lambda: 0)
