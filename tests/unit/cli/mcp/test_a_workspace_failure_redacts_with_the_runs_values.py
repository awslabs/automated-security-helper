# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan's failure texts redact with the run's values, and its
timeout names its limit through the one token every timeout message uses.

A workspace run's exception arm closed its entries with the bare error text,
which quotes whatever the raised exception carried in its message -- a value
a project's config read from the environment included. The entries are now
registered with the run's values (every project's and the operator chain's),
and the registry redacts the message it applies, so the arm that builds the
closing no longer decides whether it leaks.

The timeout reason printed its limit as ``{seconds:g}s`` while a directory
scan prints it through the shared limit phrase (``scan_timeout_seconds of
'2' s``, or "configured scan_timeout_seconds" where an environment value
types to the limit). The two tools' messages say the same thing, so they
now build the limit the same way; these cells pin the workspace side to
the phrase's two forms, under this tool's own option name.
"""

from __future__ import annotations

import asyncio
import json
import re

import pytest

from tests.unit.cli.mcp.test_mcp_resource_limits import (
    CHILD_SECONDS,
    _child_process_scans,
    _no_loop_errors,
    _operator_limits,
    _scan_workspace,
    _workspace,
    _workspace_entries,
)

SECRET = "a-value-read-from-the-environment"


@pytest.mark.asyncio
async def test_a_crashed_workspace_runs_entries_hide_a_project_config_value(
    tmp_path, monkeypatch
):
    """The run fails before its thread settles anything: the entries close
    with the failure's text, and a value a project's config read from the
    environment is hidden in every one of them."""
    from automated_security_helper.cli.mcp import workspace as workspace_module

    monkeypatch.setenv("ASH_WSNDL_HELD", SECRET)
    workspace_file = _workspace(tmp_path, "api", "web")
    for name in ("api", "web"):
        (workspace_file.parent / name / ".ash.yaml").write_text(
            "project_name: ${ASH_WSNDL_HELD:unset}\n", encoding="utf-8"
        )

    def _execute(plan, settings, **kwargs):
        raise RuntimeError(f"the run broke: {SECRET}")

    monkeypatch.setattr(workspace_module, "execute_workspace", _execute)
    response = await _scan_workspace(workspace_file)
    entries = _workspace_entries()

    if response.get("success") is not False or set(entries) != {"api", "web"}:
        raise RuntimeError(("premise: the run failed registered", response, entries))
    for key, entry in entries.items():
        message = entry.error_message or ""
        assert "the run broke: " in message, (key, message)
        assert SECRET not in message, (key, message)


@pytest.mark.asyncio
async def test_a_timed_out_workspace_scan_prints_its_limit_in_the_token_form(
    tmp_path, monkeypatch
):
    """The limit prints as the timeout token writes it -- quoted, with the
    unit apart -- the form the directory scan's reason is pinned to, so the
    two tools' timeout texts cannot drift again."""
    _operator_limits(monkeypatch, scan_timeout_seconds=2)
    _child_process_scans(
        monkeypatch, tmp_path, {"api": CHILD_SECONDS, "web": CHILD_SECONDS}
    )
    workspace_file = _workspace(tmp_path, "api", "web")

    with _no_loop_errors():
        response = await asyncio.wait_for(
            _scan_workspace(workspace_file), timeout=CHILD_SECONDS + 30
        )
    entries = _workspace_entries()

    if response.get("success") is not False or set(entries) != {"api", "web"}:
        raise RuntimeError(("premise: the run timed out", response, entries))
    for where, text in (
        ("the response", response.get("error") or ""),
        *((key, entry.error_message or "") for key, entry in entries.items()),
    ):
        assert "scan_timeout_seconds of '2' s" in text, (where, text)
        assert "of 2s" not in text, (where, text)
    # The machine-readable copy: where the text shows the number, the
    # response's context carries it too, so the redacting cell below pins a
    # gate and not a dropped key.
    assert response.get("context", {}).get("scan_timeout_seconds") == 2, response.get(
        "context"
    )


@pytest.mark.asyncio
async def test_a_timed_out_workspace_scan_hides_a_limit_the_operator_chain_read(
    tmp_path, monkeypatch
):
    """Where an environment value the operator's chain read types to the
    limit, the reason names the option instead of the number, as the
    directory scan's does: the number is a value the environment held."""
    from automated_security_helper.config import default_config
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.utils.redacted_model import (
        carry_environment_values,
    )

    base = AshConfig()
    section = base.mcp_resource_management.model_copy(
        update={"scan_timeout_seconds": 2}
    )
    operator = base.model_copy(update={"mcp_resource_management": section})
    carry_environment_values(operator, ("2",))
    monkeypatch.setattr(
        default_config,
        "get_default_config",
        lambda confine=None, views=None, repository_file=None, reads=None, texts=None: (
            operator
        ),
    )
    _child_process_scans(monkeypatch, tmp_path, {"api": CHILD_SECONDS})
    workspace_file = _workspace(tmp_path, "api")

    with _no_loop_errors():
        response = await asyncio.wait_for(
            _scan_workspace(workspace_file), timeout=CHILD_SECONDS + 30
        )
    entries = _workspace_entries()

    if response.get("success") is not False or set(entries) != {"api"}:
        raise RuntimeError(("premise: the run timed out", response, entries))
    for where, text in (
        ("the response", response.get("error") or ""),
        ("api", entries["api"].error_message or ""),
    ):
        assert "configured scan_timeout_seconds" in text, (where, text)
        assert "'2' s" not in text, (where, text)
        # The option this tool reads is scan_timeout_seconds. A bare
        # "scan_timeout" is the directory scan's option name and must not
        # appear here under any composition of the two phrases.
        assert not re.search(r"\bscan_timeout\b(?!_seconds)", text), (where, text)
    # The WHOLE response hides the limit, not only its error text: the
    # response's context carried the raw number beside the text that hid it.
    context = response.get("context") or {}
    assert "scan_timeout_seconds" not in context, context
    assert "2" not in json.dumps(context, default=str), context


@pytest.mark.asyncio
async def test_a_value_that_is_not_the_limit_keeps_the_context_key(
    tmp_path, monkeypatch
):
    """The keep side of the gate: a run that carries an environment value
    which does NOT type to the limit shows the number and keeps the
    machine-readable copy. A gate that dropped the key whenever the run
    carried any value would hide the limit from clients on every run that
    read anything from the environment."""
    from automated_security_helper.config import default_config
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.utils.redacted_model import (
        carry_environment_values,
    )

    base = AshConfig()
    section = base.mcp_resource_management.model_copy(
        update={"scan_timeout_seconds": 2}
    )
    operator = base.model_copy(update={"mcp_resource_management": section})
    # "2s" does not type to the limit 2, so the token keeps the quoted form.
    carry_environment_values(operator, ("2s",))
    monkeypatch.setattr(
        default_config,
        "get_default_config",
        lambda confine=None, views=None, repository_file=None, reads=None, texts=None: (
            operator
        ),
    )
    _child_process_scans(monkeypatch, tmp_path, {"api": CHILD_SECONDS})
    workspace_file = _workspace(tmp_path, "api")

    with _no_loop_errors():
        response = await asyncio.wait_for(
            _scan_workspace(workspace_file), timeout=CHILD_SECONDS + 30
        )
    entries = _workspace_entries()

    if response.get("success") is not False or set(entries) != {"api"}:
        raise RuntimeError(("premise: the run timed out", response, entries))
    text = response.get("error") or ""
    assert "scan_timeout_seconds of '2' s" in text, text
    assert response.get("context", {}).get("scan_timeout_seconds") == 2, response.get(
        "context"
    )
