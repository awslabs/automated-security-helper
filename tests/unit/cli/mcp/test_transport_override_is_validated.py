# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ASH_MCP_TRANSPORT`` is read case- and space-insensitively, and an unknown value fails closed.

The variable is the operator's override that makes every caller remote. It was
compared verbatim against ``streamable-http`` and ``sse``, so ``Streamable-HTTP``
or a stray space, or a typo like ``streamable_http``, silently kept local trust
for every caller -- the opposite of what the operator set it to do. A value that
names a network transport in any spelling now counts as one, an unknown value
counts as remote for an in-process caller, and ``ash mcp`` refuses to start with
an unknown value.
"""

from __future__ import annotations

import pytest
import typer

from automated_security_helper.cli.mcp import mcp_command
from automated_security_helper.cli.mcp.sandbox import (
    caller_is_remote,
    get_server_transport,
)


@pytest.mark.parametrize(
    "value", ["Streamable-HTTP", " sse ", "SSE", "STREAMABLE-HTTP\n"]
)
def test_a_network_transport_in_any_case_or_spacing_makes_callers_remote(
    monkeypatch, value
) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", value)

    assert caller_is_remote(None) is True
    assert get_server_transport() == value.strip().lower()


@pytest.mark.parametrize("value", ["streamable_http", "http", "stdi0", "tcp"])
def test_an_unknown_value_fails_closed(monkeypatch, value) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", value)

    assert caller_is_remote(None) is True


@pytest.mark.parametrize("value", ["stdio", " STDIO ", ""])
def test_stdio_or_unset_keeps_the_local_default(monkeypatch, value) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", value)

    assert caller_is_remote(None) is False


class _Ctx:
    resilient_parsing = False


def test_the_server_refuses_to_start_with_an_unknown_value(monkeypatch) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable_http")
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda *a, **k: pytest.fail("the server started"),
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp_server.run_mcp_server",
        lambda: pytest.fail("the server started"),
    )

    with pytest.raises(typer.Exit) as excinfo:
        mcp_command(ctx=_Ctx(), transport="stdio", quiet=True)

    assert excinfo.value.exit_code == 3


def test_a_known_value_in_another_case_still_starts(monkeypatch) -> None:
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "Streamable-HTTP")
    started = {}
    monkeypatch.setattr(
        "automated_security_helper.cli.mcp._run_uvicorn",
        lambda app, host, port, log_level, listen_socket=None: started.update(ok=True),
    )

    mcp_command(ctx=_Ctx(), transport="streamable-http", host="127.0.0.1", quiet=True)

    assert started.get("ok") is True
