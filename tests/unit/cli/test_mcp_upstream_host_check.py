# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--trust-upstream-host-check``: the explicit opt-out from ASH's Host check.

``test_mcp_non_loopback_bind_is_refused.py`` covers the refusal. A deployment
whose Host and Origin checking happens in front of ASH (Bedrock AgentCore
Runtime restricts Host itself and cannot be given an allowlist in advance) says
so with this flag; these tests cover what it permits and where it is refused.
"""

from __future__ import annotations

from typing import Dict

import pytest
import typer
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import (
    build_sse_app,
    build_streamable_http_app,
    mcp_command,
)
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.exceptions import ASHValidationError

# Every all-interfaces host below is the non-loopback bind the opt-out exists
# for, so the address is the condition under test. The trailing bandit markers
# say that to B104.
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "ash-test", "version": "0"},
    },
}
STREAMABLE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


class _Ctx:
    resilient_parsing = False


@pytest.fixture
def startup(monkeypatch) -> Dict[str, object]:
    seen: Dict[str, object] = {"bound": False}

    def _build(**kwargs):
        seen["kwargs"] = kwargs
        return object()

    def _serve(app, host, port, log_level, listen_socket=None):
        seen["bound"] = True

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp.build_streamable_http_app", _build
    )
    monkeypatch.setattr("automated_security_helper.cli.mcp.build_sse_app", _build)
    monkeypatch.setattr("automated_security_helper.cli.mcp._run_uvicorn", _serve)
    return seen


@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
def test_a_non_loopback_bind_starts_with_the_opt_out(startup, transport) -> None:
    mcp_command(
        ctx=_Ctx(),
        transport=transport,
        host="0.0.0.0",  # nosec B104
        trust_upstream_host_check=True,
        quiet=True,
    )

    assert startup["bound"] is True
    assert startup["kwargs"]["trust_upstream_host_check"] is True


def test_the_opt_out_app_serves_a_proxied_host() -> None:
    """With the opt-out the app checks no Host: that is what the flag claims."""
    app = build_streamable_http_app(
        mount_path="/mcp",
        stateless_http=True,
        host="0.0.0.0",  # nosec B104
        trust_upstream_host_check=True,
    )
    with TestClient(app, base_url="http://ash-mcp.example.com") as client:
        status = client.post("/mcp", json=INITIALIZE, headers=STREAMABLE_HEADERS)

    assert status.status_code == 200, status.text[:200]


@pytest.mark.parametrize("build", [build_streamable_http_app, build_sse_app])
def test_the_builders_refuse_the_opt_out_with_an_allowlist(build) -> None:
    with pytest.raises(ASHValidationError, match="contradict"):
        build(
            host="0.0.0.0",  # nosec B104
            allowed_hosts=["ash-mcp.example.com"],
            trust_upstream_host_check=True,
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "transport": "streamable-http",
            "host": "0.0.0.0",  # nosec B104
            "allowed_host": ["ash-mcp.example.com"],
            "trust_upstream_host_check": True,
        },
        {"transport": "stdio", "trust_upstream_host_check": True},
    ],
    ids=["with-allowlist", "stdio"],
)
def test_the_opt_out_is_refused_where_it_means_nothing(startup, kwargs) -> None:
    with pytest.raises(typer.Exit) as excinfo:
        mcp_command(ctx=_Ctx(), quiet=True, **kwargs)

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR
    assert startup["bound"] is False


LOOPBACK = ["127.0.0.1", "localhost", "::1"]


@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
@pytest.mark.parametrize("host", LOOPBACK)
def test_the_opt_out_is_refused_on_a_loopback_bind(startup, transport, host) -> None:
    """A loopback server checks its own origin; the flag would only turn that off."""
    with pytest.raises(typer.Exit) as excinfo:
        mcp_command(
            ctx=_Ctx(),
            transport=transport,
            host=host,
            trust_upstream_host_check=True,
            quiet=True,
        )

    assert excinfo.value.exit_code == ASH_EXIT_USAGE_ERROR
    assert startup["bound"] is False


@pytest.mark.parametrize("build", [build_streamable_http_app, build_sse_app])
@pytest.mark.parametrize("host", LOOPBACK)
def test_the_builders_refuse_the_opt_out_on_a_loopback_bind(build, host) -> None:
    with pytest.raises(ASHValidationError, match="--allowed-host"):
        build(host=host, trust_upstream_host_check=True)
