# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A non-loopback bind without a Host allowlist is refused at startup.

The MCP SDK checks the Host and Origin headers (its DNS-rebinding protection)
only when the app is built for a loopback host, and ASH builds the app with the
host it binds. So ``ash mcp --host 0.0.0.0`` with no ``--allowed-host`` serves
any Host and any Origin. The required behavior is a startup refusal with an
actionable error naming ``--allowed-host``, unless the operator passes an
explicit opt-out that says Host and Origin checking happens in front of ASH.
That opt-out is not exercised here because its spelling belongs to the change
that adds it; its tests belong with it.

The controls show the same path still starts for a loopback host and for a
non-loopback host that names its allowlist, and that the container entrypoint
shipped under deploy/terraform still produces a command line ASH accepts.
"""

from __future__ import annotations

import importlib.util
import re
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import Dict, List

import pytest
import typer
from starlette.testclient import TestClient
from typer.testing import CliRunner

from automated_security_helper.cli.main import app as ash_app
from automated_security_helper.cli.mcp import (
    build_sse_app,
    build_streamable_http_app,
    mcp_command,
)
from automated_security_helper.core.exceptions import ASHValidationError

REPO_ROOT = Path(__file__).resolve().parents[3]
TERRAFORM_ENTRYPOINT = (
    REPO_ROOT / "deploy/terraform/modules/ash-image-pipeline/files/ash-mcp-serve"
)

NON_LOOPBACK_HOSTS = ["0.0.0.0", "::", "192.0.2.10", "ash-mcp.example.com"]
LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "::1"]
HTTP_TRANSPORTS = ["streamable-http", "sse"]

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


class _ResilientFalseCtx:
    """Stand-in typer.Context with ``resilient_parsing == False``."""

    resilient_parsing = False


@pytest.fixture
def startup(monkeypatch) -> Dict[str, object]:
    """Record whether an app was built and a socket would have been bound."""
    seen: Dict[str, object] = {"built": False, "bound": False}

    def _fake_build(**kwargs):
        seen["built"] = True
        seen["kwargs"] = kwargs
        return object()

    def _fake_uvicorn(app, host, port, log_level, listen_socket=None):
        seen["bound"] = True
        seen["host"] = host

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp.build_streamable_http_app", _fake_build
    )
    monkeypatch.setattr("automated_security_helper.cli.mcp.build_sse_app", _fake_build)
    monkeypatch.setattr("automated_security_helper.cli.mcp._run_uvicorn", _fake_uvicorn)
    return seen


def _plain(text: str) -> str:
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", text).split())


# ---------------------------------------------------------------------------
# Startup refusal
# ---------------------------------------------------------------------------


class TestNonLoopbackBindWithoutAllowlist:
    @pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
    @pytest.mark.parametrize("host", NON_LOOPBACK_HOSTS)
    def test_mcp_command_refuses_to_start(self, startup, transport, host) -> None:
        with pytest.raises(typer.Exit) as excinfo:
            mcp_command(
                ctx=_ResilientFalseCtx(), transport=transport, host=host, quiet=True
            )

        assert excinfo.value.exit_code == 3
        assert startup["bound"] is False, "the server bound a socket anyway"

    @pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
    def test_the_cli_refuses_with_an_error_naming_the_allowlist_flag(
        self, startup, transport
    ) -> None:
        result = CliRunner().invoke(
            ash_app, ["mcp", "--transport", transport, "--host", "0.0.0.0"]
        )

        assert result.exit_code == 3, (
            f"`ash mcp --transport {transport} --host 0.0.0.0` started: "
            f"exit {result.exit_code}\n{result.output}"
        )
        assert startup["bound"] is False
        assert "--allowed-host" in _plain(result.output), result.output

    def test_stateless_streamable_http_is_refused_too(self, startup) -> None:
        with pytest.raises(typer.Exit) as excinfo:
            mcp_command(
                ctx=_ResilientFalseCtx(),
                transport="streamable-http",
                host="0.0.0.0",
                stateless_http=True,
                quiet=True,
            )

        assert excinfo.value.exit_code == 3


class TestBindsThatStillStart:
    """Controls: the same startup path, with inputs that need no refusal."""

    @pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
    @pytest.mark.parametrize("host", LOOPBACK_HOSTS)
    def test_a_loopback_bind_starts(self, startup, transport, host) -> None:
        mcp_command(
            ctx=_ResilientFalseCtx(), transport=transport, host=host, quiet=True
        )

        assert startup["bound"] is True
        assert startup["host"] == host

    @pytest.mark.parametrize("transport", HTTP_TRANSPORTS)
    def test_a_non_loopback_bind_with_an_allowlist_starts(
        self, startup, transport
    ) -> None:
        mcp_command(
            ctx=_ResilientFalseCtx(),
            transport=transport,
            host="0.0.0.0",
            allowed_host=["ash-mcp.example.com"],
            quiet=True,
        )

        assert startup["bound"] is True
        assert startup["kwargs"]["allowed_hosts"] == ["ash-mcp.example.com"]


# ---------------------------------------------------------------------------
# The app never serves a foreign Host or Origin unless told checking is elsewhere
# ---------------------------------------------------------------------------


def _refused_or_status(build, base_url: str, headers: Dict[str, str], path: str):
    """Build the app and POST once; None means the build itself refused."""
    try:
        app = build()
    except (ASHValidationError, ValueError):
        return None
    with TestClient(app, base_url=base_url) as client:
        return client.post(path, json=INITIALIZE, headers=headers).status_code


class TestLoopbackAliasKeepsProtection:
    """``127.0.0.2`` is a loopback address the SDK does not recognize as one.

    A page resolving its own name to any 127/8 address reaches a server bound
    there, so the Host check matters as much as it does for ``127.0.0.1``.
    """

    def test_streamable_http_rejects_a_foreign_host(self) -> None:
        status = _refused_or_status(
            lambda: build_streamable_http_app(mount_path="/mcp", host="127.0.0.2"),
            "http://ash-mcp.example.com",
            STREAMABLE_HEADERS,
            "/mcp",
        )
        assert status in (None, 421), f"a foreign Host was served: {status}"

    def test_sse_rejects_a_foreign_host(self) -> None:
        status = _refused_or_status(
            lambda: build_sse_app(mount_path="/sse", host="127.0.0.2"),
            "http://ash-mcp.example.com",
            {"Content-Type": "application/json"},
            "/messages/",
        )
        assert status in (None, 421), f"a foreign Host was served: {status}"


# ---------------------------------------------------------------------------
# Deploy targets keep starting (guard: green before the change, must stay green)
# ---------------------------------------------------------------------------


def _terraform_entrypoint_argv(monkeypatch, env: Dict[str, str]) -> List[str]:
    for name in (
        "ASH_MCP_TRANSPORT",
        "ASH_MCP_HOST",
        "ASH_MCP_PORT",
        "ASH_MCP_MOUNT_PATH",
        "ASH_MCP_STATELESS_HTTP",
        "ASH_MCP_AUTH_HEADER_NAME",
        "ASH_MCP_AUTH_HEADER_VALUE",
        "ASH_MCP_ALLOWED_HOSTS",
        "ASH_MCP_TRUST_UPSTREAM_HOST_CHECK",
        "ASH_MCP_TRUST_UPSTREAM_SESSION_ID",
        "ASH_MCP_SESSION_WORKSPACE_TTL",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    loader = SourceFileLoader("ash_mcp_serve_under_test", str(TERRAFORM_ENTRYPOINT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module.build_argv()


@pytest.mark.parametrize(
    "env",
    [
        # The environment deploy/terraform/modules/agentcore sets: the platform
        # restricts Host, so the module declares that check is upstream.
        {"ASH_MCP_TRUST_UPSTREAM_HOST_CHECK": "true"},
        {"ASH_MCP_ALLOWED_HOSTS": "ash-mcp.example.com"},
    ],
    ids=["agentcore", "with-allowed-hosts"],
)
def test_the_terraform_entrypoint_command_line_starts(
    startup, monkeypatch, env
) -> None:
    argv = _terraform_entrypoint_argv(monkeypatch, env)
    assert argv[:2] == ["ash", "mcp"], argv

    result = CliRunner().invoke(ash_app, argv[1:])

    assert result.exit_code == 0, (
        f"the deploy entrypoint's command line no longer starts: {argv}\n"
        f"{result.output}"
    )
    assert startup["bound"] is True


def test_the_terraform_entrypoint_defaults_refuse_a_wildcard_bind(
    startup, monkeypatch
) -> None:
    """An empty environment binds 0.0.0.0 with no Host check declared: refused."""
    argv = _terraform_entrypoint_argv(monkeypatch, {})

    result = CliRunner().invoke(ash_app, argv[1:])

    assert result.exit_code == 3, (argv, result.output)
    assert startup["bound"] is False
