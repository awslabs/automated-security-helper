# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Terraform container entrypoint maps its environment onto ``ash mcp`` flags.

deploy/terraform/modules/ash-image-pipeline/files/ash-mcp-serve builds the
``ash mcp`` command line from ``ASH_MCP_*`` variables, because Bedrock AgentCore
Runtime cannot override a container's command. These pin the mappings for the
operator switches the MCP server gained, and check each resulting command line
is one ``ash mcp`` accepts.
"""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app as ash_app

ENTRYPOINT = (
    Path(__file__).resolve().parents[3]
    / "deploy/terraform/modules/ash-image-pipeline/files/ash-mcp-serve"
)

_VARIABLES = (
    "ASH_MCP_TRANSPORT",
    "ASH_MCP_HOST",
    "ASH_MCP_PORT",
    "ASH_MCP_MOUNT_PATH",
    "ASH_MCP_STATELESS_HTTP",
    "ASH_MCP_AUTH_HEADER_NAME",
    "ASH_MCP_AUTH_HEADER_VALUE",
    "ASH_MCP_ALLOWED_HOSTS",
    "ASH_MCP_TRUST_UPSTREAM_SESSION_ID",
)


def _argv(monkeypatch, env: Dict[str, str]) -> List[str]:
    for name in _VARIABLES:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    loader = SourceFileLoader("ash_mcp_serve_flags_under_test", str(ENTRYPOINT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module.build_argv()


@pytest.fixture
def bound(monkeypatch) -> Dict[str, object]:
    """Stand in for the app builders and uvicorn, recording what would start."""
    seen: Dict[str, object] = {"bound": False}

    def _build(**kwargs):
        seen["kwargs"] = kwargs
        return object()

    def _serve(app, host, port, log_level):
        seen["bound"] = True

    monkeypatch.setattr(
        "automated_security_helper.cli.mcp.build_streamable_http_app", _build
    )
    monkeypatch.setattr("automated_security_helper.cli.mcp.build_sse_app", _build)
    monkeypatch.setattr("automated_security_helper.cli.mcp._run_uvicorn", _serve)
    return seen


def _starts(argv: List[str]) -> None:
    result = CliRunner().invoke(ash_app, argv[1:])
    assert result.exit_code == 0, f"{argv}\n{result.output}"


class TestTrustUpstreamSessionId:
    def test_off_by_default(self, monkeypatch) -> None:
        assert "--trust-upstream-session-id" not in _argv(monkeypatch, {})

    def test_set_for_a_stateless_server(self, monkeypatch, bound) -> None:
        argv = _argv(monkeypatch, {"ASH_MCP_TRUST_UPSTREAM_SESSION_ID": "true"})

        assert "--trust-upstream-session-id" in argv
        _starts(argv)
        assert bound["kwargs"]["trust_upstream_session_id"] is True

    @pytest.mark.parametrize(
        "env",
        [
            {"ASH_MCP_STATELESS_HTTP": "false"},
            {"ASH_MCP_TRANSPORT": "sse"},
        ],
        ids=["stateful", "sse"],
    )
    def test_never_emitted_where_the_server_issues_sessions(
        self, monkeypatch, bound, env
    ) -> None:
        argv = _argv(monkeypatch, {**env, "ASH_MCP_TRUST_UPSTREAM_SESSION_ID": "1"})

        assert "--trust-upstream-session-id" not in argv
