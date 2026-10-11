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
    "ASH_MCP_TRUST_UPSTREAM_HOST_CHECK",
    "ASH_MCP_SESSION_WORKSPACE_TTL",
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


class TestTrustUpstreamHostCheck:
    def test_the_agentcore_default_declares_the_upstream_check(
        self, monkeypatch, bound
    ) -> None:
        argv = _argv(monkeypatch, {})

        assert "--trust-upstream-host-check" in argv
        _starts(argv)

    def test_an_allowlist_replaces_the_declaration(self, monkeypatch, bound) -> None:
        argv = _argv(monkeypatch, {"ASH_MCP_ALLOWED_HOSTS": "ash-mcp.example.com"})

        assert "--trust-upstream-host-check" not in argv
        _starts(argv)

    def test_turning_it_off_without_an_allowlist_refuses_startup(
        self, monkeypatch, bound
    ) -> None:
        argv = _argv(monkeypatch, {"ASH_MCP_TRUST_UPSTREAM_HOST_CHECK": "false"})

        assert "--trust-upstream-host-check" not in argv
        result = CliRunner().invoke(ash_app, argv[1:])
        assert result.exit_code == 3, result.output
        assert bound["bound"] is False


class TestSessionWorkspaceTtl:
    def test_unset_leaves_ash_its_default(self, monkeypatch) -> None:
        assert "--session-workspace-ttl" not in _argv(monkeypatch, {})

    def test_set_is_passed_through(self, monkeypatch, bound) -> None:
        argv = _argv(monkeypatch, {"ASH_MCP_SESSION_WORKSPACE_TTL": "7200"})

        at = argv.index("--session-workspace-ttl")
        assert argv[at + 1] == "7200"
        _starts(argv)
        assert bound["kwargs"]["session_workspace_ttl"] == 7200
