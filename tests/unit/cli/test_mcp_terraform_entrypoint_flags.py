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
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType
from typing import Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app as ash_app
from automated_security_helper.cli.mcp import (
    _auth_value_from_bytes,
    _header_wire_bytes,
)
from automated_security_helper.core.exceptions import ASHValidationError

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
    "ASH_MCP_AUTH_HEADER_VALUE_FD",
    "ASH_MCP_ALLOWED_HOSTS",
    "ASH_MCP_TRUST_UPSTREAM_SESSION_ID",
    "ASH_MCP_TRUST_UPSTREAM_HOST_CHECK",
    "ASH_MCP_SESSION_WORKSPACE_TTL",
)


def _entrypoint(monkeypatch, env: Dict[str, str]) -> ModuleType:
    for name in _VARIABLES:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    loader = SourceFileLoader("ash_mcp_serve_flags_under_test", str(ENTRYPOINT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _argv(monkeypatch, env: Dict[str, str]) -> List[str]:
    return _entrypoint(monkeypatch, env).build_argv()


@pytest.fixture
def bound(monkeypatch) -> Dict[str, object]:
    """Stand in for the app builders and uvicorn, recording what would start."""
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


#: What deploy/terraform/modules/agentcore sets: the platform restricts Host.
AGENTCORE = {"ASH_MCP_TRUST_UPSTREAM_HOST_CHECK": "true"}


def _starts(argv: List[str]) -> None:
    result = CliRunner().invoke(ash_app, argv[1:])
    assert result.exit_code == 0, f"{argv}\n{result.output}"


class TestTrustUpstreamSessionId:
    def test_off_by_default(self, monkeypatch) -> None:
        assert "--trust-upstream-session-id" not in _argv(monkeypatch, {})

    def test_set_for_a_stateless_server(self, monkeypatch, bound) -> None:
        argv = _argv(
            monkeypatch, {**AGENTCORE, "ASH_MCP_TRUST_UPSTREAM_SESSION_ID": "true"}
        )

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
    def test_off_by_default(self, monkeypatch, bound) -> None:
        argv = _argv(monkeypatch, {})

        assert "--trust-upstream-host-check" not in argv

    def test_declared_when_set_true(self, monkeypatch, bound) -> None:
        argv = _argv(monkeypatch, AGENTCORE)

        assert "--trust-upstream-host-check" in argv
        _starts(argv)

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
    def test_never_declared_for_a_loopback_bind(self, monkeypatch, bound, host) -> None:
        """A loopback server checks its own origin; the declaration would undo that."""
        argv = _argv(monkeypatch, {**AGENTCORE, "ASH_MCP_HOST": host})

        assert "--trust-upstream-host-check" not in argv
        _starts(argv)

    def test_never_declared_for_stdio(self, monkeypatch, bound) -> None:
        argv = _argv(monkeypatch, {**AGENTCORE, "ASH_MCP_TRANSPORT": "stdio"})

        assert "--trust-upstream-host-check" not in argv

    def test_an_allowlist_replaces_the_declaration(self, monkeypatch, bound) -> None:
        argv = _argv(monkeypatch, {"ASH_MCP_ALLOWED_HOSTS": "ash-mcp.example.com"})

        assert "--trust-upstream-host-check" not in argv
        _starts(argv)

    @pytest.mark.parametrize(
        "env",
        [{}, {"ASH_MCP_TRUST_UPSTREAM_HOST_CHECK": "false"}],
        ids=["unset", "false"],
    )
    def test_without_it_or_an_allowlist_startup_is_refused(
        self, monkeypatch, bound, env
    ) -> None:
        argv = _argv(monkeypatch, env)

        assert "--trust-upstream-host-check" not in argv
        result = CliRunner().invoke(ash_app, argv[1:])
        assert result.exit_code == 3, result.output
        assert bound["bound"] is False


class TestSessionWorkspaceTtl:
    def test_unset_leaves_ash_its_default(self, monkeypatch) -> None:
        assert "--session-workspace-ttl" not in _argv(monkeypatch, {})

    def test_set_is_passed_through(self, monkeypatch, bound) -> None:
        argv = _argv(
            monkeypatch, {**AGENTCORE, "ASH_MCP_SESSION_WORKSPACE_TTL": "7200"}
        )

        at = argv.index("--session-workspace-ttl")
        assert argv[at + 1] == "7200"
        _starts(argv)
        assert bound["kwargs"]["session_workspace_ttl"] == 7200


def test_the_transport_is_passed_in_its_canonical_spelling(monkeypatch, bound) -> None:
    argv = _argv(monkeypatch, {**AGENTCORE, "ASH_MCP_TRANSPORT": "Streamable-HTTP"})

    assert argv[argv.index("--transport") + 1] == "streamable-http"
    _starts(argv)


#: A letter latin-1 carries and a character it does not, named by code point.
O_UMLAUT = chr(0xF6)
EURO_SIGN = chr(0x20AC)


def _handed_over(monkeypatch, value: str) -> bytes:
    """What ``ash mcp --auth-header-value-fd`` would read: the descriptor's content.

    The entrypoint is run as an image whose ``ash mcp`` has that option would run it,
    with ``ASH_MCP_AUTH_HEADER_VALUE`` set to ``value``.
    """
    module = _entrypoint(
        monkeypatch,
        {
            "ASH_MCP_AUTH_HEADER_NAME": "X-Ash-Token",
            "ASH_MCP_AUTH_HEADER_VALUE": value,
        },
    )
    monkeypatch.setattr(module, "_ash_mcp_supports", lambda flag: True)
    argv = module.build_argv()
    assert "--auth-header-value" not in argv, "the value is on the command line"
    fd = int(argv[argv.index("--auth-header-value-fd") + 1])
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        return os.read(fd, 65536)
    finally:
        os.close(fd)


@pytest.mark.skipif(
    not hasattr(os, "memfd_create"),
    reason="the entrypoint hands the value over in a memfd",
)
class TestAuthHeaderValue:
    """``ASH_MCP_AUTH_HEADER_VALUE`` reaches ``ash mcp`` on a descriptor, trimmed.

    The entrypoint drops whitespace at both ends of the value and hands the rest over
    as UTF-8 bytes, so a secret that ends in a newline, and a value with a non-ASCII
    character, are values ``ash mcp`` takes; a line break inside the value is still
    refused by ``ash mcp`` itself.
    """

    @pytest.mark.parametrize(
        "value",
        ["tok-a\n", "tok-a \n", " tok-a\t\r\n", "tok-a"],
        ids=["newline", "blank-and-newline", "blanks-and-crlf", "bare"],
    )
    def test_whitespace_at_the_ends_is_dropped_before_ash_sees_the_value(
        self, monkeypatch, value
    ) -> None:
        handed = _handed_over(monkeypatch, value)

        assert handed == b"tok-a"
        assert _auth_value_from_bytes(handed, "the descriptor") == "tok-a"

    def test_a_non_ascii_value_is_handed_over_as_its_utf8_bytes(
        self, monkeypatch
    ) -> None:
        """ash reads the bytes as latin-1 and compares the wire bytes, which are the
        UTF-8 bytes a client that sends UTF-8 puts on the wire."""
        value = "tok-" + O_UMLAUT + EURO_SIGN

        handed = _handed_over(monkeypatch, value)

        assert handed == value.encode("utf-8")
        assert _header_wire_bytes(_auth_value_from_bytes(handed, "the fd")) == handed

    def test_a_line_break_inside_the_value_is_still_refused_by_ash(
        self, monkeypatch
    ) -> None:
        handed = _handed_over(monkeypatch, "tok-a\nb")

        assert handed == b"tok-a\nb"
        with pytest.raises(ASHValidationError, match="control character"):
            _auth_value_from_bytes(handed, "the descriptor")
