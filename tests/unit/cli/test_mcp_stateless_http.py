# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ``--stateless-http`` toggle on the streamable-HTTP transport.

Why this toggle exists
----------------------
A managed runtime that load-balances MCP requests across replicas cannot rely on
one replica holding a session: the next request may land elsewhere. Such a runtime
also typically injects its own ``Mcp-Session-Id`` header, one the server never
issued. A stateful server treats that as a session it has lost and refuses the
request.

``test_stateful_rejects_a_session_id_it_did_not_issue`` and its stateless
counterpart pin exactly that difference, so the behaviour is settled here rather
than being rediscovered against a live deployment.

The default stays stateful, which is what ASH did before this toggle existed.
"""

from __future__ import annotations

import re

import pytest
import typer
from starlette.testclient import TestClient
from typer.testing import CliRunner

from automated_security_helper.cli.main import app as ash_app
from automated_security_helper.cli.mcp import build_streamable_http_app, mcp_command

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

# Both are required by the streamable-HTTP spec; omitting the SSE type makes the
# server reject the request on content negotiation before session handling is
# reached, which would make these tests pass for the wrong reason.
CLIENT_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

# A syntactically valid session id the server has certainly never issued -- the
# shape of thing a managed runtime injects.
FOREIGN_SESSION_ID = "0123456789abcdef0123456789abcdef"

# Every request in these tests must carry a Host the server accepts, or it is
# refused at 421 before session handling is reached. An earlier draft of this file
# used TestClient's default ``http://testserver`` and every session assertion
# passed on the 421 instead of the 404 it meant to observe -- both are 4xx.
LOCALHOST_BASE_URL = "http://127.0.0.1:8000"


class _ResilientFalseCtx:
    """Stand-in typer.Context with ``resilient_parsing == False``."""

    resilient_parsing = False


class TestWiring:
    def test_flag_reaches_the_sdk(self, monkeypatch) -> None:
        """``stateless_http`` must arrive as a keyword on ``streamable_http_app``.

        Pinned because the SDK takes it per call. An earlier version of this code
        set the mount path by assigning to a settings field instead, which broke
        when the SDK dropped the field -- and, worse, mutated a module-level
        singleton as a side effect.
        """
        from automated_security_helper.cli import mcp_server

        captured: dict = {}

        def _fake_app(**kwargs):
            captured.update(kwargs)
            return object()

        monkeypatch.setattr(mcp_server.mcp, "streamable_http_app", _fake_app)
        build_streamable_http_app(mount_path="/mcp", stateless_http=True)
        assert captured.get("stateless_http") is True

    def test_default_is_stateful(self, monkeypatch) -> None:
        """Omitting the flag must keep the pre-existing stateful behaviour."""
        from automated_security_helper.cli import mcp_server

        captured: dict = {}

        def _fake_app(**kwargs):
            captured.update(kwargs)
            return object()

        monkeypatch.setattr(mcp_server.mcp, "streamable_http_app", _fake_app)
        build_streamable_http_app(mount_path="/mcp")
        assert captured.get("stateless_http") is False


def _post(app, headers, base_url=LOCALHOST_BASE_URL):
    """POST an initialize request, with the app's lifespan running.

    TestClient is used as a context manager because the streamable-HTTP session
    manager builds its task group at startup and raises "Task group is not
    initialized" on the first request otherwise. The sibling auth tests get away
    with a bare TestClient only because the 401 middleware answers before the
    session manager is ever reached.
    """
    with TestClient(app, base_url=base_url) as client:
        return client.post("/mcp", json=INITIALIZE, headers=headers)


class TestSessionHandling:
    """The behavioural difference, asserted against a real ASGI app."""

    def test_stateful_rejects_a_session_id_it_did_not_issue(self) -> None:
        app = build_streamable_http_app(mount_path="/mcp", stateless_http=False)
        resp = _post(app, {**CLIENT_HEADERS, "Mcp-Session-Id": FOREIGN_SESSION_ID})
        # 404 specifically, not merely "some 4xx". A bad Host is 421 and a bad
        # token is 401; accepting any 4xx here let this assertion pass on a host
        # rejection while claiming to have observed a session rejection.
        assert resp.status_code == 404, f"{resp.status_code}: {resp.text[:200]}"
        assert "session" in resp.text.lower()

    def test_stateless_accepts_a_session_id_it_did_not_issue(self) -> None:
        app = build_streamable_http_app(mount_path="/mcp", stateless_http=True)
        resp = _post(app, {**CLIENT_HEADERS, "Mcp-Session-Id": FOREIGN_SESSION_ID})
        assert resp.status_code == 200, (
            f"stateless mode must ignore a foreign session id, got "
            f"{resp.status_code}: {resp.text[:200]}"
        )

    def test_stateless_initialize_succeeds_without_any_session_header(self) -> None:
        app = build_streamable_http_app(mount_path="/mcp", stateless_http=True)
        resp = _post(app, CLIENT_HEADERS)
        assert resp.status_code == 200, f"{resp.status_code}: {resp.text[:200]}"

    def test_stateful_initialize_succeeds_without_any_session_header(self) -> None:
        # The control for the two above: proves the 404 is about the foreign
        # session id and not about stateful mode refusing the request shape.
        app = build_streamable_http_app(mount_path="/mcp", stateless_http=False)
        resp = _post(app, CLIENT_HEADERS)
        assert resp.status_code == 200, f"{resp.status_code}: {resp.text[:200]}"


class TestHostBinding:
    """The bind host must reach the app, not just uvicorn.

    The MCP SDK auto-enables DNS-rebinding protection when the app is built with
    a loopback ``host``, allowing only ``127.0.0.1``, ``localhost`` and ``[::1]``
    in the Host header. ASH used to bind uvicorn to whatever ``--host`` said while
    building the app with the SDK's ``127.0.0.1`` default, so a server started with
    ``--host 0.0.0.0`` answered 421 Misdirected Request to every request whose Host
    header was anything else -- which is every request arriving through a load
    balancer, and every request from another machine.
    """

    PROXY_BASE_URL = "http://ash-mcp.example.com"

    def test_binding_all_interfaces_accepts_a_proxied_host_header(self) -> None:
        app = build_streamable_http_app(
            mount_path="/mcp", stateless_http=True, host="0.0.0.0"
        )
        resp = _post(app, CLIENT_HEADERS, base_url=self.PROXY_BASE_URL)
        assert resp.status_code == 200, (
            f"a server bound to 0.0.0.0 must accept a proxied Host header, got "
            f"{resp.status_code}: {resp.text[:200]}"
        )

    def test_loopback_bind_still_refuses_a_foreign_host_header(self) -> None:
        # The protection is worth keeping for the default local case: it is what
        # stops a web page resolving a name to 127.0.0.1 and driving the scanner.
        app = build_streamable_http_app(
            mount_path="/mcp", stateless_http=True, host="127.0.0.1"
        )
        resp = _post(app, CLIENT_HEADERS, base_url=self.PROXY_BASE_URL)
        assert resp.status_code == 421, f"{resp.status_code}: {resp.text[:200]}"

    def test_default_host_is_loopback_and_still_protected(self) -> None:
        app = build_streamable_http_app(mount_path="/mcp", stateless_http=True)
        resp = _post(app, CLIENT_HEADERS, base_url=self.PROXY_BASE_URL)
        assert resp.status_code == 421, f"{resp.status_code}: {resp.text[:200]}"

    def test_allowed_hosts_keeps_protection_on_for_a_known_deployment_host(
        self,
    ) -> None:
        # The best posture behind a proxy whose hostname is known: keep the
        # protection rather than switching it off by binding 0.0.0.0.
        app = build_streamable_http_app(
            mount_path="/mcp",
            stateless_http=True,
            host="0.0.0.0",
            allowed_hosts=["ash-mcp.example.com"],
        )
        assert (
            _post(app, CLIENT_HEADERS, base_url=self.PROXY_BASE_URL).status_code == 200
        )

    def test_allowed_hosts_refuses_a_host_not_on_the_list(self) -> None:
        app = build_streamable_http_app(
            mount_path="/mcp",
            stateless_http=True,
            host="0.0.0.0",
            allowed_hosts=["ash-mcp.example.com"],
        )
        resp = _post(app, CLIENT_HEADERS, base_url="http://attacker.example.net")
        assert resp.status_code == 421, f"{resp.status_code}: {resp.text[:200]}"


class TestOptionValidation:
    """Exit code 3, not a propagated exception.

    ``mcp_command`` catches ``ASHValidationError`` and converts it to
    ``typer.Exit(3)``, which is the contract its existing tests assert
    (``test_quiet_with_verbose_raises_exit_3``). Caught as ``typer.Exit`` rather
    than ``click.exceptions.Exit``: typer 0.27 vendors click as ``typer._click``,
    so the two are no longer the same class and catching click's lets the
    exception escape.
    """

    @pytest.mark.parametrize("transport", ["stdio", "sse"])
    def test_stateless_with_a_non_streamable_transport_is_refused(
        self, transport
    ) -> None:
        """``--stateless-http`` means nothing off streamable-http, so it errors.

        Silently ignoring it would leave an operator believing their server was
        stateless when it was not -- the same reasoning the scan command applies
        to workspace-only flags. Only the affirmative case is refused: an explicit
        ``--no-stateless-http`` is indistinguishable from the default and harmless.
        """
        with pytest.raises(typer.Exit) as excinfo:
            mcp_command(
                ctx=_ResilientFalseCtx(),
                transport=transport,
                stateless_http=True,
                quiet=True,
            )
        assert excinfo.value.exit_code == 3

    def test_no_stateless_http_with_stdio_is_accepted(self, monkeypatch) -> None:
        """The default must not be mistaken for an explicit request.

        Without this, adding the validation would break every existing stdio
        invocation.
        """
        called: dict = {}

        def _fake_run():
            called["ran"] = True

        monkeypatch.setattr(
            "automated_security_helper.cli.mcp_server.run_mcp_server", _fake_run
        )
        mcp_command(
            ctx=_ResilientFalseCtx(),
            transport="stdio",
            stateless_http=False,
            quiet=True,
        )
        assert called.get("ran") is True


def test_wrapper_exposes_the_flag() -> None:
    """``ash mcp --help`` must list ``--stateless-http``.

    The typer wrapper in ``cli/main.py`` duplicates every ``mcp_command``
    parameter, so a parameter added to one and not the other yields ``unknown
    option`` at the real CLI while unit tests calling ``mcp_command`` directly
    stay green.
    """
    runner = CliRunner()
    result = runner.invoke(ash_app, ["mcp", "--help"])
    assert result.exit_code == 0, result.output
    # Rich styles each flag segment separately, so escape codes sit inside the
    # flag token and a raw substring search never matches.
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    flat = " ".join(plain.split())
    assert "--stateless-http" in flat, (
        f"Missing --stateless-http in `ash mcp --help`:\n{result.output}"
    )
