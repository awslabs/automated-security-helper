# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sse transport's bind host and Host allowlist must reach the app.

Why this file exists
--------------------
``TestHostBinding`` in ``test_mcp_stateless_http.py`` pins this property for the
streamable-HTTP transport. It could not catch the same defect on sse, because
``build_sse_app`` took neither ``host`` nor ``allowed_hosts`` -- the arguments
whose absence *is* the defect. A property asserted on one of two transports that
call the same SDK autodetect is a property asserted on half the surface.

The mechanism is identical on both. ``MCPServer.sse_app`` declares
``host: str = "127.0.0.1"`` and, when ``transport_security`` is None and host is
loopback, installs an allowlist of exactly ``127.0.0.1``, ``localhost`` and
``[::1]``. So ``ash mcp --transport sse --host 0.0.0.0`` bound the wildcard
address and then answered 421 to every request whose Host header was not
loopback, and ``--allowed-host`` reached nothing at all.

Why the assertions read 421 against 400 rather than 200
-------------------------------------------------------
A POST to the sse message path is validated in two stages:
``TransportSecurityMiddleware.validate_request`` runs first and answers 421 on a
rejected Host, then ``handle_post_message`` answers 400 ``session_id is
required`` because these tests hold no session. 400 is therefore the signal that
the Host check *passed* -- it is the furthest a request can get without first
opening an sse stream, which is a long-lived GET that a TestClient cannot drive
to completion.

Asserting ``!= 421`` instead was rejected. It would also pass on a 404 from a
mount-path regression or a 500 from a broken app, so it would stop measuring the
Host allowlist while still looking green.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from automated_security_helper.cli.mcp import build_sse_app, mcp_command

#: Status the SDK returns when the Host header is not on the allowlist.
HOST_REJECTED = 421

#: Status the sse transport returns once the Host check has passed and it finds
#: no session id. Reaching this is the evidence that the allowlist accepted.
HOST_ACCEPTED_NO_SESSION = 400

#: A hostname a proxy or load balancer would put in the Host header. Not
#: loopback, which is the whole point.
PROXY_BASE_URL = "http://ash-mcp.example.com"

#: Any other name, to prove an explicit allowlist is an allowlist and not a
#: switch that turns protection off.
FOREIGN_BASE_URL = "http://attacker.example.net"


class _ResilientFalseCtx:
    """Stand-in typer.Context with ``resilient_parsing == False``."""

    resilient_parsing = False


def _post_message(app, base_url: str) -> int:
    """POST to the sse message path and return the status code.

    The mount path passed to ``build_sse_app`` names the *sse stream* route; the
    message path is the SDK's ``/messages/`` default and is what accepts a POST.
    """
    with TestClient(app, base_url=base_url) as client:
        return client.post(
            "/messages/", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}
        ).status_code


class TestHostReachesTheApp:
    def test_binding_all_interfaces_accepts_a_proxied_host_header(self) -> None:
        """The defect itself: 0.0.0.0 must not be built as though it were loopback."""
        app = build_sse_app(mount_path="/sse", host="0.0.0.0")
        assert _post_message(app, PROXY_BASE_URL) == HOST_ACCEPTED_NO_SESSION

    def test_loopback_bind_still_refuses_a_foreign_host_header(self) -> None:
        """Protection is worth keeping for the default local case.

        It is what stops a web page resolving a name to 127.0.0.1 and driving the
        scanner through the operator's own browser.
        """
        app = build_sse_app(mount_path="/sse", host="127.0.0.1")
        assert _post_message(app, PROXY_BASE_URL) == HOST_REJECTED

    def test_default_host_is_loopback_and_still_protected(self) -> None:
        """Omitting host must keep the SDK's protective default, not lose it."""
        app = build_sse_app(mount_path="/sse")
        assert _post_message(app, PROXY_BASE_URL) == HOST_REJECTED


class TestAllowedHostsReachesTheApp:
    def test_allowed_hosts_keeps_protection_on_for_a_known_deployment_host(
        self,
    ) -> None:
        """The right posture behind a proxy whose hostname is known."""
        app = build_sse_app(
            mount_path="/sse", host="0.0.0.0", allowed_hosts=["ash-mcp.example.com"]
        )
        assert _post_message(app, PROXY_BASE_URL) == HOST_ACCEPTED_NO_SESSION

    def test_allowed_hosts_refuses_a_host_not_on_the_list(self) -> None:
        app = build_sse_app(
            mount_path="/sse", host="0.0.0.0", allowed_hosts=["ash-mcp.example.com"]
        )
        assert _post_message(app, FOREIGN_BASE_URL) == HOST_REJECTED


class TestCommandWiring:
    """``mcp_command`` must hand both values to ``build_sse_app``.

    The app-level tests above pass ``host`` and ``allowed_hosts`` directly, so
    they stay green even if the CLI drops the operator's flags on the floor --
    which is exactly what it used to do. These pin the call.
    """

    @pytest.fixture
    def captured(self, monkeypatch):
        """Intercept ``build_sse_app`` and stop before uvicorn binds a socket."""
        seen: dict = {}

        def _fake_build(**kwargs):
            seen.update(kwargs)
            return object()

        def _fake_uvicorn(app, host, port, log_level):
            seen["uvicorn_host"] = host

        monkeypatch.setattr(
            "automated_security_helper.cli.mcp.build_sse_app", _fake_build
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.mcp._run_uvicorn", _fake_uvicorn
        )
        return seen

    def test_host_reaches_build_sse_app(self, captured) -> None:
        mcp_command(
            ctx=_ResilientFalseCtx(), transport="sse", host="0.0.0.0", quiet=True
        )
        assert captured.get("host") == "0.0.0.0"

    def test_the_app_is_built_with_the_host_uvicorn_binds(self, captured) -> None:
        """One host, not two.

        Passing a different value to the app than to uvicorn is the bug the
        argument exists to prevent, and it cannot be seen by checking either call
        alone.
        """
        mcp_command(
            ctx=_ResilientFalseCtx(), transport="sse", host="0.0.0.0", quiet=True
        )
        assert captured.get("host") == captured.get("uvicorn_host")

    def test_allowed_host_reaches_build_sse_app(self, captured) -> None:
        """The flag must not be accepted and discarded.

        ``--stateless-http`` on a non-streamable transport is loudly refused;
        ``--allowed-host`` on sse used to be accepted and silently dropped. Both
        options were added in the same change, so the two precedents disagreed.
        """
        mcp_command(
            ctx=_ResilientFalseCtx(),
            transport="sse",
            host="0.0.0.0",
            allowed_host=["ash-mcp.example.com"],
            quiet=True,
        )
        assert captured.get("allowed_hosts") == ["ash-mcp.example.com"]
