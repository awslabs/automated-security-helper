# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A build the auth value refuses leaves the shared server object as it was.

``build_streamable_http_app`` and ``build_sse_app`` both build their app on the
module-level ``MCPServer`` in ``cli.mcp_server``. The streamable-HTTP build puts a
new session manager on that object. Both builders used to call into it first and
build the auth middleware afterwards, so a library caller whose auth value was
refused (a character outside latin-1) got the refusal and kept the state the build
had already written. ``ash mcp`` is not affected, because its option check runs
before any build, but the builders are public.

The auth value is checked first now, before the transport security is read or the
server is touched.

The session workspace TTL is the same kind of argument: a library caller whose TTL
is refused (not a positive number of seconds) must get the refusal with the shared
server as it was, so the TTL is checked beside the auth value, before the build.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import build_sse_app, build_streamable_http_app
from automated_security_helper.cli.mcp_server import mcp as shared_server
from automated_security_helper.core.exceptions import ASHValidationError
from tests.utils.mcp_transport_harness import LOOPBACK_PORT

HEADER = "X-Ash-Token"
#: Two characters outside latin-1, named by code point.
SECRET = "token-" + chr(0x4E2D) + chr(0x6587)

#: Each builder with the method of the shared server it builds the app with.
BUILDERS = [
    pytest.param(
        build_streamable_http_app, "streamable_http_app", id="streamable-http"
    ),
    pytest.param(build_sse_app, "sse_app", id="sse"),
]


def _state() -> dict:
    """What the shared server holds: its own attributes and its low-level server's."""
    held = {}
    for owner_name, owner in (
        ("server", shared_server),
        ("low-level", getattr(shared_server, "_lowlevel_server", None)),
    ):
        if owner is not None:
            held.update(
                {(owner_name, key): value for key, value in vars(owner).items()}
            )
    return held


def _spy_on(monkeypatch, method: str) -> list:
    """Count calls to ``shared_server.<method>``, still running the real one."""
    calls: list = []
    real = getattr(shared_server, method)

    def spy(*args, **kwargs):
        calls.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(shared_server, method, spy)
    return calls


@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_refused_build_never_calls_into_the_shared_server(
    monkeypatch, build, method: str
) -> None:
    calls = _spy_on(monkeypatch, method)

    with pytest.raises(ASHValidationError, match="outside latin-1"):
        build(auth_header_name=HEADER, auth_header_value=SECRET, port=LOOPBACK_PORT)

    assert calls == []


@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_refused_build_leaves_the_shared_server_as_it_was(
    monkeypatch, build, method: str
) -> None:
    _spy_on(monkeypatch, method)
    before = _state()

    with pytest.raises(ASHValidationError, match="outside latin-1"):
        build(auth_header_name=HEADER, auth_header_value=SECRET, port=LOOPBACK_PORT)

    after = _state()
    assert after.keys() == before.keys()
    assert [key for key in before if after[key] is not before[key]] == []


@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_build_with_a_value_latin_1_carries_still_builds(
    monkeypatch, build, method: str
) -> None:
    """Control: a value the middleware accepts reaches the shared server once."""
    calls = _spy_on(monkeypatch, method)

    app = build(
        auth_header_name=HEADER, auth_header_value="ascii-token", port=LOOPBACK_PORT
    )

    assert app is not None
    assert len(calls) == 1


#: A session workspace TTL the builders refuse: zero, a negative number and a bool.
BAD_TTLS = [
    pytest.param(0, id="zero"),
    pytest.param(-5, id="negative"),
    pytest.param(True, id="bool"),
]


@pytest.mark.parametrize("ttl", BAD_TTLS)
@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_build_with_a_bad_workspace_ttl_never_calls_into_the_shared_server(
    monkeypatch, build, method: str, ttl
) -> None:
    calls = _spy_on(monkeypatch, method)

    with pytest.raises(ASHValidationError, match="--session-workspace-ttl"):
        build(session_workspace_ttl=ttl, port=LOOPBACK_PORT)

    assert calls == []


@pytest.mark.parametrize("ttl", BAD_TTLS)
@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_build_with_a_bad_workspace_ttl_leaves_the_shared_server_as_it_was(
    monkeypatch, build, method: str, ttl
) -> None:
    _spy_on(monkeypatch, method)
    before = _state()

    with pytest.raises(ASHValidationError, match="--session-workspace-ttl"):
        build(
            auth_header_name=HEADER,
            auth_header_value="ascii-token",
            session_workspace_ttl=ttl,
            port=LOOPBACK_PORT,
        )

    after = _state()
    assert after.keys() == before.keys()
    assert [key for key in before if after[key] is not before[key]] == []


@pytest.mark.parametrize(("build", "method"), BUILDERS)
def test_a_build_with_a_good_workspace_ttl_still_builds(
    monkeypatch, build, method: str
) -> None:
    """Control: a positive TTL reaches the shared server once."""
    calls = _spy_on(monkeypatch, method)

    app = build(session_workspace_ttl=3600, port=LOOPBACK_PORT)

    assert app is not None
    assert len(calls) == 1
