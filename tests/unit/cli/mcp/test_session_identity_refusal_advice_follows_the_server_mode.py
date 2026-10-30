# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The session refusal's advice holds on the server the request reached.

An unidentified sse caller was given the stateless advice, which names
``--trust-upstream-session-id``, a flag ``ash mcp`` refuses on sse: an advice
nobody can follow. The refusal also read its stamp from any object with a
``request_context`` attribute, while ``resolve_caller_session_id`` admits only a
Context the SDK built, so a stand-in could be identified one way and advised
another. The refusal now has an sse branch, reads the stamp through the same
type test as the resolution, and takes its context as a required keyword so a
caller that has one cannot leave it out.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli.mcp.http_sessions import (
    CALLER_SCOPE_KEY,
    MODE_SSE,
    MODE_STATEFUL,
    MODE_STATELESS,
    SSE,
    STREAMABLE_HTTP,
    HttpCaller,
)
from automated_security_helper.cli.mcp.session_identity import (
    SESSION_IDENTITY_REQUIRED,
    UNIDENTIFIED_SESSION_ID,
    session_identity_refusal,
)

pytestmark = pytest.mark.unit

UPSTREAM_FLAG = "--trust-upstream-session-id"


def _sdk_context_carrying(caller: HttpCaller) -> Context:
    """A Context the SDK built, whose request carries ``caller``'s stamp."""
    request = SimpleNamespace(scope={CALLER_SCOPE_KEY: caller})
    return Context(request_context=SimpleNamespace(request=request))


def _refusal(ctx: object) -> dict:
    refusal = session_identity_refusal(UNIDENTIFIED_SESSION_ID, "clear_source", ctx=ctx)
    assert refusal is not None
    assert refusal["error_type"] == SESSION_IDENTITY_REQUIRED
    return refusal


def test_an_sse_caller_is_told_how_sse_issues_its_session() -> None:
    refusal = _refusal(
        _sdk_context_carrying(HttpCaller(SSE, None, server_mode=MODE_SSE))
    )

    assert UPSTREAM_FLAG not in refusal["error"], refusal
    assert "--stateless-http" not in refusal["error"], refusal
    assert "event stream" in refusal["error"], refusal
    assert "session_id" in refusal["error"], refusal


def test_a_stateful_caller_keeps_the_initialize_advice() -> None:
    refusal = _refusal(
        _sdk_context_carrying(
            HttpCaller(STREAMABLE_HTTP, None, server_mode=MODE_STATEFUL)
        )
    )

    assert "initialize" in refusal["error"], refusal
    assert UPSTREAM_FLAG not in refusal["error"], refusal


def test_a_stateless_caller_keeps_the_operator_advice() -> None:
    refusal = _refusal(
        _sdk_context_carrying(
            HttpCaller(STREAMABLE_HTTP, None, server_mode=MODE_STATELESS)
        )
    )

    assert UPSTREAM_FLAG in refusal["error"], refusal


def test_a_stand_in_that_is_not_an_sdk_context_carries_no_stamp() -> None:
    """The resolution would read this object's headers, never its request, so the
    refusal must not read a mode from the request either."""
    # Stamped as a protocol-version refusal, so the text asserted absent below
    # would be present if the stamp were read; with the default stamp the check
    # could never fail.
    stamped = HttpCaller(
        STREAMABLE_HTTP,
        None,
        protocol_version_is_cause=True,
        server_mode=MODE_STATEFUL,
    )
    stand_in = SimpleNamespace(
        request_context=SimpleNamespace(
            request=SimpleNamespace(scope={CALLER_SCOPE_KEY: stamped})
        )
    )

    refusal = _refusal(stand_in)

    assert UPSTREAM_FLAG in refusal["error"], refusal
    assert "newer protocol version" not in refusal["error"], refusal


def test_the_context_is_a_required_keyword() -> None:
    with pytest.raises(TypeError):
        session_identity_refusal(UNIDENTIFIED_SESSION_ID, "clear_source")  # type: ignore[call-arg]
    # Keyword-only: a context handed positionally is refused too, so a caller
    # cannot pass one by place and have it read as something else.
    with pytest.raises(TypeError):
        session_identity_refusal(UNIDENTIFIED_SESSION_ID, "clear_source", None)  # type: ignore[misc]


def test_no_context_gives_the_mode_less_advice() -> None:
    refusal = _refusal(None)

    assert UPSTREAM_FLAG in refusal["error"], refusal
