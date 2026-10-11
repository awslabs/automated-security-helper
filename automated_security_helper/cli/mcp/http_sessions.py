#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which session an HTTP request belongs to, decided by the server, not the client.

Why this exists
---------------
The scan-target and config-input boundaries give two tiers of trust: stdio's
single client is the process that launched the server and keeps the local tier;
every other caller is remote. That decision used to be read from the
``Mcp-Session-Id`` header, a value the client writes. On the sse transport and on
stateless streamable-HTTP nothing checks it, so a client that sent no header got
stdio's local trust, and a client that sent another session's id read and
removed that session's sandbox.

The transport the request arrived on is the one fact a client cannot choose, so
this module decides from it. :class:`SessionBoundary` is an ASGI middleware ASH
puts in front of every HTTP app it builds. It stamps each request's ASGI scope
with an :class:`HttpCaller` naming the transport and the session the *server*
issued:

* sse: the session the server issued for the event stream, read from the
  ``session_id`` of the endpoint URL the server sent on that stream. A header on
  a message POST is ignored.
* stateful streamable-HTTP: an ``Mcp-Session-Id`` this app issued at
  ``initialize`` (seen on its own responses). Any other value is ignored. The SDK
  also routes requests that name a newer protocol version past its session
  check; those carry no identity here.
* stateless streamable-HTTP: no server-issued session exists, so there is no
  identity unless the operator passed ``--trust-upstream-session-id``, declaring
  that a platform in front of ASH issues and authenticates the header.

A request with no identity is still remote. Tools that need a session refuse it;
see ``session_identity.resolve_caller_session_id``.

Why per app and not process-wide
--------------------------------
State lives on the middleware instance, so it belongs to the app that served the
request. ``cli/mcp/sandbox.py`` records why process-wide transport state was
removed: it outlived the server and changed the answer for every later call in
the process.

Failure modes and limits
------------------------
* A request reaching a tool through an HTTP app ASH did not build carries no
  stamp and is treated as remote with no session, never as local.
* With ``--trust-upstream-session-id`` isolation is as strong as the platform's
  header and no stronger.
* The sse endpoint event is read from the response body ASH relays. If a future
  SDK stops sending ``session_id`` in that URL, sse requests carry no identity and
  session tools refuse; they do not fall back to a header.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Set, Tuple

#: ASGI scope key the stamp is stored under. Namespaced so no framework or SDK key
#: can collide with it.
CALLER_SCOPE_KEY = "ash.mcp.caller"

#: ``HttpCaller.transport`` values.
SSE = "sse"
STREAMABLE_HTTP = "streamable-http"

#: The app shapes :class:`SessionBoundary` serves.
MODE_SSE = "sse"
MODE_STATEFUL = "stateful"
MODE_STATELESS = "stateless"

_SESSION_HEADER = b"mcp-session-id"

#: The query parameter of the sse endpoint URL. The SDK writes ``uuid.hex``.
_ENDPOINT_SESSION = re.compile(rb"[?&]session_id=([0-9A-Fa-f-]{32,36})")

Scope = Dict[str, Any]
Message = Dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


@dataclass(frozen=True)
class HttpCaller:
    """Who an HTTP request is, as the server decided it.

    Attributes:
        transport: ``sse`` or ``streamable-http``.
        session_id: The session the server issued (or, on a stateless app run
            with ``--trust-upstream-session-id``, the platform's header), or None
            when the request has no session identity.
    """

    transport: str
    session_id: Optional[str]


def caller_of(scope: Any) -> Optional[HttpCaller]:
    """Return the stamp on ``scope``, or None if ASH did not stamp it."""

    if not isinstance(scope, dict):
        return None
    caller = scope.get(CALLER_SCOPE_KEY)
    return caller if isinstance(caller, HttpCaller) else None


def _header(scope: Scope, name: bytes) -> Optional[str]:
    for key, value in scope.get("headers") or ():
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _response_header(
    headers: Iterable[Tuple[bytes, bytes]], name: bytes
) -> Optional[str]:
    for key, value in headers or ():
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _canonical_sse_session(raw: Optional[str]) -> Optional[str]:
    """The hex form the SDK issues, for any spelling ``uuid.UUID`` accepts."""

    if not raw:
        return None
    try:
        return uuid.UUID(hex=raw).hex
    except ValueError:
        return None


def _query_value(scope: Scope, name: str) -> Optional[str]:
    from urllib.parse import parse_qs

    raw = scope.get("query_string") or b""
    values = parse_qs(raw.decode("latin-1")).get(name)
    return values[0] if values else None


class SessionBoundary:
    """ASGI middleware that stamps each request with the caller the server decided.

    Args:
        app: The SDK's Starlette app, or the next middleware.
        mode: :data:`MODE_SSE`, :data:`MODE_STATEFUL` or :data:`MODE_STATELESS`.
        trust_upstream_session_id: Stateless only. Take the ``Mcp-Session-Id``
            header as the caller's identity, because the operator declared that a
            platform in front of ASH issues and authenticates it.
    """

    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        *,
        mode: str,
        trust_upstream_session_id: bool = False,
    ) -> None:
        if mode not in (MODE_SSE, MODE_STATEFUL, MODE_STATELESS):
            raise ValueError(f"unknown session boundary mode: {mode!r}")
        self.app = app
        self.mode = mode
        self.trust_upstream_session_id = (
            trust_upstream_session_id and mode == MODE_STATELESS
        )
        # Sessions this app issued and has not seen end. Stateful: ids seen on
        # the app's own responses. sse: ids read from the endpoint event of an
        # event stream that is still open.
        self._issued: Set[str] = set()

    # -- identity --------------------------------------------------------------

    def _identify(self, scope: Scope) -> HttpCaller:
        if self.mode == MODE_SSE:
            session = _canonical_sse_session(_query_value(scope, "session_id"))
            return HttpCaller(SSE, session if session in self._issued else None)
        header = _header(scope, _SESSION_HEADER)
        if self.mode == MODE_STATEFUL:
            return HttpCaller(
                STREAMABLE_HTTP, header if header in self._issued else None
            )
        if self.trust_upstream_session_id and header and header.strip():
            return HttpCaller(STREAMABLE_HTTP, header.strip())
        return HttpCaller(STREAMABLE_HTTP, None)

    # -- ASGI ------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        scope[CALLER_SCOPE_KEY] = self._identify(scope)

        if self.mode == MODE_SSE and scope.get("method") == "GET":
            await self._serve_event_stream(scope, receive, send)
            return
        if self.mode == MODE_STATEFUL:
            await self.app(scope, receive, self._watch_issued_session(send))
            return
        await self.app(scope, receive, send)

    def _watch_issued_session(self, send: Send) -> Send:
        """Record the session id a stateful app hands out on its responses."""

        async def watched(message: Message) -> None:
            if message.get("type") == "http.response.start":
                issued = _response_header(message.get("headers"), _SESSION_HEADER)
                if issued:
                    self._issued.add(issued)
            await send(message)

        return watched

    async def _serve_event_stream(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Serve one sse stream, recording the session it carries while it is open."""

        opened: Dict[str, str] = {}

        async def watched(message: Message) -> None:
            if "session" not in opened and message.get("type") == "http.response.body":
                found = _ENDPOINT_SESSION.search(message.get("body") or b"")
                session = _canonical_sse_session(
                    found.group(1).decode("ascii") if found else None
                )
                if session:
                    opened["session"] = session
                    self._issued.add(session)
            await send(message)

        try:
            await self.app(scope, receive, watched)
        finally:
            session = opened.get("session")
            if session:
                self._issued.discard(session)


__all__ = [
    "CALLER_SCOPE_KEY",
    "HttpCaller",
    "MODE_SSE",
    "MODE_STATEFUL",
    "MODE_STATELESS",
    "SSE",
    "STREAMABLE_HTTP",
    "SessionBoundary",
    "caller_of",
]
