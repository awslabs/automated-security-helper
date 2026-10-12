#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which session an HTTP request belongs to, decided by the server, not the client.

Why this exists
---------------
The scan-target and config-input boundaries give two tiers of trust: stdio's
single client is the process that launched the server and keeps the local tier;
every other caller is remote. The ``Mcp-Session-Id`` header is a value the client
writes, and on the sse transport and on stateless streamable-HTTP nothing checks
it, so it never decides a request's session on its own. The transport the
request arrived on is the one fact a client cannot choose, so this module
decides from it. :class:`SessionBoundary` is an ASGI middleware ASH
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
request and ends with it. Process-wide transport state would outlive the server
and change the answer for every later call in the process; see
``cli/mcp/sandbox.py``.

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


def _route_path(scope: Scope) -> str:
    """The path Starlette routes on: ``path`` without the ``root_path`` prefix."""

    path = scope.get("path") or ""
    root = scope.get("root_path") or ""
    if root and path.startswith(root) and path[len(root) : len(root) + 1] in ("", "/"):
        return path[len(root) :]
    return path


def _on_the_sdk_session_path(scope: Scope, endpoint_path: Optional[str]) -> bool:
    """True when the SDK's session endpoint handles this request's session.

    Two conditions. The request is for the endpoint itself: Starlette answers
    404 for a path the app has no route for, and that says nothing about a
    session. And it names a protocol version the SDK sends through its session
    check: a request that names a version outside the ``initialize`` handshake
    versions goes to a separate, sessionless path. The same rule as the SDK's,
    from its own list. If the list cannot be read, no request counts, so a 404
    never ends a session.
    """
    if endpoint_path is None or _route_path(scope) != endpoint_path:
        return False
    try:
        from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
    except ImportError:
        return False
    version = _header(scope, b"mcp-protocol-version")
    return version is None or version in HANDSHAKE_PROTOCOL_VERSIONS


def _canonical_sse_session(raw: Optional[str]) -> Optional[str]:
    """The hex form the SDK issues, for any spelling ``uuid.UUID`` accepts."""

    if not raw:
        return None
    try:
        return uuid.UUID(hex=raw).hex
    except ValueError:
        return None


def _query_value(scope: Scope, name: str) -> Optional[str]:
    """The one value of ``name`` in the query, or None if it is absent or repeated.

    Repeated is refused rather than resolved: the SDK routes an sse message by
    the last ``session_id`` and this module would read one of them, so any
    choice can disagree with the SDK about which session a call belongs to.
    """
    from urllib.parse import parse_qs

    raw = scope.get("query_string") or b""
    values = parse_qs(raw.decode("latin-1"), keep_blank_values=True).get(name)
    return values[0] if values and len(values) == 1 else None


#: How long a session workspace may go unused before the sweep removes it, by
#: default. Long enough that no live session loses its tree: a stateful session
#: the SDK keeps is idle for at most 30 minutes, and every request naming a
#: session refreshes its workspace.
DEFAULT_SESSION_WORKSPACE_TTL_SECONDS = 24 * 60 * 60

#: How often, at most, the sweep runs after the first request.
_SWEEP_INTERVAL_SECONDS = 5 * 60

_LIFESPAN_SHUTDOWN_DONE = ("lifespan.shutdown.complete", "lifespan.shutdown.failed")


class SessionBoundary:
    """ASGI middleware that decides each request's session and sees sessions end.

    Args:
        app: The SDK's Starlette app, or the next middleware.
        mode: :data:`MODE_SSE`, :data:`MODE_STATEFUL` or :data:`MODE_STATELESS`.
        trust_upstream_session_id: Stateless only. Take the ``Mcp-Session-Id``
            header as the caller's identity, because the operator declared that a
            platform in front of ASH issues and authenticates it.
        session_workspace_ttl: Seconds a session workspace may go unused before
            the sweep removes it.
        endpoint_path: Stateful only, and required there: the path the SDK's
            streamable endpoint was built at (``streamable_http_path``). Only a
            404 on that path ends a session.

    A session's workspace and bound profile are removed
    (``sessions.end_session``) when this app sees the session end: a stateful
    session's ``DELETE``, answered only after the removal is complete; the SDK
    answering 404 on its endpoint for a stateful session it discarded (a 404
    for any other path is Starlette's, for a path with no route); an sse event stream
    finishing; and every session this app issued when it shuts down. Sessions
    whose end it cannot see -- every stateless one, and a stateful one the SDK
    closed for being idle that no client asks about again -- are removed by the
    TTL sweep, which runs before the first request is answered and then at most
    every five minutes.
    """

    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        *,
        mode: str,
        trust_upstream_session_id: bool = False,
        session_workspace_ttl: float = DEFAULT_SESSION_WORKSPACE_TTL_SECONDS,
        endpoint_path: Optional[str] = None,
    ) -> None:
        if mode not in (MODE_SSE, MODE_STATEFUL, MODE_STATELESS):
            raise ValueError(f"unknown session boundary mode: {mode!r}")
        if session_workspace_ttl <= 0:
            raise ValueError("session_workspace_ttl must be a positive number")
        if mode == MODE_STATEFUL and not endpoint_path:
            raise ValueError(
                "a stateful session boundary needs the endpoint path, to tell the "
                "SDK's 404 for a discarded session from a 404 for no route"
            )
        self.app = app
        self.mode = mode
        self.endpoint_path = endpoint_path
        self.trust_upstream_session_id = (
            trust_upstream_session_id and mode == MODE_STATELESS
        )
        self.session_workspace_ttl = session_workspace_ttl
        # Sessions this app issued and has not seen end. Stateful: ids seen on
        # the app's own responses. sse: ids read from the endpoint event of an
        # event stream that is still open.
        self._issued: Set[str] = set()
        self._next_sweep = 0.0
        self._sweep_lock: Optional[Any] = None

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

    # -- session end -------------------------------------------------------------

    async def _end(self, session_id: str) -> None:
        import anyio

        from automated_security_helper.cli.mcp.sessions import end_session

        self._issued.discard(session_id)
        try:
            # Shielded: an sse stream ends by being cancelled, and the removal
            # has to complete anyway.
            with anyio.CancelScope(shield=True):
                await anyio.to_thread.run_sync(end_session, session_id)
        except Exception as exc:
            # Cleanup must not fail the response it follows.
            _logger().warning(f"MCP session {session_id}: could not remove: {exc}")

    async def _sweep_if_due(self) -> None:
        import time

        import anyio

        from automated_security_helper.cli.mcp.sessions import sweep_stale_workspaces

        if time.monotonic() < self._next_sweep:
            return
        if self._sweep_lock is None:
            self._sweep_lock = anyio.Lock()
        if self._sweep_lock.locked():
            # Another request is sweeping; only the request that started the
            # sweep waits for it.
            return
        async with self._sweep_lock:
            if time.monotonic() < self._next_sweep:
                return
            try:
                await anyio.to_thread.run_sync(
                    sweep_stale_workspaces, self.session_workspace_ttl
                )
            except Exception as exc:
                # A sweep must not fail the request that started it.
                _logger().warning(f"MCP session workspace sweep failed: {exc}")
            self._next_sweep = time.monotonic() + min(
                self.session_workspace_ttl, _SWEEP_INTERVAL_SECONDS
            )

    # -- ASGI ------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope.get("type")
        if kind == "lifespan":
            await self.app(scope, receive, self._end_all_on_shutdown(send))
            return
        if kind != "http":
            await self.app(scope, receive, send)
            return

        caller = self._identify(scope)
        scope[CALLER_SCOPE_KEY] = caller
        if caller.session_id:
            from automated_security_helper.cli.mcp.sessions import (
                touch_session_workspace,
            )

            # Before the sweep, so the session this request belongs to counts as
            # in use however long ago it was last called.
            touch_session_workspace(caller.session_id)
        await self._sweep_if_due()

        if self.mode == MODE_SSE and scope.get("method") == "GET":
            await self._serve_event_stream(scope, receive, send)
            return
        if self.mode == MODE_STATEFUL:
            await self.app(scope, receive, self._watch_stateful(scope, send))
            return
        await self.app(scope, receive, send)

    def _end_all_on_shutdown(self, send: Send) -> Send:
        """End every session this app issued before reporting shutdown complete."""

        async def watched(message: Message) -> None:
            if message.get("type") in _LIFESPAN_SHUTDOWN_DONE:
                for session_id in sorted(self._issued):
                    await self._end(session_id)
            await send(message)

        return watched

    def _watch_stateful(self, scope: Scope, send: Send) -> Send:
        """Record the ids a stateful app issues, and end the ones it ends.

        An id counts as issued only from a successful response: the SDK also
        sends one on a refused opening request and then discards that session.
        A session ends here when its ``DELETE`` succeeds, and when the SDK
        answers 404 for it on its own session path, which it does once it has
        discarded the session (its idle timeout, for one). A 404 for another path
        is Starlette's, for a path with no route, and a 404 on the newer
        protocol's path can mean an unknown method, so neither ends anything.
        """

        header = _header(scope, _SESSION_HEADER)
        known = header if header in self._issued else None
        deleting = scope.get("method") == "DELETE"
        session_path = _on_the_sdk_session_path(scope, self.endpoint_path)

        async def watched(message: Message) -> None:
            if message.get("type") == "http.response.start":
                status = int(message.get("status", 0))
                issued = _response_header(message.get("headers"), _SESSION_HEADER)
                if known and deleting and 200 <= status < 300:
                    # Before the response leaves: a client that has its DELETE
                    # answered can rely on the workspace being gone.
                    await self._end(known)
                elif known and status == 404 and session_path:
                    await self._end(known)
                elif issued and 200 <= status < 300:
                    self._issued.add(issued)
            await send(message)

        return watched

    async def _serve_event_stream(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Serve one sse stream; the session it carries ends when it finishes."""

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
                await self._end(session)


def _logger():
    from automated_security_helper.utils.log import ASH_LOGGER

    return ASH_LOGGER


__all__ = [
    "CALLER_SCOPE_KEY",
    "DEFAULT_SESSION_WORKSPACE_TTL_SECONDS",
    "HttpCaller",
    "MODE_SSE",
    "MODE_STATEFUL",
    "MODE_STATELESS",
    "SSE",
    "STREAMABLE_HTTP",
    "SessionBoundary",
    "caller_of",
]
