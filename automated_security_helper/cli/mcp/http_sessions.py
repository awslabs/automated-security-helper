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

import functools
import re
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    Optional,
    Set,
    Tuple,
)

if TYPE_CHECKING:
    from automated_security_helper.utils.log import ASHLogger

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
        protocol_version_is_cause: True when a stateful app issued the session
            the request names and the request's protocol version, outside the
            ``initialize`` handshake versions, is the one reason it carries no
            identity. That is the one refusal a caller fixes by sending a
            handshake version; a request with no session header, or with an id
            the app never issued, gains nothing from a version change, so it
            never carries the flag.
        server_mode: The mode of the :class:`SessionBoundary` that stamped the
            request (:data:`MODE_SSE`, :data:`MODE_STATEFUL` or
            :data:`MODE_STATELESS`), so a refusal can give advice that holds on
            the server the request actually reached. None on a stamp built
            outside a boundary.
        session_expired: True when a stateful app issued the session the request
            names and the TTL sweep has since removed it. The request carries no
            identity, as one naming an id the app never issued does, but the
            refusal can say the session expired and what went with it, which a
            client cannot learn from "not issued".
    """

    transport: str
    session_id: Optional[str]
    protocol_version_is_cause: bool = False
    server_mode: Optional[str] = None
    session_expired: bool = False


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
    headers: Optional[Iterable[Tuple[bytes, bytes]]], name: bytes
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


def _handshake_protocol_versions() -> FrozenSet[str]:
    """The protocol versions the SDK sends through its session check.

    Read from the SDK's own list. A stateful :class:`SessionBoundary` reads it
    once, when it is built.

    Raises:
        RuntimeError: if the SDK's list cannot be imported. A stateful server
            without it could identify no session, so every session tool would
            refuse its caller.
    """
    try:
        from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
    except ImportError as exc:
        raise RuntimeError(
            "a stateful session boundary needs the MCP SDK's list of handshake "
            "protocol versions (mcp_types.version.HANDSHAKE_PROTOCOL_VERSIONS), "
            f"and importing it failed: {exc}"
        ) from exc
    return frozenset(HANDSHAKE_PROTOCOL_VERSIONS)


def _through_the_sdk_session_check(
    scope: Scope, handshake_versions: FrozenSet[str]
) -> bool:
    """True when the request names a protocol version the SDK session-checks.

    A request that names a version outside the ``initialize`` handshake
    versions goes to a separate, sessionless path. The same rule as the SDK's,
    from its own list.
    """
    version = _header(scope, b"mcp-protocol-version")
    return version is None or version in handshake_versions


def _on_the_sdk_session_path(
    scope: Scope, endpoint_path: Optional[str], through_the_sdk_session_check: bool
) -> bool:
    """True when the SDK's session endpoint handles this request's session.

    Two conditions. The request is for the endpoint itself: Starlette answers
    404 for a path the app has no route for, and that says nothing about a
    session. And it names a protocol version the SDK sends through its session
    check; see :func:`_through_the_sdk_session_check`.
    """
    if endpoint_path is None or _route_path(scope) != endpoint_path:
        return False
    return through_the_sdk_session_check


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
#: default. It bounds the sessions whose end this app cannot see: every
#: stateless one, and a stateful session the SDK dropped for being idle without
#: telling this app. Every request naming a session refreshes its workspace, and
#: the sweep keeps a session whose event stream is open (an sse stream, or a
#: stateful session's standalone GET stream) whatever its age, so an open but
#: idle stream never loses its tree to a TTL shorter than its idle time.
DEFAULT_SESSION_WORKSPACE_TTL_SECONDS = 24 * 60 * 60

#: How often, at most, the sweep runs after the first request.
_SWEEP_INTERVAL_SECONDS = 5 * 60

#: How many swept stateful session ids a boundary remembers, to tell a client
#: whose session expired that it did (``HttpCaller.session_expired``). The oldest
#: is forgotten first, and a request naming a forgotten id is answered as one
#: naming an id the app never issued, which is still a refusal.
_EXPIRED_SESSIONS_REMEMBERED = 1024

_LIFESPAN_SHUTDOWN_DONE = ("lifespan.shutdown.complete", "lifespan.shutdown.failed")

_REMOVAL_FAILED_BODY = b"the session could not be removed; send the DELETE again"


def _removal_failed_response() -> Tuple[Message, Message]:
    """The answer to a stateful ``DELETE`` whose session removal failed: a 500.

    Sent in place of the SDK's 2xx. The session is still issued, so the client
    can send the ``DELETE`` again.
    """
    start: Message = {
        "type": "http.response.start",
        "status": 500,
        "headers": [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(_REMOVAL_FAILED_BODY)).encode("ascii")),
        ],
    }
    return start, {"type": "http.response.body", "body": _REMOVAL_FAILED_BODY}


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
        handshake_versions: Stateful only: the protocol versions the SDK
            session-checks, read by the caller with
            :func:`_handshake_protocol_versions`. ``build_streamable_http_app``
            reads the list at build time and passes it, so a missing SDK list
            fails the build itself; Starlette constructs middleware at the
            app's first ASGI call, so a read deferred to here would surface
            only once the server is up. None (the default) reads the list here,
            for a boundary built directly.

    Raises:
        RuntimeError: building a stateful boundary without ``handshake_versions``,
            if the SDK's list of handshake protocol versions cannot be imported.

    A session's workspace and bound profile are removed
    (``sessions.end_session``) when this app sees the session end: a stateful
    session's ``DELETE``, answered 2xx only after the removal succeeded (when the
    removal raises, the answer is a 500 and the session stays issued, so the
    client can send the ``DELETE`` again; a removal that waits for a running
    scan, a change or a write of the session counts as succeeded, because it
    completes when that holder returns, and so does one that leaves the tree for
    the TTL sweep because the scan presence lock was refused); the SDK answering
    404 on its endpoint for a stateful session it discarded (a 404 for any other
    path is Starlette's, for a path with no route); an sse event stream
    finishing; and every session this app still holds when it is asked to shut
    down, ended at the shutdown request, before the app's own lifespan exit,
    which can end the process, and again before shutdown is reported complete
    for a removal that failed. Sessions whose end it cannot see -- every
    stateless one, and a stateful session the SDK closed for being idle that no
    client asks about again, since nothing tells this app it ended -- are
    removed by the TTL sweep, which runs before the first request is answered
    and then at most every five minutes. The sweep keeps only the sessions
    whose event stream is open (an sse stream, or a stateful session's
    standalone ``GET`` stream), whatever their age, and marks their
    workspaces used so another server sharing the root keeps them too; an
    issued stateful id is not kept on its own account, or the tree of every
    client that disconnects without a ``DELETE`` would stay for the life of the
    process. A stateful session the sweep removes is ended here too: its id
    leaves ``_issued``, so its next request carries no identity and the tools
    that need a session refuse it, saying the session expired
    (``HttpCaller.session_expired``). Left issued, the session's next scan
    would run with the bound profile and the delivered source gone and nothing
    said to the client.
    """

    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        *,
        mode: str,
        trust_upstream_session_id: bool = False,
        session_workspace_ttl: float = DEFAULT_SESSION_WORKSPACE_TTL_SECONDS,
        endpoint_path: Optional[str] = None,
        handshake_versions: Optional[FrozenSet[str]] = None,
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
        # Stateful only: the protocol versions the SDK session-checks, read
        # once -- by the app build where it passed them, here otherwise.
        self._handshake_versions: FrozenSet[str] = (
            (
                handshake_versions
                if handshake_versions is not None
                else _handshake_protocol_versions()
            )
            if mode == MODE_STATEFUL
            else frozenset()
        )
        # Sessions this app issued and has not seen end. Stateful: ids seen on
        # the app's own responses. sse: ids read from the endpoint event of an
        # event stream that is still open.
        self._issued: Set[str] = set()
        # The sessions whose event stream is open right now (an sse stream, or a
        # stateful session's standalone GET): the one kind of session the TTL
        # sweep keeps whatever its age (_sweep_if_due). A stateful id stays
        # issued after the SDK drops its idle session, since nothing tells this
        # app, so it is not kept on that account.
        self._open_streams: Set[str] = set()
        # How many event streams of a stateful session are open: a session stays
        # in _open_streams until the last of them closes. The SDK allows one
        # standalone GET stream per session and refuses a second at once, and
        # that refusal must not close the first's hold.
        self._stream_holds: Dict[str, int] = {}
        # Stateful sessions the sweep removed, oldest first, so a request that
        # names one is refused as an expired session (HttpCaller.session_expired).
        self._expired: "OrderedDict[str, None]" = OrderedDict()
        self._next_sweep = 0.0
        self._sweep_lock: Optional[Any] = None

    # -- identity --------------------------------------------------------------

    def _identify(self, scope: Scope, through_check: bool) -> HttpCaller:
        if self.mode == MODE_SSE:
            session = _canonical_sse_session(_query_value(scope, "session_id"))
            return HttpCaller(
                SSE,
                session if session in self._issued else None,
                server_mode=self.mode,
            )
        header = _header(scope, _SESSION_HEADER)
        if self.mode == MODE_STATEFUL:
            # The SDK routes a request naming a newer protocol past its session
            # check, so an id this app issued names no session there.
            known = header in self._issued and through_check
            return HttpCaller(
                STREAMABLE_HTTP,
                header if known else None,
                session_expired=not known and header in self._expired,
                # Only an issued id refused for its version alone: that is the
                # one refusal a handshake version fixes. A request with no
                # session header, or an id this app never issued, gains nothing
                # from a version change, so the hint would misdirect it.
                protocol_version_is_cause=header in self._issued and not through_check,
                server_mode=self.mode,
            )
        if self.trust_upstream_session_id and header and header.strip():
            return HttpCaller(STREAMABLE_HTTP, header.strip(), server_mode=self.mode)
        return HttpCaller(STREAMABLE_HTTP, None, server_mode=self.mode)

    # -- session end -------------------------------------------------------------

    async def _end(self, session_id: str) -> bool:
        """End ``session_id``; True when its removal succeeded.

        The id leaves ``_issued`` only then, so a removal that failed can be
        asked for again: by the client's next ``DELETE``, or at shutdown.
        """
        import anyio

        from automated_security_helper.cli.mcp.sessions import end_session

        try:
            # Shielded: an sse stream ends by being cancelled, and the removal
            # has to complete anyway.
            with anyio.CancelScope(shield=True):
                await anyio.to_thread.run_sync(end_session, session_id)
        except Exception as exc:
            _logger().warning(f"MCP session {session_id}: could not remove: {exc}")
            return False
        self._issued.discard(session_id)
        return True

    def _end_what_the_sweep_removed(self, removed: Iterable[str]) -> None:
        """Forget, as issued, the stateful sessions the sweep just removed.

        The sweep removed the workspace, the bound profile and the delivered
        source of each. A session still held as issued would take its next
        request as a live session's: a scan of it would run with none of that
        and nothing said to the client. Forgotten here, the request carries no
        identity and the tools that need a session refuse it, as for an id the
        app never issued, and ``HttpCaller.session_expired`` lets the refusal
        say what happened. A session with an open stream is never removed by
        the sweep, so none is forgotten with its stream open.
        """
        if self.mode != MODE_STATEFUL:
            return
        for session_id in removed:
            if session_id not in self._issued:
                continue
            self._issued.discard(session_id)
            self._expired[session_id] = None
            self._expired.move_to_end(session_id)
        while len(self._expired) > _EXPIRED_SESSIONS_REMEMBERED:
            self._expired.popitem(last=False)

    def _stream_opened(self, session_id: str) -> None:
        """A stateful session's event stream is open: the sweep keeps it."""
        self._stream_holds[session_id] = self._stream_holds.get(session_id, 0) + 1
        self._open_streams.add(session_id)

    def _stream_closed(self, session_id: str) -> None:
        """An event stream of a stateful session closed; the last one frees it."""
        remaining = self._stream_holds.get(session_id, 0) - 1
        if remaining > 0:
            self._stream_holds[session_id] = remaining
            return
        self._stream_holds.pop(session_id, None)
        self._open_streams.discard(session_id)

    async def _sweep_if_due(self) -> None:
        import time

        import anyio

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
            # The sessions whose sse event stream is open right now are kept
            # whatever their age: an open but idle stream has not ended, and its
            # end comes through _end, not the sweep. Each is also marked used
            # now, since another server sharing the root sweeps by age alone
            # and cannot see this app's open streams. A stateful session is not
            # kept by being issued: the SDK drops an idle stateful session
            # without telling this app, so its id would stay issued, and its
            # workspace kept, for the life of the process; every request that
            # names it refreshes its workspace instead, and the TTL covers it.
            open_streams = frozenset(self._open_streams)
            try:
                removed = await anyio.to_thread.run_sync(
                    functools.partial(
                        _sweep_keeping_open_streams,
                        self.session_workspace_ttl,
                        open_streams,
                    )
                )
            except Exception as exc:
                # A sweep must not fail the request that started it.
                _logger().warning(f"MCP session workspace sweep failed: {exc}")
            else:
                self._end_what_the_sweep_removed(removed or ())
            self._next_sweep = time.monotonic() + min(
                self.session_workspace_ttl, _SWEEP_INTERVAL_SECONDS
            )

    # -- ASGI ------------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope.get("type")
        if kind == "lifespan":
            await self.app(
                scope,
                self._end_all_at_shutdown_request(receive),
                self._end_all_on_shutdown(send),
            )
            return
        if kind != "http":
            await self.app(scope, receive, send)
            return

        # Decided once, so the identity and the end-of-session watch cannot
        # disagree about whether this request names a session.
        through_check = self.mode == MODE_STATEFUL and _through_the_sdk_session_check(
            scope, self._handshake_versions
        )
        caller = self._identify(scope, through_check)
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
            watched = self._watch_stateful(scope, send, through_check)
            # A session's standalone GET stream is its open event stream: the
            # sweep keeps the session while the request is being served, as it
            # keeps an sse session while its stream is open.
            stream_of = (
                caller.session_id
                if scope.get("method") == "GET"
                and _on_the_sdk_session_path(scope, self.endpoint_path, through_check)
                else None
            )
            if stream_of is None:
                await self.app(scope, receive, watched)
                return
            self._stream_opened(stream_of)
            try:
                await self.app(scope, receive, watched)
            finally:
                self._stream_closed(stream_of)
            return
        await self.app(scope, receive, send)

    async def _end_all(self) -> None:
        """End every session this app still holds as issued."""

        for session_id in sorted(self._issued):
            await self._end(session_id)

    def _end_all_at_shutdown_request(self, receive: Receive) -> Receive:
        """End the issued sessions as soon as the app is asked to shut down.

        At the ``lifespan.shutdown`` message, before it reaches the app: the
        app's own lifespan exit runs next, and it can end the process without
        coming back (a signal ended the server while a scan was still running;
        see ``cli/mcp/__init__._exit_if_a_signal_stopped_the_server``), so a
        boundary that waited for ``lifespan.shutdown.complete`` ended nothing
        then. The server has closed its connections by the time it asks for the
        shutdown, so no request of these sessions is in flight. A session a
        running scan or write still holds is deferred as on its ``DELETE``, and
        completed when the holder returns (``sessions.finish_ended_session``),
        which the app's cancellation of its scans brings about.
        """

        async def watched() -> Message:
            message = await receive()
            if message.get("type") == "lifespan.shutdown":
                await self._end_all()
            return message

        return watched

    def _end_all_on_shutdown(self, send: Send) -> Send:
        """End what is still issued before reporting shutdown complete.

        The second pass: a session whose removal failed at the shutdown request
        stays issued and is tried once more here.
        """

        async def watched(message: Message) -> None:
            if message.get("type") in _LIFESPAN_SHUTDOWN_DONE:
                await self._end_all()
            await send(message)

        return watched

    def _watch_stateful(self, scope: Scope, send: Send, through_check: bool) -> Send:
        """Record the ids a stateful app issues, and end the ones it ends.

        An id counts as issued only from a successful response: the SDK also
        sends one on a refused opening request and then discards that session.
        A session ends here when its ``DELETE`` succeeds (a ``DELETE`` that names
        a newer protocol version names no session, so it ends none), and when the SDK
        answers 404 for it on its own session path, which it does once it has
        discarded the session (its idle timeout, for one). A 404 for another path
        is Starlette's, for a path with no route, and a 404 on the newer
        protocol's path can mean an unknown method, so neither ends anything.

        A ``DELETE`` the SDK answered 2xx is passed on only once the removal
        succeeded. If it failed, the client gets a 500 instead, the SDK's answer
        is dropped, and the id stays in ``_issued`` for the next ``DELETE``.
        """

        header = _header(scope, _SESSION_HEADER)
        # A request naming a newer protocol names no session here, as in
        # _identify, so its DELETE ends none.
        known = header if header in self._issued and through_check else None
        deleting = scope.get("method") == "DELETE"
        session_path = _on_the_sdk_session_path(
            scope, self.endpoint_path, through_check
        )

        refused = False

        async def watched(message: Message) -> None:
            nonlocal refused
            if refused:
                return
            if message.get("type") == "http.response.start":
                status = int(message.get("status", 0))
                issued = _response_header(message.get("headers"), _SESSION_HEADER)
                if known and deleting and 200 <= status < 300:
                    # Before the response leaves: a DELETE answered 2xx means
                    # the removal succeeded. When it failed the client is told so
                    # and the id stays issued, so the DELETE can be sent again.
                    if not await self._end(known):
                        refused = True
                        for answer in _removal_failed_response():
                            await send(answer)
                        return
                elif known and status == 404 and session_path:
                    await self._end(known)
                elif issued and not header and session_path and 200 <= status < 300:
                    # Only a successful response, on the SDK's session path, to a
                    # request that carried no session header (``initialize``) is
                    # an issue. A response to a request that named a session, or
                    # one from the sessionless path, issues nothing.
                    self._issued.add(issued)
            await send(message)

        return watched

    async def _serve_event_stream(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Serve one sse stream; the session it carries ends when it finishes.

        The session is read from the endpoint event, the first event the SDK
        writes on the stream, and from nothing else: the first body chunk that
        carries an event field decides it, with or without a ``session_id`` (a
        ping before it is a comment line with no field, and is passed over).
        Reading every later chunk would adopt an id a relayed message happens to
        contain, such as a URL in a tool result, as a session this app issued.
        """

        opened: Dict[str, Optional[str]] = {}

        async def watched(message: Message) -> None:
            if "session" not in opened and message.get("type") == "http.response.body":
                body = message.get("body") or b""
                if b"data:" in body:
                    found = _ENDPOINT_SESSION.search(body)
                    session = _canonical_sse_session(
                        found.group(1).decode("ascii") if found else None
                    )
                    opened["session"] = session
                    if session:
                        self._issued.add(session)
                        self._open_streams.add(session)
            await send(message)

        try:
            await self.app(scope, receive, watched)
        finally:
            session = opened.get("session")
            if session:
                self._open_streams.discard(session)
                await self._end(session)


def _sweep_keeping_open_streams(ttl_seconds: float, open_streams: FrozenSet[str]):
    """Run the TTL sweep with the open event streams' sessions kept and marked used.

    On the worker thread the sweep runs on. Each open stream's workspace is
    touched first: this process keeps it by name (``in_use``), and another
    server sharing the root, which sweeps by age alone and cannot see this
    app's streams, then reads it as used now, so an open stream's workspace is
    kept there too for as long as the stream stays open and the sweeps run.
    """
    from automated_security_helper.cli.mcp.sessions import (
        sweep_stale_workspaces,
        touch_session_workspace,
    )

    for session_id in open_streams:
        touch_session_workspace(session_id)
    return sweep_stale_workspaces(ttl_seconds, in_use=open_streams)


def _logger() -> ASHLogger:
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
