#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which session an MCP tool call belongs to.

A source tree delivered over the protocol lands in a per-session workspace, so
every tool that delivers one -- or scans the result -- has to know which session
it is acting for. The transport is what supplies that: the streamable-HTTP
transport carries an ``Mcp-Session-Id`` request header.

A multi-call delivery therefore needs that header to hold still. The chunk
uploads, the finalize that extracts them, and the scan that reads the extracted
tree all have to resolve to the same directory, so a client whose connection
carries a stable id gets a coherent workspace and one that does not gets a scan
that finds nothing.

CAUTION ON BEDROCK AGENTCORE RUNTIME. The MCP protocol contract for that target
says the platform generates the header, includes it in the request to the server,
and routes requests carrying it to the same microVM
(https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html).
Do not treat that as settled. Measured against two live runtimes, the platform
mints a fresh id on nearly every *response* and honors only the one returned by
``initialize``, so following the contract's own advice to adopt the latest
returned id produces ``404 Session not found`` on the third call. What the
container sees per *request* was not determinable from outside -- that needs
header logging inside the image -- so whether this function returns the same value
twice in one AgentCore session is an open question. On that target the caller
should pass the ``source_dir`` a delivery tool returned straight back to
``run_ash_scan`` rather than relying on the no-argument form, which is what
deploy/cdk/README.md tells adopters to do.

An unstable id does not silently misdirect a scan. ``run_ash_scan`` refuses the
no-argument form when this session holds no delivered tree, rather than falling
back to the working directory -- see ``_resolve_omitted_source_dir`` in
cli/mcp_server.py, which reports the rotating-id case specifically. Every tool
that calls this function also echoes the resolved id in its response, so two
calls compared against a live runtime settle the open question above without an
image change.

stdio carries no headers and serves a single client, so it resolves to
``DEFAULT_SESSION_ID``, the sentinel the profile registry already uses for
callers that name no session. Only a caller known to be that local client gets
it (:func:`serving_local_client`): a Context the SDK built with no HTTP request
behind it is not enough on its own. A request that carries headers but names no
session is never that client: it resolves to :data:`UNIDENTIFIED_SESSION_ID`.
Naming the default session in the header is refused
(:func:`is_reserved_session_id`), and leaving the header out must not reach it
either.

The one caller the mark does not decide is an in-process caller's stand-in
context (a plain object with a ``headers`` attribute, which no transport ever
builds: the SDK builds a Context for every call it dispatches). A stand-in with
no headers at all is that caller by construction and resolves to the default
session without the mark; see :func:`resolve_session_id`. Gating it on the mark
too would be a change of contract for every in-process caller, not a guard.

Which session a network call belongs to is decided by the transport, never by
the header alone: see :func:`resolve_caller_session_id` and
``cli/mcp/http_sessions.py``. A header a client sets on sse, or on a stateless
streamable-HTTP server, names no session; a stateful server's header counts only
when the server issued it. A network caller with no session identity resolves
to :data:`UNIDENTIFIED_SESSION_ID`, which is remote and owns no sandbox, so it
never falls back to stdio's local trust.

Where a header is the identity -- a stateless server whose operator declared
with ``--trust-upstream-session-id`` that a platform in front issues and
authenticates it -- isolation between two callers is only as strong as the
platform makes it. What this module guarantees is that an id names one
directory and not a path: an id that could traverse, or that carries a separator
or a control character, is refused rather than sanitized. Sanitizing would map
two distinct ids onto one workspace and silently merge two callers' source
trees.

That guarantee lives in ``session_paths.validated_path_component``, the one
implementation shared by the transport, the ``sessions`` registry and
``source_delivery``; :func:`validate_path_component` here only delegates to it.
``source_delivery`` once carried its own weaker copy of three of these
predicates, and ``session_paths`` and this module later carried two rules that
disagreed. One rule, several labels (the header, ``session_id``, ``upload_id``).
"""

from __future__ import annotations

import contextlib
import re
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Dict, Iterator, Mapping, Optional, cast

from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

if TYPE_CHECKING:
    from automated_security_helper.cli.mcp.http_sessions import HttpCaller
    from mcp.server.mcpserver import Context as SdkContext

# Lowercase because HTTP header names are case-insensitive and this is compared
# against a lowercased key.
MCP_SESSION_ID_HEADER = "mcp-session-id"

#: The session id of a network caller the server cannot identify: stateless
#: streamable-HTTP without ``--trust-upstream-session-id``, or a header the
#: server never issued, or headers that name no session. Remote, owns no
#: sandbox, and every tool that needs a session refuses it. Never accepted from
#: a client.
UNIDENTIFIED_SESSION_ID = "__unidentified__"

#: ``error_type`` of the refusal a session-dependent tool returns for
#: :data:`UNIDENTIFIED_SESSION_ID`.
SESSION_IDENTITY_REQUIRED = "session_identity_required"

#: Set while the caller is the local client; see :func:`serving_local_client`.
_LOCAL_CLIENT: ContextVar[bool] = ContextVar("ash_mcp_local_client", default=False)

#: Set by :func:`resolve_caller_session_id` for the call it resolves: the caller
#: has no identity because its request names a protocol version outside the
#: ``initialize`` handshake versions. :func:`session_identity_refusal` reads it.
_PROTOCOL_VERSION_IS_CAUSE: ContextVar[bool] = ContextVar(
    "ash_mcp_protocol_version_is_cause", default=False
)


@contextlib.contextmanager
def serving_local_client() -> Iterator[None]:
    """Serve tool calls made inside this block as the local client's.

    ``run_mcp_server`` serves stdio inside it, and so should a process that
    drives the server through the MCP SDK's in-memory client. A Context the SDK
    built with no HTTP request behind it is stdio's ``DEFAULT_SESSION_ID``, with
    local trust, only inside it; anywhere else it is
    :data:`UNIDENTIFIED_SESSION_ID`. So a transport that ever hands a tool no
    request gets remote trust rather than stdio's. Tasks the server starts
    inside the block inherit the mark. The mark does not decide an in-process
    caller's stand-in context, which no transport builds: see the module
    docstring and :func:`resolve_session_id`.
    """

    token = _LOCAL_CLIENT.set(True)
    try:
        yield
    finally:
        _LOCAL_CLIENT.reset(token)


def validate_path_component(value: str, label: str) -> str:
    """Refuse a caller-supplied value that could name anything but one directory.

    A delegate, not a rule. The rule lives in
    :func:`automated_security_helper.cli.mcp.session_paths.validated_path_component`
    and is the only one: this module and ``session_paths`` each used to carry a
    copy, the copies disagreed about ``~``, ``+``, ``=`` and length, and an id one
    accepted and the other refused was admitted at the transport and then failed
    inside the session registry. Kept under this name so the transport and its
    tests keep their import; ``label`` names the refused input in the message.

    Returns:
        ``value`` unchanged when it names exactly one path component.

    Raises:
        ValueError: under exactly the conditions ``validated_path_component``
            raises.
    """

    from automated_security_helper.cli.mcp.session_paths import (
        validated_path_component,
    )

    return validated_path_component(value, label)


def _header_value(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Return the value of ``name`` from ``headers``, matched case-insensitively.

    Starlette's ``Headers`` already lowercases its keys, but a tool may be
    handed a plain dict by another transport or by a test, and HTTP header
    names are case-insensitive either way. Matching on a lowercased key works
    for both rather than depending on which mapping arrived.
    """

    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def resolve_session_id(headers: Optional[Mapping[str, str]]) -> str:
    """Resolve the session id a tool call belongs to.

    This is the path of an in-process caller's stand-in context, reached through
    :func:`resolve_caller_session_id`. A context the MCP SDK built is decided by
    its transport and never gets here.

    Args:
        headers: Request headers carried by the call, or ``None`` when it has
            none (stdio, an in-process caller). ``Context.headers`` supplies
            this.

    Returns:
        The ``Mcp-Session-Id`` header value when the headers carry a usable one;
        :data:`DEFAULT_SESSION_ID` when there are no headers at all, the shape
        of the local client; :data:`UNIDENTIFIED_SESSION_ID` when there are
        headers and none of them names a session (the header absent, empty, or
        whitespace-only).

    Raises:
        ValueError: if the header names one of the reserved sentinels (see
            :func:`is_reserved_session_id`), or is present but could not name a
            single directory, per :func:`validate_path_component` -- it contains a path
            separator, is a relative-path component, carries a control character
            or a character with path meaning such as a drive-specifying ``:``,
            or exceeds ``session_paths.MAX_COMPONENT_LEN``. Refused rather than
            sanitized: see the module docstring.

    No headers at all (``None``, or a mapping with no entries) has no request
    behind it, so it is the default session with local trust, matching the
    ``session_id or DEFAULT_SESSION_ID`` form the profile registry already uses.
    Headers that name no session are a request that named nothing, and the
    default session is the one name a request may not have: a header that spells
    it is refused above, so leaving the header out resolves to
    :data:`UNIDENTIFIED_SESSION_ID`, remote with no sandbox, as the HTTP arm of
    :func:`resolve_caller_session_id` does. So does anything that is not a
    mapping: it is not headers, and not the absence of them, so a stand-in that
    left its ``headers`` unset does not reach the default session's local trust
    by the way it was misconfigured. A header that is present and non-empty but
    unusable is an error, because quietly falling back would put that caller's
    source in the shared default workspace.
    """

    # Imported here rather than at module scope: profile_registry imports the
    # config stack, and cli/mcp modules are imported from mcp_server at tool
    # registration time.
    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )

    # No header of any kind: no request is behind the call, and the caller is
    # the in-process one. A mapping that holds nothing is the same shape.
    if headers is None or (isinstance(headers, Mapping) and not headers):
        return DEFAULT_SESSION_ID
    # Anything else that is not a mapping is not headers, and is not the absence
    # of them either (an attribute a stand-in left unset reads as an object that
    # holds nothing, and the default session, with its local trust, is not what
    # such a call is). It names no session, as headers that name none do.
    if not isinstance(headers, Mapping):
        return UNIDENTIFIED_SESSION_ID

    raw = _header_value(headers, MCP_SESSION_ID_HEADER)
    candidate = raw.strip() if raw is not None else ""
    if not candidate:
        return UNIDENTIFIED_SESSION_ID

    _refuse_reserved_session_id(candidate)
    return validate_path_component(candidate, MCP_SESSION_ID_HEADER)


def _refuse_reserved_session_id(candidate: str) -> None:
    """Raise ``ValueError`` when ``candidate`` is one of the reserved names.

    The one refusal both arms apply -- the stand-in/header path of
    :func:`resolve_session_id` and the HTTP arm of
    :func:`resolve_caller_session_id` -- so the two cannot word it differently
    or disagree about which names it covers.
    """

    if is_reserved_session_id(candidate):
        raise ValueError(
            f"{MCP_SESSION_ID_HEADER} {candidate!r} is reserved and cannot name a "
            f"session"
        )


def _short_name_pattern(name: str) -> "re.Pattern[str]":
    """The pattern the generated 8.3 short names of ``name`` match.

    NTFS gives a name longer than eight characters a short alias made of its
    first six characters (leading periods dropped) and ``~`` plus a number.
    Matched casefolded and without an extension, which none of the reserved
    names carries.
    """

    return re.compile(rf"{re.escape(name.lstrip('.')[:6].casefold())}~[0-9]+")


def is_reserved_session_id(value: str) -> bool:
    """True if ``value`` names a directory under the workspace root ASH owns.

    Those are stdio's workspace (``DEFAULT_SESSION_ID``), the unidentified
    sentinel, the stdio servers' presence registry, the running scans' presence
    registry, and the guard file each registry locks (``.lock``,
    ``sessions.PRESENCE_LOCK_NAME``): under the scans' registry a session's
    holder directory and that file would share one name, so a session called
    ``.lock`` could register no scan and would never be swept. Compared
    casefolded: on a case-insensitive filesystem (the macOS and Windows
    defaults) ``__DEFAULT__`` opens the same directory as ``__default__``.
    Trailing periods and spaces are dropped before the comparison, because
    Windows drops them when it opens the name (``__default__.`` is
    ``__default__``), and a generated 8.3 short name of a reserved name
    (``__DEFAU~1``) is reserved too, since it opens the same directory. The
    guard file's name is shorter than eight characters, so no short name
    aliases it and none is reserved for it.
    """

    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )
    from automated_security_helper.cli.mcp.sessions import (
        PRESENCE_LOCK_NAME,
        SCAN_PRESENCE_DIR,
        STDIO_SERVERS_DIR,
    )

    reserved = (
        DEFAULT_SESSION_ID,
        UNIDENTIFIED_SESSION_ID,
        STDIO_SERVERS_DIR,
        SCAN_PRESENCE_DIR,
    )
    folded = value.casefold().rstrip(". ")
    if folded in {name.casefold() for name in (*reserved, PRESENCE_LOCK_NAME)}:
        return True
    return any(_short_name_pattern(name).fullmatch(folded) for name in reserved)


def _as_sdk_context(ctx: object) -> Optional["SdkContext"]:
    """``ctx`` if it is a Context the MCP SDK built, None for a stand-in.

    ``type()`` rather than ``isinstance``: a ``MagicMock(spec=Context)`` passes
    ``isinstance``, and a stand-in carries no request a transport produced.
    """
    from mcp.server.mcpserver import Context as SdkContext

    if issubclass(type(ctx), SdkContext):
        return cast("SdkContext", ctx)
    return None


def resolve_caller_session_id(ctx: object) -> str:
    """The session a tool call acts for, decided by the transport it arrived on.

    * No request object: inside :func:`serving_local_client` (stdio, an
      in-memory client its embedder drives), the single local client,
      :data:`DEFAULT_SESSION_ID`; anywhere else :data:`UNIDENTIFIED_SESSION_ID`.
    * An HTTP request: the session ``http_sessions.SessionBoundary`` stamped on
      it -- one the server issued, or, on a stateless server run with
      ``--trust-upstream-session-id``, the platform's header. A request with no
      stamp (an HTTP app ASH did not build) or no session in it is
      :data:`UNIDENTIFIED_SESSION_ID`: remote, with no sandbox.
    * Anything that is not a Context the SDK built (an in-process caller's
      stand-in): the ``Mcp-Session-Id`` in its ``headers``, as
      :func:`resolve_session_id` reads it. A stand-in with no headers at all is
      the in-process caller, :data:`DEFAULT_SESSION_ID`; one whose headers name
      no session, or are not a mapping at all, is
      :data:`UNIDENTIFIED_SESSION_ID`, as an HTTP request that names none is.

    Raises:
        ValueError: if the identity is a header value that could not name one
            directory, or names one of the reserved sentinels.
    """

    from automated_security_helper.cli.mcp.http_sessions import caller_of
    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )

    # Every resolution states its own cause, so one request's does not reach
    # the next one's refusal.
    _PROTOCOL_VERSION_IS_CAUSE.set(False)
    sdk_context = _as_sdk_context(ctx)
    if sdk_context is None:
        return resolve_session_id(getattr(ctx, "headers", None))

    try:
        request = sdk_context.request_context.request
    except ValueError:
        # A Context used outside a request has no transport behind it.
        request = None
    if request is None:
        return DEFAULT_SESSION_ID if _LOCAL_CLIENT.get() else UNIDENTIFIED_SESSION_ID

    caller = caller_of(getattr(request, "scope", None))
    if caller is None or caller.session_id is None:
        _PROTOCOL_VERSION_IS_CAUSE.set(
            caller is not None and caller.protocol_version_is_cause
        )
        return UNIDENTIFIED_SESSION_ID
    candidate = caller.session_id.strip()
    if not candidate:
        return UNIDENTIFIED_SESSION_ID
    _refuse_reserved_session_id(candidate)
    return validate_path_component(candidate, MCP_SESSION_ID_HEADER)


def _caller_behind(ctx: object) -> Optional["HttpCaller"]:
    """The :class:`HttpCaller` stamped on the request behind ``ctx``, or None.

    Read from the request's own scope, so it is a fact about one request and
    nothing else: no resolution order, no task-local state. Only a Context the
    SDK built carries a request a transport produced (:func:`_as_sdk_context`,
    the same test :func:`resolve_caller_session_id` applies), so the refusal
    reads the stamp of exactly the request the resolution read. A ``ctx`` that
    carries no request -- a stand-in, a Context used outside a request -- has
    no stamp.
    """

    from automated_security_helper.cli.mcp.http_sessions import caller_of

    sdk_context = _as_sdk_context(ctx)
    if sdk_context is None:
        return None
    try:
        request = sdk_context.request_context.request
    except ValueError:
        # A Context used outside a request has no transport behind it.
        return None
    return caller_of(getattr(request, "scope", None))


def session_identity_refusal(
    session_id: str, operation: str, *, ctx: object
) -> Optional[Dict[str, Any]]:
    """The refusal a session-dependent tool returns for an unidentified caller.

    Returns None when ``session_id`` names a session, or is None: only the
    :data:`UNIDENTIFIED_SESSION_ID` sentinel is refused.

    ``ctx`` is the refused call's context, and is required so that a caller
    that has one cannot leave it out and get the mode-less advice for a request
    whose mode is known. Whether the protocol version is the cause, and which
    server mode the advice holds on, are read from the stamp on the request
    behind it (:func:`_caller_behind`, which admits only a Context the SDK built,
    as :func:`resolve_caller_session_id` does), so the text depends only on the
    request being refused, never on whichever resolution ran last in the same
    task. A refusal built with ``ctx=None`` -- an id another tool resolved and
    passed down, with no request in reach -- claims no cause and gives the
    mode-less advice.

    The advice names what works on the server the request reached: a stateful
    server issues sessions at ``initialize``; an sse server issues its session
    with the event stream, and ``--trust-upstream-session-id`` is refused there
    (``mcp_command``), so the stateless advice would send an sse caller to a
    flag the server cannot take; a stateless server serves no session unless
    the operator declared an upstream one.
    """

    if session_id != UNIDENTIFIED_SESSION_ID:
        return None
    from automated_security_helper.cli.mcp.http_sessions import (
        MODE_SSE,
        MODE_STATEFUL,
    )

    caller = _caller_behind(ctx) if ctx is not None else None
    protocol_sentence = (
        "This request names a newer protocol version, and a request that does "
        "names no session, whatever Mcp-Session-Id it sends, so a session tool "
        "needs a handshake Mcp-Protocol-Version: send the protocol version the "
        "initialize handshake negotiated. "
        if caller is not None and caller.protocol_version_is_cause
        else ""
    )
    if caller is not None and caller.server_mode == MODE_SSE:
        # The server issues the session with the event stream; what works here
        # is in the caller's hands, and no operator flag applies to sse.
        error = (
            f"{operation} needs a session, and this call carries none the server "
            f"issued. An sse server issues its session with the event stream: "
            f"send tool calls to the messages URL the stream's endpoint event "
            f"gave, exactly as given, whose session_id names it. A session_id the "
            f"server did not issue, or one given more than once in the URL, names "
            f"no session, and an Mcp-Session-Id header is not read on sse."
        )
    elif caller is not None and caller.server_mode == MODE_STATEFUL:
        # The server already issues sessions, so operator advice to change the
        # mode would be noise; what works here is in the caller's hands. A
        # session the TTL sweep removed is told apart from an id the server never
        # issued: the client chose that profile and sent that upload, and both
        # went with it.
        named = (
            "That session expired: the server removes the workspace of a session "
            "nobody used for --session-workspace-ttl seconds, and its bound "
            "profile and uploads are removed with it. "
            if caller.session_expired
            else "An Mcp-Session-Id header the server did not issue does not name one. "
        )
        error = (
            f"{operation} needs a session, and this call carries none the server "
            f"issued. {named}{protocol_sentence}"
            f"Open a session with initialize at a handshake protocol version and "
            f"send the Mcp-Session-Id it returns with that version."
        )
    else:
        error = (
            f"{operation} needs a session, and this call carries none the server "
            f"issued. A stateless streamable-HTTP server issues no session, and an "
            f"Mcp-Session-Id header the server did not issue does not name one. "
            f"{protocol_sentence}"
            f"To serve sessions at all, use a stateful server (without "
            f"--stateless-http), or, when a platform in front of ASH issues and "
            f"authenticates Mcp-Session-Id, start a stateless server with "
            f"--trust-upstream-session-id."
        )
    return {
        "success": False,
        "operation": operation,
        "error_type": SESSION_IDENTITY_REQUIRED,
        "error": raw_controls_on_one_line(error),
    }


__all__ = [
    "MCP_SESSION_ID_HEADER",
    "SESSION_IDENTITY_REQUIRED",
    "UNIDENTIFIED_SESSION_ID",
    "is_reserved_session_id",
    "resolve_caller_session_id",
    "resolve_session_id",
    "serving_local_client",
    "session_identity_refusal",
    "validate_path_component",
]
