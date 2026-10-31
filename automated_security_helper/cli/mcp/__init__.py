# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
MCP (Model Context Protocol) CLI command for ASH.

This package provides a CLI command to start an MCP server that exposes ASH
security scanning capabilities through the Model Context Protocol. The server
supports multiple transports:

- ``stdio`` (default): legacy in-process transport, no network
- ``streamable-http``: MCPServer streamable-HTTP app served via uvicorn, with
  optional single-tenant header auth
- ``sse``: legacy MCPServer SSE app served via uvicorn (best-effort; the SSE
  transport is deprecated upstream)
"""

from __future__ import annotations

import functools
import os
import signal
import stat
import types
from pathlib import Path
from typing import Annotated, Callable, Dict, List, Optional
import typer

from automated_security_helper.cli.mcp.http_sessions import (
    DEFAULT_SESSION_WORKSPACE_TTL_SECONDS,
    MODE_SSE,
    MODE_STATEFUL,
    MODE_STATELESS,
    SessionBoundary,
    _handshake_protocol_versions,
)
from automated_security_helper.cli.mcp.profile_registry import (
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.core.constants import (
    ASH_EXIT_INTERRUPTED,
    ASH_EXIT_USAGE_ERROR,
)
from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.utils.ash_install import ash_reinstall_command
from automated_security_helper.utils.console import ash_console
from automated_security_helper.utils.error_text import error_text, log_unexpected_error
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    configure_last_resort_level,
    escape_markup,
)
from automated_security_helper.utils.process_env import environ_overrides

# Import MCP dependencies directly. We capture both the server class and the
# Starlette type so the streamable-HTTP path can build a typed ASGI app.
try:
    from mcp.server.mcpserver import MCPServer, Context
except ImportError:  # pragma: no cover - exercised only when MCP missing
    MCPServer = None  # type: ignore[assignment]
    Context = None  # type: ignore[assignment]

# Configure module logger
_logger = ASH_LOGGER

# Everything this command writes goes to stderr. On the stdio transport stdout is
# the JSON-RPC channel, so one human-readable line there makes the client fail to
# parse the stream -- the reported symptom was "Expecting value". Binding the
# console to stderr makes that structural instead of depending on each call site
# remembering to check --quiet, which the dependency-missing and validation-error
# paths never did. --quiet still controls *whether* to write, not where.
_stderr = ash_console(stderr=True)

# Valid --transport values. Kept as a tuple so typer can render help cleanly
# without forcing an Enum class on the public CLI surface.
_VALID_TRANSPORTS = ("stdio", "streamable-http", "sse")

#: Exit code for an invocation the server can't run with: a usage error, apart
#: from 3, which reports a config that can't be used. An unknown
#: ``ASH_MCP_TRANSPORT`` exits with it.
_EXIT_USAGE = 5

#: Bind addresses for which the MCP SDK turns its Host and Origin check on by
#: itself. Exactly the SDK's literal list: ``127.0.0.2`` is loopback too, but the
#: SDK leaves the check off for it, so it is treated like any other address.
_SDK_PROTECTED_HOSTS = ("127.0.0.1", "localhost", "::1")


def validate_log_options(
    verbose: bool, debug: bool, log_level: AshLogLevel
) -> AshLogLevel:
    """Resolve the effective log level given verbose/debug flags."""
    if debug:
        return AshLogLevel.DEBUG
    elif verbose:
        return AshLogLevel.VERBOSE
    else:
        return log_level


def validate_mcp_dependencies() -> bool:
    """Validate that MCP dependencies are available.

    Returns:
        True if MCPServer and Context are importable, False otherwise
    """
    return MCPServer is not None and Context is not None


def validate_command_options(verbose: bool, debug: bool, quiet: bool) -> None:
    """Validate command options for consistency.

    Raises:
        ASHValidationError: if --quiet is combined with --verbose or --debug.
    """
    if quiet and (verbose or debug):
        raise ASHValidationError("Cannot use --quiet with --verbose or --debug options")


#: The longest auth header value, on the command line or read from a file or a
#: descriptor. HTTP servers refuse header lines far shorter than this, so a longer
#: value is a wrong file.
_AUTH_VALUE_MAX_BYTES = 16 * 1024

#: The whitespace an HTTP implementation drops from the ends of a header value.
_HEADER_EDGE_BLANKS = " \t"

#: The bytes an HTTP field value cannot hold: 0x00 to 0x1F except the tab, and DEL.
#: The bytes 0x80 to 0xFF are kept, as latin-1 characters.
_HEADER_CONTROL_BYTES = frozenset([*range(0x09), *range(0x0A, 0x20), 0x7F])


def _refuse_a_blank_at_an_end(value: str, source: str) -> None:
    """Refuse a non-empty ``value`` that starts or ends with a space or tab.

    A client or server leaves that whitespace out of a header value, so the value
    could never be matched by a request and every request would be answered 401.
    A space or tab between other characters is part of the value and is kept.

    Raises:
        ASHValidationError: naming ``source``, not repeating the value.
    """
    if value and (value[0] in _HEADER_EDGE_BLANKS or value[-1] in _HEADER_EDGE_BLANKS):
        raise ASHValidationError(
            f"{source} starts or ends with a space or tab, which an HTTP header "
            f"value never keeps, so no request could match it; put a character "
            f"at each end"
        )


def _refuse_a_control_byte(data: bytes, source: str) -> None:
    """Refuse ``data`` when it holds a byte an HTTP field value cannot hold.

    A conforming client never sends one, so a server configured with such a value
    would answer 401 to every request. The tab and the bytes 0x80 to 0xFF are kept.

    Raises:
        ASHValidationError: naming ``source``, not repeating the value.
    """
    if not _HEADER_CONTROL_BYTES.isdisjoint(data):
        raise ASHValidationError(
            f"{source} holds a control character (a line break, NUL, another byte "
            f"below 0x20 except a tab, or DEL), which a header value can't contain"
        )


def _auth_value_from_bytes(data: bytes, source: str) -> str:
    """The header value in ``data`` (one trailing newline dropped), or refuse.

    Decoded as latin-1, so the value's latin-1 encoding is the file's bytes: the
    auth middleware compares the header's wire bytes against exactly those.

    Raises:
        ASHValidationError: for more than ``_AUTH_VALUE_MAX_BYTES`` bytes, no
            value, a control byte (a line break, NUL, any other byte below 0x20
            but the tab, or DEL), or a space or tab at either end (the newline
            is dropped first, so ``tok`` plus a space and a newline is refused,
            not read as ``tok`` plus a space). A tab between other characters
            and the bytes 0x80 to 0xFF are kept.
    """
    if len(data) > _AUTH_VALUE_MAX_BYTES:
        raise ASHValidationError(
            f"{source} holds more than {_AUTH_VALUE_MAX_BYTES} bytes, which no "
            f"header value is"
        )
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]
    if not data:
        raise ASHValidationError(f"{source} holds no auth header value")
    _refuse_a_control_byte(data, source)
    value = data.decode("latin-1")
    _refuse_a_blank_at_an_end(value, source)
    return value


def _read_bounded(fd: int) -> bytes:
    chunks: List[bytes] = []
    size = 0
    while size <= _AUTH_VALUE_MAX_BYTES:
        chunk = os.read(fd, _AUTH_VALUE_MAX_BYTES + 1 - size)
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def _auth_value_from_file(path: Path) -> str:
    """Read the auth header value from a private regular file.

    Refused: a symlink, anything but a regular file, and (on POSIX) a file with
    any permission bit for its group or other users. Opened without following a
    link and without blocking, and checked again on the open descriptor, so a
    file swapped in between is refused too.
    """
    source = f"--auth-header-value-file {path}"
    try:
        named = os.lstat(path)
    except OSError as exc:
        raise ASHValidationError(f"{source} can't be read: {exc.strerror}") from None
    if stat.S_ISLNK(named.st_mode):
        raise ASHValidationError(f"{source} is a symlink; name the file itself")
    if not stat.S_ISREG(named.st_mode):
        raise ASHValidationError(f"{source} is not a regular file")
    if os.name != "nt" and named.st_mode & 0o077:
        raise ASHValidationError(
            f"{source} has mode {stat.S_IMODE(named.st_mode):04o}, which lets other "
            f"users read or change it; make it readable by its owner only "
            f"(chmod 600)"
        )
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_BINARY"):
        flags |= getattr(os, name, 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ASHValidationError(f"{source} can't be read: {exc.strerror}") from None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            named.st_dev,
            named.st_ino,
        ):
            raise ASHValidationError(f"{source} changed while it was opened")
        data = _read_bounded(fd)
    except OSError as exc:
        raise ASHValidationError(f"{source} can't be read: {exc.strerror}") from None
    finally:
        os.close(fd)
    return _auth_value_from_bytes(data, source)


def _auth_value_from_fd(fd: int) -> str:
    """Read the auth header value from an inherited descriptor, then close it.

    A regular file (a memfd, say) is read from its start; a pipe from where it is.
    0, 1 and 2 are the server's own standard streams and are refused.
    """
    source = f"--auth-header-value-fd {fd}"
    if fd < 3:
        raise ASHValidationError(
            f"{source} is not a descriptor the server can take: 0, 1 and 2 are its "
            f"standard streams"
        )
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise ASHValidationError(
            f"{source} is not an open descriptor: {exc.strerror}"
        ) from None
    try:
        if stat.S_ISREG(info.st_mode):
            os.lseek(fd, 0, os.SEEK_SET)
        elif not stat.S_ISFIFO(info.st_mode):
            raise ASHValidationError(f"{source} is neither a file nor a pipe")
        data = _read_bounded(fd)
    except OSError as exc:
        raise ASHValidationError(f"{source} can't be read: {exc.strerror}") from None
    finally:
        os.close(fd)
    return _auth_value_from_bytes(data, source)


_AUTH_VALUE_ARGV_NOT_VISIBLE_ASCII = (
    "--auth-header-value takes visible ASCII only (letters, digits and "
    "punctuation, with spaces or tabs between them); a terminal and an HTTP "
    "client can disagree about any other byte, so pass it with "
    "--auth-header-value-file or --auth-header-value-fd"
)


def _auth_value_from_argv(value: str) -> str:
    """``value`` as given on the command line, or refuse.

    The file and descriptor forms hand the server the header's own bytes. The
    command line gives it text: Python decoded ``argv`` with the filesystem
    encoding, so a character latin-1 carries as one byte (an accented letter) is
    one byte here and two to a client that sends UTF-8, and a value no client
    could match would pass the option check. Visible ASCII is the same bytes
    under every encoding; a line break, a NUL or any other control character is
    refused as the file form refuses it. A tab between other characters is a
    legal header value and is kept.

    A space or tab at either end is refused, as it is on the other two forms: an
    HTTP implementation drops it from a header value, so no request could carry
    the value. At most ``_AUTH_VALUE_MAX_BYTES`` characters are taken, the bound a
    file or a descriptor has (it counts the newline too).

    Raises:
        ASHValidationError: for a character that is not visible ASCII, a space or
            a tab, a space or tab at either end, or more than
            ``_AUTH_VALUE_MAX_BYTES`` characters. The message does not repeat the
            value.
    """
    if not all(
        0x20 <= ord(character) <= 0x7E or character == "\t" for character in value
    ):
        raise ASHValidationError(_AUTH_VALUE_ARGV_NOT_VISIBLE_ASCII)
    _refuse_a_blank_at_an_end(value, "--auth-header-value")
    if len(value) > _AUTH_VALUE_MAX_BYTES:
        raise ASHValidationError(
            f"--auth-header-value holds more than {_AUTH_VALUE_MAX_BYTES} bytes, "
            f"which no header value is"
        )
    return value


def _resolve_auth_header_value(
    auth_header_value: Optional[str],
    auth_header_value_file: Optional[Path],
    auth_header_value_fd: Optional[int],
) -> Optional[str]:
    """The auth header value from whichever one of its three forms was given.

    Raises:
        ASHValidationError: for more than one form, a file or descriptor that
            holds no usable value, a command-line value that is not visible
            ASCII (``_auth_value_from_argv``), or a value in any form with a
            space or tab at either end.
    """
    given = [
        name
        for name, value in (
            ("--auth-header-value", auth_header_value),
            ("--auth-header-value-file", auth_header_value_file),
            ("--auth-header-value-fd", auth_header_value_fd),
        )
        if value is not None
    ]
    if len(given) > 1:
        raise ASHValidationError(f"pass only one of {' and '.join(given)}")
    if auth_header_value_file is not None:
        return _auth_value_from_file(Path(auth_header_value_file))
    if auth_header_value_fd is not None:
        return _auth_value_from_fd(int(auth_header_value_fd))
    if auth_header_value is None:
        return None
    return _auth_value_from_argv(auth_header_value)


_AUTH_VALUE_NOT_LATIN_1 = (
    "the auth header value has a character outside latin-1, which an HTTP header "
    "value can't carry; use an ASCII value such as hex or base64"
)


def _header_wire_bytes(value: str) -> Optional[bytes]:
    """The header bytes ``value`` stands for (its latin-1 encoding), or None.

    Strict: a character outside latin-1 is not a header byte, and encoding it
    with ``errors="replace"`` gave "?", which made values that differ only in
    such characters compare equal.
    """
    try:
        return value.encode("latin-1")
    except UnicodeEncodeError:
        return None


def _validate_auth_options(
    auth_header_name: Optional[str], auth_header_value: Optional[str]
) -> None:
    """Reject partial auth configuration: both or neither.

    Raises:
        ASHValidationError: if exactly one of the two auth options is set, or the
            value has a character outside latin-1 (``_header_wire_bytes``).
    """
    if bool(auth_header_name) != bool(auth_header_value):
        raise ASHValidationError(
            "--auth-header-name and --auth-header-value must be set together"
        )
    if auth_header_value and _header_wire_bytes(auth_header_value) is None:
        raise ASHValidationError(_AUTH_VALUE_NOT_LATIN_1)


def _validate_stateless_http(transport: str, stateless_http: bool) -> None:
    """Reject ``--stateless-http`` on a transport that has no sessions to skip.

    Refused rather than ignored. An operator who passes it expects a server that
    tolerates being load-balanced; silently dropping it on the wrong transport
    would leave them running a stateful server and only find out when a request
    landed on the wrong replica in production.

    Only the affirmative case is checked. ``--no-stateless-http`` is
    indistinguishable from the default, so treating it as an error would break
    every existing stdio invocation for no gain.

    Raises:
        ASHValidationError: if stateless_http is set on a non-streamable transport.
    """
    if stateless_http and transport != "streamable-http":
        raise ASHValidationError(
            f"--stateless-http only applies to '--transport streamable-http', but "
            f"transport is '{transport}'. stdio has a single implicit session and "
            f"sse holds an open connection per client, so neither has a session to "
            f"make stateless."
        )


def _validate_trust_upstream_session_id(
    transport: str, stateless_http: bool, trust_upstream_session_id: bool
) -> None:
    """Reject ``--trust-upstream-session-id`` where the server issues the session.

    Only a stateless streamable-HTTP server has no session of its own. On a
    stateful server and on sse the server issues the session id, and stdio has
    one client, so the flag would claim something about a header nothing reads.
    Refused rather than ignored, for the reason ``_validate_stateless_http`` gives.

    Raises:
        ASHValidationError: if the flag is set anywhere but stateless
            streamable-HTTP.
    """
    if trust_upstream_session_id and not (
        transport == "streamable-http" and stateless_http
    ):
        raise ASHValidationError(
            "--trust-upstream-session-id only applies to '--transport "
            "streamable-http --stateless-http'. A stateful server and an sse server "
            "issue their own session ids, and stdio has a single client."
        )


def _validate_bind(
    host: str,
    allowed_hosts: Optional[List[str]],
    trust_upstream_host_check: bool,
) -> None:
    """Refuse an HTTP bind that would serve any Host and any Origin.

    The MCP SDK checks Host and Origin (its DNS-rebinding protection) only when
    the app is built for one of :data:`_SDK_PROTECTED_HOSTS`. Building for any
    other address without an explicit allowlist leaves both headers unchecked,
    so how Host is checked is a decision the operator states, not a default:
    ``--allowed-host`` keeps the check on with the names clients use, and
    ``--trust-upstream-host-check`` says a proxy or platform in front of ASH
    checks Host and Origin instead.

    On a loopback host the SDK protects, ASH accepts only its own origin
    (``_transport_security``), and ``--trust-upstream-host-check`` would turn that
    off. A proxy on the same host that forwards another Host name keeps the check
    with ``--allowed-host`` for that name, so the flag is refused there.

    Raises:
        ASHValidationError: for a non-loopback host with neither option, for
            both options, which contradict each other, and for
            ``--trust-upstream-host-check`` on a loopback host.
    """
    if allowed_hosts and trust_upstream_host_check:
        raise ASHValidationError(
            "--allowed-host and --trust-upstream-host-check contradict each other: "
            "the first keeps ASH's Host check on for the names given, the second "
            "turns it off because something in front of ASH checks Host. Pass one."
        )
    if trust_upstream_host_check and host in _SDK_PROTECTED_HOSTS:
        raise ASHValidationError(
            f"--trust-upstream-host-check does not apply to --host {host}: a "
            f"loopback server accepts only its own origin, and the flag would turn "
            f"that check off. If a proxy on this host forwards another Host name, "
            f"pass --allowed-host with that name instead."
        )
    if allowed_hosts or trust_upstream_host_check or host in _SDK_PROTECTED_HOSTS:
        return
    raise ASHValidationError(
        f"--host {host} is not a loopback name the MCP SDK protects, and no "
        f"--allowed-host was given, so the server would answer any Host and any "
        f"Origin header. Pass --allowed-host with each host name clients use to "
        f"reach the server (repeatable), or --trust-upstream-host-check if a proxy "
        f"or platform in front of ASH checks Host and Origin."
    )


#: How a loopback server's own address is spelled in a Host header.
_LOOPBACK_HOST_NAMES = ("127.0.0.1", "localhost", "[::1]")


def _transport_security(
    host: str,
    allowed_hosts: Optional[List[str]],
    trust_upstream_host_check: bool,
    port: Optional[int],
):
    """The ``transport_security`` to build an app with.

    On a loopback bind with no allowlist the SDK's own check accepts a
    ``localhost`` origin on any port. This server accepts its
    own origin only: Host ``127.0.0.1``, ``localhost`` or ``[::1]`` with the
    port it is bound to, and the same as ``http://`` origins. On port 80 the
    names without a port are accepted too, because clients and browsers leave
    the default port out of Host and Origin.

    Raises:
        ASHValidationError: per :func:`_validate_bind`, and on a loopback bind
            with no allowlist when ``port`` is None or 0: an app built for a
            port other than the one it listens on answers 421 to every request.
    """
    _validate_bind(host, allowed_hosts, trust_upstream_host_check)
    from mcp.server.transport_security import TransportSecuritySettings

    if allowed_hosts:
        # Supplying transport_security suppresses the SDK's host-based autodetect
        # entirely, so this is the only branch that can keep protection on while
        # accepting a non-loopback name. allowed_origins is left empty rather than
        # mirroring allowed_hosts: Origin is a browser-supplied header, and an MCP
        # server reached through a proxy has no reason to trust one.
        return TransportSecuritySettings(
            allowed_hosts=list(allowed_hosts),
            allowed_origins=[],
        )
    if trust_upstream_host_check:
        # Stated explicitly rather than left to the SDK's default for a
        # non-loopback host, so the decision is visible here.
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    if port is None or int(port) == 0:
        raise ASHValidationError(
            "A loopback server without allowed_hosts accepts only its own address, "
            "port included, so it has to be built with the port it listens on. "
            "Pass port= the bound port; when the system picks the port, bind the "
            "socket first and pass the port it got."
        )
    own = [f"{name}:{int(port)}" for name in _LOOPBACK_HOST_NAMES]
    if int(port) == 80:
        own.extend(_LOOPBACK_HOST_NAMES)
    return TransportSecuritySettings(
        allowed_hosts=own,
        allowed_origins=[f"http://{name}" for name in own],
    )


def _workspace_ttl(session_workspace_ttl: Optional[int]) -> int:
    """The session workspace TTL to build with: the given one, or the default.

    Raises:
        ASHValidationError: for a value that is not a positive integer.
    """
    if session_workspace_ttl is None:
        return DEFAULT_SESSION_WORKSPACE_TTL_SECONDS
    if isinstance(session_workspace_ttl, bool) or session_workspace_ttl <= 0:
        raise ASHValidationError(
            f"--session-workspace-ttl must be a positive number of seconds, got "
            f"{session_workspace_ttl!r}"
        )
    return int(session_workspace_ttl)


def _build_auth_middleware(header_name: str, header_value: str):
    """Build a Starlette middleware class that enforces a static header.

    Returns a class suitable for ``Starlette.add_middleware``. Requests missing
    the header — or carrying a different value — receive ``401 Unauthorized``.
    The header name is matched case-insensitively, mirroring HTTP semantics.

    Uses ``hmac.compare_digest`` for the value comparison to defeat timing
    side channels: a naive ``!=`` leaks per-byte equality timing, which an
    attacker can exploit to recover the expected token one byte at a time.

    Method handling is uniform: there is no special case for OPTIONS,
    HEAD, PROPFIND, TRACE, or any other method. Every request that
    reaches the middleware must carry the expected header — a permissive
    front-proxy that strips the header for preflight, or a future bug
    that adds method-specific short-circuit handling, would have to be
    introduced inside this dispatch to weaken the boundary.

    Raises:
        ASHValidationError: if ``header_value`` has a character outside latin-1, a
            control byte (below 0x20 but the tab, or DEL), or starts or ends with a
            space or tab (no request could carry it).
    """
    import hmac
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    expected_name = header_name.lower()
    # Encode with latin-1 to match Starlette's wire-byte semantics.
    # Per RFC 7230 (and Starlette's implementation), HTTP header values
    # are decoded as latin-1; encoding back as utf-8 here would mutate
    # any byte ≥ 0x80 and silently fail-auth for non-ASCII tokens.
    # Settled in an earlier review.
    # Strict, here and on the received value: a character outside latin-1 is
    # refused, never replaced by "?" (_header_wire_bytes).
    expected_value_bytes = _header_wire_bytes(header_value)
    if expected_value_bytes is None:
        raise ASHValidationError(_AUTH_VALUE_NOT_LATIN_1)
    # The checks the command line, a file and a descriptor make, made here too: every
    # entry point builds the middleware through this function, and a library caller
    # of the app builders gives the value as a string that none of those checked.
    _refuse_a_control_byte(expected_value_bytes, "the auth header value")
    _refuse_a_blank_at_an_end(header_value, "the auth header value")

    class _StaticHeaderAuth(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            received = request.headers.get(expected_name)
            received_bytes = (
                _header_wire_bytes(received) if received is not None else None
            )
            if received_bytes is None or not hmac.compare_digest(
                received_bytes, expected_value_bytes
            ):
                return JSONResponse(
                    {
                        "error": "unauthorized",
                        "detail": "missing or invalid auth header",
                    },
                    status_code=401,
                )
            return await call_next(request)

    return _StaticHeaderAuth


def _auth_middleware_if_configured(
    auth_header_name: Optional[str], auth_header_value: Optional[str]
):
    """The auth middleware class when both options are set, else None.

    The app builders call this before they touch the shared server, so a value
    ``_build_auth_middleware`` refuses stops the build with nothing set on it. A
    name given without a value, or the reverse, is refused here as the command line
    refuses it (``_validate_auth_options``): the builders are public, and reading it
    as "no authentication" would return an app that lets every request through.

    Raises:
        ASHValidationError: if exactly one of the two options is set, or if
            ``auth_header_value`` has a character outside latin-1 or a control
            byte, or starts or ends with a space or tab.
    """
    _validate_auth_options(auth_header_name, auth_header_value)
    if auth_header_name and auth_header_value:
        return _build_auth_middleware(auth_header_name, auth_header_value)
    return None


def build_streamable_http_app(
    mount_path: str = "/mcp",
    auth_header_name: Optional[str] = None,
    auth_header_value: Optional[str] = None,
    stateless_http: bool = False,
    host: str = "127.0.0.1",
    allowed_hosts: Optional[List[str]] = None,
    trust_upstream_session_id: bool = False,
    trust_upstream_host_check: bool = False,
    session_workspace_ttl: Optional[int] = None,
    port: Optional[int] = None,
):
    """Build the MCPServer streamable-HTTP ASGI app, optionally guarded by auth.

    Args:
        mount_path: HTTP path the streamable transport listens on.
        auth_header_name: When set with ``auth_header_value``, requests
            missing the header (or carrying a different value) get 401.
        auth_header_value: Expected value for ``auth_header_name``.
        stateless_http: When True, treat every request independently instead of
            binding it to a server-held session. Needed by any runtime that
            load-balances requests across replicas -- the next request may reach
            a replica that never saw the session -- and by runtimes that inject
            their own ``Mcp-Session-Id``, which a stateful server refuses as a
            session it does not know. Defaults to False, preserving the stateful
            behaviour ASH had before this option existed.
        host: The address the server will bind. This must be the *same* value
            handed to uvicorn -- see below.
        allowed_hosts: Explicit Host-header allowlist. When given, DNS-rebinding
            protection stays on and accepts exactly these hosts, which is the
            right posture behind a proxy whose hostname is known.
        trust_upstream_session_id: Stateless only. Take the ``Mcp-Session-Id``
            header as the caller's session identity, because a platform in front
            of ASH issues and authenticates it. Without it a stateless server
            identifies no session, and the tools that need one refuse; see
            ``cli/mcp/http_sessions.py``.
        trust_upstream_host_check: A proxy or platform in front of ASH checks
            Host and Origin, so the app checks neither. Required for a
            non-loopback ``host`` without ``allowed_hosts``; refused with them.
        session_workspace_ttl: Seconds a session workspace may go unused before
            it is swept; None is the default, 24 hours. See
            ``http_sessions.SessionBoundary`` for when sessions end.
        port: The port the server listens on, the same value handed to
            uvicorn. Required on a loopback ``host`` without ``allowed_hosts``
            or ``trust_upstream_host_check``, where the server accepts only its
            own origin, port included (see :func:`_transport_security`); unused
            otherwise. Not 0: bind first and pass the port the system chose.

    The host argument is load-bearing, not cosmetic
    ----------------------------------------------
    The SDK turns DNS-rebinding protection on automatically when *this* host is
    loopback, and the allowlist it installs then contains only ``127.0.0.1``,
    ``localhost`` and ``[::1]``. ASH previously omitted the argument entirely, so
    the app was always built as though bound to ``127.0.0.1`` no matter what
    ``--host`` said. A server started with ``--host 0.0.0.0`` bound correctly and
    then answered ``421 Misdirected Request`` to every request whose Host header
    was anything but loopback -- so every request through a load balancer, and
    every request from another machine. Passing the real bind address is what
    makes the app's security match the socket's reachability.

    It also means a non-loopback ``host`` builds an app with no Host or Origin
    check at all, so that combination is refused unless ``allowed_hosts`` or
    ``trust_upstream_host_check`` says how Host is checked; see
    :func:`_validate_bind`.

    Returns:
        A Starlette application ready to hand to uvicorn.

    Raises:
        RuntimeError: if MCPServer is not installed; or, building a stateful
            app, if the SDK's list of handshake protocol versions cannot be
            imported. Raised here, at build time: Starlette constructs
            middleware at the app's first ASGI call, so a read deferred to the
            session boundary would let the build and the startup succeed and
            then fail every served request with a 500.
        ASHValidationError: for a non-loopback ``host`` with neither
            ``allowed_hosts`` nor ``trust_upstream_host_check``, or with both,
            for an ``auth_header_value`` with a character outside latin-1, a
            control byte, or a space or tab at either end, for exactly one of
            ``auth_header_name`` and ``auth_header_value``, and for a
            ``session_workspace_ttl`` that is not a positive number of
            seconds. Each is raised before the shared server is touched.
    """
    if MCPServer is None:
        raise RuntimeError(
            "MCPServer is not installed. The 'mcp' package is required for "
            "the streamable-http transport."
        )
    # First, so a value the middleware refuses, or a TTL that is not a positive
    # number of seconds, leaves nothing behind: the app is built on a module-level
    # server that keeps what the build sets on it.
    auth_middleware = _auth_middleware_if_configured(
        auth_header_name, auth_header_value
    )
    workspace_ttl = _workspace_ttl(session_workspace_ttl)
    # Stateful only: the SDK's handshake-version list, read at the top of the
    # build so a missing list fails the build itself (see Raises above). A
    # stateless boundary never reads the list, and must stay buildable
    # without it.
    handshake_versions = None if stateless_http else _handshake_protocol_versions()
    security = _transport_security(host, allowed_hosts, trust_upstream_host_check, port)
    # Import here to keep the stdio path zero-cost when the streamable-HTTP
    # transport is not used.
    from automated_security_helper.cli.mcp_server import mcp as _mcp_instance

    # MCP SDK v2 takes the mount path as a keyword argument here. Under FastMCP
    # it was a Settings field, assigned before materializing the app; v2's
    # Settings has no such field, so the old assignment raised
    # `ValueError: "Settings" object has no field "streamable_http_path"`.
    # Passing it per call is also better behaved: the previous form mutated a
    # module-level singleton's settings as a side effect.
    app_kwargs = {
        "streamable_http_path": mount_path,
        "stateless_http": stateless_http,
        "host": host,
    }
    app_kwargs["transport_security"] = security
    app = _mcp_instance.streamable_http_app(**app_kwargs)
    # Decides which session each request belongs to from what this app issued,
    # never from a header alone. Added before the auth middleware so an
    # unauthenticated request is refused before it is identified.
    app.add_middleware(
        SessionBoundary,
        mode=MODE_STATELESS if stateless_http else MODE_STATEFUL,
        trust_upstream_session_id=trust_upstream_session_id,
        session_workspace_ttl=workspace_ttl,
        # The same path the SDK routes its endpoint on, so only its 404 for a
        # discarded session ends one.
        endpoint_path=mount_path,
        # Read at the top of this build; the boundary then imports nothing at
        # its own (first-request) construction.
        handshake_versions=handshake_versions,
    )

    if auth_middleware is not None:
        app.add_middleware(auth_middleware)

    return _stop_scans_when_the_app_stops(app)


def build_sse_app(
    mount_path: str = "/sse",
    auth_header_name: Optional[str] = None,
    auth_header_value: Optional[str] = None,
    host: str = "127.0.0.1",
    allowed_hosts: Optional[List[str]] = None,
    trust_upstream_host_check: bool = False,
    session_workspace_ttl: Optional[int] = None,
    port: Optional[int] = None,
):
    """Build the MCPServer SSE ASGI app (legacy).

    Args:
        mount_path: HTTP path the SSE transport listens on.
        auth_header_name: When set with ``auth_header_value``, requests
            missing the header (or carrying a different value) get 401.
        auth_header_value: Expected value for ``auth_header_name``.
        host: The address the server will bind. Load-bearing for the same
            reason it is on the streamable-HTTP path -- see below.
        allowed_hosts: Explicit Host-header allowlist. When given, DNS-rebinding
            protection stays on and accepts exactly these hosts.
        trust_upstream_host_check: A proxy or platform in front of ASH checks
            Host and Origin; as on the streamable-HTTP path.
        session_workspace_ttl: As on the streamable-HTTP path.
        port: As on the streamable-HTTP path.

    Why sse_app gets host and allowed_hosts too
    -------------------------------------------
    ``sse_app`` carries the same loopback autodetect as ``streamable_http_app``:
    ``host`` defaults to ``127.0.0.1``, and when ``transport_security`` is None
    and host is loopback the SDK installs an allowlist containing only
    ``127.0.0.1``, ``localhost`` and ``[::1]``. Omitting both arguments here
    therefore reproduced, on sse, exactly the defect that was fixed for
    streamable-http: ``--host 0.0.0.0 --transport sse`` bound the wildcard
    address and then answered ``421 Misdirected Request`` to every request whose
    Host header was not loopback, which is every request through a proxy.

    Refusing ``--allowed-host`` on sse the way ``_validate_stateless_http``
    refuses ``--stateless-http`` was considered and rejected. It would turn a
    silently dropped flag into a loud refusal, which is an improvement, but it
    would leave the 421 defect in place: an operator who passes only
    ``--host 0.0.0.0`` never mentions ``--allowed-host`` and so trips no
    validation, and their server still refuses every proxied request. sse being
    deprecated upstream is an argument against giving it new capabilities, not
    against making a transport ASH still advertises in ``_VALID_TRANSPORTS``
    work at the address the operator asked for.

    Returns:
        A Starlette application ready to hand to uvicorn.

    Raises:
        RuntimeError: if MCPServer is not installed.
        ASHValidationError: for the bind :func:`_validate_bind` refuses, for an
            ``auth_header_value`` with a character outside latin-1, a control
            byte, or a space or tab at either end, for exactly one of
            ``auth_header_name`` and ``auth_header_value``, and for a
            ``session_workspace_ttl`` that is not a positive number of seconds.
            Each is raised before the shared server is touched.
    """
    if MCPServer is None:
        raise RuntimeError(
            "MCPServer is not installed. The 'mcp' package is required for "
            "the sse transport."
        )
    # First, as on the streamable-HTTP path: a value the middleware refuses, or a
    # TTL that is not a positive number of seconds, stops the build before it
    # reads the transport security or calls the server.
    auth_middleware = _auth_middleware_if_configured(
        auth_header_name, auth_header_value
    )
    workspace_ttl = _workspace_ttl(session_workspace_ttl)
    security = _transport_security(host, allowed_hosts, trust_upstream_host_check, port)
    from automated_security_helper.cli.mcp_server import mcp as _mcp_instance

    # Same v2 change as the streamable-HTTP path above: sse_path is a keyword
    # argument on sse_app() rather than a Settings field.
    app_kwargs = {"sse_path": mount_path, "host": host}
    app_kwargs["transport_security"] = security
    app = _mcp_instance.sse_app(**app_kwargs)
    # The session of an sse request is the one the server issued for its event
    # stream; a header on a message POST is ignored.
    app.add_middleware(
        SessionBoundary,
        mode=MODE_SSE,
        session_workspace_ttl=workspace_ttl,
    )

    if auth_middleware is not None:
        app.add_middleware(auth_middleware)

    return _stop_scans_when_the_app_stops(app)


def _ash_log_level_to_uvicorn(level: AshLogLevel) -> str:
    """Map AshLogLevel onto uvicorn's accepted log level names."""
    # uvicorn accepts: critical, error, warning, info, debug, trace.
    # AshLogLevel.VERBOSE is treated as debug for HTTP transport noise.
    name = level.value.lower() if hasattr(level, "value") else str(level).lower()
    if name in {"critical", "error", "warning", "info", "debug", "trace"}:
        return name
    if name == "verbose":
        return "debug"
    return "info"


def _bind_listen_socket(host: str):
    """Bind ``host`` on a port the system chooses, the way uvicorn binds a host.

    Used for ``--port 0``: the app has to be built for the port it listens on
    (see :func:`_transport_security`), and that port is known only once bound.
    """
    import socket

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listen_socket = socket.socket(family=family)
    try:
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_socket.bind((host, 0))
    except OSError:
        listen_socket.close()
        raise
    listen_socket.set_inheritable(True)
    return listen_socket


def _log_where_the_server_listens(config, listen_socket) -> None:
    """Log uvicorn's "Uvicorn running on" line for a socket ASH bound itself.

    uvicorn logs that line from ``Server.startup`` only for a socket it binds.
    Measured on uvicorn 0.54.0: given ``sockets``, it logs nothing, on the
    assumption that ``Config.bind_socket`` already did. A caller that starts
    ``ash mcp`` on ``--port 0`` learns its port from this line, so it is logged
    here instead, on uvicorn's logger and in its format, colored message
    included: the address part bold, as uvicorn's own ``style`` writes it. The
    host is the one uvicorn was given, as in uvicorn's line, and the port is the
    one the socket is bound to.

    The line is written out here rather than by calling uvicorn's private
    ``Server._log_started_message``, which a release inside the supported
    ``uvicorn>=0.54.0,<1`` range could rename or change. A unit test checks that
    the two log the same record.
    """
    import logging

    host = "0.0.0.0" if config.host is None else config.host  # nosec B104 - the host shown in the "running on" line; the socket is already bound, nothing binds here
    address = "%s://[%s]:%d" if ":" in host else "%s://%s:%d"
    logging.getLogger("uvicorn.error").info(
        f"Uvicorn running on {address} (Press CTRL+C to quit)",
        "https" if config.ssl else "http",
        host,
        listen_socket.getsockname()[1],
        extra={
            "color_message": (
                f"Uvicorn running on \033[1m{address}\033[0m (Press CTRL+C to quit)"
            )
        },
    )


def _stop_scans_when_the_app_stops(app):
    """Make ``app``'s lifespan stop the scans and their tools when it ends.

    A scanner's tool runs in a session of its own (utils/subprocess_utils), so
    the server's exit does not end it. A graceful uvicorn stop ends the app's
    lifespan and then cancels the scans' tasks, which stopped the tools with the
    ordinary ten-second grace while the process waited; the stdio server stops
    them promptly instead (cli/mcp_server._lifespan). The app's lifespan, not
    the MCP server's: over HTTP that one is entered per session, and a session
    that ends does not end the server's scans.

    A scan still running once the stop is done, busy where no cancel check
    reaches it, does not hold up a server that a signal stopped
    (_exit_if_a_signal_stopped_the_server).
    """
    from contextlib import asynccontextmanager

    from automated_security_helper.cli import mcp_server

    inner = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(scope_app):
        async with inner(scope_app) as state:
            try:
                yield state
            finally:
                still_running = await mcp_server.stop_scans_at_server_exit(
                    "the HTTP server is stopping"
                )
                if still_running:
                    _exit_if_a_signal_stopped_the_server()

    app.router.lifespan_context = lifespan
    return app


#: The status `ash mcp` exits with when a signal stopped the HTTP server and a
#: scan was still running once the stop was done: 130 for Ctrl-C, as on every
#: transport, and 0 for SIGHUP, as when uvicorn returns. SIGTERM is not here.
#: uvicorn raises it again once the lifespan is done, and its default action ends
#: the process there, before anything waits for a scan's thread.
_EXIT_STATUS_BY_STOP_SIGNAL: Dict[int, int] = {signal.SIGINT: ASH_EXIT_INTERRUPTED}
if hasattr(signal, "SIGHUP"):
    _EXIT_STATUS_BY_STOP_SIGNAL[signal.SIGHUP] = 0

#: The first signal that asked the uvicorn server _run_uvicorn runs to stop, until
#: _run_uvicorn returns; None when none has (_note_the_signal_that_stops).
_stop_signal: Optional[int] = None


def _exit_if_a_signal_stopped_the_server() -> None:
    """Exit at once with the signal's status, if a signal stopped the server.

    Called when the app's lifespan has stopped the scans and one was still
    running, busy in Python where no cancel check reaches it. Left to uvicorn,
    the process then waited for that scan's thread, when asyncio closed its loop
    and again at interpreter exit: measured with a stand-in phase busy for 30 s,
    Ctrl-C exited 130 and SIGHUP 0 about 32 s after the signal, and a second
    Ctrl-C did not help. A stdio server exits the same way after the same stop
    (cli/mcp_server._stop_on_signal).

    The exit comes after the stop, as on stdio, so the scans that did stop have
    put their previous results back by then, each on its own thread. The scan
    still running keeps its previous results held in .ash_previous_results, where
    the next scan in that directory takes them back.
    """
    stop_signal = _stop_signal
    if stop_signal is None:
        return
    status = _EXIT_STATUS_BY_STOP_SIGNAL.get(stop_signal)
    if status is None:
        return
    from automated_security_helper.cli import mcp_server

    name = signal.Signals(stop_signal).name
    _logger.warning(
        f"{name} received and a scan did not stop: exiting without waiting for it"
    )
    mcp_server.exit_at_once(status)


def _ask_server_to_stop_on_sighup(server) -> Callable[[], None]:
    """Treat SIGHUP as uvicorn treats SIGTERM, and return what puts it back.

    uvicorn handles SIGINT and SIGTERM only, so SIGHUP (a closed terminal, a
    supervisor's reload) ended the process at once, before the app's lifespan
    could stop the scans, and every scanner's tool kept running. Only the main
    thread can set a handler, and Windows has no SIGHUP.

    A process started with SIGHUP ignored keeps it ignored, as a stdio server
    does (cli/mcp_server._watched_stop_signals). nohup starts a command that way
    so that it outlives the terminal it was started from, and this handler
    replaced it, so that closing the terminal stopped the server, with exit 0.
    Nothing in `ash mcp` sets SIGHUP before this, so one that is ignored here was
    ignored when the process started.
    """
    import threading

    if (
        not hasattr(signal, "SIGHUP")
        or threading.current_thread() is not threading.main_thread()
        or signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
    ):
        return lambda: None
    previous = signal.signal(signal.SIGHUP, server.handle_exit)

    def put_back() -> None:
        signal.signal(signal.SIGHUP, previous)

    return put_back


def _uvicorn_server_class():
    """uvicorn's Server, kept off SIGINT when the process started with it ignored.

    A shell starts a background job (``ash mcp --transport streamable-http &``)
    with SIGINT ignored, so that a Ctrl-C meant for the job in the foreground
    does not reach it. Python and asyncio leave an ignored SIGINT ignored, and so
    does the stdio server (cli/mcp_server._watched_stop_signals). uvicorn does
    not. Measured on uvicorn 0.54.0: ``Server.capture_signals`` points SIGINT and
    SIGTERM at ``handle_exit`` with ``signal.signal`` whatever was set before, so
    Ctrl-C would stop the background server, which would then exit 0.

    The subclass lets uvicorn install its handlers and then ignores SIGINT again
    before the server starts, and uvicorn puts back what it found on the way out,
    which is SIG_IGN again. The subclass's ``handle_exit`` drops a SIGINT
    delivered in the instant between the two. SIGTERM and SIGHUP
    (_ask_server_to_stop_on_sighup) stop the server. Whether SIGINT was
    ignored is the disposition the process started with, which is what the shell
    set (automated_security_helper.cli.SIGINT_IGNORED_AT_START).
    """
    import contextlib
    import threading

    import uvicorn

    from automated_security_helper import cli

    if not cli.SIGINT_IGNORED_AT_START:
        return uvicorn.Server

    class _SigintIgnoringServer(uvicorn.Server):
        @contextlib.contextmanager
        def capture_signals(self):
            with super().capture_signals():
                # uvicorn sets no handler off the main thread, and neither can we.
                if threading.current_thread() is threading.main_thread():
                    signal.signal(signal.SIGINT, signal.SIG_IGN)
                yield

        def handle_exit(self, sig, frame) -> None:
            if sig != signal.SIGINT:
                super().handle_exit(sig, frame)

    return _SigintIgnoringServer


def _note_the_signal_that_stops(server) -> None:
    """Record in _stop_signal the first signal that asks ``server`` to stop.

    By wrapping its handle_exit, which uvicorn installs for SIGINT and SIGTERM,
    and _ask_server_to_stop_on_sighup for SIGHUP. A SIGINT that the server of
    _uvicorn_server_class drops does not ask it to stop, and is not recorded.

    A Ctrl-C that forces the stop ends the process (_exit_when_forced).

    The wrapper is bound to the server, as uvicorn's own handler is:
    sse_starlette finds the server from the SIGTERM handler's ``__self__``, to
    end its event streams when the server stops, if its patch of uvicorn's
    ``Server.handle_exit`` did not take.
    """
    handle_exit = server.handle_exit

    def noting(self, sig, frame) -> None:
        global _stop_signal
        forced_before = self.force_exit
        handle_exit(sig, frame)
        if _stop_signal is None and self.should_exit:
            _stop_signal = sig
        if self.force_exit and not forced_before:
            _exit_when_forced()

    server.handle_exit = types.MethodType(noting, server)


def _exit_when_forced() -> None:
    """Kill the scanners' tools' groups and exit with 130, at once.

    For the second Ctrl-C, which uvicorn takes as a force quit, while its
    graceful stop waits for the open connections to close. The app's lifespan,
    which stops the scans, runs after that wait, and a forced stop skips it. Nor
    does a forced stop end the wait: uvicorn still awaits asyncio's
    Server.wait_closed, which since Python 3.12.1 returns only once every
    connection has closed. Measured on uvicorn 0.54.0 under Python 3.14, with a
    client that kept a request open, the server went on running after the second
    Ctrl-C, its scans' tools with it, for as long as the client kept the request
    open, and SIGKILL, the signal left to end it with, left the tools running.
    _run_uvicorn's finally is never reached in that wait, so the exit is made
    here.

    Scheduled on the event loop, whose thread the handler runs on, rather than
    run in the handler: the handler can interrupt that thread in the middle of
    kill_running_groups, whose lock is not reentrant, or of a write to stdout,
    which exit_at_once flushes. Between callbacks the loop holds neither, and
    while uvicorn waits it has nothing else to run. The scans' previous results
    stay held, or halfway back, in their output directories, where the next scan
    in each takes them back (core/previous_results).
    """
    import asyncio

    from automated_security_helper.cli import mcp_server

    def exit_now() -> None:
        _logger.warning(
            "SIGINT received again while the server was stopping: killing the "
            "scanners' tools and exiting without waiting for the open connections"
        )
        # uvicorn forces a stop only on SIGINT, which exits 130 on every transport.
        mcp_server.exit_at_once(ASH_EXIT_INTERRUPTED)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        exit_now()
    else:
        loop.call_soon_threadsafe(exit_now)


#: How long uvicorn's graceful stop waits for the open connections and their
#: requests before it cancels them and goes on to the app's lifespan, which stops
#: the scans and ends their tools. Unbounded, it waited for as long as a client
#: kept a request open, the tools running throughout. A service manager follows
#: SIGTERM with SIGKILL once a grace of its own runs out (``docker stop``: 10 s
#: for a Linux container, https://docs.docker.com/reference/cli/docker/container/stop/),
#: and a SIGKILL leaves the tools running, so this stays short enough for the
#: whole stop to finish inside that.
_GRACEFUL_SHUTDOWN_SECONDS = 5


def _run_uvicorn(
    app, host: str, port: int, log_level: AshLogLevel, listen_socket=None
) -> None:
    """Run an ASGI app via uvicorn, blocking until shutdown.

    Raises ``RuntimeError`` when uvicorn returns without the server having
    started and no signal stopped it, which is how a failed application
    startup ends; the failure itself is in the log.

    ``listen_socket`` is an already bound socket to serve on instead of binding
    ``host`` and ``port`` (see :func:`_bind_listen_socket`). Once the server
    listens on it, the line that names its address is logged as uvicorn logs it
    for a socket of its own (see :func:`_log_where_the_server_listens`).

    Whatever is left of the scanners' tools' groups when uvicorn returns or
    raises is killed: a server that failed before or during its lifespan's
    shutdown stopped no scan. A SIGKILL cannot be handled; see the MCP server
    guide for what it leaves behind. A SIGINT the process started with ignored
    stays ignored (_uvicorn_server_class), and so does a SIGHUP
    (_ask_server_to_stop_on_sighup). The signal that stops the server is
    recorded, so that a scan that does not stop cannot keep a Ctrl-C or SIGHUP
    waiting (_exit_if_a_signal_stopped_the_server). The graceful stop's wait for
    the open connections is bounded (_GRACEFUL_SHUTDOWN_SECONDS). A second
    Ctrl-C, uvicorn's force quit, kills the groups and exits from the event loop
    at once, because uvicorn may not return then (_exit_when_forced).
    """
    global _stop_signal
    import socket

    import uvicorn

    from automated_security_helper.utils.log import (
        check_commands_of_stderr,
        check_commands_of_stdout,
        route_library_handlers_through_command_check,
    )
    from automated_security_helper.utils.subprocess_utils import kill_running_groups

    # The sinks that are not handlers (lastResort, warnings, the excepthooks, a
    # stray print) write to the console a CI step reads, as for stdio
    # (cli/mcp_server.run_mcp_server). Wrapped before uvicorn.Config, whose
    # logging setup gives uvicorn's handlers sys.stderr and sys.stdout as they
    # are then: so they write through these wraps, and one line state sees
    # their lines and every other write to the stream.
    check_commands_of_stderr()
    check_commands_of_stdout()
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_level=_ash_log_level_to_uvicorn(log_level),
        access_log=False,
        timeout_graceful_shutdown=_GRACEFUL_SHUTDOWN_SECONDS,
    )

    class _Server(_uvicorn_server_class()):
        async def startup(self, sockets: Optional[List[socket.socket]] = None) -> None:
            # uvicorn exits from startup when the app's startup fails, so the
            # line is logged only for a server that started and listens.
            await super().startup(sockets=sockets)
            if sockets:
                _log_where_the_server_listens(self.config, sockets[0])

    server = _Server(config)
    # uvicorn has configured its loggers' handlers by now, on the wraps the two
    # calls above put in sys.stdout's and sys.stderr's place; the routing leaves
    # a stream that is checked already as it is and wraps any other std stream a
    # library's handler writes to.
    route_library_handlers_through_command_check()
    _note_the_signal_that_stops(server)
    put_sighup_back = _ask_server_to_stop_on_sighup(server)
    try:
        server.run(sockets=None if listen_socket is None else [listen_socket])
        if not server.started and _stop_signal is None:
            # uvicorn returns from run() when the app's lifespan startup fails,
            # having logged the failure itself, and the process then exited 0
            # as if it had served and been asked to stop. Nothing listened. A
            # server stopped by a signal before it started is not this: the
            # signal's own exit status applies.
            raise RuntimeError(
                "the MCP server did not start: its application failed during "
                "startup (see the log above)"
            )
    finally:
        _stop_signal = None
        put_sighup_back()
        kill_running_groups()


def _ash_config_refusal() -> Optional[str]:
    """Why ``ASH_CONFIG`` can't be the server's policy, or None when it can.

    ``ASH_CONFIG`` is the operator's explicit policy for every scan that names no
    config of its own, so the server loads it at startup with
    :meth:`AshConfig.from_file`, as it loads each ``--profile``. A path that
    names nothing or a directory, a file the server can't read, and a file that
    fails to parse or validate are each refused here, before anything is served.

    The path is checked with ``stat`` rather than ``Path.is_file``. For a path
    under a directory the server can't search, ``is_file`` raises on some Python
    versions and returns False on others; ``stat`` raises ``PermissionError`` on
    all of them.
    """
    from automated_security_helper.config.ash_config import AshConfig

    value = os.environ.get("ASH_CONFIG")
    if not value:
        return None
    path = Path(value)
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return f"ASH_CONFIG={value} names no config file."
    except OSError as exc:
        return f"ASH_CONFIG={value} could not be read: {exc}"
    if not stat.S_ISREG(mode):
        return f"ASH_CONFIG={value} names no config file."
    try:
        AshConfig.from_file(path)
    except Exception as exc:
        # The same breadth as register_profiles: OSError, YAML and JSON errors,
        # pydantic's ValidationError, and the ValueError an extends chain raises.
        return f"ASH_CONFIG={value} could not be loaded: {exc}"
    return None


def _logging_to_stderr(command):
    """Run ``command`` with ``ASH_LOG_TO_STDERR=1``, then put the variable back.

    The MCP server runs scans in-process: mcp_tools hands run_ash_scan to
    loop.run_in_executor, which is a thread in this same process. That scan calls
    get_logger, which reads this variable to choose the stream of the RichHandler it
    attaches to the shared "ash" logger. Without it every log record from the scan
    phase, suppression matching and the reporters would be written to stdout --
    inside the JSON-RPC stream on the stdio transport, which is the reported
    "Expecting value" failure. It applies to the HTTP transports too, where it is
    harmless.

    Set for the call, not for the process, so a get_logger call after the command
    returns (another command in a process that lives on, or the next test on a
    worker) does not build a stderr console. The previous
    value, or its absence, comes back on every way out, typer.Exit and
    KeyboardInterrupt included.

    Nothing ASH starts while serving needs the variable: the scanners' tools do not
    read it, and ASH's worker processes do not configure logging.
    """

    @functools.wraps(command)
    def run(*args, **kwargs):
        with environ_overrides({"ASH_LOG_TO_STDERR": "1"}):
            return command(*args, **kwargs)

    return run


@_logging_to_stderr
def mcp_command(
    ctx: typer.Context,
    log_level: Annotated[
        AshLogLevel,
        typer.Option(
            "--log-level",
            help="Set the log level.",
            case_sensitive=False,
        ),
    ] = AshLogLevel.INFO,
    verbose: Annotated[
        bool,
        typer.Option("--verbose/--no-verbose", "-v", help="Enable verbose logging"),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("--debug/--no-debug", "-d", help="Enable debug logging"),
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    # Off by default, as on `ash mcp` (the wrapper in cli/main.py). On by default,
    # -v and -d would fail the --quiet check below unless --no-quiet was also
    # given.
    quiet: Annotated[bool, typer.Option(help="Hide all log output")] = False,
    transport: Annotated[
        str,
        typer.Option(
            "--transport",
            help="Transport: 'stdio' (default), 'streamable-http', or 'sse'.",
        ),
    ] = "stdio",
    host: Annotated[
        str,
        typer.Option("--host", help="Host to bind for HTTP transports."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", help="Port to bind for HTTP transports."),
    ] = 8000,
    mount_path: Annotated[
        str,
        typer.Option(
            "--mount-path",
            help="HTTP path the transport listens on (default: /mcp for streamable-http, /sse for sse).",
        ),
    ] = "/mcp",
    auth_header_name: Annotated[
        Optional[str],
        typer.Option(
            "--auth-header-name",
            help="Required HTTP header name for single-tenant auth (HTTP transports only).",
        ),
    ] = None,
    auth_header_value: Annotated[
        Optional[str],
        typer.Option(
            "--auth-header-value",
            help="Expected value of --auth-header-name. Visible to other local "
            "users on the command line; prefer --auth-header-value-file or "
            "--auth-header-value-fd.",
        ),
    ] = None,
    auth_header_value_file: Annotated[
        Optional[Path],
        typer.Option(
            "--auth-header-value-file",
            help="Read the expected value of --auth-header-name from this file, "
            "once at startup: a regular file, not a symlink, readable by its owner "
            "only. One trailing newline is dropped.",
        ),
    ] = None,
    auth_header_value_fd: Annotated[
        Optional[int],
        typer.Option(
            "--auth-header-value-fd",
            help="Read the expected value of --auth-header-name from this inherited "
            "file descriptor (3 or above), once at startup, then close it.",
        ),
    ] = None,
    stateless_http: Annotated[
        bool,
        typer.Option(
            "--stateless-http/--no-stateless-http",
            help="Handle each streamable-HTTP request independently instead of "
            "binding it to a server-held session. Required behind a load balancer "
            "that may route consecutive requests to different replicas, and by "
            "managed runtimes that inject their own Mcp-Session-Id. Only valid "
            "with --transport streamable-http.",
        ),
    ] = False,
    trust_upstream_session_id: Annotated[
        bool,
        typer.Option(
            "--trust-upstream-session-id",
            help="Stateless streamable-HTTP only. Declare that a platform in front "
            "of ASH issues and authenticates the Mcp-Session-Id header, so it can "
            "name the caller's session. Without it a stateless server identifies "
            "no session, and tools that need one (source delivery, profiles, the "
            "scan registry) refuse.",
        ),
    ] = False,
    allowed_host: Annotated[
        Optional[List[str]],
        typer.Option(
            "--allowed-host",
            help="Host header value to accept, repeatable. Keeps DNS-rebinding "
            "protection enabled while allowing a known proxy or load balancer "
            "hostname. Required with a non-loopback --host unless "
            "--trust-upstream-host-check is given.",
        ),
    ] = None,
    session_workspace_ttl: Annotated[
        Optional[int],
        typer.Option(
            "--session-workspace-ttl",
            help="HTTP transports only. Seconds a session workspace (delivered "
            "source, uploads, bound profile) may go unused before it is removed. "
            "Covers sessions whose end the server cannot see, such as every "
            "stateless one. Default: 86400 (24 hours).",
        ),
    ] = None,
    trust_upstream_host_check: Annotated[
        bool,
        typer.Option(
            "--trust-upstream-host-check",
            help="HTTP transports only. Declare that a proxy or platform in front "
            "of ASH checks the Host and Origin headers, so ASH serves any. Without "
            "it, a non-loopback --host needs --allowed-host or the server refuses "
            "to start. Cannot be combined with --allowed-host.",
        ),
    ] = False,
    profile: Annotated[
        Optional[List[str]],
        typer.Option(
            "--profile",
            help="Register a named config profile as NAME=path/to/ash.yaml, "
            "repeatable. Clients list them with the list_profiles tool and bind "
            "one to their session with select_profile; a bound profile supplies "
            "the config for every later call in that session that names none. "
            "Each file is loaded and schema-validated now, so a typo fails "
            "startup rather than a scan.",
        ),
    ] = None,
) -> None:
    """Start the ASH MCP server.

    Default transport is ``stdio`` — identical to prior behavior. Pass
    ``--transport streamable-http`` to expose the server over HTTP via
    uvicorn, optionally guarded by a single static auth header.
    """
    # Handle resilient parsing for command discovery
    if ctx.resilient_parsing:
        return

    # ASH_LOG_TO_STDERR is set for the whole call by @_logging_to_stderr above.

    # Check for MCP dependencies using our validation function
    if not validate_mcp_dependencies():
        _stderr.print("[red]Error: MCP dependencies are not available.[/red]")
        _stderr.print()
        _stderr.print(
            "MCP support is included by default in ASH v3. Try reinstalling ASH:"
        )
        # Reinstall from where the running ASH was installed from: its git
        # commit, its checkout, or its archive. ASH's distribution name on its
        # own ("pip install --force-reinstall automated-security-helper", the
        # earlier text) is not a reinstall of ASH: on PyPI that name belongs to
        # an unrelated project. The command is escaped because a path can hold
        # a "[" that rich would read as markup.
        # soft_wrap keeps it on one line: stderr is rarely a terminal here, rich
        # then wraps at 80 columns, and a command split before its source is a
        # pip install with no requirement.
        _stderr.print(
            f"  [cyan]{escape_markup(ash_reinstall_command())}[/cyan]",
            soft_wrap=True,
        )
        # For a checkout, the MCP testing guide's sync. --inexact keeps the extras
        # installed there; a plain `uv sync` is exact and removes them.
        _stderr.print(
            "  uv sync --inexact --reinstall-package automated-security-helper",
            style="cyan",
            markup=False,
            soft_wrap=True,
        )
        _stderr.print()
        _stderr.print(
            "If the issue persists, check your Python environment and ASH installation."
        )
        raise typer.Exit(1)

    # If we reach here, MCP dependencies are available
    if not quiet:
        _stderr.print("[green]MCP dependencies found. Starting MCP server...[/green]")

    # Validate command options for consistency. The auth header value is read
    # here, once, from whichever form carries it; a file or descriptor that holds
    # no usable value stops startup like any other bad option. Each refusal below
    # is of the command line itself -- a value or a combination of options the
    # server cannot run with -- so each exits with the usage-error code, not 3,
    # which reports an invalid config.
    try:
        validate_command_options(verbose, debug, quiet)
        argv_auth_value = auth_header_value is not None
        auth_header_value = _resolve_auth_header_value(
            auth_header_value, auth_header_value_file, auth_header_value_fd
        )
        _validate_auth_options(auth_header_name, auth_header_value)
    except ASHValidationError as e:
        _stderr.print(f"[red]Validation Error: {escape_markup(error_text(e))}[/red]")
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)
    if argv_auth_value:
        # Not gated on --quiet: the value is already on the command line, where
        # every local user can read it, and this is the one place that says so.
        _stderr.print(
            "[yellow]Warning: --auth-header-value puts the value on this "
            "process's command line, which other local users can read. Pass it "
            "with --auth-header-value-file or --auth-header-value-fd "
            "instead.[/yellow]",
            highlight=False,
        )

    # ASH_MCP_TRANSPORT is the operator's override that makes every caller
    # remote. A value that names no transport (a typo such as "http") would leave
    # the override in an unknown state, so the server refuses to start. The
    # value is part of how the server was invoked, not a config file, so the
    # refusal is a usage error, exit 5, where a config that can't be used is 3.
    #
    # Before the --transport check: the container entrypoint (ash-mcp-serve)
    # passes this variable's value as --transport too, and the variable is the
    # operator's mistake to report.
    from automated_security_helper.cli.mcp.sandbox import (
        ASH_MCP_TRANSPORT_ENV,
        KNOWN_TRANSPORTS,
        unknown_transport_override,
    )

    unknown = unknown_transport_override()
    if unknown is not None:
        _stderr.print(
            f"[red]Validation Error: {ASH_MCP_TRANSPORT_ENV}={escape_markup(repr(unknown))} "
            f"names no transport; use one of {sorted(KNOWN_TRANSPORTS)} (any case), "
            f"or unset it.[/red]",
            highlight=False,
        )
        raise typer.Exit(_EXIT_USAGE)

    # Each value below is the operator's or an error's, printed to a console that
    # reads markup, so it is escaped once: a "[/x]" in it raised MarkupError.
    if transport not in _VALID_TRANSPORTS:
        _stderr.print(
            f"[red]Validation Error: --transport must be one of {_VALID_TRANSPORTS}, "
            f"got '{escape_markup(transport)}'.[/red]"
        )
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)

    # A value the server can't load would leave every scan that names no config
    # on the built-in default, so the server refuses to start instead.
    refusal = _ash_config_refusal()
    if refusal is not None:
        _stderr.print(
            f"[red]Validation Error: {escape_markup(refusal)} "
            f"Point ASH_CONFIG at the operator's config file, or unset it to scan "
            f"with the built-in default.[/red]",
            highlight=False,
        )
        raise typer.Exit(3)

    # After the transport check, not with the auth options above: an unknown
    # transport combined with --stateless-http should be reported as an unknown
    # transport, which is the operator's actual mistake.
    try:
        _validate_stateless_http(transport, stateless_http)
        _validate_trust_upstream_session_id(
            transport, stateless_http, trust_upstream_session_id
        )
        if transport == "stdio":
            if trust_upstream_host_check:
                raise ASHValidationError(
                    "--trust-upstream-host-check only applies to the HTTP "
                    "transports; stdio has no Host header to check."
                )
            if session_workspace_ttl is not None:
                raise ASHValidationError(
                    "--session-workspace-ttl only applies to the HTTP transports; "
                    "a stdio server removes its session workspace when it exits."
                )
        else:
            _workspace_ttl(session_workspace_ttl)
            # Before anything is built or bound: a refused bind must never
            # reach the socket.
            _validate_bind(host, allowed_host, trust_upstream_host_check)
    except ASHValidationError as e:
        _stderr.print(f"[red]Validation Error: {escape_markup(error_text(e))}[/red]")
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)

    # Deliberately NOT recording the transport here. The scan-target and
    # config-input boundaries decide "is this caller remote" per call, from the
    # session the transport supplied -- cli/mcp/http_sessions.py stamps each HTTP
    # request with it, per app -- which is request-scoped and needs nothing from
    # this function.
    #
    # An earlier version did set it, and process-wide state turned out to be the
    # wrong shape: the value outlives the server object, so a process that ran this
    # command and then did anything else evaluated every later call as remote. That
    # is fail-closed, so it surfaced as unrelated refusals rather than unsafe
    # accepts -- 32 tests, none of them about transports -- but a boundary whose
    # answer depends on what ran earlier in the process is not one worth having.
    #
    # ASH_MCP_TRANSPORT remains available as an operator override that makes every
    # caller remote. Like ASH_MCP_ALLOWED_ROOTS it is read and never written, which
    # is what keeps it from leaking.

    # Load and validate every --profile now, so an operator's typo fails startup
    # with a message about the profile rather than surfacing later as a scan that
    # ran under a config nobody chose. register_profiles raises
    # ProfileRegistryError, a ValueError, for a malformed spec, a missing file,
    # unparseable YAML, or an unknown top-level key.
    if profile:
        try:
            set_profile_registry(register_profiles(list(profile)))
        except ValueError as e:
            _stderr.print(
                f"[red]Validation Error: {escape_markup(error_text(e))}[/red]"
            )
            raise typer.Exit(3)
        if not quiet:
            _stderr.print(
                f"[green]Registered {len(profile)} config profile(s).[/green]"
            )

    # Validate and configure logging options
    log_level_value = validate_log_options(verbose, debug, log_level)

    # The process-wide last-resort gate, set once at the server's start: the
    # level the operator asked for here; a name logging does not know (SIMPLE,
    # say) falls back to ASH_LOG_LEVEL, WARNING by default. The hosted scans'
    # own logger setup never moves this gate.
    configure_last_resort_level(log_level_value.value)

    # Log the command execution
    _logger.info(
        f"Starting MCP server with transport={transport}, log level={log_level_value}"
    )

    # Before any transport starts: MCP scans never run a tool from inside a scanned
    # tree, whatever ASH_ALLOW_IN_TREE_TOOLS says. See MCP_HONORS_IN_TREE_OPT_IN.
    from automated_security_helper.cli.mcp_server import MCP_HONORS_IN_TREE_OPT_IN
    from automated_security_helper.utils.subprocess_utils import honor_in_tree_opt_in

    honor_in_tree_opt_in(MCP_HONORS_IN_TREE_OPT_IN)

    # For the except clause below; imported lazily so importing this package
    # does not pull the sessions module in.
    from automated_security_helper.cli.mcp.sessions import PresenceLockError

    # Initialize and start the MCP server with comprehensive error handling
    listen_socket = None
    try:
        if transport != "stdio" and port == 0:
            # A loopback app accepts only its own port, so it is built for the
            # port the system chose: bind first. The bind is checked before
            # anything is bound.
            _validate_bind(host, allowed_host, trust_upstream_host_check)
            listen_socket = _bind_listen_socket(host)
            port = listen_socket.getsockname()[1]
        if transport == "stdio":
            # Import and run the stdio MCP server implementation here to avoid
            # circular imports.
            from automated_security_helper.cli.mcp_server import run_mcp_server

            run_mcp_server()
        elif transport == "streamable-http":
            app = build_streamable_http_app(
                mount_path=mount_path,
                auth_header_name=auth_header_name,
                auth_header_value=auth_header_value,
                stateless_http=stateless_http,
                # The same host uvicorn is about to bind. Passing a different
                # value here than to _run_uvicorn below is the bug this argument
                # exists to prevent.
                host=host,
                allowed_hosts=allowed_host,
                trust_upstream_session_id=trust_upstream_session_id,
                trust_upstream_host_check=trust_upstream_host_check,
                session_workspace_ttl=session_workspace_ttl,
                port=port,
            )
            if not quiet:
                _stderr.print(
                    f"[green]Streamable-HTTP MCP server listening on "
                    f"{escape_markup(f'http://{host}:{port}{mount_path}')}[/green]"
                )
            _run_uvicorn(
                app,
                host=host,
                port=port,
                log_level=log_level_value,
                listen_socket=listen_socket,
            )
        elif transport == "sse":
            # The mount-path default is /mcp, but SSE conventionally lives at
            # /sse. Honor whatever the user passed; only override if they kept
            # the streamable-HTTP default.
            sse_path = mount_path if mount_path != "/mcp" else "/sse"
            app = build_sse_app(
                mount_path=sse_path,
                auth_header_name=auth_header_name,
                auth_header_value=auth_header_value,
                # Same reason as the streamable-HTTP branch: the SDK decides
                # whether to install a loopback-only Host allowlist from the host
                # it is *built* with, so building with a different value than
                # uvicorn binds makes the app answer 421 to every proxied request.
                host=host,
                allowed_hosts=allowed_host,
                trust_upstream_host_check=trust_upstream_host_check,
                session_workspace_ttl=session_workspace_ttl,
                port=port,
            )
            if not quiet:
                _stderr.print(
                    f"[green]SSE MCP server listening on "
                    f"{escape_markup(f'http://{host}:{port}{sse_path}')}[/green]"
                )
            _run_uvicorn(
                app,
                host=host,
                port=port,
                log_level=log_level_value,
                listen_socket=listen_socket,
            )
    except KeyboardInterrupt:
        # Ctrl-C, ASH_EXIT_INTERRUPTED on every transport. uvicorn raises SIGINT
        # again once its graceful stop is done, and it arrives here as
        # KeyboardInterrupt; with a scan that did not stop, the HTTP server exits
        # with the same status before that (_exit_if_a_signal_stopped_the_server),
        # and so it does on a second Ctrl-C (_exit_when_forced).
        # A stdio server exits from its signal watcher without
        # returning (cli/mcp_server._stop_on_signal), and raises KeyboardInterrupt
        # only where it cannot watch for signals. A process started with SIGINT
        # ignored gets no Ctrl-C on any transport (_uvicorn_server_class).
        _logger.info("MCP server shutdown requested by user")
        if not quiet:
            _stderr.print("\n[yellow]MCP server shutdown requested by user[/yellow]")
        raise typer.Exit(ASH_EXIT_INTERRUPTED)
    except PresenceLockError as e:
        # The error's own message names the entry, the error that refused the
        # lock and the option that moves the root (ASH_MCP_WORKSPACE_ROOT), so
        # print it alone: "MCP server failed" and a "check system resources"
        # hint would bury it. Exit 3, as for the other operator-configuration
        # errors, and printed with --quiet too, which hides log output and not
        # the reason the process stopped.
        _logger.error(error_text(e))
        _stderr.print(f"[red]{escape_markup(error_text(e))}[/red]", highlight=False)
        raise typer.Exit(3)
    except PresenceLockError as e:
        # The error's own message carries the fix (set ASH_MCP_WORKSPACE_ROOT),
        # so print it alone: a traceback and a "check system resources" hint
        # would bury it. Exit 3, as for the other operator-configuration errors.
        _logger.error(str(e))
        if not quiet:
            _stderr.print(f"[red]{escape_markup(str(e))}[/red]", highlight=False)
        raise typer.Exit(3)
    except Exception as e:
        # Also what run_mcp_server raises when the stdio server fails while it
        # serves. The line naming the error is printed even with --quiet, which
        # hides log output: it is why the process exits 1, and the log may be off.
        log_unexpected_error(_logger, e, "MCP server failed")
        _stderr.print(
            f"[red]MCP server failed: {escape_markup(type(e).__name__)}: "
            f"{escape_markup(error_text(e))}[/red]"
        )
        if not quiet:
            _stderr.print(
                "[yellow]Please check system resources and ASH installation.[/yellow]"
            )
        raise typer.Exit(1)
    finally:
        if listen_socket is not None:
            listen_socket.close()
