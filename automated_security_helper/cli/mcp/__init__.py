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

from typing import Annotated, List, Optional
import typer
from rich.console import Console
from rich.markup import escape

from automated_security_helper.cli.mcp.http_sessions import (
    DEFAULT_SESSION_WORKSPACE_TTL_SECONDS,
    MODE_SSE,
    MODE_STATEFUL,
    MODE_STATELESS,
    SessionBoundary,
)
from automated_security_helper.cli.mcp.profile_registry import (
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.core.exceptions import ScannerError, ASHValidationError
from automated_security_helper.utils.ash_install import ash_reinstall_command
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import set_environ

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
_stderr = Console(stderr=True)

# Valid --transport values. Kept as a tuple so typer can render help cleanly
# without forcing an Enum class on the public CLI surface.
_VALID_TRANSPORTS = ("stdio", "streamable-http", "sse")

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


def _validate_auth_options(
    auth_header_name: Optional[str], auth_header_value: Optional[str]
) -> None:
    """Reject partial auth configuration: both or neither.

    Raises:
        ASHValidationError: if exactly one of the two auth options is set.
    """
    if bool(auth_header_name) != bool(auth_header_value):
        raise ASHValidationError(
            "--auth-header-name and --auth-header-value must be set together"
        )


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
    other address without an explicit allowlist switches the check off, so a
    page in a browser that resolves its own name to the server reaches every
    tool. That has to be a decision the operator states, not a default:
    ``--allowed-host`` keeps the check on with the names clients use, and
    ``--trust-upstream-host-check`` says a proxy or platform in front of ASH
    checks Host and Origin instead.

    Raises:
        ASHValidationError: for a non-loopback host with neither option, or with
            both, which contradict each other.
    """
    if allowed_hosts and trust_upstream_host_check:
        raise ASHValidationError(
            "--allowed-host and --trust-upstream-host-check contradict each other: "
            "the first keeps ASH's Host check on for the names given, the second "
            "turns it off because something in front of ASH checks Host. Pass one."
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
    port: int,
):
    """The ``transport_security`` to build an app with.

    On a loopback bind with no allowlist the SDK's own check would accept any
    ``localhost`` origin on any port, so a page served by any other local web
    server could drive this one from the user's browser. The server accepts its
    own origin only: Host ``127.0.0.1``, ``localhost`` or ``[::1]`` with the
    port it is bound to, and the same as ``http://`` origins.

    Raises:
        ASHValidationError: per :func:`_validate_bind`.
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
    own = [f"{name}:{int(port)}" for name in _LOOPBACK_HOST_NAMES]
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
    # See DA r6 #7.
    expected_value_bytes = header_value.encode("latin-1", errors="replace")

    class _StaticHeaderAuth(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            received = request.headers.get(expected_name)
            if received is None or not hmac.compare_digest(
                received.encode("latin-1", errors="replace"), expected_value_bytes
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
    port: int = 8000,
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
        port: The port the server will bind, the same value handed to uvicorn.
            A loopback server accepts only its own origin, which includes the
            port; see :func:`_transport_security`.

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
        RuntimeError: if MCPServer is not installed.
        ASHValidationError: for a non-loopback ``host`` with neither
            ``allowed_hosts`` nor ``trust_upstream_host_check``, or with both.
    """
    if MCPServer is None:
        raise RuntimeError(
            "MCPServer is not installed. The 'mcp' package is required for "
            "the streamable-http transport."
        )
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
        session_workspace_ttl=_workspace_ttl(session_workspace_ttl),
    )

    if auth_header_name and auth_header_value:
        middleware_cls = _build_auth_middleware(auth_header_name, auth_header_value)
        app.add_middleware(middleware_cls)

    return app


def build_sse_app(
    mount_path: str = "/sse",
    auth_header_name: Optional[str] = None,
    auth_header_value: Optional[str] = None,
    host: str = "127.0.0.1",
    allowed_hosts: Optional[List[str]] = None,
    trust_upstream_host_check: bool = False,
    session_workspace_ttl: Optional[int] = None,
    port: int = 8000,
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
        ASHValidationError: for the bind :func:`_validate_bind` refuses.
    """
    if MCPServer is None:
        raise RuntimeError(
            "MCPServer is not installed. The 'mcp' package is required for "
            "the sse transport."
        )
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
        session_workspace_ttl=_workspace_ttl(session_workspace_ttl),
    )

    if auth_header_name and auth_header_value:
        middleware_cls = _build_auth_middleware(auth_header_name, auth_header_value)
        app.add_middleware(middleware_cls)

    return app


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


def _run_uvicorn(app, host: str, port: int, log_level: AshLogLevel) -> None:
    """Run an ASGI app via uvicorn, blocking until shutdown."""
    import uvicorn

    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_level=_ash_log_level_to_uvicorn(log_level),
        access_log=False,
    )
    server = uvicorn.Server(config)
    server.run()


def mcp_command(
    ctx: typer.Context,
    log_level: Annotated[
        AshLogLevel,
        typer.Option(
            "--log-level",
            help="Set the log level.",
        ),
    ] = AshLogLevel.INFO,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    quiet: Annotated[bool, typer.Option(help="Hide all log output")] = True,
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
            help="Expected value of --auth-header-name.",
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

    # The MCP server runs scans in-process: mcp_tools hands run_ash_scan to
    # loop.run_in_executor, which is a thread in this same process. That scan calls
    # get_logger and attaches a RichHandler to the shared "ash" logger, so without
    # this every log record from the scan phase, suppression matching and the
    # reporters would be written to stdout -- inside the JSON-RPC stream on the
    # stdio transport, which is the reported "Expecting value" failure.
    #
    # Set before the transport is chosen so it also covers the HTTP transports,
    # where it is harmless, and before any scan can start.
    set_environ("ASH_LOG_TO_STDERR", "1")

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
            f"  [cyan]{escape(ash_reinstall_command())}[/cyan]",
            soft_wrap=True,
        )
        _stderr.print("  [cyan]uv sync --reinstall[/cyan]")
        _stderr.print()
        _stderr.print(
            "If the issue persists, check your Python environment and ASH installation."
        )
        raise typer.Exit(1)

    # If we reach here, MCP dependencies are available
    if not quiet:
        _stderr.print("[green]MCP dependencies found. Starting MCP server...[/green]")

    # Validate command options for consistency
    try:
        validate_command_options(verbose, debug, quiet)
        _validate_auth_options(auth_header_name, auth_header_value)
    except ASHValidationError as e:
        _stderr.print(f"[red]Validation Error: {str(e)}[/red]")
        raise typer.Exit(3)

    if transport not in _VALID_TRANSPORTS:
        _stderr.print(
            f"[red]Validation Error: --transport must be one of {_VALID_TRANSPORTS}, got '{transport}'.[/red]"
        )
        raise typer.Exit(3)

    # ASH_MCP_TRANSPORT is the operator's override that makes every caller
    # remote. A value it cannot read would be ignored by nothing and obeyed by
    # nobody: refuse to start rather than serve with an override in an unknown
    # state.
    from automated_security_helper.cli.mcp.sandbox import (
        ASH_MCP_TRANSPORT_ENV,
        KNOWN_TRANSPORTS,
        unknown_transport_override,
    )

    unknown = unknown_transport_override()
    if unknown is not None:
        _stderr.print(
            f"[red]Validation Error: {ASH_MCP_TRANSPORT_ENV}={unknown!r} names no "
            f"transport; use one of {sorted(KNOWN_TRANSPORTS)} (any case), or unset "
            f"it.[/red]"
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
        _stderr.print(f"[red]Validation Error: {str(e)}[/red]")
        raise typer.Exit(3)

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
            _stderr.print(f"[red]Validation Error: {str(e)}[/red]")
            raise typer.Exit(3)
        if not quiet:
            _stderr.print(
                f"[green]Registered {len(profile)} config profile(s).[/green]"
            )

    # Validate and configure logging options
    log_level_value = validate_log_options(verbose, debug, log_level)

    # Log the command execution
    _logger.info(
        f"Starting MCP server with transport={transport}, log level={log_level_value}"
    )

    # Before any transport starts: MCP scans never run a tool from inside a scanned
    # tree, whatever ASH_ALLOW_IN_TREE_TOOLS says. See MCP_HONORS_IN_TREE_OPT_IN.
    from automated_security_helper.cli.mcp_server import MCP_HONORS_IN_TREE_OPT_IN
    from automated_security_helper.utils.subprocess_utils import honor_in_tree_opt_in

    honor_in_tree_opt_in(MCP_HONORS_IN_TREE_OPT_IN)

    # Initialize and start the MCP server with comprehensive error handling
    try:
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
                    f"http://{host}:{port}{mount_path}[/green]"
                )
            _run_uvicorn(app, host=host, port=port, log_level=log_level_value)
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
                    f"http://{host}:{port}{sse_path}[/green]"
                )
            _run_uvicorn(app, host=host, port=port, log_level=log_level_value)
    except KeyboardInterrupt:
        _logger.info("MCP server shutdown requested by user")
        if not quiet:
            _stderr.print("\n[yellow]MCP server shutdown requested by user[/yellow]")
        raise typer.Exit(0)
    except ScannerError as e:
        _logger.error(f"ASH Scanner Error: {str(e)}")
        if not quiet:
            _stderr.print(f"[red]ASH Scanner Error: {str(e)}[/red]")
            _stderr.print(
                "[yellow]This indicates an issue with ASH configuration or dependencies.[/yellow]"
            )
        raise typer.Exit(2)
    except ASHValidationError as e:
        _logger.error(f"ASH Validation Error: {str(e)}")
        if not quiet:
            _stderr.print(f"[red]ASH Validation Error: {str(e)}[/red]")
            _stderr.print(
                "[yellow]This indicates invalid configuration or parameters.[/yellow]"
            )
        raise typer.Exit(3)
    except Exception as e:
        _logger.exception(f"Unexpected error starting MCP server: {str(e)}")
        if not quiet:
            _stderr.print(f"[red]Unexpected error starting MCP server: {str(e)}[/red]")
            _stderr.print(f"[red]Error type: {type(e).__name__}[/red]")
            _stderr.print(
                "[yellow]Please check system resources and ASH installation.[/yellow]"
            )
        raise typer.Exit(1)
