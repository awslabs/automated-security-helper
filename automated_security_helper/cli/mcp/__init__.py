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

import os
from typing import Annotated, List, Optional
import typer
from rich.console import Console

from automated_security_helper.core.constants import ASH_REPO_URL
from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.core.exceptions import ScannerError, ASHValidationError
from automated_security_helper.utils.log import ASH_LOGGER

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

    Returns:
        A Starlette application ready to hand to uvicorn.

    Raises:
        RuntimeError: if MCPServer is not installed.
    """
    if MCPServer is None:
        raise RuntimeError(
            "MCPServer is not installed. The 'mcp' package is required for "
            "the streamable-http transport."
        )
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
    if allowed_hosts:
        # Supplying transport_security suppresses the SDK's host-based autodetect
        # entirely, so this is the only branch that can keep protection on while
        # accepting a non-loopback name. allowed_origins is left empty rather than
        # mirroring allowed_hosts: Origin is a browser-supplied header, and an MCP
        # server reached through a proxy has no reason to trust one.
        from mcp.server.transport_security import TransportSecuritySettings

        app_kwargs["transport_security"] = TransportSecuritySettings(
            allowed_hosts=list(allowed_hosts),
            allowed_origins=[],
        )
    app = _mcp_instance.streamable_http_app(**app_kwargs)

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
    """
    if MCPServer is None:
        raise RuntimeError(
            "MCPServer is not installed. The 'mcp' package is required for "
            "the sse transport."
        )
    from automated_security_helper.cli.mcp_server import mcp as _mcp_instance

    # Same v2 change as the streamable-HTTP path above: sse_path is a keyword
    # argument on sse_app() rather than a Settings field.
    app_kwargs = {"sse_path": mount_path, "host": host}
    if allowed_hosts:
        # Supplying transport_security suppresses the SDK's host-based autodetect
        # entirely, exactly as on the streamable-HTTP path. allowed_origins is
        # left empty for the same reason: Origin is browser-supplied, and a
        # server reached through a proxy has no reason to trust one.
        from mcp.server.transport_security import TransportSecuritySettings

        app_kwargs["transport_security"] = TransportSecuritySettings(
            allowed_hosts=list(allowed_hosts),
            allowed_origins=[],
        )
    app = _mcp_instance.sse_app(**app_kwargs)

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
    allowed_host: Annotated[
        Optional[List[str]],
        typer.Option(
            "--allowed-host",
            help="Host header value to accept, repeatable. Keeps DNS-rebinding "
            "protection enabled while allowing a known proxy or load balancer "
            "hostname. Without this, protection is enabled only when --host is "
            "loopback, matching the MCP SDK's own default.",
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
    os.environ["ASH_LOG_TO_STDERR"] = "1"

    # Check for MCP dependencies using our validation function
    if not validate_mcp_dependencies():
        _stderr.print("[red]Error: MCP dependencies are not available.[/red]")
        _stderr.print()
        _stderr.print(
            "MCP support is included by default in ASH v3. Try reinstalling ASH:"
        )
        # Reinstall from git, which is how ASH is distributed. This hint used to
        # read "pip install --force-reinstall automated-security-helper", which
        # is an unrelated project's name on PyPI -- so following it replaced the
        # user's working ASH install with a stranger's package.
        _stderr.print(
            f"  [cyan]pip install --force-reinstall 'git+{ASH_REPO_URL}.git'[/cyan]"
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

    # After the transport check, not with the auth options above: an unknown
    # transport combined with --stateless-http should be reported as an unknown
    # transport, which is the operator's actual mistake.
    try:
        _validate_stateless_http(transport, stateless_http)
    except ASHValidationError as e:
        _stderr.print(f"[red]Validation Error: {str(e)}[/red]")
        raise typer.Exit(3)

    # Validate and configure logging options
    log_level_value = validate_log_options(verbose, debug, log_level)

    # Log the command execution
    _logger.info(
        f"Starting MCP server with transport={transport}, log level={log_level_value}"
    )

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
