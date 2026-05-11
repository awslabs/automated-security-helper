# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
MCP (Model Context Protocol) CLI command for ASH.

This package provides a CLI command to start an MCP server that exposes ASH
security scanning capabilities through the Model Context Protocol. The server
supports multiple transports:

- ``stdio`` (default): legacy in-process transport, no network
- ``streamable-http``: FastMCP streamable-HTTP app served via uvicorn, with
  optional single-tenant header auth
- ``sse``: legacy FastMCP SSE app served via uvicorn (best-effort; the SSE
  transport is deprecated upstream)
"""

from __future__ import annotations

from typing import Annotated, Optional
import typer
from rich import print

from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.core.exceptions import ScannerError, ASHValidationError
from automated_security_helper.utils.log import ASH_LOGGER

# Import MCP dependencies directly. We capture both the FastMCP class and the
# Starlette type so the streamable-HTTP path can build a typed ASGI app.
try:
    from mcp.server.fastmcp import FastMCP, Context
except ImportError:  # pragma: no cover - exercised only when MCP missing
    FastMCP = None  # type: ignore[assignment]
    Context = None  # type: ignore[assignment]

# Configure module logger
_logger = ASH_LOGGER

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
    """Return True when FastMCP and Context are importable."""
    return FastMCP is not None and Context is not None


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
                    {"error": "unauthorized", "detail": "missing or invalid auth header"},
                    status_code=401,
                )
            return await call_next(request)

    return _StaticHeaderAuth


def build_streamable_http_app(
    mount_path: str = "/mcp",
    auth_header_name: Optional[str] = None,
    auth_header_value: Optional[str] = None,
):
    """Build the FastMCP streamable-HTTP ASGI app, optionally guarded by auth.

    Args:
        mount_path: HTTP path the streamable transport listens on.
        auth_header_name: When set with ``auth_header_value``, requests
            missing the header (or carrying a different value) get 401.
        auth_header_value: Expected value for ``auth_header_name``.

    Returns:
        A Starlette application ready to hand to uvicorn.

    Raises:
        RuntimeError: if FastMCP is not installed.
    """
    if FastMCP is None:
        raise RuntimeError(
            "FastMCP is not installed. The 'mcp' package is required for "
            "the streamable-http transport."
        )
    # Import here to keep the stdio path zero-cost when the streamable-HTTP
    # transport is not used.
    from automated_security_helper.cli.mcp_server import mcp as _mcp_instance

    # Configure the FastMCP routing on its settings before materializing the
    # app so the path matches what the user requested.
    _mcp_instance.settings.streamable_http_path = mount_path
    app = _mcp_instance.streamable_http_app()

    if auth_header_name and auth_header_value:
        middleware_cls = _build_auth_middleware(auth_header_name, auth_header_value)
        app.add_middleware(middleware_cls)

    return app


def build_sse_app(
    mount_path: str = "/sse",
    auth_header_name: Optional[str] = None,
    auth_header_value: Optional[str] = None,
):
    """Build the FastMCP SSE ASGI app (legacy)."""
    if FastMCP is None:
        raise RuntimeError(
            "FastMCP is not installed. The 'mcp' package is required for "
            "the sse transport."
        )
    from automated_security_helper.cli.mcp_server import mcp as _mcp_instance

    _mcp_instance.settings.sse_path = mount_path
    app = _mcp_instance.sse_app()

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
) -> None:
    """Start the ASH MCP server.

    Default transport is ``stdio`` — identical to prior behavior. Pass
    ``--transport streamable-http`` to expose the server over HTTP via
    uvicorn, optionally guarded by a single static auth header.
    """
    # Handle resilient parsing for command discovery
    if ctx.resilient_parsing:
        return

    # Check for MCP dependencies using our validation function
    if not validate_mcp_dependencies():
        print("[red]Error: MCP dependencies are not available.[/red]")
        print()
        print("MCP support is included by default in ASH v3. Try reinstalling ASH:")
        print("  [cyan]pip install --force-reinstall automated-security-helper[/cyan]")
        print("  [cyan]uv sync --reinstall[/cyan]")
        print()
        print(
            "If the issue persists, check your Python environment and ASH installation."
        )
        raise typer.Exit(1)

    # If we reach here, MCP dependencies are available
    if not quiet:
        print("[green]MCP dependencies found. Starting MCP server...[/green]")

    # Validate command options for consistency
    try:
        validate_command_options(verbose, debug, quiet)
        _validate_auth_options(auth_header_name, auth_header_value)
    except ASHValidationError as e:
        print(f"[red]Validation Error: {str(e)}[/red]")
        raise typer.Exit(3)

    if transport not in _VALID_TRANSPORTS:
        print(
            f"[red]Validation Error: --transport must be one of {_VALID_TRANSPORTS}, got '{transport}'.[/red]"
        )
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
            )
            if not quiet:
                print(
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
            )
            if not quiet:
                print(
                    f"[green]SSE MCP server listening on "
                    f"http://{host}:{port}{sse_path}[/green]"
                )
            _run_uvicorn(app, host=host, port=port, log_level=log_level_value)
    except KeyboardInterrupt:
        _logger.info("MCP server shutdown requested by user")
        if not quiet:
            print("\n[yellow]MCP server shutdown requested by user[/yellow]")
        raise typer.Exit(0)
    except ScannerError as e:
        _logger.error(f"ASH Scanner Error: {str(e)}")
        if not quiet:
            print(f"[red]ASH Scanner Error: {str(e)}[/red]")
            print(
                "[yellow]This indicates an issue with ASH configuration or dependencies.[/yellow]"
            )
        raise typer.Exit(2)
    except ASHValidationError as e:
        _logger.error(f"ASH Validation Error: {str(e)}")
        if not quiet:
            print(f"[red]ASH Validation Error: {str(e)}[/red]")
            print(
                "[yellow]This indicates invalid configuration or parameters.[/yellow]"
            )
        raise typer.Exit(3)
    except Exception as e:
        _logger.exception(f"Unexpected error starting MCP server: {str(e)}")
        if not quiet:
            print(f"[red]Unexpected error starting MCP server: {str(e)}[/red]")
            print(f"[red]Error type: {type(e).__name__}[/red]")
            print(
                "[yellow]Please check system resources and ASH installation.[/yellow]"
            )
        raise typer.Exit(1)
