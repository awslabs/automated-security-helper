# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
MCP (Model Context Protocol) CLI command for ASH.

This module provides a CLI command to start an MCP server that exposes ASH security
scanning capabilities through the Model Context Protocol. The MCP server allows
LLMs and other tools to interact with ASH programmatically.
"""

from typing import Annotated
import typer
from rich import print

from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.core.exceptions import ScannerError, ASHValidationError
from automated_security_helper.utils.log import ASH_LOGGER

# Import MCP dependencies directly
try:
    from mcp.server.fastmcp import FastMCP, Context
except ImportError:
    FastMCP = None
    Context = None

# Configure module logger
_logger = ASH_LOGGER


def validate_log_options(
    verbose: bool, debug: bool, log_level: AshLogLevel
) -> AshLogLevel:
    """Validate and resolve log level options.

    Args:
        verbose: Whether verbose logging is enabled
        debug: Whether debug logging is enabled
        log_level: The specified log level

    Returns:
        The resolved log level
    """
    # Resolve log level based on options
    if debug:
        return AshLogLevel.DEBUG
    elif verbose:
        return AshLogLevel.VERBOSE
    else:
        return log_level


def validate_mcp_dependencies() -> bool:
    """Validate that MCP dependencies are available.

    Returns:
        True if dependencies are available, False otherwise
    """
    return FastMCP is not None and Context is not None


def validate_command_options(verbose: bool, debug: bool, quiet: bool) -> None:
    """Validate command options for consistency.

    Args:
        verbose: Whether verbose logging is enabled
        debug: Whether debug logging is enabled
        quiet: Whether to hide all log output

    Raises:
        ASHValidationError: If options are inconsistent
    """
    if quiet and (verbose or debug):
        raise ASHValidationError("Cannot use --quiet with --verbose or --debug options")


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
) -> None:
    """Start the ASH MCP server for Model Context Protocol integration.

    The MCP server exposes ASH security scanning capabilities through the Model Context Protocol,
    allowing LLMs and other tools to perform security scans and analyze results programmatically.

    MCP support is included by default in ASH v3. If you encounter dependency issues, please
    check your ASH installation.

    The MCP server provides the following capabilities:
    - scan_directory: Start security scans with progress tracking
    - get_scan_progress: Monitor running scan progress
    - get_scan_results: Retrieve completed scan results
    - list_active_scans: View all active and recent scans
    - cancel_scan: Stop running scans
    - check_installation: Verify ASH installation and version
    - Resources for status and help information
    - Prompts for analyzing security findings
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
    except ASHValidationError as e:
        print(f"[red]Validation Error: {str(e)}[/red]")
        raise typer.Exit(3)

    # Validate and configure logging options
    log_level_value = validate_log_options(verbose, debug, log_level)

    # Log the command execution
    _logger.info(f"Starting MCP server with log level: {log_level_value.name}")

    # Initialize and start the MCP server with comprehensive error handling
    try:
        # Import and run the MCP server implementation here to avoid circular imports
        from automated_security_helper.cli.mcp_server import run_mcp_server

        run_mcp_server()
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
    finally:
        # Our logging patch will handle cleanup automatically
        pass
