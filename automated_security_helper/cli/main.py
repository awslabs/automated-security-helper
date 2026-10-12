# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path

import typer
from automated_security_helper.cli.config import config_app
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.cli.inspect import inspect_app
from automated_security_helper.cli.json_input import CliJsonInputCommand
from automated_security_helper.cli.merge import merge_command
from automated_security_helper.cli.plugin import plugin_app
from automated_security_helper.cli.scan import run_ash_scan_cli_command
from automated_security_helper.cli.report import report_command


app = typer.Typer(
    name="ash",
    help="AWS Labs - Automated Security Helper",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper()
    in ["YES", "1", "TRUE"],
)

app.callback(invoke_without_command=True)(run_ash_scan_cli_command)
app.command(
    name="scan",
    cls=CliJsonInputCommand,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    no_args_is_help=False,
)(run_ash_scan_cli_command)

app.command(
    name="build-image",
    cls=CliJsonInputCommand,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    no_args_is_help=False,
    help="""Builds the ASH container image then runs a scan with it.

Any additional arguments passed will be forwarded to ASH inside the container image when starting the scan.
""",
)(build_ash_image_cli_command)

app.command(name="report", cls=CliJsonInputCommand)(report_command)

app.command(
    name="merge",
    cls=CliJsonInputCommand,
    help="""Merges the results of a sharded scan into one unified report.

Pass one --results per shard. The command refuses to merge a set of shards that does not reconstruct exactly one whole scan, and its exit code is the verdict for the union — a shard that owned no failing scanner exits 0, so CI must gate on this command rather than on per-shard success.
""",
)(merge_command)


@app.command(name="mcp", help="Start the ASH MCP server (Model Context Protocol)")
def _mcp_wrapper(
    ctx: typer.Context,
    log_level: str = typer.Option("INFO", help="Log level"),
    verbose: bool = typer.Option(False, help="Verbose output"),
    debug: bool = typer.Option(False, help="Debug output"),
    color: bool = typer.Option(True, help="Enable color output"),
    quiet: bool = typer.Option(False, help="Quiet output"),
    transport: str = typer.Option(
        "stdio",
        "--transport",
        help="Transport: 'stdio' (default), 'streamable-http', or 'sse'.",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Host to bind for HTTP transports.",
    ),
    port: int = typer.Option(
        8000,
        "--port",
        help="Port to bind for HTTP transports.",
    ),
    mount_path: str = typer.Option(
        "/mcp",
        "--mount-path",
        help="HTTP path the transport listens on (default: /mcp for streamable-http, /sse for sse).",
    ),
    auth_header_name: str = typer.Option(
        None,
        "--auth-header-name",
        help="Required HTTP header name for single-tenant auth (HTTP transports only).",
    ),
    auth_header_value: str = typer.Option(
        None,
        "--auth-header-value",
        help="Expected value of --auth-header-name. Visible to other local users "
        "on the command line; prefer --auth-header-value-file or "
        "--auth-header-value-fd.",
    ),
    auth_header_value_file: Path = typer.Option(
        None,
        "--auth-header-value-file",
        help="Read the expected value of --auth-header-name from this file, once at "
        "startup: a regular file, not a symlink, readable by its owner only. One "
        "trailing newline is dropped.",
    ),
    auth_header_value_fd: int = typer.Option(
        None,
        "--auth-header-value-fd",
        help="Read the expected value of --auth-header-name from this inherited "
        "file descriptor (3 or above), once at startup, then close it.",
    ),
    stateless_http: bool = typer.Option(
        False,
        "--stateless-http/--no-stateless-http",
        help="Handle each streamable-HTTP request independently instead of binding "
        "it to a server-held session. Required behind a load balancer that may "
        "route consecutive requests to different replicas, and by managed runtimes "
        "that inject their own Mcp-Session-Id. Only valid with "
        "--transport streamable-http.",
    ),
    trust_upstream_session_id: bool = typer.Option(
        False,
        "--trust-upstream-session-id",
        help="Stateless streamable-HTTP only. Declare that a platform in front of "
        "ASH issues and authenticates the Mcp-Session-Id header, so it can name "
        "the caller's session. Without it a stateless server identifies no "
        "session, and tools that need one (source delivery, profiles, the scan "
        "registry) refuse.",
    ),
    allowed_host: list[str] | None = typer.Option(
        None,
        "--allowed-host",
        help="Host header value to accept, repeatable. Keeps DNS-rebinding "
        "protection enabled while allowing a known proxy or load balancer "
        "hostname. Required with a non-loopback --host unless "
        "--trust-upstream-host-check is given.",
    ),
    session_workspace_ttl: int | None = typer.Option(
        None,
        "--session-workspace-ttl",
        help="HTTP transports only. Seconds a session workspace (delivered source, "
        "uploads, bound profile) may go unused before it is removed. Covers "
        "sessions whose end the server cannot see, such as every stateless one. "
        "Default: 86400 (24 hours).",
    ),
    trust_upstream_host_check: bool = typer.Option(
        False,
        "--trust-upstream-host-check",
        help="HTTP transports only. Declare that a proxy or platform in front of "
        "ASH checks the Host and Origin headers, so ASH serves any. Without it, a "
        "non-loopback --host needs --allowed-host or the server refuses to start. "
        "Cannot be combined with --allowed-host.",
    ),
):
    """Lazy wrapper that imports and delegates to the real MCP command."""
    from automated_security_helper.cli.mcp import mcp_command

    mcp_command(
        ctx=ctx,
        log_level=log_level,
        verbose=verbose,
        debug=debug,
        color=color,
        quiet=quiet,
        transport=transport,
        host=host,
        port=port,
        mount_path=mount_path,
        auth_header_name=auth_header_name,
        auth_header_value=auth_header_value,
        auth_header_value_file=auth_header_value_file,
        auth_header_value_fd=auth_header_value_fd,
        stateless_http=stateless_http,
        trust_upstream_session_id=trust_upstream_session_id,
        allowed_host=allowed_host,
        trust_upstream_host_check=trust_upstream_host_check,
        session_workspace_ttl=session_workspace_ttl,
    )


@app.command(name="get-genai-guide")
def get_genai_guide(
    output_path: str = typer.Option(
        "ash-genai-guide.md",
        "--output",
        "-o",
        help="Output path for the GenAI integration guide",
    ),
    from_github: bool = typer.Option(
        False,
        "--from-github",
        help="Fetch from GitHub instead of local installation",
    ),
    branch: str = typer.Option(
        "main",
        "--branch",
        "-b",
        help="GitHub branch to fetch from when using --from-github (default: main)",
    ),
):
    """Download the ASH GenAI Integration Guide for use with AI assistants and LLMs.

    This guide provides comprehensive instructions for GenAI tools on how to properly
    interact with ASH scan results, including:
    - Correct file formats to use (JSON vs HTML)
    - How to handle severity discrepancies
    - Creating suppressions properly
    - Working with CycloneDX SBOM for dependencies
    - Configuration file schema
    - Common pitfalls and solutions
    """
    import requests
    from pathlib import Path

    guide_content = None
    source = None

    # Try local file first (unless --from-github is specified)
    if not from_github:
        try:
            guide_path = (
                Path(__file__).parent.parent.parent
                / "docs"
                / "content"
                / "docs"
                / "genai-steering-guide.md"
            )
            if guide_path.exists():
                guide_content = guide_path.read_text()
                source = "local"
        except Exception:
            # Local file read failed; fall through to GitHub fetch
            guide_content = None

    # If local file not found or --from-github specified, try GitHub
    if guide_content is None:
        github_url = f"https://raw.githubusercontent.com/awslabs/automated-security-helper/{branch}/docs/content/docs/genai-steering-guide.md"

        try:
            typer.echo(
                f"Fetching GenAI Integration Guide from GitHub ({branch} branch)..."
            )
            response = requests.get(github_url, timeout=10)
            response.raise_for_status()
            guide_content = response.text
            source = "github"
        except requests.RequestException as e:
            typer.echo(f"Error: Could not fetch from GitHub: {e}", err=True)
            typer.echo("\nYou can download it directly from:", err=True)
            typer.echo(github_url, err=True)
            raise typer.Exit(1)

    # Write to output file, as a new file renamed over the destination: a symlink
    # there is refused rather than written through (fs_guard).
    from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
    from automated_security_helper.utils.sandbox.fs_guard import (
        replace_without_following,
    )

    output_file = Path(output_path)
    try:
        replace_without_following(output_file, guide_content)
    except OutputDirLinkRefused as refused:
        # The family's base, a symlink or a file another name refers to alike.
        typer.echo(f"Error: {refused}", err=True)
        raise typer.Exit(1)

    typer.echo(f"✓ GenAI Integration Guide saved to: {output_file.absolute()}")
    if source:
        typer.echo(f"  Source: {source}")
    typer.echo(f"  File size: {len(guide_content):,} bytes")
    typer.echo("\nThis guide can be provided to AI assistants to help them:")
    typer.echo("  • Use the correct ASH output formats (JSON, not HTML)")
    typer.echo("  • Handle severity discrepancies properly")
    typer.echo("  • Create suppressions correctly")
    typer.echo("  • Analyze dependencies using CycloneDX SBOM")
    typer.echo("  • Avoid common pitfalls and known issues")


app.add_typer(config_app, name="config")
app.add_typer(dependencies_app, name="dependencies")
app.add_typer(inspect_app, name="inspect")
app.add_typer(plugin_app, name="plugin")


def reset_logging_config():
    """Reset the logging configuration to prevent duplicate handlers."""
    import logging

    # Reset the root logger
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[
        :
    ]:  # Use a copy of the list to avoid modification during iteration
        root_logger.removeHandler(handler)

    # Reset the ASH logger
    ash_logger = logging.getLogger("ash")
    for handler in ash_logger.handlers[
        :
    ]:  # Use a copy of the list to avoid modification during iteration
        ash_logger.removeHandler(handler)

    # Disable propagation for the ASH logger
    ash_logger.propagate = False


def run_app():
    """Run the ASH application with clean logging configuration."""
    # Reset logging configuration to prevent duplicate messages
    reset_logging_config()

    # Run the application
    app()


if __name__ == "__main__":
    # Routed through the console scripts' entry point so running this file
    # directly gets the same guaranteed-diagnosable failure path they do.
    from automated_security_helper.cli.entrypoint import main

    main()
