# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import sys

import typer
from automated_security_helper.cli.config import config_app
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.cli.inspect import inspect_app
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
    # click injects --help and nothing else, so -h has to be asked for. Set on
    # the app rather than per command: click's Context inherits
    # help_option_names from its parent, so every subcommand picks it up from
    # the root group. -h came from the deleted root bash script.
    context_settings={"help_option_names": ["-h", "--help"]},
)

app.callback(invoke_without_command=True)(run_ash_scan_cli_command)
# No allow_extra_args/ignore_unknown_options here. `scan` used to swallow any
# unrecognized flag and run a full scan regardless, so a typo in CI scanned the
# wrong thing and exited 0. Nothing read ctx.args on this path, so the swallowed
# arguments were discarded rather than forwarded -- dropping the pass-through
# removes a silent failure without removing a feature. `build-image` below is
# the deliberate exception.
app.command(
    name="scan",
    no_args_is_help=False,
)(run_ash_scan_cli_command)

app.command(
    name="build-image",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    no_args_is_help=False,
    help="""Builds the ASH container image then runs a scan with it.

Any additional arguments passed will be forwarded to ASH inside the container image when starting the scan.
""",
)(build_ash_image_cli_command)

app.command(name="report")(report_command)

app.command(
    name="merge",
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
    # "  /-C" with its leading whitespace, matching the other commands: that is
    # how click attaches a short form to the OFF side of a boolean flag. Written
    # out here rather than inherited, because this wrapper declares its own
    # params and delegates to mcp_command by keyword.
    color: bool = typer.Option(
        True, "--color/--no-color", "  /-C", help="Enable color output"
    ),
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
        help="Expected value of --auth-header-name.",
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
    allowed_host: list[str] | None = typer.Option(
        None,
        "--allowed-host",
        help="Host header value to accept, repeatable. Keeps DNS-rebinding "
        "protection enabled while allowing a known proxy or load balancer "
        "hostname. Without this, protection is enabled only when --host is "
        "loopback, matching the MCP SDK's own default.",
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
        stateless_http=stateless_http,
        allowed_host=allowed_host,
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

    # Write to output file
    output_file = Path(output_path)
    output_file.write_text(guide_content)

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


ASHV3_DEPRECATION_MESSAGE = (
    "warning: the 'ashv3' command is deprecated and is scheduled for removal; "
    "use 'ash' instead."
)


def _warn_ashv3_deprecation(stream=None):
    """Announce that the ``ashv3`` console script is going away.

    Written to stderr so it cannot corrupt a scan's stdout, which callers pipe
    into report tooling.
    """
    print(ASHV3_DEPRECATION_MESSAGE, file=stream or sys.stderr)


def run_ashv3():
    """Entry point for the deprecated ``ashv3`` console script.

    ``ashv3`` names a version, so it ages badly the moment v4 exists -- that is
    the reason it is deprecated rather than any problem with the alias itself.
    ``automated-security-helper`` is deliberately NOT deprecated alongside it: it
    is the escape hatch for environments where a bare ``ash`` resolves to
    something else, and that collision is real. MSYS2 ships the Almquist shell as
    ``ash`` and it has already shadowed ASH's entry point.

    The warning lives here, in a dedicated entry point, rather than in a Typer
    callback. A callback would fire for the ``ash`` name too, and group callbacks
    can run more than once for a single command line.
    """
    _warn_ashv3_deprecation()
    app()


if __name__ == "__main__":
    # Routed through the console scripts' entry point so running this file
    # directly gets the same guaranteed-diagnosable failure path they do.
    from automated_security_helper.cli.entrypoint import main

    main()
