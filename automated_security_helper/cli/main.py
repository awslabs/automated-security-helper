# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import typer
from automated_security_helper.cli.config import config_app
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.cli.inspect import inspect_app
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
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
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


# Register MCP command using a function to avoid circular imports
def register_mcp_command():
    from automated_security_helper.cli.mcp import mcp_command

    app.command(name="mcp")(mcp_command)


# Register MCP command
register_mcp_command()


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
            pass

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


if __name__ == "__main__":
    run_app()
