#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Auto-generate CLI reference documentation from Typer command definitions and MCP tool functions.

Usage:
    uv run python scripts/generate_cli_docs.py
    uv run python scripts/generate_cli_docs.py --output docs/content/docs/cli-reference-generated.md
    python -m scripts.generate_cli_docs --output -  # write to stdout
"""

import argparse
import inspect
import re
import sys
import textwrap
from pathlib import Path
from typing import Any, get_args, get_origin


def _get_type_name(annotation: Any) -> str:
    """Convert a type annotation to a human-readable string."""
    if annotation is inspect.Parameter.empty:
        return "str"

    origin = get_origin(annotation)

    # Handle Optional (Union[X, None])
    if origin is type(None):
        return "None"

    # Handle Annotated - extract the base type
    try:
        import typing
        if hasattr(typing, "get_args") and hasattr(typing, "get_origin"):
            if typing.get_origin(annotation) is typing.Annotated:
                args = typing.get_args(annotation)
                if args:
                    return _get_type_name(args[0])
    except Exception:
        pass

    # Handle Union types (Optional[X] = Union[X, None])
    if origin is type(None):
        return "None"
    try:
        import types as builtin_types
        if isinstance(annotation, builtin_types.UnionType):
            inner = [a for a in get_args(annotation) if a is not type(None)]
            if len(inner) == 1:
                return _get_type_name(inner[0])
            return " | ".join(_get_type_name(a) for a in inner)
    except Exception:
        pass

    # typing.Union
    try:
        import typing
        if origin is typing.Union:
            inner = [a for a in get_args(annotation) if a is not type(None)]
            if len(inner) == 1:
                return _get_type_name(inner[0])
            return " | ".join(_get_type_name(a) for a in inner)
    except Exception:
        pass

    # Handle List[X]
    if origin is list:
        args = get_args(annotation)
        if args:
            return f"List[{_get_type_name(args[0])}]"
        return "List"

    # Handle Optional[X] via typing
    try:
        import typing
        if origin is typing.Optional:
            args = get_args(annotation)
            if args:
                return _get_type_name(args[0])
    except Exception:
        pass

    # Enum types
    import enum
    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        values = [e.value for e in annotation]
        if len(values) <= 6:
            return f"enum({', '.join(str(v) for v in values)})"
        return f"enum({', '.join(str(v) for v in values[:4])}, ...)"

    # Basic types
    if annotation is str:
        return "str"
    if annotation is int:
        return "int"
    if annotation is float:
        return "float"
    if annotation is bool:
        return "bool"
    if annotation is Path:
        return "Path"

    # Fallback to the name
    if hasattr(annotation, "__name__"):
        return annotation.__name__
    return str(annotation).replace("typing.", "")


def _format_default(default: Any) -> str:
    """Format a default value for display."""
    if default is inspect.Parameter.empty:
        return "*required*"
    if default is None:
        return ""
    if isinstance(default, bool):
        return str(default)
    if isinstance(default, str):
        if default == "":
            return '""'
        return f"`{default}`"
    if isinstance(default, list):
        return "[]"
    # Enum values
    import enum
    if isinstance(default, enum.Enum):
        return f"`{default.value}`"
    return str(default)


def _escape_md(text: str) -> str:
    """Escape pipe characters for markdown tables."""
    if not text:
        return ""
    return text.replace("|", "\\|").replace("\n", " ")


def extract_typer_params(func) -> list[dict]:
    """
    Extract parameter metadata from a Typer-decorated function using introspection.

    Returns a list of dicts with keys: flags, type, default, envvar, help, is_argument.
    """
    import typing

    sig = inspect.signature(func)
    params = []

    for name, param in sig.parameters.items():
        # Skip the typer.Context parameter
        if name == "ctx":
            continue

        annotation = param.annotation
        default = param.default

        # Check if this is an Annotated type
        if typing.get_origin(annotation) is typing.Annotated:
            args = typing.get_args(annotation)
            base_type = args[0]
            metadata = args[1:]  # Everything after the type is metadata

            # Find the typer.Option or typer.Argument in metadata
            import typer.models
            option_info = None
            for meta in metadata:
                if isinstance(meta, (typer.models.OptionInfo, typer.models.ArgumentInfo)):
                    option_info = meta
                    break

            if option_info is None:
                continue

            # Extract flag names from param_decls
            is_argument = isinstance(option_info, typer.models.ArgumentInfo)
            flags = []
            if hasattr(option_info, "param_decls") and option_info.param_decls:
                flags = list(option_info.param_decls)
            if not flags and not is_argument:
                # Generate default flag name from parameter name
                flags = [f"--{name.replace('_', '-')}"]

            # Extract help text
            help_text = ""
            if hasattr(option_info, "help") and option_info.help:
                help_text = option_info.help

            # Extract envvar
            envvar = ""
            if hasattr(option_info, "envvar") and option_info.envvar:
                ev = option_info.envvar
                if isinstance(ev, (list, tuple)):
                    envvar = ", ".join(ev)
                else:
                    envvar = str(ev)

            # Determine actual default
            actual_default = default if default is not inspect.Parameter.empty else None
            if hasattr(option_info, "default") and option_info.default is not None:
                # typer stores defaults too, but param.default is more reliable
                pass

            # Resolve type name
            type_name = _get_type_name(base_type)

            params.append({
                "flags": flags,
                "type": type_name,
                "default": _format_default(actual_default),
                "envvar": envvar,
                "help": help_text,
                "is_argument": is_argument,
                "param_name": name,
            })
        else:
            # Non-Annotated parameters (simple typer.Option defaults in main.py wrapper)
            if default is inspect.Parameter.empty:
                continue

            # These are typically from the mcp wrapper or get-genai-guide
            type_name = _get_type_name(annotation)
            flags = [f"--{name.replace('_', '-')}"]

            # Check if default is a typer.Option instance
            import typer.models
            if isinstance(default, typer.models.OptionInfo):
                option_info = default
                help_text = option_info.help or ""
                envvar = ""
                if option_info.envvar:
                    ev = option_info.envvar
                    envvar = ", ".join(ev) if isinstance(ev, (list, tuple)) else str(ev)
                actual_default = option_info.default
                if option_info.param_decls:
                    flags = list(option_info.param_decls)
                params.append({
                    "flags": flags,
                    "type": type_name,
                    "default": _format_default(actual_default),
                    "envvar": envvar,
                    "help": help_text,
                    "is_argument": False,
                    "param_name": name,
                })
            elif isinstance(default, typer.models.ArgumentInfo):
                help_text = default.help or ""
                envvar = ""
                if default.envvar:
                    ev = default.envvar
                    envvar = ", ".join(ev) if isinstance(ev, (list, tuple)) else str(ev)
                actual_default = default.default
                params.append({
                    "flags": [],
                    "type": type_name,
                    "default": _format_default(actual_default),
                    "envvar": envvar,
                    "help": help_text,
                    "is_argument": True,
                    "param_name": name,
                })

    return params


def render_command_section(command_name: str, func, description: str = "") -> str:
    """Render a markdown section for a single CLI command."""
    params = extract_typer_params(func)
    if not params:
        return ""

    lines = []
    lines.append(f"### `ash {command_name}`")
    lines.append("")

    # Add description from docstring if available
    doc = description or (inspect.getdoc(func) or "")
    if doc:
        first_para = doc.split("\n\n")[0].strip()
        if first_para:
            lines.append(first_para)
            lines.append("")

    # Separate arguments and options
    arguments = [p for p in params if p["is_argument"]]
    options = [p for p in params if not p["is_argument"]]

    if arguments:
        lines.append("**Arguments:**")
        lines.append("")
        lines.append("| Argument | Type | Default | Env Var | Description |")
        lines.append("|----------|------|---------|---------|-------------|")
        for p in arguments:
            arg_name = p["param_name"].upper()
            lines.append(
                f"| `{arg_name}` | {p['type']} | {p['default']} | {_escape_md(p['envvar'])} | {_escape_md(p['help'])} |"
            )
        lines.append("")

    if options:
        lines.append("| Flag | Type | Default | Env Var | Description |")
        lines.append("|------|------|---------|---------|-------------|")
        for p in options:
            flag_str = ", ".join(f"`{f}`" for f in p["flags"]) if p["flags"] else f"`--{p['param_name'].replace('_', '-')}`"
            lines.append(
                f"| {flag_str} | {p['type']} | {p['default']} | {_escape_md(p['envvar'])} | {_escape_md(p['help'])} |"
            )
        lines.append("")

    return "\n".join(lines)


def extract_mcp_tools() -> list[dict]:
    """
    Extract MCP tool definitions from the mcp_server module by introspecting
    functions decorated with @mcp.tool().
    """
    from automated_security_helper.cli import mcp_server

    tools = []

    # Find all functions decorated with @mcp.tool()
    # The FastMCP server registers tools - we can find them by looking at module-level
    # async functions that are decorated (they'll be in the mcp server's tool registry,
    # but we can also find them by scanning the module for known patterns)
    module = mcp_server

    # Get the mcp instance and its registered tools
    mcp_instance = module.mcp

    # FastMCP stores tools internally - try to access them
    # But the simplest approach: scan module for async functions that we know are tools
    # by checking if they're registered in the mcp._tool_manager or similar
    tool_functions = []

    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if callable(obj) and inspect.iscoroutinefunction(obj):
            # Skip private/internal functions
            if attr_name.startswith("_"):
                continue
            # Skip imported helper functions
            if attr_name.startswith("mcp_"):
                continue
            # These are the tool functions registered with @mcp.tool()
            tool_functions.append((attr_name, obj))

    for tool_name, func in tool_functions:
        sig = inspect.signature(func)
        doc = inspect.getdoc(func) or ""

        # Extract description: first paragraph before Args: section
        description = ""
        if doc:
            # Split at Args: or Returns: sections
            parts = re.split(r"\n\s*(Args|Returns|Example|CRITICAL|IMPORTANT):", doc, maxsplit=1)
            description = parts[0].strip()
            # Take only first paragraph
            description = description.split("\n\n")[0].strip()
            # Collapse multi-line into single line
            description = " ".join(description.split())

        # Extract parameters (skip ctx)
        tool_params = []
        # Also try to parse Args: section from docstring for per-param descriptions
        args_descriptions = {}
        if "Args:" in doc:
            args_section = doc.split("Args:")[1]
            # Stop at Returns: or end
            if "Returns:" in args_section:
                args_section = args_section.split("Returns:")[0]
            # Parse indented lines
            for line in args_section.strip().split("\n"):
                line = line.strip()
                if ":" in line and not line.startswith("-"):
                    param_name, param_desc = line.split(":", 1)
                    param_name = param_name.strip()
                    param_desc = param_desc.strip()
                    args_descriptions[param_name] = param_desc

        for param_name, param in sig.parameters.items():
            if param_name == "ctx":
                continue
            param_type = _get_type_name(param.annotation)
            param_default = _format_default(param.default)
            param_desc = args_descriptions.get(param_name, "")

            tool_params.append({
                "name": param_name,
                "type": param_type,
                "default": param_default,
                "description": param_desc,
            })

        tools.append({
            "name": tool_name,
            "description": description,
            "params": tool_params,
        })

    # Sort tools by name for deterministic output
    tools.sort(key=lambda t: t["name"])
    return tools


def render_mcp_section(tools: list[dict]) -> str:
    """Render markdown section for MCP tools."""
    lines = []
    lines.append("## MCP Tools")
    lines.append("")
    lines.append("The ASH MCP server exposes the following tools for integration with AI assistants via the Model Context Protocol.")
    lines.append("")

    for tool in tools:
        lines.append(f"### `{tool['name']}`")
        lines.append("")
        if tool["description"]:
            lines.append(tool["description"])
            lines.append("")

        if tool["params"]:
            lines.append("| Parameter | Type | Default | Description |")
            lines.append("|-----------|------|---------|-------------|")
            for p in tool["params"]:
                lines.append(
                    f"| `{p['name']}` | {p['type']} | {p['default']} | {_escape_md(p['description'])} |"
                )
            lines.append("")

    return "\n".join(lines)


def generate_cli_docs() -> str:
    """Generate the complete CLI reference markdown document."""
    # Import all the command functions
    from automated_security_helper.cli.scan import run_ash_scan_cli_command
    from automated_security_helper.cli.image import build_ash_image_cli_command
    from automated_security_helper.cli.report import report_command
    from automated_security_helper.cli.config import config_app
    from automated_security_helper.cli.inspect import inspect_app
    from automated_security_helper.cli.main import _mcp_wrapper, get_genai_guide

    # Get config subcommand functions
    from automated_security_helper.cli.config import (
        init as config_init,
        get as config_get,
        update as config_update,
        validate_plugin_dependencies as config_validate_deps,
        lint as config_lint,
        wizard as config_wizard,
        validate as config_validate,
    )

    # Get inspect subcommand functions
    from automated_security_helper.cli.inspect.inspect_findings_app import findings_command
    from automated_security_helper.cli.inspect.sarif_fields import analyze_sarif_fields

    sections = []

    # Header
    sections.append("# CLI Reference (Auto-Generated)")
    sections.append("")
    sections.append("This document is auto-generated from the ASH CLI source code using introspection.")
    sections.append("Do not edit manually. Regenerate with: `uv run python scripts/generate_cli_docs.py`")
    sections.append("")

    # Main commands
    sections.append("## Commands")
    sections.append("")

    # scan command
    sections.append(render_command_section("scan", run_ash_scan_cli_command,
        "Runs an ASH scan against the source-dir, outputting results to the output-dir."))

    # build-image command
    sections.append(render_command_section("build-image", build_ash_image_cli_command,
        "Builds the ASH container image then runs a scan with it."))

    # report command
    sections.append(render_command_section("report", report_command))

    # mcp command
    sections.append(render_command_section("mcp", _mcp_wrapper,
        "Start the ASH MCP server (Model Context Protocol)."))

    # get-genai-guide command
    sections.append(render_command_section("get-genai-guide", get_genai_guide))

    # Config subcommands
    sections.append("## Config Subcommands")
    sections.append("")
    sections.append(render_command_section("config init", config_init))
    sections.append(render_command_section("config get", config_get))
    sections.append(render_command_section("config update", config_update))
    sections.append(render_command_section("config validate-plugin-dependencies", config_validate_deps))
    sections.append(render_command_section("config lint", config_lint))
    sections.append(render_command_section("config wizard", config_wizard))
    sections.append(render_command_section("config validate", config_validate))

    # Inspect subcommands
    sections.append("## Inspect Subcommands")
    sections.append("")
    sections.append(render_command_section("inspect findings", findings_command))
    sections.append(render_command_section("inspect sarif-fields", analyze_sarif_fields))

    # MCP Tools
    tools = extract_mcp_tools()
    sections.append(render_mcp_section(tools))

    return "\n".join(sections)


def main():
    parser = argparse.ArgumentParser(
        description="Generate CLI reference documentation from Typer command definitions."
    )
    parser.add_argument(
        "--output",
        default="docs/content/docs/cli-reference-generated.md",
        help="Output file path. Use '-' for stdout. Default: docs/content/docs/cli-reference-generated.md",
    )
    args = parser.parse_args()

    content = generate_cli_docs()

    if args.output == "-":
        sys.stdout.write(content)
    else:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)
        print(f"Generated CLI reference docs at: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
