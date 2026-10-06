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
import enum
import inspect
import re
import sys
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
    except (AttributeError, TypeError):
        # Falling through to the next branch is the intended handling: each of
        # these blocks asks "is the annotation shaped like X?", and a no means try
        # the next shape. Only the two errors such a probe can actually produce
        # are caught -- AttributeError if a typing member is absent on the running
        # interpreter, TypeError if get_origin/get_args/isinstance is handed
        # something that is not a type. Catching Exception also swallowed anything
        # raised by the recursive _get_type_name call below, which would put a
        # wrong type name in published docs with no other symptom.
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
    except (AttributeError, TypeError):
        pass  # Not a types.UnionType; see the Annotated block above.

    # typing.Union
    try:
        import typing

        if origin is typing.Union:
            inner = [a for a in get_args(annotation) if a is not type(None)]
            if len(inner) == 1:
                return _get_type_name(inner[0])
            return " | ".join(_get_type_name(a) for a in inner)
    except (AttributeError, TypeError):
        pass  # Not a typing.Union; see the Annotated block above.

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
    except (AttributeError, TypeError):
        pass  # Not a typing.Optional; see the Annotated block above.

    # Enum types
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
    """Format a default value for display.

    The enum test comes before the scalar ones on purpose. Every enum the CLI
    uses for a flag default is declared as a mixin -- ``class AshLogLevel(str,
    Enum)``, ``RunMode``, ``BuildTarget`` -- so ``isinstance(default, str)`` is
    true of its members. With the scalar tests first, those members were
    rendered by the str branch's f-string, which is ``format(member)``, and
    Python changed what that returns in 3.11: 3.10 gives the mixed-in value
    (``INFO``) and 3.11+ gives ``AshLogLevel.INFO``. The output of this script
    therefore depended on which interpreter ran it, across the whole supported
    range, and the freshness check could not be satisfied by regenerating --
    a file matching 3.10 is stale on 3.11+ and the other way round.

    Reading ``.value`` explicitly is also the form the reader wants. These are
    the strings a user types: ``--log-level INFO``, ``--mode local``,
    ``--build-target non-root``. The member name is a Python identifier that
    does not always match -- ``BuildTarget.NON_ROOT`` is not a value the CLI
    accepts -- so documenting it was wrong as well as unstable.
    """
    if default is inspect.Parameter.empty:
        return "*required*"
    if default is None:
        return ""
    if isinstance(default, enum.Enum):
        return f"`{default.value}`"
    if isinstance(default, bool):
        return str(default)
    if isinstance(default, str):
        if default == "":
            return '""'
        return f"`{default}`"
    if isinstance(default, list):
        return "[]"
    return str(default)


def _escape_md(text: str) -> str:
    """Escape pipe characters for markdown tables."""
    if not text:
        return ""
    return text.replace("|", "\\|").replace("\n", " ")


def _format_envvar(envvar: Any) -> str:
    """Render an OptionInfo/ArgumentInfo `envvar` as a comma-separated string."""
    if not envvar:
        return ""
    if isinstance(envvar, (list, tuple)):
        return ", ".join(str(e) for e in envvar)
    return str(envvar)


def extract_typer_params(func) -> list[dict]:
    """
    Extract parameter metadata from a Typer-decorated function using introspection.

    Returns a list of dicts with keys: flags, type, default, envvar, help, is_argument.

    Flag names are resolved by handing the function to typer's own
    ``typer.utils.get_params_from_function`` rather than reading
    ``OptionInfo.param_decls`` directly. That indirection is load-bearing, not
    stylistic. ``typer.Option`` has the signature ``Option(default, *param_decls)``,
    so ``typer.Option("--config", "-c")`` -- the form used throughout
    ``automated_security_helper/cli/`` -- binds ``"--config"`` to ``default`` and
    leaves ``param_decls == ("-c",)``. Typer repairs that itself when the
    ``OptionInfo`` is used inside ``Annotated``, by prepending ``default`` back onto
    ``param_decls`` and resetting ``default`` to ``...``; see the "When used as a
    default, `Option` takes a default value and option names as positional
    arguments" branch in ``typer.utils.get_params_from_function``.

    Reading ``param_decls`` raw therefore dropped the FIRST declared alias of every
    such option, so the generated reference advertised ``-c`` with no ``--config``,
    ``-v`` with no ``--verbose``, and so on -- flags a reader would copy and find
    broken only for the long form. Deferring to typer means this cannot drift again
    if typer changes the rule: there is one implementation of it, and it is typer's.
    """
    import typer.models
    import typer.utils

    params = []

    for name, param_meta in typer.utils.get_params_from_function(func).items():
        # Skip the typer.Context parameter. It is a framework handle, not a flag.
        if name == "ctx":
            continue

        pinfo = param_meta.default
        # Parameters whose default is a plain value (no typer.Option/Argument
        # attached) are not CLI-visible parameters and have nothing to document.
        if not isinstance(pinfo, typer.models.ParameterInfo):
            continue

        is_argument = isinstance(pinfo, typer.models.ArgumentInfo)

        flags = list(pinfo.param_decls or ())
        if not flags and not is_argument:
            # Typer derives the long flag from the parameter name when no
            # param_decls are declared at all.
            flags = [f"--{name.replace('_', '-')}"]

        # After typer's normalization, `pinfo.default` holds the real default
        # (the value bound by `=` in the signature), or Ellipsis when required.
        actual_default = pinfo.default
        if actual_default is ...:
            actual_default = inspect.Parameter.empty

        params.append(
            {
                "flags": flags,
                "type": _get_type_name(param_meta.annotation),
                "default": _format_default(actual_default),
                "envvar": _format_envvar(pinfo.envvar),
                "help": pinfo.help or "",
                "is_argument": is_argument,
                "param_name": name,
            }
        )

    return params


def _render_flag_decl(decl: str) -> str:
    """Render one declared option spelling the way a reader types it.

    A boolean whose OFF side has a short form but whose ON side does not is
    declared as ``"  /-C"``: click needs the leading whitespace to read the decl
    as an on/off pair with an empty ON half, and without it ``/-C`` would be a
    literal option name. Printed raw, that whitespace lands inside the backticks
    of the generated table. Stripping it leaves ``/-C``, the same on/off
    notation the table already uses for ``-p/-P``, with nothing before the slash.
    """
    if "/" in decl:
        on, _, off = decl.partition("/")
        return f"{on.strip()}/{off.strip()}"
    return decl.strip()


def extract_command_class_options(command_name: str) -> list[dict]:
    """Options a command gets from its command class rather than its function.

    ``--cli-json-input`` and ``--generate-cli-skeleton`` are added by
    ``CliJsonInputCommand`` and never appear in the function signature that
    ``extract_typer_params`` reads. They are taken here from the click command
    Typer actually builds, so a command that gains or loses the class gains or
    loses the rows with it.
    """
    import typer.main

    from automated_security_helper.cli.json_input import (
        CLI_JSON_INPUT_FLAG,
        GENERATE_CLI_SKELETON_FLAG,
    )
    from automated_security_helper.cli.main import app

    command = typer.main.get_command(app)
    for part in command_name.split():
        command = command.commands[part]  # type: ignore[attr-defined]

    rows = []
    for param in command.params:
        if param.expose_value or not param.opts:
            continue
        if param.opts[0] not in (CLI_JSON_INPUT_FLAG, GENERATE_CLI_SKELETON_FLAG):
            continue
        rows.append(
            {
                "param_name": param.name,
                "flags": list(param.opts),
                "type": "bool" if param.is_flag else "str",
                "default": "",
                "envvar": "",
                "help": param.help or "",
                "is_argument": False,
            }
        )
    return rows


def render_command_section(command_name: str, func, description: str = "") -> str:
    """Render a markdown section for a single CLI command."""
    params = extract_typer_params(func) + extract_command_class_options(command_name)
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
            flag_str = (
                ", ".join(f"`{_render_flag_decl(f)}`" for f in p["flags"])
                if p["flags"]
                else f"`--{p['param_name'].replace('_', '-')}`"
            )
            lines.append(
                f"| {flag_str} | {p['type']} | {p['default']} | {_escape_md(p['envvar'])} | {_escape_md(p['help'])} |"
            )
        lines.append("")

    return "\n".join(lines)


def extract_mcp_tools() -> list[dict]:
    """
    Extract MCP tool definitions by asking the MCP server for its registered tools.

    The tool set comes from ``mcp.list_tools()`` -- the same registry the server
    serves to a client -- not from scanning ``dir(mcp_server)``. The previous
    ``dir()`` scan asked "is this a public module-level coroutine?", which is not
    the same question as "is this a registered tool", and it was wrong in both
    directions:

    * It carried ``monitor_scan_progress``, an imported helper (``from
      automated_security_helper.cli.mcp.progress_monitor import
      monitor_scan_progress``), because an imported coroutine is
      indistinguishable from a locally-defined one under ``dir()``.
    * It omitted every tool declared with a plain ``def`` rather than ``async
      def`` -- ``list_scanners`` and ``validate_config`` -- because
      ``inspect.iscoroutinefunction`` is false for them. ``@mcp.tool()`` accepts
      both, so "async" was never the right discriminator.

    Asking the registry makes the documented set equal the served set by
    construction, so a tool added, removed, or renamed cannot silently diverge.
    """
    import asyncio

    from automated_security_helper.cli import mcp_server

    module = mcp_server
    registered = asyncio.run(module.mcp.list_tools())

    tool_functions = []
    for tool in registered:
        func = getattr(module, tool.name, None)
        if func is None or not callable(func):
            # A registered tool with no resolvable module attribute would silently
            # vanish from the docs, which is the exact failure this function
            # exists to prevent. Fail loudly instead.
            raise RuntimeError(
                f"MCP tool {tool.name!r} is registered with the server but is not "
                f"resolvable as an attribute of {module.__name__}; the generator "
                f"cannot introspect its signature."
            )
        tool_functions.append((tool.name, func))

    tools = []
    for tool_name, func in tool_functions:
        sig = inspect.signature(func)
        doc = inspect.getdoc(func) or ""

        # Extract description: first paragraph before Args: section
        description = ""
        if doc:
            # Split at Args: or Returns: sections
            parts = re.split(
                r"\n\s*(Args|Returns|Example|CRITICAL|IMPORTANT):", doc, maxsplit=1
            )
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

            tool_params.append(
                {
                    "name": param_name,
                    "type": param_type,
                    "default": param_default,
                    "description": param_desc,
                }
            )

        tools.append(
            {
                "name": tool_name,
                "description": description,
                "params": tool_params,
            }
        )

    # Sort tools by name for deterministic output
    tools.sort(key=lambda t: t["name"])
    return tools


def render_mcp_section(tools: list[dict]) -> str:
    """Render markdown section for MCP tools."""
    lines = []
    lines.append("## MCP Tools")
    lines.append("")
    lines.append(
        "The ASH MCP server exposes the following tools for integration with AI assistants via the Model Context Protocol."
    )
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
    from automated_security_helper.cli.merge import merge_command
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
    from automated_security_helper.cli.inspect.inspect_findings_app import (
        findings_command,
    )
    from automated_security_helper.cli.inspect.sarif_fields import analyze_sarif_fields

    sections = []

    # Header
    sections.append("# CLI Reference (Auto-Generated)")
    sections.append("")
    sections.append(
        "This document is auto-generated from the ASH CLI source code using introspection."
    )
    sections.append(
        "Do not edit manually. Regenerate with: `uv run python scripts/generate_cli_docs.py`"
    )
    sections.append("")
    sections.append(
        "**Which CLI reference is authoritative.** Two pages describe the CLI: this one "
        "and the hand-written [CLI Reference](cli-reference.md). They are not "
        "interchangeable, and the split is deliberate rather than accidental:"
    )
    sections.append("")
    sections.append(
        "* For **flag names and aliases, parameter types, defaults, and environment "
        "variables**, this page wins. Every row here is introspected from the Typer "
        "command definitions, and `tests/unit/test_generated_docs_freshness.py` fails "
        "the build if this file and the code disagree. The hand-written page has no "
        "such gate and has drifted."
    )
    sections.append(
        "* For **worked examples, exit codes, configuration-override syntax, and "
        "narrative guidance**, the hand-written page wins. None of that can be "
        "introspected, so it is not reproduced here."
    )
    sections.append("")
    sections.append(
        "The intended end state is a single page: this one, with the hand-written "
        "page's narrative content folded in. Until that migration lands, treat a "
        "disagreement about a flag between the two pages as a defect in the "
        "hand-written page."
    )
    sections.append("")

    # Main commands
    sections.append("## Commands")
    sections.append("")

    # scan command
    sections.append(
        render_command_section(
            "scan",
            run_ash_scan_cli_command,
            "Runs an ASH scan against the source-dir, outputting results to the output-dir.",
        )
    )

    # build-image command
    sections.append(
        render_command_section(
            "build-image",
            build_ash_image_cli_command,
            "Builds the ASH container image then runs a scan with it.",
        )
    )

    # report command
    sections.append(render_command_section("report", report_command))

    # merge command
    sections.append(
        render_command_section(
            "merge",
            merge_command,
            "Merges the results of a sharded scan into one unified report.",
        )
    )

    # mcp command
    sections.append(
        render_command_section(
            "mcp", _mcp_wrapper, "Start the ASH MCP server (Model Context Protocol)."
        )
    )

    # get-genai-guide command
    sections.append(render_command_section("get-genai-guide", get_genai_guide))

    # Config subcommands
    sections.append("## Config Subcommands")
    sections.append("")
    sections.append(render_command_section("config init", config_init))
    sections.append(render_command_section("config get", config_get))
    sections.append(render_command_section("config update", config_update))
    sections.append(
        render_command_section(
            "config validate-plugin-dependencies", config_validate_deps
        )
    )
    sections.append(render_command_section("config lint", config_lint))
    sections.append(render_command_section("config wizard", config_wizard))
    sections.append(render_command_section("config validate", config_validate))

    # Inspect subcommands
    sections.append("## Inspect Subcommands")
    sections.append("")
    sections.append(render_command_section("inspect findings", findings_command))
    sections.append(
        render_command_section("inspect sarif-fields", analyze_sarif_fields)
    )

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
