#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate docs/content/reference/cli.md from the click command tree.

Usage:
    uv run python scripts/generate_cli_docs.py            # rewrite the page
    uv run python scripts/generate_cli_docs.py --check    # exit 1 with a diff if stale
    uv run python scripts/generate_cli_docs.py --output - # write to stdout

Why the click tree and not the function signatures
--------------------------------------------------
The previous version of this script read each command function's signature
through ``typer.utils.get_params_from_function`` and was handed a hand-written
list of the functions to document. Both halves could drift. The list could miss a
command (``dependencies install`` and ``plugin list`` were registered and absent),
and a signature does not carry what the command class adds:
``CliJsonInputCommand`` contributes ``--cli-json-input`` and
``--generate-cli-skeleton``, and typer adds ``--install-completion`` and
``--show-completion`` to the root, none of which exist in any signature.

``typer.main.get_command(app)`` returns the click command that ``ash`` actually
parses its arguments with, so walking it documents exactly the commands and
options a user can type. It also settles the alias problem the old script's
docstring spent a page on: click has already normalized every ``param_decls``
tuple into ``opts`` and ``secondary_opts``, so ``--config``/``-c`` and
``--progress``/``--no-progress`` come out whole.

Typer ships its own copy of click (``typer._click``), so nothing here checks
``isinstance(cmd, click.Group)``: a group is anything with a ``commands`` mapping.

Anchors
-------
Every command and every option gets an explicit ``<a id>`` so prose can link to
it without depending on heading slugs, which change when a heading is reworded:

* a command: its path without ``ash``, joined with ``-``: ``#scan``,
  ``#config-init``, ``#dependencies-install``. The root command is ``#ash``.
* an option: the command anchor, two hyphens, and the option's first long name
  without its leading dashes: ``#scan--output-dir``, ``#config-init--force``. An
  option with no long name uses its first short name (``#mcp--p``).
* an argument: the command anchor, two hyphens, ``arg-``, and the argument's
  name: ``#config-get--arg-config-path``.

Two parameters producing one anchor is an error rather than a silent
``_1`` suffix, so an anchor that prose links to cannot move to another option.

Defaults
--------
Enum defaults are rendered from ``.value``. Every enum the CLI uses for a default
is a ``str`` mixin (``AshLogLevel``, ``RunMode``, ``BuildTarget``), and
``format(member)`` returns the value on Python 3.10 but ``Class.MEMBER`` on 3.11
and later, so formatting the member directly made this page depend on the
interpreter that generated it. ``.value`` is also what a user types:
``BuildTarget.NON_ROOT`` is not an accepted value, ``non-root`` is.

A Default cell is a value in one code span that reads back with
``yaml.safe_load`` (a list is one JSON list), or one of the phrases ``required``,
``computed at run time``, ``not set``, ``on`` and ``off``. A boolean flag's
default is ``on`` or ``off`` whether or not it has a ``--no-`` spelling: the
Option column already shows both spellings. The docs checks compare each cell
with the option's default, so the forms are kept this small.
"""

from __future__ import annotations

import argparse
import enum
import re
import sys
import textwrap
import unicodedata
from pathlib import Path
from typing import Any, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _reference_docs import (
    NO_DESCRIPTION,
    add_docs_root_argument,
    banner,
    code,
    generated_note,
    md_prose,
    normalize_paths,
    options_marker,
    prepare_environment,
    reference_dir,
    refuse_check_to_stdout,
    write_or_check,
    yaml_value,
)

GENERATOR = "scripts/generate_cli_docs.py"
PAGE = "cli.md"
#: The width click wraps usage lines to. Fixed, because click otherwise takes it
#: from the terminal the generator runs in (78 is what it uses with no terminal).
USAGE_WIDTH = 78
SOURCE = "the `ash` click command tree (`typer.main.get_command`)"


def _is_group(cmd: Any) -> bool:
    return hasattr(cmd, "commands")


def iter_commands(root: Any) -> Iterator[tuple[list[str], Any, Any]]:
    """Yield ``(path, command, context)`` for the root and every subcommand.

    Depth first, subcommands in name order, so the page order is stable and a
    group's own section comes before its subcommands.
    """

    def walk(cmd: Any, path: list[str], parent_ctx: Any):
        info_name = path[-1] if path else "ash"
        ctx = cmd.context_class(
            cmd, info_name=info_name, parent=parent_ctx, terminal_width=USAGE_WIDTH
        )
        yield path, cmd, ctx
        if _is_group(cmd):
            for name in sorted(cmd.commands):
                yield from walk(cmd.commands[name], path + [name], ctx)

    yield from walk(root, [], None)


def command_anchor(path: list[str]) -> str:
    return "-".join(path) if path else "ash"


def param_anchor(path: list[str], param: Any) -> str:
    base = command_anchor(path)
    if param.param_type_name == "argument":
        return f"{base}--arg-{param.name.replace('_', '-')}"
    longs = [o for o in param.opts if o.startswith("--")]
    name = longs[0] if longs else param.opts[0]
    return f"{base}--{name.lstrip('-')}"


def _plain_value(value: Any) -> Any:
    """A default as the value a user would write: enums by value, paths as text."""
    if isinstance(value, enum.Enum):
        value = value.value
    if isinstance(value, Path):
        value = value.as_posix()
    if isinstance(value, str):
        value = normalize_paths(value)
    return value


def format_default(param: Any) -> str:
    """The default as a reader would type it, or the reason there is none."""
    if param.required:
        return "required"
    # A string show_default is the text the option's author chose for --help in
    # place of the resolved value (`~/.ash/bin` for a path resolved from $HOME at
    # import), so it is the text the page shows too: the resolved value is the
    # generator host's, not the reader's.
    shown = getattr(param, "show_default", None)
    if isinstance(shown, str) and shown:
        return code(normalize_paths(shown))
    default = param.default
    if callable(default):
        return "computed at run time"
    if getattr(param, "is_flag", False) and getattr(param, "is_bool_flag", True):
        if default is None:
            # An action flag (typer's --install-completion) never reaches the
            # command, so not passing it is simply off. A --x/--no-x flag whose
            # default is None is three-way: unset leaves the decision to the config.
            return "off" if not getattr(param, "expose_value", True) else "not set"
        return "on" if default else "off"
    if default is None:
        return "not set"
    if isinstance(default, (list, tuple)):
        if not default:
            return "not set"
        return code(yaml_value([_plain_value(v) for v in default]))
    return code(yaml_value(_plain_value(default)))


def format_type(param: Any) -> str:
    """A short description of the values a parameter accepts."""
    ptype = param.type
    type_name = getattr(ptype, "name", "") or type(ptype).__name__
    if getattr(param, "is_flag", False) and type_name == "boolean":
        text = "flag"
    elif hasattr(ptype, "choices"):
        text = "one of " + ", ".join(code(_choice(c)) for c in ptype.choices)
    else:
        text = {
            "text": "text",
            "str": "text",
            "string": "text",
            "integer": "integer",
            "int": "integer",
            "float": "number",
            "boolean": "boolean",
            "path": "path",
            "filename": "file",
            "file": "file",
        }.get(type_name.lower(), type_name.lower())
    if getattr(param, "multiple", False):
        text += ", repeatable"
    nargs = getattr(param, "nargs", 1)
    if nargs == -1:
        text += ", any number"
    elif isinstance(nargs, int) and nargs > 1:
        text += f", {nargs} values"
    return text


def _choice(value: Any) -> str:
    return str(value.value if isinstance(value, enum.Enum) else value)


def format_flags(param: Any) -> str:
    if param.param_type_name == "argument":
        return code(param.human_readable_name)
    flags = ", ".join(code(o) for o in param.opts)
    secondary = list(getattr(param, "secondary_opts", None) or [])
    if secondary:
        flags += " / " + ", ".join(code(o) for o in secondary)
    return flags


def format_envvar(param: Any) -> str:
    envvar = param.envvar
    if not envvar:
        return ""
    if isinstance(envvar, (list, tuple)):
        return ", ".join(code(e) for e in envvar)
    return code(envvar)


_LIST_ITEM = re.compile(r"^\s*(?:[-*]|\d+\.)\s+\S")


def slugify(text: str) -> str:
    """python-markdown's default heading slug (``markdown.extensions.toc.slugify``).

    Reimplemented rather than imported so the generator does not depend on the docs
    toolchain; used only to prove no explicit anchor collides with a heading id.
    """
    value = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    value = re.sub(r"[^\w\s-]", "", value).strip().lower()
    return re.sub(r"[-\s]+", "-", value)


def render_help_block(text: str) -> list[str]:
    """A command's help text as markdown paragraphs.

    Lines indented four or more spaces relative to the text (the ``Examples:``
    blocks several commands carry) become a ``text`` fence: as bare indented lines
    following a paragraph, markdown would fold them into that paragraph. Click's
    ``\\b`` no-rewrap marker lines are dropped.
    """
    lines = [ln for ln in textwrap.dedent(text).splitlines() if ln.strip() != "\b"]
    out: list[str] = []
    block: list[str] = []

    def flush_block():
        if not block:
            return
        while block and not block[-1].strip():
            block.pop()
        if out and out[-1] != "":
            out.append("")
        out.append("```text")
        out.extend(textwrap.dedent("\n".join(block)).splitlines())
        out.append("```")
        out.append("")
        block.clear()

    for line in lines:
        indented = line.startswith("    ") and line.strip()
        if indented or (block and not line.strip()):
            block.append(normalize_paths(line))
            continue
        flush_block()
        # Markdown starts a list only after a blank line; help text often puts the
        # first item directly under its lead-in sentence.
        if _LIST_ITEM.match(line) and out and out[-1] and not _LIST_ITEM.match(out[-1]):
            out.append("")
        out.append(md_prose(normalize_paths(line.rstrip())) if line.strip() else "")
    flush_block()
    while out and not out[-1].strip():
        out.pop()
    return out


def _param_signature(param: Any) -> tuple:
    return (
        param.param_type_name,
        tuple(param.opts),
        tuple(getattr(param, "secondary_opts", None) or ()),
        format_type(param),
        format_default(param),
        format_envvar(param),
        " ".join((getattr(param, "help", None) or "").split()),
    )


def render_param_table(path: list[str], params: list[Any], seen: set[str]) -> list[str]:
    """One table for the command's arguments, then one for its options.

    Each is marked for the docs checks with ``of=cli.<command words>``.
    """
    arguments = [p for p in params if p.param_type_name == "argument"]
    options = [p for p in params if p.param_type_name != "argument"]
    marker = options_marker(".".join(["cli", *path]))
    out: list[str] = []
    if arguments:
        out += [
            marker,
            "| Argument | Type | Default | Environment variable | Description |",
            "|----------|------|---------|----------------------|-------------|",
            *(_param_row(path, p, seen) for p in arguments),
            "",
        ]
    if options:
        out += [
            marker,
            "| Option | Type | Default | Environment variable | Description |",
            "|--------|------|---------|----------------------|-------------|",
            *(_param_row(path, p, seen) for p in options),
            "",
        ]
    return out[:-1]


def _builtin_reporters() -> list[str]:
    """The built-in reporters' config names, which is what selects a reporter."""
    from _plugin_reference import discover

    return sorted(p.name for p in discover("reporter") if p.builtin)


def _output_formats_note(_param: Any) -> str:
    """``ash scan --output-formats``: accepted values, and which of them write a report.

    cli/scan.py checks each value with ``ExportFormat(value)`` and refuses anything
    else, and the report phase selects a reporter whose config name equals a value
    (``reporter_format_name``). So an ExportFormat value that names no reporter is
    accepted and writes nothing, and a reporter whose name is not one is refused.
    """
    from automated_security_helper.core.enums import ExportFormat

    accepted = [f.value for f in ExportFormat]
    reporters = _builtin_reporters()
    writes = [v for v in accepted if v in reporters]
    nothing = [v for v in accepted if v not in reporters]
    refused = [r for r in reporters if r not in accepted]
    sentences = [
        "Values that write a report: " + ", ".join(code(v) for v in writes) + ".",
        "Values that name no reporter and write no report: "
        + ", ".join(code(v) for v in nothing)
        + ".",
    ]
    if refused:
        sentences.append(
            "Built-in reporters that are refused: "
            + ", ".join(code(r) for r in refused)
            + "; so are the reporters in plugin modules."
        )
    return " ".join(sentences)


def _report_format_note(_param: Any) -> str:
    """``ash report --format``: cli/report.py looks the value up among loaded reporters."""
    return (
        "Accepted values: the name of a reporter that is loaded: "
        + ", ".join(code(r) for r in _builtin_reporters())
        + ", and the reporters of any plugin module the configuration loads. "
        "Any other value exits with code 1."
    )


#: Options whose values the command checks in its own code, after click has parsed
#: them, keyed by (command path, first long name). Their help text alone does not
#: say what is accepted; the note is computed from the code that decides it.
VALUE_NOTES = {
    (("scan",), "--output-formats"): _output_formats_note,
    (("report",), "--format"): _report_format_note,
}


def _value_note(path: list[str], param: Any) -> str:
    longs = [o for o in getattr(param, "opts", []) if o.startswith("--")]
    note = VALUE_NOTES.get((tuple(path), longs[0] if longs else ""))
    return note(param) if note else ""


def _param_row(path: list[str], param: Any, seen: set[str]) -> str:
    anchor = param_anchor(path, param)
    if anchor in seen:
        raise SystemExit(
            f"ERROR: two parameters of `ash {' '.join(path)}` produce the anchor "
            f"#{anchor}. Change the anchor scheme in {GENERATOR} deliberately; "
            "do not let one option take over another option's links."
        )
    seen.add(anchor)
    help_text = getattr(param, "help", None) or ""
    description = md_prose(normalize_paths(help_text)) if help_text else NO_DESCRIPTION
    note = _value_note(path, param)
    if note:
        description = f"{description} {note}"
    if getattr(param, "hidden", False):
        # Said of commands too: a reader who finds the option here will not find
        # it in --help.
        description = f"{description} This option is hidden from `--help` output."
    columns = [
        f'<a id="{anchor}"></a>{format_flags(param)}',
        format_type(param),
        format_default(param),
        format_envvar(param),
        description,
    ]
    return "| " + " | ".join(table_cell(column) for column in columns) + " |"


_CODE_SPAN_PARTS = re.compile(r"(`+[^`]*`+)")


def table_cell(text: str) -> str:
    """``text`` with every pipe outside a code span escaped, so it stays in one column.

    A pipe in a type name or a help sentence used to split the row into extra
    columns and shift every value after it. Inside a code span nothing is
    escaped, for the reason ``md_prose`` gives: python-markdown, which renders
    the docs, does not end a column on a pipe inside backticks and would show the
    backslash literally.
    """
    parts = _CODE_SPAN_PARTS.split(text)
    for index in range(0, len(parts), 2):
        parts[index] = parts[index].replace(r"\|", "|").replace("|", r"\|")
    return "".join(parts)


def generate(root: Any) -> tuple[str, dict]:
    """Render the page. Returns ``(markdown, stats)``."""
    commands = list(iter_commands(root))
    stats = {"commands": 0, "parameters": 0, "missing_help": []}
    seen_anchors: set[str] = set()
    heading_slugs: set[str] = {"cli-reference", "commands"}

    by_path = {tuple(path): cmd for path, cmd, _ in commands}
    scan = by_path.get(("scan",))
    scan_signatures = (
        {_param_signature(p) for p in scan.params} if scan is not None else set()
    )

    lines = banner(
        GENERATOR,
        SOURCE,
        extra=[
            "",
            "Anchors (stable; link to them from prose):",
            "  command:  #<command path joined by '-'>        e.g. #scan, #config-init; root is #ash",
            "  option:   #<command anchor>--<first long name>  e.g. #scan--output-dir",
            "  argument: #<command anchor>--arg-<name>         e.g. #config-get--arg-config-path",
        ],
    )
    lines += [
        "# CLI reference",
        "",
        generated_note(GENERATOR, "the command definitions in the ASH source code"),
        "",
        (
            "The Environment variable column names the variable click reads for the "
            "option; an option given on the command line takes precedence over it. Some "
            "behavior is also controlled by variables read elsewhere in the code; see "
            "[Environment variables](environment-variables.md)."
        ),
        "",
        "## Commands",
        "",
        "| Command | Description |",
        "|---------|-------------|",
    ]
    for path, cmd, _ctx in commands:
        summary = (cmd.short_help or (cmd.help or "").strip().split("\n\n")[0]).strip()
        summary = md_prose(summary) if summary else NO_DESCRIPTION
        label = "ash" + ("".join(f" {p}" for p in path))
        lines.append(f"| [{code(label)}](#{command_anchor(path)}) | {summary} |")
    lines.append("")

    for path, cmd, ctx in commands:
        stats["commands"] += 1
        label = "ash" + ("".join(f" {p}" for p in path))
        anchor = command_anchor(path)
        if anchor in seen_anchors:
            raise SystemExit(f"ERROR: two commands produce the anchor #{anchor}.")
        seen_anchors.add(anchor)

        heading = "##" if len(path) <= 1 else "###"
        heading_slugs.add(slugify(label))
        if slugify(label) == anchor:
            # Only the root: its heading id is already `ash`, and a second element
            # with the same id would be invalid HTML.
            lines += [f"{heading} {code(label)}", ""]
        else:
            lines += [f'{heading} <a id="{anchor}"></a>{code(label)}', ""]

        help_text = (cmd.help or "").strip()
        if help_text:
            lines += render_help_block(help_text)
        else:
            lines.append(NO_DESCRIPTION)
            stats["missing_help"].append(label)
        lines.append("")

        usage = cmd.get_usage(ctx).strip()
        usage = re.sub(r"^Usage:\s*", "", usage)
        lines += ["```text", usage, "```", ""]

        if (getattr(cmd, "context_settings", None) or {}).get("ignore_unknown_options"):
            lines += [
                (
                    "This command does not reject an option it does not define: an "
                    "unknown or misspelled option is ignored, with no error."
                ),
                "",
            ]
        if getattr(cmd, "hidden", False):
            lines += ["This command is hidden from `--help` output.", ""]
        if getattr(cmd, "deprecated", False):
            lines += ["This command is deprecated.", ""]

        params = list(cmd.params)
        if not path and scan is not None:
            # The root runs a scan when no subcommand is given (its callback is the
            # scan command), so most of its options are scan's. Listing them twice
            # would double the page; the shared set is computed, not assumed.
            shared = [p for p in params if _param_signature(p) in scan_signatures]
            own = [p for p in params if _param_signature(p) not in scan_signatures]
            if shared:
                lines += [
                    "Run with no command, `ash` runs a scan. It accepts these options "
                    "of [`ash scan`](#scan), with the same types, defaults and "
                    "environment variables: "
                    + ", ".join(
                        f"[{code(p.opts[0])}](#{param_anchor(['scan'], p)})"
                        for p in shared
                    )
                    + ".",
                    "",
                ]
            params = own
            if own:
                lines += ["Options that only `ash` itself accepts:", ""]

        if params:
            for param in params:
                stats["parameters"] += 1
                if not (getattr(param, "help", None) or "") and (
                    param.param_type_name != "argument"
                ):
                    stats["missing_help"].append(f"{label} {param.opts[0]}")
            lines += render_param_table(path, params, seen_anchors)
            lines.append("")
        elif path:
            lines += ["This command takes no options.", ""]

        if _is_group(cmd):
            subs = sorted(cmd.commands)
            if subs:
                lines += [
                    "Subcommands: "
                    + ", ".join(
                        f"[{code(label + ' ' + s)}](#{command_anchor(path + [s])})"
                        for s in subs
                    )
                    + ".",
                    "",
                ]

    clashes = sorted((seen_anchors - {"ash"}) & heading_slugs)
    if clashes:
        raise SystemExit(
            f"ERROR: explicit anchors {clashes} equal heading ids on the page; a link "
            "to either would be ambiguous."
        )

    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n", stats


def load_root_command() -> Any:
    import typer.main

    from automated_security_helper.cli.main import app

    return typer.main.get_command(app)


def main():
    parser = argparse.ArgumentParser(
        description="Generate CLI reference documentation from Typer command definitions."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write. Exit 1 with a diff if the page is stale.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"Output path, or '-' for stdout. Default: <docs root>/docs/content/reference/{PAGE}",
    )
    add_docs_root_argument(parser)
    args = parser.parse_args()
    refuse_check_to_stdout(parser, args)

    prepare_environment(Path(args.docs_root))
    output = Path(args.output) if args.output else reference_dir(args.docs_root) / PAGE
    content, stats = generate(load_root_command())
    summary = (
        f"{stats['commands']} commands, {stats['parameters']} parameters, "
        f"{len(stats['missing_help'])} without help text."
    )
    if args.output == "-":
        sys.stdout.write(content)
        print(summary, file=sys.stderr)
        return 0
    return write_or_check(output, content, args.check, GENERATOR, summary)


if __name__ == "__main__":
    sys.exit(main())
