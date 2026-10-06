# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--cli-json-input`` and ``--generate-cli-skeleton`` for any Typer command.

Modelled on the AWS CLI's ``--cli-input-json`` / ``--generate-cli-skeleton``.
A command opts in with ``cls=CliJsonInputCommand``; nothing else about the
command changes, and no list of its parameters is kept here. Both the accepted
keys and the skeleton are read from the command's own click parameters at parse
time, so a flag added to a command is accepted from JSON, validated and listed
in the skeleton without touching this module.

Precedence, highest first:

1. a value given on the command line, as a flag or a positional argument;
2. a value in the ``--cli-json-input`` document;
3. the parameter's environment variable;
4. the parameter's default.

The document sits above environment variables because it is named on the
command line of this invocation, while an environment variable is ambient. A
list parameter given on the command line replaces the document's list for that
parameter; the two are not merged.

Validation is click's own. Each value is converted with the parameter's click
type before the command runs, so ``"strategy": "sideways"`` fails the same
Choice check ``--strategy sideways`` does, and the error names the JSON key.
The only checks added here are structural ones that argv makes impossible and
JSON does not: an array or object where one value is expected, a bare value
where a list is expected, and a JSON boolean for a parameter that is not a
boolean (``int(True)`` is 1, so ``"shard_index": true`` would otherwise be
shard 1).

Security: the document is parsed with ``json`` and nothing else. No value is
evaluated, and no environment-variable or ``~`` expansion is applied to it,
which is also what click does with a flag's value. ``-`` reads stdin.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path, PurePath
from typing import Any

import typer
from typer.core import TyperCommand, TyperOption

# Typer 0.27 vendors click as ``typer._click``, and Typer's commands and
# contexts are instances of that copy, not of the ``click`` distribution.
# ``UsageError``, ``ParameterSource`` and the base ``Parameter`` class are not
# re-exported on Typer's public surface, so they are taken from
# the vendored package directly. pyproject.toml pins ``typer<0.28``; a release
# that moves these names fails tests/unit/cli/test_cli_json_input.py at import.
from typer._click.core import Context, Parameter, ParameterSource
from typer._click.exceptions import UsageError
from typer._click.types import BoolParamType

CLI_JSON_INPUT_FLAG = "--cli-json-input"
GENERATE_CLI_SKELETON_FLAG = "--generate-cli-skeleton"
_FILE_URI_PREFIX = "file://"
_HELP_PANEL = "Structured input"


def json_input_parameters(command: Any, ctx: Context) -> list[Parameter]:
    """The parameters a JSON document may set, in definition order.

    Every parameter whose value reaches the command function, except hidden
    options. ``--help`` and the two options this module adds do not reach the
    function (``expose_value=False``), so they are excluded by the same rule.
    """
    return [
        param
        for param in command.get_params(ctx)
        if param.expose_value
        and param.name is not None
        and not (isinstance(param, TyperOption) and param.hidden)
    ]


def _key_index(params: list[Parameter]) -> dict[str, Parameter]:
    """Map every accepted key to its parameter.

    A parameter is addressed by its name (``source_dir``) or by any of its long
    flag spellings (``--source-dir``). The negative half of a boolean pair
    (``--no-offline``) is not a key: ``"--no-offline": true`` would read as
    "offline" to anyone not holding click's flag model in their head.
    """
    index: dict[str, Parameter] = {}
    for param in params:
        if param.name is None:
            continue
        index[param.name] = param
        if isinstance(param, TyperOption):
            for opt in param.opts:
                if opt.startswith("--"):
                    index[opt] = param
    return index


def _to_json(value: Any) -> Any:
    if isinstance(value, Enum):
        return _to_json(value.value)
    if isinstance(value, PurePath):
        return value.as_posix()
    if isinstance(value, (list, tuple)):
        return [_to_json(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def build_skeleton(command: Any, ctx: Context) -> dict[str, Any]:
    """A document accepted by ``--cli-json-input``, holding each parameter's default.

    Keys are parameter names. A parameter whose default is computed at run time
    (``source_dir`` defaults to the working directory inside the command) shows
    ``null``, which ``--cli-json-input`` reads as "not provided".
    """
    skeleton: dict[str, Any] = {}
    for param in json_input_parameters(command, ctx):
        default = param.default
        if callable(default):
            default = default()
        if param.required:
            default = None
        if param.name is not None:
            skeleton[param.name] = _to_json(default)
    return skeleton


def _print_skeleton(ctx: Context, _param: Parameter, value: Any) -> None:
    if not value or ctx.resilient_parsing:
        return
    typer.echo(json.dumps(build_skeleton(ctx.command, ctx), indent=2))
    raise typer.Exit(0)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"key {key!r} appears more than once")
        document[key] = value
    return document


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


def _read_document(source: str, ctx: Context) -> dict[str, Any]:
    if source == "-":
        label = "stdin"
        text = typer.get_text_stream("stdin").read()
    else:
        path = source.removeprefix(_FILE_URI_PREFIX)
        label = path
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise UsageError(
                f"{CLI_JSON_INPUT_FLAG}: cannot read {path}: {exc}", ctx=ctx
            ) from exc

    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ValueError as exc:
        raise UsageError(
            f"{CLI_JSON_INPUT_FLAG}: {label} is not valid JSON: {exc}", ctx=ctx
        ) from exc

    if not isinstance(document, dict):
        raise UsageError(
            f"{CLI_JSON_INPUT_FLAG}: {label} must contain a JSON object whose keys "
            f"are parameter names, not a {type(document).__name__}",
            ctx=ctx,
        )
    return document


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool))


def _check_shape(param: Parameter, value: Any) -> str | None:
    """Why ``value`` cannot be this parameter's value, or None if it can."""
    takes_list = param.multiple or param.nargs != 1
    items = value if isinstance(value, list) else [value]
    if takes_list and not isinstance(value, list):
        return "expected a JSON array, because this parameter takes a list"
    if not takes_list and isinstance(value, list):
        return "expected a single value, not a JSON array"
    for item in items:
        if not _is_scalar(item):
            return "expected a string, number or boolean"
        if isinstance(item, bool) and not isinstance(param.type, BoolParamType):
            return "a JSON boolean is only accepted for a true/false parameter"
    return None


def _validated_values(
    document: dict[str, Any], command: Any, ctx: Context, label: str
) -> dict[str, Any]:
    """Map the document onto parameter names, rejecting anything click would.

    Returns raw values keyed by parameter name. They are converted again when
    click processes them as defaults; converting here as well is what lets an
    error name the JSON key instead of the flag.
    """
    params = json_input_parameters(command, ctx)
    index = _key_index(params)
    values: dict[str, Any] = {}
    seen_as: dict[str, str] = {}

    for key, value in document.items():
        param = index.get(key)
        if param is None:
            valid = ", ".join(p.name for p in params if p.name)
            raise UsageError(
                f"{CLI_JSON_INPUT_FLAG}: unknown key {key!r} in {label}. Valid keys "
                f"are the parameter names {valid}; each option's long flag "
                f"spelling is accepted as well. Run with "
                f"{GENERATE_CLI_SKELETON_FLAG} for a template.",
                ctx=ctx,
            )
        if param.name is None:
            continue
        if param.name in seen_as:
            raise UsageError(
                f"{CLI_JSON_INPUT_FLAG}: keys {seen_as[param.name]!r} and {key!r} in "
                f"{label} both set the parameter {param.name!r}.",
                ctx=ctx,
            )
        seen_as[param.name] = key
        if value is None:
            continue

        problem = _check_shape(param, value)
        if problem is None:
            try:
                param.type_cast_value(ctx, value)
            except typer.BadParameter as exc:
                problem = exc.format_message()
        if problem is not None:
            raise UsageError(
                f"{CLI_JSON_INPUT_FLAG}: invalid value for key {key!r} in {label}: "
                f"{problem}",
                ctx=ctx,
            )
        values[param.name] = value
    return values


def _meta_options() -> list[Parameter]:
    return [
        TyperOption(
            param_decls=[CLI_JSON_INPUT_FLAG],
            metavar="PATH",
            expose_value=False,
            rich_help_panel=_HELP_PANEL,
            help=(
                "Read parameter values from a JSON object: a path, a file:// URI, "
                "or '-' for stdin. Keys are parameter names (output_dir) or long "
                "flag spellings (--output-dir). Flags given on the command line "
                "override the file; the file overrides environment variables. "
                f"Run with {GENERATE_CLI_SKELETON_FLAG} for a template."
            ),
        ),
        TyperOption(
            param_decls=[GENERATE_CLI_SKELETON_FLAG],
            is_flag=True,
            default=False,
            expose_value=False,
            is_eager=True,
            callback=_print_skeleton,
            rich_help_panel=_HELP_PANEL,
            help=(
                f"Print a JSON template for {CLI_JSON_INPUT_FLAG}, listing every "
                "parameter of this command with its default, and exit."
            ),
        ),
    ]


class CliJsonInputCommand(TyperCommand):
    """A Typer command that also takes its parameters from a JSON document."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.params.extend(_meta_options())

    def parse_args(self, ctx: Context, args: list[str]) -> list[str]:
        supplied: dict[str, Any] = {}
        if not ctx.resilient_parsing:
            # Parse once without processing anything, only to learn whether a
            # document was named. Any usage error raised here is the one the
            # real parse below would raise for the same argv.
            opts, _, _ = self.make_parser(ctx).parse_args(args=list(args))
            source = opts.get(CLI_JSON_INPUT_FLAG.lstrip("-").replace("-", "_"))
            if source is not None:
                label = "stdin" if source == "-" else str(source)
                document = _read_document(str(source), ctx)
                supplied = _validated_values(document, self, ctx, label)
                # click consults default_map only for a parameter the command
                # line did not set, which is rule 1 of the precedence.
                ctx.default_map = {**(ctx.default_map or {}), **supplied}

        remaining = super().parse_args(ctx, args)

        # click ranks an environment variable above default_map. Re-process
        # those parameters from the document so that it ranks above the
        # environment (rule 2 over rule 3).
        for name, value in supplied.items():
            if ctx.get_parameter_source(name) is ParameterSource.ENVIRONMENT:
                param = next(p for p in self.get_params(ctx) if p.name == name)
                ctx.params[name] = param.process_value(ctx, value)
                ctx.set_parameter_source(name, ParameterSource.DEFAULT_MAP)
        return remaining


__all__ = [
    "CLI_JSON_INPUT_FLAG",
    "GENERATE_CLI_SKELETON_FLAG",
    "CliJsonInputCommand",
    "build_skeleton",
    "json_input_parameters",
]
