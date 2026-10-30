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
where a list is expected, a JSON boolean for a parameter that is not a
boolean (``int(True)`` is 1, so ``"shard_index": true`` would otherwise be
shard 1), a JSON number for a boolean parameter (click reads a boolean from
text, so ``"verbose": 2`` would otherwise be an internal error, not a refusal),
and a JSON number with a fraction or an exponent for an integer parameter
(``int(1.9)`` is 1, so ``"shard_index": 1.9`` would otherwise be shard 1).

Security: the document is parsed with ``json`` and nothing else. No value is
evaluated, and no environment-variable or ``~`` expansion is applied to it,
which is also what click does with a flag's value. ``-`` reads stdin.
"""

from __future__ import annotations

import ast
import json
import re
import warnings
from enum import Enum
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import unquote
from urllib.request import url2pathname

import typer
from typer.core import TyperCommand, TyperOption

from automated_security_helper.utils.console import echo_raw
from automated_security_helper.utils.error_text import (
    error_text,
    os_error_without_named_file,
)
from automated_security_helper.utils.terminal_text import (
    ShownText,
    shown_on_one_line,
)

# Typer 0.27 vendors click as ``typer._click``, and Typer's commands and
# contexts are instances of that copy, not of the ``click`` distribution.
# ``UsageError`` and the base ``Parameter`` class are not re-exported on
# Typer's public surface, so they are taken from the vendored package directly.
# pyproject.toml pins ``typer<0.28``; a release that moves these names fails
# tests/unit/cli/test_cli_json_input.py at import.
from typer._click.core import Context, Parameter
from typer._click.exceptions import BadParameter, MissingParameter, UsageError
from typer._click.types import (
    BoolParamType,
    DateTime,
    FloatParamType,
    IntParamType,
    UUIDParameterType,
)
from typer._types import TyperChoice
from typer.models import TyperPath

CLI_JSON_INPUT_FLAG = "--cli-json-input"
GENERATE_CLI_SKELETON_FLAG = "--generate-cli-skeleton"
_FILE_URI_PREFIX = "file://"
_HELP_PANEL = "Structured input"

#: A string literal as repr writes one, in either quote.
_STRING_LITERAL = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"")

#: The parameter types whose refusals name the refused value by its repr: typer's
#: choices and paths, and click's numbers (ranges included), booleans, UUIDs and
#: dates.
_NAMES_VALUE_BY_REPR = (
    TyperChoice,
    TyperPath,
    IntParamType,
    FloatParamType,
    BoolParamType,
    UUIDParameterType,
    DateTime,
)


def _names_values_by_repr(exc: UsageError) -> bool:
    """Whether click or typer named a value in *exc* by its repr."""
    if isinstance(exc, MissingParameter):
        # It names no value: a choice's lists its choices, a line each.
        return False
    if isinstance(exc, BadParameter):
        return isinstance(getattr(exc.param, "type", None), _NAMES_VALUE_BY_REPR)
    # typer's group, for a command it does not have.
    return exc.message.startswith("No such command ")


def _as_typed(match: re.Match[str]) -> str:
    literal = match.group()
    try:
        with warnings.catch_warnings():
            # An invalid escape only warns, and no repr writes one.
            warnings.simplefilter("error")
            value = ast.literal_eval(literal)
    except (SyntaxError, ValueError, Warning):
        return literal
    if not isinstance(value, str) or repr(value) != literal:
        return literal
    # Between the quotes repr chose: it quotes a'b with double quotes.
    return literal[0] + value + literal[0]


def _typed_text(exc: UsageError) -> str:
    """*exc*'s message, with a value click or typer named by its repr given as typed.

    Only the messages that name a value that way are read, and only a literal that
    is its value's own repr is put back: text that merely looks like one is left
    as it is. Not shown: a message built from it shows the whole of itself once.
    """
    text = exc.format_message()
    if not _names_values_by_repr(exc):
        return text
    return _STRING_LITERAL.sub(_as_typed, text)


def usage_error_text(exc: UsageError) -> ShownText:
    """*exc*'s message as the usage error's printer writes it, shown once.

    A repr writes a control as the text of its escape, and the printer shows the text
    it is given (utils/terminal_text.py), so a value named by its repr was shown
    twice: a refused --mode of U+202E printed "\\\\u202e", which reads as the six
    characters typed literally. Put back as typed, the value is shown once. Such a
    message is one line, so it is shown on one line: a newline the value held,
    which the repr wrote as "\\n", would otherwise start an output line of its
    own.

    Every message is shown on one line, whatever the error's type: most can
    carry an argv token as typed (an unknown option's name, an extra argument,
    a path), and the type says nothing about where the text came from, so a
    MissingParameter's text is shown on one line as well. Only a missing
    Choice parameter's own layout is flattened: when the error's parameter is
    a Choice and the message ends with the exact text that type's
    get_missing_message built (its values one per line, ":\\n\\t" then
    ",\\n\\t", from the parameter's declaration, never an argv token), that
    tail reads "Choose from: local, container" instead of an escape per
    choice. The tail is matched against the builder's own text, not an
    English phrase, so a builder a translation changed flattens the same way,
    while the phrase in a message some other code built is text like any
    other: its separators stay escaped, like every other error's, so different
    texts stay distinct. One whose text was built shown, a DocumentRefused,
    has only tab, newline and carriage return left to write, and it holds
    none.
    """
    if _names_values_by_repr(exc):
        return shown_on_one_line(_typed_text(exc))
    if isinstance(exc, MissingParameter):
        text = exc.format_message()
        param = exc.param
        param_type = None if param is None else param.type
        if param is not None and isinstance(param_type, TyperChoice):
            suffix = param_type.get_missing_message(param=param, ctx=exc.ctx)
            if suffix and text.endswith(suffix):
                flattened = suffix.replace(":\n\t", ": ").replace(",\n\t", ", ")
                text = text[: len(text) - len(suffix)] + flattened
        return shown_on_one_line(text)
    return shown_on_one_line(exc.format_message())


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
    ``null``, which ``--cli-json-input`` reads as "not provided". So does a
    parameter that has an environment variable (``mode`` and ASH_MODE): the
    document sits above the environment, so a skeleton that wrote such a
    parameter's default as an explicit value overrode the variable with the
    default on every run of the unedited skeleton. The variable keeps its say
    until the key is filled in.
    """
    skeleton: dict[str, Any] = {}
    for param in json_input_parameters(command, ctx):
        default = param.default
        if callable(default):
            default = default()
        if param.required or getattr(param, "envvar", None):
            default = None
        if param.name is not None:
            skeleton[param.name] = _to_json(default)
    return skeleton


def _print_skeleton(ctx: Context, _param: Parameter, value: Any) -> None:
    if not value or ctx.resilient_parsing:
        return
    # Machine output: a script reads this JSON, so it is written as given.
    echo_raw(json.dumps(build_skeleton(ctx.command, ctx), indent=2))
    raise typer.Exit(0)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            # As given, not by repr: the usage error's printer shows it.
            raise ValueError(f"key '{key}' appears more than once")
        document[key] = value
    return document


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


class DocumentRefused(UsageError):
    """A refusal of a --cli-json-input document. The class names the kind of
    refusal, nothing more: nothing checks for the type, and it prints as
    every usage error does."""


class PathRefused(BadParameter):
    """A refusal of an option's value that names one or more paths. The class
    names the kind of refusal, nothing more: nothing checks for the type,
    and it prints as every usage error does."""


def _refused(message: str, ctx: Context) -> DocumentRefused:
    """A refusal of the document, its keys and values given raw in *message*.

    Shown here, whole and once, on one line: the printer leaves shown text as
    it is, and a newline in a key, a value or the file's name would otherwise
    start an output line of its own.
    """
    return DocumentRefused(shown_on_one_line(message), ctx=ctx)


def _document_path(source: str) -> str:
    """The file *source* names: a path as given, or the file a ``file://`` names.

    Read as the AWS CLI reads ``file://``: the text after the prefix is a path,
    relative (``file://params.json``, ``file://./params.json``) or absolute,
    percent-decoded. A ``file:///...`` or ``file://localhost/...`` URI's path is
    made a local one with ``url2pathname``, so on Windows ``/C:/dir/params.json``
    is a drive path and a URI a tool wrote is read as the file it names. A drive
    letter right after the two slashes (``file://C:\\dir\\params.json``, the
    spelling a Windows path is pasted into) is a path too.

    Nothing after the prefix is parsed as a URI's host, query or fragment:
    ``file://share.example/params.json`` names the relative path
    ``share.example/params.json``, which is refused when it cannot be read, and a
    ``#`` or a tab in a file's name stays in it. Parsing the text as a URI refused
    every relative form as a remote host, cut the name at a ``#``, and dropped a
    tab or a newline from it, so a file was looked up under a name it does not
    have.
    """
    if not source.startswith(_FILE_URI_PREFIX):
        return source
    rest = source[len(_FILE_URI_PREFIX) :]
    if rest.startswith("localhost/"):
        rest = rest[len("localhost") :]
    if rest.startswith("/"):
        return url2pathname(rest)
    return unquote(rest)


def _read_stdin(ctx: Context) -> str:
    """The document on stdin, read as UTF-8 whatever the locale, or a refusal.

    Read from the bytes under the stream, so a document piped on Windows is
    decoded as the file branch decodes a file, not with the process's code
    page; a stream with no byte buffer under it (a test's) is read as text. A
    byte order mark is dropped, as for a file. A read that fails, or bytes that
    are not UTF-8, are the same refusal the file branch gives, not a traceback.
    """
    stream = typer.get_text_stream("stdin")
    binary = getattr(stream, "buffer", None)
    try:
        if binary is not None:
            return binary.read().decode("utf-8-sig")
        return stream.read().removeprefix("\ufeff")
    except (OSError, UnicodeDecodeError) as exc:
        raise _refused(
            f"{CLI_JSON_INPUT_FLAG}: cannot read stdin: {error_text(exc)}", ctx
        ) from exc


def _read_document(source: str, ctx: Context) -> dict[str, Any]:
    if source == "-":
        label = "stdin"
        text = _read_stdin(ctx)
    else:
        path = _document_path(source)
        label = path
        try:
            # utf-8-sig: a document a Windows editor or PowerShell 5 saved starts
            # with a byte order mark, which json.loads refuses as text.
            text = Path(path).read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            # The message names the file, so an OSError's own copy of it is dropped.
            reason = (
                os_error_without_named_file(exc, path)
                if isinstance(exc, OSError)
                else error_text(exc)
            )
            raise _refused(
                f"{CLI_JSON_INPUT_FLAG}: cannot read {path}: {reason}", ctx
            ) from exc

    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except RecursionError:
        # A document nested deeper than the parser can follow is refused like
        # one that does not parse, not left as a traceback.
        raise _refused(
            f"{CLI_JSON_INPUT_FLAG}: {label} is not valid JSON: nested too deeply "
            "to parse",
            ctx,
        ) from None
    except ValueError as exc:
        raise _refused(
            f"{CLI_JSON_INPUT_FLAG}: {label} is not valid JSON: {exc}", ctx
        ) from exc

    if not isinstance(document, dict):
        raise _refused(
            f"{CLI_JSON_INPUT_FLAG}: {label} must contain a JSON object whose keys "
            f"are parameter names, not a {type(document).__name__}",
            ctx,
        )
    return document


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool))


def _check_shape(param: Parameter, value: Any) -> str | None:
    """Why ``value`` cannot be this parameter's value, or None if it can.

    The checks are the ones argv makes impossible and JSON does not. A JSON
    number for a true/false parameter is refused: the click typer bundles reads
    a boolean from a bool or from text (``"yes"``, ``"1"``), so every number, 0
    and 1 included, reached its text conversion and raised AttributeError
    (upstream click's ``BoolParamType`` takes 0 and 1 as the booleans; the
    bundled copy does not). A JSON number with a fraction for an integer
    parameter is refused too, as ``--shard-index 3.5`` is: click's integer type
    truncated ``3.5`` to 3 without a word.
    """
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
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            # click reads a boolean from text (``"yes"``, ``"1"``), so a number
            # reached its text handling and raised an AttributeError, which
            # is an internal error, not a refusal naming the key.
            if isinstance(param.type, BoolParamType):
                return (
                    "expected a JSON boolean (true or false) for a true/false "
                    "parameter, not a number"
                )
            # click's integer type is ``int(value)``, which truncates a float:
            # 1.9 was accepted as 1, and 1e2 as 100.
            if isinstance(param.type, IntParamType) and not isinstance(item, int):
                return (
                    "expected a JSON integer for this parameter, not a number "
                    "with a fraction or an exponent"
                )
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
            raise _refused(
                f"{CLI_JSON_INPUT_FLAG}: unknown key '{key}' in {label}. Valid keys "
                f"are the parameter names {valid}; each option's long flag "
                f"spelling is accepted as well. Run with "
                f"{GENERATE_CLI_SKELETON_FLAG} for a template.",
                ctx,
            )
        if param.name is None:
            continue
        if param.name in seen_as:
            raise _refused(
                f"{CLI_JSON_INPUT_FLAG}: keys '{seen_as[param.name]}' and '{key}' in "
                f"{label} both set the parameter '{param.name}'.",
                ctx,
            )
        seen_as[param.name] = key
        if value is None:
            continue

        problem = _check_shape(param, value)
        if problem is None:
            try:
                param.type_cast_value(ctx, value)
            except typer.BadParameter as exc:
                # Its value as given, not yet shown: the refusal shows it once.
                problem = _typed_text(exc)
            except OverflowError:
                # A number JSON reads as infinite (1e400) handed to an integer
                # parameter: click's conversion raises past its own check.
                problem = "the number is too large for this parameter"
        if problem is not None:
            raise _refused(
                f"{CLI_JSON_INPUT_FLAG}: invalid value for key '{key}' in {label}: "
                f"{problem}",
                ctx,
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
                "parameter of this command with its default, or null where it is "
                "required or an environment variable backs it, and exit."
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
            # --help and --generate-cli-skeleton are eager: click runs them
            # before any other value is processed, and the command never runs.
            # The document is read before that processing, so a document that
            # does not parse blocked both; it is not read when either is asked.
            # The pre-parse has already put a token that is another option's
            # value where it belongs, so a value spelled "--help" is not help.
            skeleton = GENERATE_CLI_SKELETON_FLAG.lstrip("-").replace("-", "_")
            eager = bool(opts.get("help")) or bool(opts.get(skeleton))
            if source is not None and not eager:
                label = "stdin" if source == "-" else str(source)
                document = _read_document(str(source), ctx)
                supplied = _validated_values(document, self, ctx, label)
                # click consults default_map only for a parameter the command
                # line did not set, which is rule 1 of the precedence.
                ctx.default_map = {**(ctx.default_map or {}), **supplied}

        # click ranks an environment variable above default_map, and converts
        # each parameter's value as it consumes it. Re-processing the document's
        # parameters after the parse put the document above the environment only
        # when the variable's value converted: one the type refused (an
        # ASH_SHARD_INDEX of "nine") was a usage error before the re-processing
        # ran, with the document's valid value never read. So for the parameters
        # the document sets, the environment is not read at all (rule 2 over
        # rule 3): their variables are suspended for the parse and put back
        # after it, because the parameter objects are the command's and outlive
        # this invocation.
        suspended: list[tuple[Parameter, Any, bool | None]] = []
        for param in self.get_params(ctx):
            if param.name not in supplied:
                continue
            auto = param.allow_from_autoenv if isinstance(param, TyperOption) else None
            suspended.append((param, param.envvar, auto))
            param.envvar = None
            if isinstance(param, TyperOption):
                param.allow_from_autoenv = False
        try:
            return super().parse_args(ctx, args)
        finally:
            for param, envvar, auto in suspended:
                param.envvar = envvar
                if auto is not None:
                    param.allow_from_autoenv = auto


__all__ = [
    "CLI_JSON_INPUT_FLAG",
    "GENERATE_CLI_SKELETON_FLAG",
    "CliJsonInputCommand",
    "build_skeleton",
    "json_input_parameters",
]
