# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan <subject>``: the scan group and its ``fs`` subject.

``scan`` is a group whose subjects name what is scanned. ``fs`` scans a directory
and is today's scan with the directory as an argument. It is built from the same
function as the root callback, ``run_ash_scan_cli_command``, with one argument
added to its signature, so the 100+ options exist once and every option added to
the engine reaches ``fs`` with no second declaration.

``ash scan [options]`` with no subject, and bare ``ash [options]``, still run the
scan and print the deprecation line of ``scan_deprecation``; both are removed in
ASH v4.0. This module imports nothing heavy: ``ash scan --help`` prints ``fs``'s help
(the options tools read it for), and the engine's heavy trees stay deferred as they
are for ``ash --version`` (tests/unit/cli/test_version_startup_budget.py).
"""

from __future__ import annotations

import inspect
from typing import Annotated, Any, Optional

import typer
from typer.core import TyperGroup

from automated_security_helper.cli.json_input import CliJsonInputCommand
from automated_security_helper.cli.scan import run_ash_scan_cli_command
from automated_security_helper.cli.scan_deprecation import (
    SCAN_FORM_META,
    SCAN_NOUN_META,
    SOURCE_DIR_KEY_LINE,
    SOURCE_DIR_LINE,
    warn_deprecated,
)

#: The subject ``ash scan`` takes when none is named, and the only one today.
DEFAULT_SUBJECT = "fs"

_PATH_HELP = (
    "The directory to scan. Defaults to the current directory. "
    "--source-dir and ASH_SOURCE_DIR also name it."
)

#: The refusal for a directory named twice, as the PATH argument and with --source-dir.
_NAMED_TWICE = (
    "Name the directory once: as the PATH argument or with --source-dir, not both."
)
#: Added to it when a --cli-json-input document gave one of the two names.
_NAMED_TWICE_IN_A_DOCUMENT = (
    " In a --cli-json-input document they are the keys `path` and `source_dir` "
    "(also written `--source-dir`)."
)


def _spellings(param: Any) -> set[str]:
    return {*param.opts, *param.secondary_opts}


def _read_tokens(args: list[str], params: list[Any]) -> tuple[int | None, bool]:
    """``(index of the first positional, whether an option no param names came first)``."""
    owners = {opt: param for param in params for opt in _spellings(param)}
    expecting_value = False
    unknown = False
    for index, token in enumerate(args):
        if expecting_value:
            expecting_value = False
            continue
        if token == "--":
            return None, unknown
        if token.startswith("--"):
            name, equals, _ = token.partition("=")
            owner = owners.get(name)
            if owner is None:
                unknown = True
            expecting_value = owner is not None and not owner.is_flag and not equals
            continue
        if token.startswith("-") and len(token) > 1:
            rest = token[1:]
            while rest:
                name, rest = "-" + rest[0], rest[1:]
                owner = owners.get(name)
                if owner is None:
                    unknown = True
                    break
                if not owner.is_flag:
                    expecting_value = not rest
                    break
            continue
        return index, unknown
    return None, unknown


def first_positional(args: list[str], params: list[Any]) -> int | None:
    """Index of the first token in *args* that is neither an option nor an option's value.

    Read as click reads the tokens: a long option takes the next token as its value
    unless it is a flag or carries ``=value``; in a cluster of short options the
    first one that takes a value takes the rest of the cluster, or the next token
    when it is last. Nothing after a bare ``--`` is looked at.
    """
    return _read_tokens(args, params)[0]


def _not_a_subject(word: str, names: str) -> str:
    """The refusal for a word that is not a subject, naming the way to scan it.

    A word that starts with a dash is given after ``--``, which is what it needed
    when it was typed, so the suggested command keeps it.
    """
    separator = "-- " if word.startswith("-") else ""
    return (
        f"'{word}' is not a scan subject (subjects: {names}). "
        f"To scan a directory, run 'ash scan {DEFAULT_SUBJECT} {separator}{word}'."
    )


class ScanTyperGroup(TyperGroup):
    """The ``scan`` group: subjects by name, the old no-subject form as an alias.

    A subject may be given after options (``ash --output-dir out scan fs .`` hands
    the root's option on in front of it), so the first token that is not an option
    or an option's value is read as the subject. With no subject the arguments run
    as ``fs`` and the deprecation line prints. A lone ``--help`` is among them, so
    ``ash scan --help`` shows ``fs``'s help, options included, as it showed the scan's.
    """

    #: The subject the arguments run as when none is named. The docs checker reads
    #: this to model ``ash scan [options]`` (scripts/docs_checks.py).
    legacy_default_subject = DEFAULT_SUBJECT

    def fs_command(self) -> Any:
        return self.commands[DEFAULT_SUBJECT]

    def forwarding_target(self, ctx: Any, args: list[str]) -> Any:
        """The command that owns the options in *args*: the named subject, else ``fs``."""
        command = self.fs_command()
        index = first_positional(args, list(command.get_params(ctx)))
        if index is not None and args[index] in self.commands:
            return self.commands[args[index]]
        return command

    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        if not ctx.resilient_parsing:
            args = self._routed(ctx, list(args))
        return super().parse_args(ctx, args)

    def _routed(self, ctx: Any, args: list[str]) -> list[str]:
        params = list(self.fs_command().get_params(ctx))
        index, unknown_option = _read_tokens(args, params)
        if index is None or (unknown_option and args[index] not in self.commands):
            # No subject: the arguments run as `fs`, `--help` included. Tools read
            # `ash scan --help` for the scan's options (the deploy gates probe it
            # for --fail-on-incomplete-scanners), so it keeps listing them. An
            # option `fs` does not have, before a word, is `fs`'s to refuse as the
            # unknown option it is (it may take the word as its value).
            ctx.meta[SCAN_FORM_META] = "scan"
            return [DEFAULT_SUBJECT, *args]
        subject = args[index]
        if subject in self.commands:
            return [subject, *args[:index], *args[index + 1 :]]
        ctx.fail(_not_a_subject(subject, ", ".join(self.commands)))


def _fs_signature() -> inspect.Signature:
    engine = inspect.signature(run_ash_scan_cli_command)
    parameters = list(engine.parameters.values())
    path = inspect.Parameter(
        "path",
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        default=None,
        annotation=Annotated[
            Optional[str],
            typer.Argument(
                metavar="[PATH]",
                help=_PATH_HELP,
                show_default=False,
                rich_help_panel="Scan",
            ),
        ],
    )
    return engine.replace(parameters=[parameters[0], path, *parameters[1:]])


def run_ash_scan_fs_cli_command(*args: Any, **kwargs: Any) -> Any:
    """Scan a directory for code, infrastructure, secrets, and dependency findings.

    Start with: ash scan fs . --mode container

    Review the result with: ash results inspect findings

    Options are grouped by workflow below. `fs` is the only subject of `ash scan`
    today; `ash scan` with no subject runs it, but that form is deprecated.
    """
    ctx = kwargs["ctx"]
    path = kwargs.pop("path", None)
    routed_without_subject = ctx.meta.get(SCAN_FORM_META) == "scan"
    source_dir_source = getattr(ctx.get_parameter_source("source_dir"), "name", None)
    from_command_line = source_dir_source == "COMMANDLINE"
    # A --cli-json-input document's values reach click through the context's
    # default_map (cli/json_input.py), so a document that names the directory with
    # the deprecated option's key reads as DEFAULT_MAP.
    from_document = source_dir_source == "DEFAULT_MAP"
    if path is not None:
        if kwargs.get("source_git") is not None:
            ctx.fail(
                "--source-git cannot be combined with the PATH argument: the clone "
                "is the directory that is scanned."
            )
        # A path typed on the command line in the subject-less form is a word that
        # is not a subject (it reaches here after `--`, which the group does not
        # read). One from a --cli-json-input document arrives as a default, and its
        # skeleton lists `path`, so that is accepted.
        path_typed = (
            getattr(ctx.get_parameter_source("path"), "name", None) == "COMMANDLINE"
        )
        if routed_without_subject and path_typed:
            ctx.fail(_not_a_subject(path, DEFAULT_SUBJECT))
        # The document is named on this command line, so a directory it names is
        # given here as much as a typed one is (cli/json_input.py ranks it above the
        # environment for that reason). Two names that differ are refused wherever
        # each came from, so neither is dropped without a word. A key the document
        # leaves null names nothing. ASH_SOURCE_DIR is ambient, and the PATH
        # replaces it.
        if (from_command_line or from_document) and kwargs.get("source_dir") != path:
            ctx.fail(
                _NAMED_TWICE
                if path_typed and from_command_line
                else _NAMED_TWICE + _NAMED_TWICE_IN_A_DOCUMENT
            )
        kwargs["source_dir"] = path
    if not routed_without_subject:
        ctx.meta[SCAN_NOUN_META] = DEFAULT_SUBJECT
        if from_command_line:
            warn_deprecated(SOURCE_DIR_LINE)
        elif from_document:
            warn_deprecated(SOURCE_DIR_KEY_LINE)
    return run_ash_scan_cli_command(*args, **kwargs)


run_ash_scan_fs_cli_command.__signature__ = _fs_signature()  # type: ignore[attr-defined]
run_ash_scan_fs_cli_command.__annotations__ = {
    **run_ash_scan_cli_command.__annotations__,
    "path": _fs_signature().parameters["path"].annotation,
}


def build_scan_app() -> typer.Typer:
    """The ``scan`` Typer app with its subjects registered."""
    scan_app = typer.Typer(
        name="scan",
        cls=ScanTyperGroup,
        help=(
            "Scan code, infrastructure, secrets, and dependencies.\n\n"
            "Name what to scan: `ash scan fs <path>` scans a directory. "
            "`ash scan` with no subject still scans the working directory, but that "
            "form is deprecated and will be removed in ASH v4.0."
        ),
        no_args_is_help=False,
    )
    scan_app.command(
        name=DEFAULT_SUBJECT,
        cls=CliJsonInputCommand,
        no_args_is_help=False,
        # `ash scan --help` is this subject's help (see ScanTyperGroup._routed), so
        # the list of subjects is shown here, where that help ends.
        epilog=(
            f"Subjects of `ash scan`: {DEFAULT_SUBJECT} (scan a directory). "
            "Run `ash scan <subject> --help` for a subject's own options."
        ),
    )(run_ash_scan_fs_cli_command)
    return scan_app
