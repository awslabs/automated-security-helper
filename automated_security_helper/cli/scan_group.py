# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan <subject>``: the scan group and its ``fs`` and ``workspace`` subjects.

``scan`` is a group whose subjects name what is scanned. ``fs`` scans a directory and
``workspace`` scans the projects of a ``.code-workspace`` file. Each is built from the
same function as the root callback, ``run_ash_scan_cli_command``: it takes the engine's
signature, leaves out the options that belong to another subject, and adds the argument
that names what it scans, so the 100+ options exist once and every option added to the
engine reaches the subjects that read it with no second declaration.

``ash scan [options]`` with no subject, and bare ``ash [options]``, still run the
scan and print the deprecation line of ``scan_deprecation``; both are removed in
ASH v4.0. The form with no subject is the scan as it was before it had subjects, so
it runs the group's legacy command, which takes every option of the engine
(``--workspace`` included) and the PATH argument. That command is not a subject: the
group keeps it out of its commands. This module imports nothing heavy: ``ash scan
--help`` prints the legacy command's help (the options tools read it for), and the
engine's heavy trees stay deferred as they are for ``ash --version``
(tests/unit/cli/test_version_startup_budget.py).
"""

from __future__ import annotations

import inspect
from typing import Annotated, Any, Callable, Iterable, Optional

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

#: The subject ``ash scan`` takes when none is named.
DEFAULT_SUBJECT = "fs"
#: The subject that scans the projects of a ``.code-workspace`` file.
WORKSPACE_SUBJECT = "workspace"

#: What each subject scans, in the order ``ash scan --help`` lists them. The listing is
#: built from this table, and a test reads the group against it, so a subject the group
#: gains has to be named here.
SUBJECTS: dict[str, str] = {
    DEFAULT_SUBJECT: "scan a directory",
    WORKSPACE_SUBJECT: "scan the projects of a .code-workspace file",
}

#: The engine's name for the workspace file. On the workspace subject it is the FILE
#: argument, named ``file``, and the engine is handed it under this name.
WORKSPACE_FILE_OPTION = "workspace"
#: The options of a workspace scan. ``fs`` takes none of them. The workspace subject
#: takes the last three as options and the first as its FILE argument.
WORKSPACE_OPTIONS = (
    WORKSPACE_FILE_OPTION,
    "workspace_config",
    "allow_missing_projects",
    "dry_run",
)
#: The options that read the one directory a scan starts in, or a scan of it made
#: before. The workspace subject takes none of them: its scan root is the directory
#: that holds the workspace file, and each project is scanned on its own.
DIRECTORY_OPTIONS = (
    "source_dir",
    "use_existing",
    "changed_files_only",
    "base_ref",
    "staged",
    "baseline",
    "shard_index",
    "shard_count",
)
#: The options that name a subject of their own, an image or a remote repository.
#: The workspace subject takes none of them.
OTHER_SUBJECT_OPTIONS = (
    "image",
    "image_archive",
    "image_layout",
    "source_git",
    "git_ref",
    "git_depth",
)

#: The name the subject-less form's command is registered under. It is not a subject,
#: so ``ScanTyperGroup`` takes it out of its commands as the group is built.
_LEGACY_KEY = "legacy"

_PATH_HELP = (
    "The directory to scan. Defaults to the current directory. "
    "--source-dir and ASH_SOURCE_DIR also name it."
)
_FILE_HELP = (
    "The '.code-workspace' file whose folders are scanned as separate, "
    "independently-scoped projects. Pass 'auto' to use the single "
    "'*.code-workspace' file in the current directory."
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

#: What ``ash scan --help`` ends with, the help of the form with no subject and of each
#: subject: the subjects, and where each one's own options are.
_EPILOG = (
    "Subjects of `ash scan`: "
    + ", ".join(f"{name} ({what})" for name, what in SUBJECTS.items())
    + ". Run `ash scan <subject> --help` for a subject's own options."
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
    as the legacy command and the deprecation line prints. A lone ``--help`` is among
    them, so ``ash scan --help`` shows the legacy command's help, options included,
    as it showed the scan's.
    """

    #: The subject the arguments run as when none is named. The docs checker reads
    #: this to model ``ash scan [options]`` (scripts/docs_checks.py). The legacy
    #: command, not this subject, is what runs: see :meth:`legacy_command`.
    legacy_default_subject = DEFAULT_SUBJECT

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # The legacy command is registered with the subjects, so it is built the way
        # they are, and is taken out of the group's commands here: it is not a subject,
        # and every tool that lists the subjects (the help, the generated tables, the
        # completion) reads the commands.
        legacy = self.commands.pop(_LEGACY_KEY, None)
        if legacy is not None:
            legacy.name = DEFAULT_SUBJECT
        self._legacy = legacy

    def fs_command(self) -> Any:
        return self.commands[DEFAULT_SUBJECT]

    def legacy_command(self) -> Any:
        """The command ``ash scan [options]`` runs when no subject is named.

        It takes every option of the engine, the workspace options included, and the
        PATH argument: the scan as it was before it had subjects. ``fs`` takes only
        the options of a directory scan, so a reader that models the form with no
        subject reads its options here.
        """
        return self.fs_command() if self._legacy is None else self._legacy

    def forwarding_target(self, ctx: Any, args: list[str]) -> Any:
        """The command that owns the options in *args*.

        The named subject, else the legacy command the form with no subject runs.
        """
        command = self.legacy_command()
        index = first_positional(args, list(command.get_params(ctx)))
        if index is not None and args[index] in self.commands:
            return self.commands[args[index]]
        return command

    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        if not ctx.resilient_parsing:
            args = self._routed(ctx, list(args))
        return super().parse_args(ctx, args)

    def _routed(self, ctx: Any, args: list[str]) -> list[str]:
        # The tokens are read with the legacy command's options, every one the engine
        # has, so the value of an option that only a subject takes (``--workspace``,
        # ``--source-dir``) is never read as the subject.
        params = list(self.legacy_command().get_params(ctx))
        index, unknown_option = _read_tokens(args, params)
        if index is None or (unknown_option and args[index] not in self.commands):
            # No subject: the arguments run as the legacy command, `--help` included.
            # Tools read `ash scan --help` for the scan's options (the deploy gates
            # probe it for --fail-on-incomplete-scanners), so it keeps listing them.
            # An option the legacy command does not have, before a word, is its to
            # refuse as the unknown option it is (it may take the word as its value).
            ctx.meta[SCAN_FORM_META] = "scan"
            return [DEFAULT_SUBJECT, *args]
        subject = args[index]
        if subject in self.commands:
            return [subject, *args[:index], *args[index + 1 :]]
        ctx.fail(_not_a_subject(subject, ", ".join(self.commands)))

    def resolve_command(
        self, ctx: Any, args: list[str]
    ) -> tuple[str | None, Any, list[str]]:
        # The subject-less route names `fs`, and `fs` is the legacy command there.
        if (
            self._legacy is not None
            and ctx.meta.get(SCAN_FORM_META) == "scan"
            and args
            and args[0] == DEFAULT_SUBJECT
        ):
            return DEFAULT_SUBJECT, self._legacy, args[1:]
        return super().resolve_command(ctx, args)


def _path_parameter() -> inspect.Parameter:
    return inspect.Parameter(
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


def _file_parameter() -> inspect.Parameter:
    return inspect.Parameter(
        "file",
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        annotation=Annotated[
            str,
            typer.Argument(
                metavar="FILE",
                help=_FILE_HELP,
                envvar="ASH_WORKSPACE",
                show_default=False,
                rich_help_panel="Scan",
            ),
        ],
    )


def _signature(
    argument: inspect.Parameter, *, without: Iterable[str] = ()
) -> inspect.Signature:
    """The engine's signature without the options in *without*, and with *argument*
    right after the context."""
    engine = inspect.signature(run_ash_scan_cli_command)
    left_out = set(without)
    kept = [p for p in engine.parameters.values() if p.name not in left_out]
    return engine.replace(parameters=[kept[0], argument, *kept[1:]])


def _fs_signature() -> inspect.Signature:
    return _signature(_path_parameter(), without=WORKSPACE_OPTIONS)


def _legacy_signature() -> inspect.Signature:
    return _signature(_path_parameter())


def _workspace_signature() -> inspect.Signature:
    return _signature(
        _file_parameter(),
        without=(WORKSPACE_FILE_OPTION, *DIRECTORY_OPTIONS, *OTHER_SUBJECT_OPTIONS),
    )


def _declared(
    function: Callable[..., Any], signature: inspect.Signature
) -> Callable[..., Any]:
    """*function* as a command that takes *signature*'s parameters.

    Typer reads a command's parameters from its signature and its annotations, so both
    are set; the function itself only hands what it is given on.
    """
    function.__signature__ = signature  # type: ignore[attr-defined]
    function.__annotations__ = {
        name: parameter.annotation
        for name, parameter in signature.parameters.items()
        if parameter.annotation is not inspect.Parameter.empty
    }
    return function


def run_ash_scan_fs_cli_command(*args: Any, **kwargs: Any) -> Any:
    """Scan a directory for code, infrastructure, secrets, and dependency findings.

    Start with: ash scan fs . --mode container

    Review the result with: ash results inspect findings

    Options are grouped by workflow below. To scan the projects of a `.code-workspace`
    file, use `ash scan workspace`. `ash scan` with no subject runs this subject, but
    that form is deprecated.
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
            ctx.fail(_not_a_subject(path, ", ".join(SUBJECTS)))
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


def run_ash_scan_workspace_cli_command(*args: Any, **kwargs: Any) -> Any:
    """Scan the projects of a VS Code workspace file, each on its own.

    Start with: ash scan workspace my.code-workspace --mode container

    Review the result with: ash results inspect findings

    Each folder of the workspace is a project with its own configuration and its own
    result, and the results are combined. Options are grouped by workflow below. The
    options that read one directory (--changed-files-only, --baseline, --shard-index
    and the others) belong to `ash scan fs`.
    """
    ctx = kwargs["ctx"]
    # The engine names the workspace file `workspace`; the argument is `file`.
    kwargs["workspace"] = kwargs.pop("file")
    ctx.meta[SCAN_NOUN_META] = WORKSPACE_SUBJECT
    return run_ash_scan_cli_command(*args, **kwargs)


def run_ash_scan_without_subject_cli_command(*args: Any, **kwargs: Any) -> Any:
    return run_ash_scan_fs_cli_command(*args, **kwargs)


_declared(run_ash_scan_fs_cli_command, _fs_signature())
_declared(run_ash_scan_workspace_cli_command, _workspace_signature())
# The form with no subject runs the same body with every option of the engine, and shows
# the same help.
run_ash_scan_without_subject_cli_command.__doc__ = run_ash_scan_fs_cli_command.__doc__
_declared(run_ash_scan_without_subject_cli_command, _legacy_signature())


def build_scan_app() -> typer.Typer:
    """The ``scan`` Typer app with its subjects registered."""
    scan_app = typer.Typer(
        name="scan",
        cls=ScanTyperGroup,
        help=(
            "Scan code, infrastructure, secrets, and dependencies.\n\n"
            "Name what to scan: `ash scan fs <path>` scans a directory and "
            "`ash scan workspace <file>` scans the projects of a `.code-workspace` "
            "file. `ash scan` with no subject still scans the working directory, but "
            "that form is deprecated and will be removed in ASH v4.0."
        ),
        no_args_is_help=False,
    )
    for name, callback in (
        (DEFAULT_SUBJECT, run_ash_scan_fs_cli_command),
        (WORKSPACE_SUBJECT, run_ash_scan_workspace_cli_command),
        (_LEGACY_KEY, run_ash_scan_without_subject_cli_command),
    ):
        scan_app.command(
            name=name,
            cls=CliJsonInputCommand,
            no_args_is_help=False,
            # `ash scan --help` is the legacy command's help (see
            # ScanTyperGroup._routed), so the list of subjects is shown here, where
            # that help ends, and on each subject.
            epilog=_EPILOG,
        )(callback)
    return scan_app
