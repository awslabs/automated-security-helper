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

``fs`` alone takes ``--archive FILE``, a zip of source code to scan in place of a
directory. The option is declared on that subject and read by its callback, which
extracts the archive and hands the engine the extracted directory as the one to scan,
so the engine and the forms that share it know nothing of archives, and the module
that reads the zip (``utils/source_archive``) is imported only when one is given.

The skeleton of a subject (``--generate-cli-skeleton``) leaves out the deprecated keys,
``source_dir`` and ``scanners``, while a ``--cli-json-input`` document that names one is
still read, so a document written by filling in the skeleton prints no deprecation line.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Annotated, Any, Callable, Iterable, Optional

import typer
from typer.core import TyperGroup

from automated_security_helper.cli.json_input import CliJsonInputCommand
from automated_security_helper.cli.scan import _fail_state, run_ash_scan_cli_command
from automated_security_helper.cli.scan_deprecation import (
    SCAN_FORM_META,
    SCAN_NOUN_META,
    SOURCE_DIR_KEY_LINE,
    SOURCE_DIR_LINE,
    SOURCE_DIR_VARIABLE_LINE,
    WORKSPACE_CONFIG_VARIABLE_LINE,
    WORKSPACE_VARIABLE_LINE,
    warn_deprecated,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line

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
#: The deprecated options a subject still reads from a ``--cli-json-input`` document
#: and leaves out of its skeleton. The skeleton is the template a document is written
#: from, so listing one would send whoever fills it in to a key that prints its
#: deprecation line. ``source_dir`` is the older spelling of the PATH argument and
#: ``scanners`` of ``--only-scanners`` and ``--add-scanners``. ``--workspace`` is
#: deprecated too and is no key of either subject: ``fs`` takes none of the workspace
#: options, and the FILE argument of ``workspace`` is named ``file``.
DEPRECATED_KEYS = frozenset({"source_dir", "scanners"})

#: The name the subject-less form's command is registered under. It is not a subject,
#: so ``ScanTyperGroup`` takes it out of its commands as the group is built.
_LEGACY_KEY = "legacy"

_PATH_HELP = (
    "The directory to scan. Defaults to the current directory. --source-dir and "
    "ASH_SOURCE_DIR also name it, and both are deprecated and will be removed in "
    "ASH v4.0."
)
_FILE_HELP = (
    "The '.code-workspace' file whose folders are scanned as separate, "
    "independently-scoped projects. Pass 'auto' to use the single "
    "'*.code-workspace' file in the current directory. ASH_WORKSPACE also names it; "
    "that variable is deprecated and will be removed in ASH v4.0."
)

_ARCHIVE_HELP = (
    "A zip of source code to scan in place of a directory. ASH checks it against its "
    "size, name and link rules, extracts it to a temporary directory that is removed "
    "when the command ends, and scans that; results go to .ash/ash_output in the "
    "working directory unless --output-dir names another. Cannot be combined with the "
    "PATH argument, --source-dir, --source-git, an image option, --staged, "
    "--use-existing or --changed-files-only."
)

#: Why ``--archive`` cannot be given with each of the options it excludes. A refusal
#: reads "--archive cannot be combined with <option>: <reason>".
_ARCHIVE_IS_THE_DIRECTORY = (
    "the archive is the directory that is scanned. Use one or the other."
)
_ARCHIVE_IS_NO_CLONE = (
    "the archive is the directory that is scanned, not a clone. Use one or the other."
)
_ONLY_FOR_A_CLONE = "it applies to a clone, and the archive is not one."
_ONE_SUBJECT = "one scan has one subject. Scan the archive and the image as two runs."
_NO_GIT_INDEX = "the staged scope is read from a git index, and an archive has none."
_NO_GIT_DIFF = (
    "the changed-files scope is read from a git diff, and an archive has none."
)
_SCANS_NOTHING = (
    "--use-existing reports the results of an earlier run and scans nothing, so "
    "there is no archive to read."
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


def _archive_parameter() -> inspect.Parameter:
    return inspect.Parameter(
        "archive",
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        default=None,
        annotation=Annotated[
            Optional[str],
            typer.Option(
                "--archive",
                metavar="FILE",
                help=_ARCHIVE_HELP,
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
    """The engine's signature without the workspace options, with the PATH argument
    and ``--archive``, which only this subject takes, listed right after
    ``--source-dir``."""
    signature = _signature(_path_parameter(), without=WORKSPACE_OPTIONS)
    parameters = list(signature.parameters.values())
    after_source_dir = 1 + next(
        index for index, p in enumerate(parameters) if p.name == "source_dir"
    )
    parameters.insert(after_source_dir, _archive_parameter())
    return signature.replace(parameters=parameters)


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


def _refuse_what_an_archive_replaces(
    ctx: Any, kwargs: dict[str, Any], path: str | None, *, directory_named: bool
) -> None:
    """Refuse ``--archive`` beside anything else that names or scopes the tree scanned.

    The archive is extracted to be the directory that is scanned, so every other way to
    name a directory, a clone or an image is refused, and so are the scopes that read a
    git checkout or an earlier run's results, which an archive has none of. Each refusal
    names both options and exits with the usage-error code, before anything is
    extracted. ``ASH_SOURCE_DIR`` is ambient, so the archive replaces it, as the clone
    of ``--source-git`` does; *directory_named* is whether ``--source-dir`` was given
    on the command line or by a ``--cli-json-input`` document.
    """
    for other, given, reason in (
        ("the PATH argument", path is not None, _ARCHIVE_IS_THE_DIRECTORY),
        ("--source-dir", directory_named, _ARCHIVE_IS_THE_DIRECTORY),
        ("--source-git", kwargs.get("source_git") is not None, _ARCHIVE_IS_NO_CLONE),
        ("--git-ref", kwargs.get("git_ref") is not None, _ONLY_FOR_A_CLONE),
        ("--git-depth", kwargs.get("git_depth") is not None, _ONLY_FOR_A_CLONE),
        ("--image", bool(kwargs.get("image")), _ONE_SUBJECT),
        ("--image-archive", kwargs.get("image_archive") is not None, _ONE_SUBJECT),
        ("--image-layout", kwargs.get("image_layout") is not None, _ONE_SUBJECT),
        ("--staged", bool(kwargs.get("staged")), _NO_GIT_INDEX),
        ("--use-existing", bool(kwargs.get("use_existing")), _SCANS_NOTHING),
        ("--changed-files-only", bool(kwargs.get("changed_files_only")), _NO_GIT_DIFF),
    ):
        if given:
            ctx.fail(f"--archive cannot be combined with {other}: {reason}")


def _extract_archive(ctx: Any, archive: str) -> str:
    """Extract ``--archive`` into a temporary directory and return it as the directory
    to scan.

    ``utils/source_archive`` is imported here and nowhere else, so ``ash --version`` and
    ``ash scan --help`` do not load it (tests/unit/cli/test_version_startup_budget.py).
    It reads the zip under one set of limits and member rules, the ones the MCP
    ``set_source_zip_finalize`` upload is held to. The temporary directory is removed
    when the click context closes, which every ending of the command reaches, an exit
    and an error included, and a refused archive too: the extraction can stop partway,
    and the caller owns what it wrote. An archive the rules refuse is a usage error
    that prints the rule's own message; a problem with the disk (no room, an
    unreadable file system) exits 1, the answer for a run that produced no scan.
    """
    import shutil
    import tempfile

    from automated_security_helper.utils.source_archive import (
        SourceArchiveRefused,
        extract_source_archive,
    )

    try:
        root = Path(tempfile.mkdtemp(prefix="ash-source-archive-"))
    except OSError as error:
        _fail_state(shown_on_one_line(f"--archive: {error}"))
    ctx.call_on_close(lambda: shutil.rmtree(root, ignore_errors=True))
    try:
        return extract_source_archive(Path(archive), root).as_posix()
    except SourceArchiveRefused as refusal:
        ctx.fail(f"--archive: {refusal}")
    except OSError as error:
        _fail_state(shown_on_one_line(f"--archive: {error}"))


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
    # The engine has no `archive` parameter: this subject takes the option, and the
    # engine is handed the directory the archive was extracted to.
    archive = kwargs.pop("archive", None)
    routed_without_subject = ctx.meta.get(SCAN_FORM_META) == "scan"
    source_dir_source = getattr(ctx.get_parameter_source("source_dir"), "name", None)
    from_command_line = source_dir_source == "COMMANDLINE"
    # A --cli-json-input document's values reach click through the context's
    # default_map (cli/json_input.py), so a document that names the directory with
    # the deprecated option's key reads as DEFAULT_MAP.
    from_document = source_dir_source == "DEFAULT_MAP"
    # The variable names the directory alone when nothing else in the command does: no
    # PATH, no archive and no clone replace it, and an image option refuses it with
    # the engine's own words.
    from_variable_alone = (
        source_dir_source == "ENVIRONMENT"
        and path is None
        and archive is None
        and not any(
            kwargs.get(name)
            for name in ("source_git", "image", "image_archive", "image_layout")
        )
    )
    if archive is not None:
        _refuse_what_an_archive_replaces(
            ctx, kwargs, path, directory_named=from_command_line or from_document
        )
        kwargs["source_dir"] = _extract_archive(ctx, archive)
        if kwargs.get("output_dir") is None:
            # The default is beside the source directory, which here is a temporary
            # tree that is removed when the command ends, with the results in it.
            kwargs["output_dir"] = Path.cwd().joinpath(".ash", "ash_output").as_posix()
    elif path is not None:
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
        elif from_variable_alone:
            warn_deprecated(SOURCE_DIR_VARIABLE_LINE)
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
    # A variable that names what no argument does is told once, each by its own line.
    for parameter, line in (
        ("file", WORKSPACE_VARIABLE_LINE),
        ("workspace_config", WORKSPACE_CONFIG_VARIABLE_LINE),
    ):
        if getattr(ctx.get_parameter_source(parameter), "name", None) == "ENVIRONMENT":
            warn_deprecated(line)
    return run_ash_scan_cli_command(*args, **kwargs)


def run_ash_scan_without_subject_cli_command(*args: Any, **kwargs: Any) -> Any:
    return run_ash_scan_fs_cli_command(*args, **kwargs)


_declared(run_ash_scan_fs_cli_command, _fs_signature())
_declared(run_ash_scan_workspace_cli_command, _workspace_signature())
# The form with no subject runs the same body with every option of the engine, and shows
# the same help.
run_ash_scan_without_subject_cli_command.__doc__ = run_ash_scan_fs_cli_command.__doc__
_declared(run_ash_scan_without_subject_cli_command, _legacy_signature())


class _SubjectCommand(CliJsonInputCommand):
    """A subject's command: its skeleton leaves out the deprecated keys.

    A document that names one is still read, with the deprecation line it always
    printed. The command of the form with no subject keeps them in its skeleton: that
    form is the scan as it was, and is deprecated as a whole.
    """

    skeleton_omits = DEPRECATED_KEYS


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
    for name, callback, command_class in (
        (DEFAULT_SUBJECT, run_ash_scan_fs_cli_command, _SubjectCommand),
        (WORKSPACE_SUBJECT, run_ash_scan_workspace_cli_command, _SubjectCommand),
        (_LEGACY_KEY, run_ash_scan_without_subject_cli_command, CliJsonInputCommand),
    ):
        scan_app.command(
            name=name,
            cls=command_class,
            no_args_is_help=False,
            # `ash scan --help` is the legacy command's help (see
            # ScanTyperGroup._routed), so the list of subjects is shown here, where
            # that help ends, and on each subject.
            epilog=_EPILOG,
        )(callback)
    return scan_app
