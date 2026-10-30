# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
import os
import re
import stat

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form. It is utils/console.py's print, not rich's:
# its console checks each line it writes off a terminal, so none reads as a CI command.
from automated_security_helper.utils.console import echo
from automated_security_helper.utils.console import print  # noqa: A004
from typing import Annotated, List, NoReturn, Optional
import typer
from pathlib import Path

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
    shutdown_cancels,
    shutdown_requested,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_SOURCES_DESCRIPTION,
    ASH_EXIT_INTERRUPTED,
    ASH_EXIT_TERMINATED,
    ASH_EXIT_USAGE_ERROR,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
    MinSeverity,
    RunMode,
    SandboxMode,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ShardSelectionError,
    WorkspaceDefinitionError,
    WorkspacePathNotUtf8Error,
)
from automated_security_helper.core.sharding import validate_shard_selection
from automated_security_helper.interactions.run_ash_scan import (
    PRECOMMIT_MODE_SCANNERS,
    resolve_workspace_execution_config,
    resolved_console_log_level,
    run_ash_scan,
)
from automated_security_helper.core.enums import (
    AWS_PLUGIN_MODULE_FORMATS,
    FORMATS_NO_REPORTER_WRITES,
    ExportFormat,
)
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.content_databases import (
    content_db_staleness_flag_overrides,
    get as get_content_database,
    go_duration,
)
from automated_security_helper.utils.directory_refusals import (
    output_dir_refusal,
    source_dir_refusal,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.get_scan_set import (
    InvalidBaseRefError,
    validate_base_ref,
)
from automated_security_helper.utils.log import (
    configure_last_resort_level,
    escape_markup,
)
from automated_security_helper.utils.output_dir_links import (
    OUTPUT_GITIGNORE,
    OUTPUT_GITIGNORE_TEXT,
    OUTPUT_LOG_FILES,
    OUTPUT_RESULT_FILES,
    OUTPUT_WORKING_DIRS,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line
from automated_security_helper.workspace.plan import WorkspacePlan
from automated_security_helper.workspace.resolver import resolve_workspace
from automated_security_helper.workspace.workspace_file import (
    WORKSPACE_AUTO,
    discover_workspace_file,
)


def _from_environment(ctx: typer.Context, param: str) -> bool:
    """Whether click took *param*'s value from its ``envvar``."""
    return getattr(ctx.get_parameter_source(param), "name", None) == "ENVIRONMENT"


def _fail_config_mark(message: str) -> NoReturn:
    """A usage error in container mode's marks for the scan inside: exit 3.

    Written with utils/console.py's ``echo`` for the reason ``_fail_workspace``
    gives below, and raised ``from None`` the same way. The message quotes
    operator-supplied paths, so the whole message is shown once, on one line
    (``shown_on_one_line``); callers pass raw values.
    """
    echo(shown_on_one_line(message), err=True)
    raise typer.Exit(3) from None


def _chain_files(configs: List[Path]) -> Optional[set[Path]]:
    """The real path of every file of the extends chain of any of *configs*:
    ``--config`` and the file ``ASH_CONFIG`` names.

    Read once for all the marks of a command. A chain that does not load gives
    None: the scan reports it, with its own exit code, and the marks are not judged
    against a chain that is not there.
    """
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
    )
    from automated_security_helper.config.resolve_config import read_config_document

    files: set[Path] = set()
    for config in configs:
        try:
            chain = read_config_document(
                config, confine_to=default_confinement_root(config), log_failure=False
            ).chain
        except Exception:  # noqa: BLE001 - the scan reports a config that does not load
            return None
        files.update(Path(os.path.realpath(path)) for path in chain)
    return files


def _marks_outside_the_chain(
    chain_files: set[Path], marks: List[tuple[str, List[str]]]
) -> List[str]:
    """One sentence for each option of *marks* (its name and the files it marks)
    that names a file outside *chain_files*, listing those files.

    Container mode names each file it marks by its path inside the container, so a
    name that misses both chains would leave that file's grants in place
    unnoticed; it is refused instead.
    """
    sentences = []
    for option, marked in marks:
        outside = [
            path for path in marked if Path(os.path.realpath(path)) not in chain_files
        ]
        if outside:
            sentences.append(
                f"{option} names {', '.join(outside)}, which is not a file of the "
                "chain of --config or of the file ASH_CONFIG names."
            )
    return sentences


def _fail_workspace(
    message: str,
    code: WorkspaceExitCode = WorkspaceExitCode.WORKSPACE_ERROR,
) -> NoReturn:
    """Report a workspace-mode refusal and exit with its contract code.

    Written with utils/console.py's ``echo`` rather than the Rich ``print``
    imported above, because these messages quote operator-supplied paths and Rich
    would read a bracketed fragment in one as a style name and fail while
    rendering the error. ``echo`` shows the text's controls, not markup.

    Raised ``from None``: the dry run calls this inside its ``except``
    handlers, and the exit would otherwise chain the error being handled,
    whose unredacted text anything formatting the exit prints.
    """
    echo(message, err=True)
    raise typer.Exit(code) from None


def _fail_workspace_definition(exc: WorkspaceDefinitionError) -> NoReturn:
    """Report a refused workspace definition, each of its lines on one line.

    A refusal that lists problems keeps its layout (``exc.lines``, ASH's own
    text), and each line, which quotes a project name or a path as it is, is
    shown on one line, so a newline in a name cannot start a list item of its
    own. A refusal with no list is one message, shown on one line as a whole.
    The text is the real run's (error_text, applied per kept line): the
    prewarm carries the values a failing plugin load read from the
    environment on the error (carry_environment_values), and ``str(exc)``
    printed them raw where the real run's handler redacts them.
    """
    from automated_security_helper.utils.error_text import (
        carried_environment_values,
        error_text,
        text_without_values,
    )

    values = carried_environment_values(exc)
    for line in exc.lines[:-1]:
        echo(shown_on_one_line(text_without_values(line, values)), err=True)
    if exc.lines:
        _fail_workspace(shown_on_one_line(text_without_values(exc.lines[-1], values)))
    _fail_workspace(shown_on_one_line(error_text(exc)))


def _fail_workspace_config(exc: ASHConfigValidationError) -> NoReturn:
    """Report a config file the workspace plan refused, exit 3.

    It names the file, whose path is the caller's text, so each of its lines is
    shown on one line. Which lines there are is parser_text.refusal_own_lines'
    one rule, shared with the scan's refusal
    (interactions/run_ash_scan._printed_config_refusal): a parser's message that
    names its file keeps the parser's lines, and anything else is one line. The
    text is error_text's, as the scan's refusal is, so values carried on the
    error (carry_environment_values) are redacted, where ``str(exc)`` printed
    them raw.
    """
    from automated_security_helper.utils.error_text import error_text
    from automated_security_helper.utils.parser_text import refusal_own_lines

    code = WorkspaceExitCode.INVALID_PROJECT_CONFIG
    lines = refusal_own_lines(exc, error_text(exc))
    for line in lines[:-1]:
        echo(shown_on_one_line(line), err=True)
    _fail_workspace(shown_on_one_line(lines[-1]), code=code)


def _fail_shard_selection(message: str) -> NoReturn:
    """Report a shard-selection refusal and exit with ASH's usage-error code.

    The same code click's own usage errors exit with (see ``AshTyperGroup`` in
    cli/main.py), and neither 2 nor 1: 2 is "actionable findings were found" and 1
    is "the scan failed or is incomplete", and a pipeline reading either would look
    for the problem in the scan rather than in its own command line.

    Written with ``echo`` rather than the Rich ``print`` imported above, for the
    same reason as :func:`_fail_workspace`: these messages quote operator-supplied
    values.
    """
    echo(message, err=True)
    raise typer.Exit(ASH_EXIT_USAGE_ERROR)


def _fail_usage(message: str) -> NoReturn:
    """Report a refused invocation and exit with ASH's usage-error code.

    The code shard-selection refusals use, for the reason
    :func:`_fail_shard_selection` gives. Written with ``echo`` to stderr because
    these messages quote operator-supplied paths, which Rich would try to read as
    markup.
    """
    echo(message, err=True)
    raise typer.Exit(ASH_EXIT_USAGE_ERROR)


def _fail_state(message: str) -> NoReturn:
    """Report a refusal caused by what is on disk, not by the command line, and exit 1.

    The invocation is well formed; what it asks to use is not there yet, such as
    the results ``--use-existing`` reads. That is ASH's code for a run that did not
    produce a scan, the same answer ``ash report`` gives for missing results, and
    not the usage-error code, which would tell the operator to fix the command.
    Written with ``echo`` to stderr for the reason :func:`_fail_usage` gives.
    """
    echo(message, err=True)
    raise typer.Exit(1)


def _resolved(path: str | Path) -> Path:
    """*path* with its links followed and its ``..`` folded, for a comparison.

    Falls back to the absolute spelling when resolving fails: a symbolic link
    that leads back to itself made ``Path.resolve`` raise (RuntimeError before
    Python 3.13, OSError in strict mode), which ended ``ash scan`` in a traceback
    where the output directory refusal below would have named the link.
    """
    try:
        return Path(path).resolve()
    except (OSError, RuntimeError):
        return Path(path).absolute()


#: The most bytes read from a marker file to decide whether ASH wrote it.
_MARKER_HEAD_BYTES = 64 * 1024

#: The first line of ash.log as utils/log.py writes it: the record's time, level
#: and source, tab-separated (the TABULAR formatter's fmt).
_ASH_LOG_FIRST_LINE = re.compile(
    rb"\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\t[A-Z]+\t[^\t\n]+:\d+\t"
)

#: The keys every line of ash.log.jsonl carries (utils/log.py's JsonFormatter).
_ASH_JSONL_KEYS = frozenset({"timestamp", "level", "message"})


def _marker_head(path: Path) -> Optional[bytes]:
    """The first _MARKER_HEAD_BYTES of *path* when it is a regular file reached
    without following a link, else None (a link, a directory, nothing there, or
    an unreadable file is no marker)."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        with open(path, "rb") as handle:
            return handle.read(_MARKER_HEAD_BYTES)
    except OSError:
        return None


def _written_by_ash(name: str, head: bytes) -> bool:
    """Whether the first bytes of the output-directory file *name* are what ASH
    writes there: the aggregated results, a JSON object with the report's
    ``metadata`` key in its head; ``ash.log``, whose first line is the tabular
    record format; ``ash.log.jsonl``, whose first line is a JSON object with the
    formatter's keys. The two text listings have no shape of ASH's own to read, so
    they are no marker. A file with the right name and other content is the tree's."""
    if name == "ash_aggregated_results.json":
        return head.lstrip().startswith(b"{") and b'"metadata"' in head
    if name == "ash.log":
        return _ASH_LOG_FIRST_LINE.match(head) is not None
    if name == "ash.log.jsonl":
        first_line = head.split(b"\n", 1)[0]
        try:
            record = json.loads(first_line)
        except ValueError:
            return False
        return isinstance(record, dict) and _ASH_JSONL_KEYS <= record.keys()
    return False


def _ash_output_dir(source_dir: str, output_resolved: Path) -> bool:
    """Whether *output_resolved*, inside the scanned tree, is ASH's own output
    directory and not a directory of the tree's: the default
    ``<source_dir>/.ash/ash_output``, or one holding a result, log or ignore file a
    run of ASH wrote, read by its content and not its name alone (the
    ``.gitignore`` is written before any scanner starts, so a run that got no
    further still left it). A tree directory that happens to hold a file named
    ``ash.log`` is not ASH's; a link at a marker's name counts for nothing."""
    if output_resolved == _resolved(Path(source_dir).joinpath(".ash", "ash_output")):
        return True
    for name in (*OUTPUT_RESULT_FILES, *OUTPUT_LOG_FILES):
        head = _marker_head(output_resolved.joinpath(name))
        if head is not None and _written_by_ash(name, head):
            return True
    head = _marker_head(output_resolved.joinpath(OUTPUT_GITIGNORE))
    if head is None:
        return False
    # ASH writes the file in text mode (output_dir_links.ignore_output_dir_in_git),
    # so on Windows its line ends are \r\n; the text is compared, not the bytes.
    return head.replace(b"\r\n", b"\n") == OUTPUT_GITIGNORE_TEXT.encode("utf-8")


def _not_clearable(directory: Path) -> Optional[str]:
    """Why the scan must not clear *directory*, or None when it may: a directory
    (not a link) that holds an entry, or one that cannot be read, so whether it
    holds the tree's files cannot be told. An unreadable one read as empty before,
    and the refusal was not given; the clear itself then failed on the same
    permission, deleting nothing, with a traceback instead of the reason."""
    try:
        if stat.S_ISLNK(os.lstat(directory).st_mode):
            return None
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"cannot be read ({type(exc).__name__})"
    if not directory.is_dir():
        return None
    try:
        with os.scandir(directory) as entries:
            if next(entries, None) is None:
                return None
    except OSError as exc:
        return f"cannot be read ({type(exc).__name__})"
    return "already holds files that are not ASH's"


def _settle_output_dir(
    source_dir: str,
    output_dir: str | Path | None,
    use_existing: bool,
    ignore_suppressions: bool = False,
) -> tuple[str | Path, str | None]:
    """The output directory the scan writes to, and the existing results it reads.

    Defaults ``output_dir`` to ``<source_dir>/.ash/ash_output``, moves it there when
    it is the source directory itself, refuses one the scan would clear the scanned
    tree through, refuses one that cannot be written into, refuses
    ``--use-existing`` together with ``--ignore-suppressions``, and resolves
    ``--use-existing`` to the results file or refuses when it is not there. Every
    refusal exits, so the caller gets back only a pair the scan can run with.

    Called where the real run settles them, and from the workspace dry run before
    it prints its plan, so a dry run that exits 0 describes a command line the
    real run accepts.

    The two directories are compared resolved (``Path.resolve``: ``..`` folded and
    links followed), not as the absolute spellings given. Compared lexically,
    ``--output-dir src/../src`` and a link to the source directory read as
    different from it, and the scan then cleared ``reports/``, ``scanners/``,
    ``converted/`` and ``analysis/`` inside the tree it was scanning. The same
    resolved reading refuses a source directory that is one of those cleared
    directories or inside one (``--source-dir reports --output-dir .``): the scan
    removes each of them before it starts, so it would delete what it was asked
    to scan and then report a clean tree.
    """
    if output_dir is None:
        # Default output_dir is relative to source_dir, not CWD.
        # This ensures that when --source-dir points to a different project,
        # the output (and config resolution) happens in the correct location.
        output_dir = Path(source_dir).joinpath(".ash", "ash_output").as_posix()

    source_resolved = _resolved(source_dir)
    if source_resolved == _resolved(output_dir):
        output_dir = Path(output_dir).joinpath(".ash", "ash_output")
        print(
            "[bold yellow]output-dir has been adjusted to the following to avoid "
            "collisions and potential impact to source code: "
            f"{escape_markup(Path(output_dir).as_posix())}[/bold yellow]"
        )
    output_resolved = _resolved(output_dir)
    for working_dir in OUTPUT_WORKING_DIRS:
        cleared = output_resolved.joinpath(working_dir)
        if source_resolved == cleared or source_resolved.is_relative_to(cleared):
            _fail_usage(
                shown_on_one_line(
                    f"Source directory {os.fspath(source_dir)} is inside "
                    f"{cleared.as_posix()}, which the scan removes from the output "
                    f"directory {os.fspath(output_dir)} before it starts, so the "
                    "scan would delete the directory it was asked to scan. Point "
                    "--output-dir at a directory that does not contain the source "
                    "directory, or scan a directory outside the output directory."
                )
            )
    # A file where the output directory goes ended the run in a FileExistsError
    # traceback, from the first mkdir of it. A missing one is still made. For a
    # path that is not a directory that exists, this is asked before the
    # containment question below: an output path that is a file, or under one, is
    # refused as that (the refusal every runner prints alike), not as a working
    # directory "that cannot be read (NotADirectoryError)". For a directory that
    # exists it is asked after: its write probe makes and removes a file in the
    # directory, and a directory of the tree's that the scan refuses to clear is
    # not written into first, not even for a moment.
    # A directory on the way that cannot be searched: before CPython 3.13,
    # Path.is_dir() re-raised that PermissionError (3.13 reads it as False), so
    # the run ended in a traceback where the refusal below names the reason.
    try:
        probe_after_containment = output_resolved.is_dir()
    except OSError:
        probe_after_containment = False
    if not probe_after_containment:
        output_refusal = output_dir_refusal(output_dir)
        if output_refusal is not None:
            _fail_usage(shown_on_one_line(output_refusal))
    # The reverse: an output directory inside the scanned tree whose working
    # directories already hold something of the tree's. The scan removes each of
    # them before it starts (the orchestrator's ensure_directories), so
    # `--source-dir . --output-dir docs` with a real docs/reports/ deleted part of
    # the tree it was asked to scan. What git tracks at those paths is refused by
    # the orchestrator (core/committed_output.py); this covers what that does not
    # see: files git ignores or was never told about, and a tree outside git. An
    # output directory ASH wrote before is still cleared, as it always was
    # (_ash_output_dir); so is an empty directory, which is recreated as it was.
    if (
        output_resolved != source_resolved
        and output_resolved.is_relative_to(source_resolved)
        and not _ash_output_dir(source_dir, output_resolved)
    ):
        for working_dir in OUTPUT_WORKING_DIRS:
            cleared = output_resolved.joinpath(working_dir)
            reason = _not_clearable(cleared)
            if reason is not None:
                _fail_usage(
                    shown_on_one_line(
                        f"Output directory {os.fspath(output_dir)} is inside the "
                        f"source directory {os.fspath(source_dir)}, and "
                        f"{cleared.as_posix()} {reason}: the scan removes "
                        f"{working_dir}/ from the output directory before it "
                        "starts, so it would delete part of the tree it was asked "
                        "to scan. Point --output-dir at a directory of its own "
                        "(the default, .ash/ash_output, is one), or move those "
                        "files out of it."
                    )
                )
    if probe_after_containment:
        output_refusal = output_dir_refusal(output_dir)
        if output_refusal is not None:
            _fail_usage(shown_on_one_line(output_refusal))

    existing_results = None
    if use_existing:
        # The stored results were written with ASH's suppressions applied, and a
        # report made from them cannot lift those suppressions: the scan phase that
        # --ignore-suppressions changes is the one --use-existing skips. The
        # combination used to run and keep the stored suppressions while the
        # command line said they were ignored. A mistake in the command line, so
        # the usage code, and checked before the on-disk check below: the operator
        # has to change the command, whatever is in the output directory.
        if ignore_suppressions:
            _fail_usage(
                "--ignore-suppressions cannot be combined with --use-existing: the "
                "existing results were written with suppressions applied, and a "
                "report made from them cannot lift those suppressions. Run a new "
                "scan with --ignore-suppressions, or drop it to report the existing "
                "results as they are."
            )
        poss_existing_results = Path(output_dir).joinpath("ash_aggregated_results.json")
        if poss_existing_results.exists():
            existing_results = poss_existing_results.as_posix()
        else:
            # A clean refusal, not the uncaught ValueError traceback this was, on one
            # line: the path is the --output-dir as given.
            _fail_state(
                shown_on_one_line(
                    f"--use-existing was given, but there are no existing results to "
                    f"use: {poss_existing_results.as_posix()} does not exist. Run a "
                    "scan first, or point --output-dir at the output of a previous "
                    "one."
                )
            )
    return output_dir, existing_results


def _refuse_sandbox_in_container_mode(
    sandbox: SandboxMode | str | None, mode: RunMode | str | None
) -> None:
    """Refuse ``--sandbox <mode>`` with ``--mode container``, before anything runs.

    Container mode does not apply the scanner sandbox: the scan inside runs its
    scanners unsandboxed and the container is the boundary. Asked for explicitly on
    the command line, a sandbox that would not be applied is a usage error rather
    than a warning, so a run that was asked to be sandboxed never runs without it.
    ``--sandbox off`` asks for nothing and passes. A mode from a config file or
    ``--config-overrides`` is not refused here; ``_run_container_mode`` warns about
    it, so a config shared between local and container runs keeps working.
    """
    if sandbox is None or SandboxMode(sandbox) == SandboxMode.off:
        return
    if mode is None or RunMode(mode) != RunMode.container:
        return
    requested = SandboxMode(sandbox).value
    echo(
        f"--sandbox {requested} cannot be used with --mode container: container mode "
        "runs the scanners unsandboxed inside the container. Run with --mode local "
        f"--sandbox {requested} to sandbox each scanner, or drop --sandbox.",
        err=True,
    )
    raise typer.Exit(ASH_EXIT_USAGE_ERROR)


def _refuse_changed_files_only_in_container_mode(
    changed_files_only: bool,
    mode: RunMode | str | None,
    from_environment: bool,
) -> None:
    """Refuse ``--changed-files-only`` with ``--mode container``, before anything runs.

    The scan in the container is not given it (``run_ash_container`` forwards no such
    option), so it reported the findings in every file, and the host said so only in
    a log record that --quiet hides. Asked for a scope this mode cannot apply, it
    refuses, as for ``--sandbox``. Set through ASH_CHANGED_FILES_ONLY it is refused
    too, naming the variable: it asks for the same scope.
    """
    if not changed_files_only:
        return
    if mode is None or RunMode(mode) != RunMode.container:
        return
    if from_environment:
        echo(
            "ASH_CHANGED_FILES_ONLY is set, and --changed-files-only is not supported "
            "with --mode container: the scan in the container would report the "
            "findings in every file. Run with --mode local, or unset "
            "ASH_CHANGED_FILES_ONLY.",
            err=True,
        )
    else:
        echo(
            "--changed-files-only is not supported with --mode container: the scan in "
            "the container would report the findings in every file. Run with --mode "
            "local, or drop --changed-files-only.",
            err=True,
        )
    raise typer.Exit(ASH_EXIT_USAGE_ERROR)


def _validate_shard_options(
    shard_index: int | None,
    shard_count: int | None,
    workspace: str | None,
) -> None:
    """Refuse an unusable shard selection, or one that workspace mode cannot honour.

    Called before workspace resolution and before any cwd-based default is
    applied. Every case here means the operator's CI matrix is wrong, and the scan
    they are about to pay for would cover part of the repository while reporting
    itself as a whole one.

    The workspace conflict is checked first. When both problems are present,
    telling the operator the pair is unavailable in workspace mode saves them from
    fixing a missing ``--shard-count`` that would then be rejected anyway.
    """
    if workspace is not None and (shard_index is not None or shard_count is not None):
        _fail_shard_selection(
            "--shard-index/--shard-count cannot be combined with --workspace. "
            "Both spread one scan over more compute, but along different axes, and "
            "only sharding is recombinable: it partitions the scanners and stamps "
            "the partition onto the results so 'ash merge' can prove the shards "
            "reconstruct exactly one whole scan. Workspace mode's unified results "
            "file is assembled from the per-project payloads and carries none of "
            "each project's scan metadata, so a sharded workspace run would write "
            "results that merge has no provenance to verify coverage from -- and "
            "an unverifiable partial scan reads as a clean one. Either scan the "
            "workspace whole on one executor, or give each CI job one project via "
            "--source-dir and shard that."
        )

    try:
        validate_shard_selection(shard_index, shard_count)
    except ShardSelectionError as exc:
        _fail_shard_selection(str(exc))


def _handle_workspace_mode(
    workspace: str,
    source_dir: str | None,
    allow_missing_projects: bool,
    workspace_config: str | None = None,
    config_overrides: tuple[str, ...] = (),
    config: str | None = None,
) -> "WorkspacePlan":
    """Resolve a workspace and return the plan, or exit.

    Every failure path is an exit, because a workspace that will not resolve has
    nothing to scan: 4 for a workspace definition or policy problem, 3 for a
    project whose own config is invalid. Never 2 -- that code means a scan ran and
    found actionable findings, which is the opposite of what any exit from here
    reports.

    The success path returns rather than exiting, and the caller runs the scans
    from the same plan object the operator would have inspected. Re-resolving for
    execution would let the two drift, which is exactly what ``--dry-run`` exists
    to rule out. The dry run itself is the caller's (``_exit_with_workspace_dry_run``),
    after the preflight the real run makes on the plan's root: the source and
    output directory refusals, ``--use-existing``. Done here, before those, a dry
    run exited 0 for a command line the run then refused, and the two made their
    checks in different orders.

    Argument validation happens before any filesystem work, so an operator who
    passed a contradictory pair of flags is told that rather than being sent to
    debug their workspace file first.

    ``config`` is ``--config`` (or ``ASH_CONFIG``). The fields it sets are final
    for every project, so it has to reach resolution as well as the scan, which
    gets it as ``ProjectScanSettings.default_config_path``: resolved without it,
    the plan and ``--dry-run`` would report each project's own values for them.
    """
    if source_dir is not None:
        _fail_workspace(
            "--workspace and --source-dir are mutually exclusive. In workspace "
            "mode the directory holding the workspace file is the scan root, so "
            "honouring both would leave it ambiguous which tree was scanned. "
            "Note that --source-dir is also set by the ASH_SOURCE_DIR "
            "environment variable, which counts as setting it."
        )

    try:
        workspace_file = (
            discover_workspace_file(Path.cwd())
            if workspace == WORKSPACE_AUTO
            else Path(workspace)
        )
        plan = resolve_workspace(
            workspace_file,
            allow_missing_projects=allow_missing_projects,
            workspace_config=(
                Path(workspace_config) if workspace_config is not None else None
            ),
            # Resolution needs these so each project's DECLARED threshold
            # reflects an override. The ceiling applies to that, and --dry-run
            # prints the value the scan will actually enforce.
            config_overrides=config_overrides,
            # The same reason, for the operator's config file. Resolved here as
            # the scan resolves it, so a missing or broken file is refused at
            # planning, --dry-run included, and the plan's thresholds are the
            # ones the scan applies.
            default_config=Path(config) if config else None,
        )
    except WorkspacePathNotUtf8Error as exc:
        # The message names its paths as they are. Shown once, as a whole, on one
        # line, so a newline in a name is written \x0a; echo passes it on as it is.
        _fail_workspace(shown_on_one_line(str(exc)))
    except WorkspaceDefinitionError as exc:
        # It can quote the definition's and the policy's text, a pattern with a
        # newline in it included. Each line of its layout is shown on one line.
        _fail_workspace_definition(exc)
    except ASHConfigValidationError as exc:
        _fail_workspace_config(exc)

    # The workspace root's own config sets how the run executes (parallelism,
    # timeouts), and the run refuses one that cannot be loaded with exit 3. Read
    # here too, so --dry-run does not report a plan the run would refuse.
    try:
        resolve_workspace_execution_config(Path(plan.workspace_root), config)
    except ASHConfigValidationError as exc:
        # Through _fail_workspace_config, as the plan's own config refusal is:
        # the refusal quotes the config's path, the caller's text, so each line
        # is shown on one line. Echoed as it was, a newline in the path began a
        # line of the path's choosing inside the refusal.
        _fail_workspace_config(exc)

    return plan


def _exit_with_workspace_dry_run(
    plan: "WorkspacePlan",
    scanners: tuple[str, ...],
    exclude_scanners: tuple[str, ...],
    ash_plugin_modules: tuple[str, ...],
) -> None:
    """Print *plan* and exit 0, the ``--dry-run`` answer, after the real run's own
    pre-checks.

    Called where the real run would start executing: after ``_handle_workspace_mode``
    resolved the plan and the shared preflight (the source directory refusal,
    ``_settle_output_dir``) ran on its root, in that order. So a dry run refuses
    what the run refuses, with the run's code and text, and refuses it in the
    run's order: made inside the resolution, before the preflight, a dry run
    exited 0 for a command line the run then rejected, and with two problems
    present the two named different first errors.

    The selection pre-check is the one the real run makes, with the same code and
    text, so the dry run answers for the scan it describes: a dry run that exits 0
    for a selection the real run refuses tells the operator the command line is
    good, and the real run then refuses it.
    """
    from automated_security_helper.core.exceptions import ScannerSelectionError
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        prewarm_plugin_registry,
        refuse_unresolvable_scanner_selection,
    )

    selection = ProjectScanSettings(
        # The pre-check and the prewarm read only the selection and the
        # plugin modules; nothing is written anywhere. The prewarm imports
        # the workspace's plugin modules, as the real run does, because the
        # pre-check judges the selection by the scanners they provide.
        output_dir=Path(plan.workspace_root),
        enabled_scanners=tuple(scanners),
        excluded_scanners=tuple(exclude_scanners),
        ash_plugin_modules=tuple(ash_plugin_modules),
    )
    try:
        prewarm_plugin_registry(plan, selection)
        refuse_unresolvable_scanner_selection(plan, selection)
    except ScannerSelectionError as exc:
        _fail_workspace(shown_on_one_line(str(exc)), code=WorkspaceExitCode.USAGE_ERROR)
    except WorkspaceDefinitionError as exc:
        # The workspace's own refusal, with its code, as the real run
        # answers one raised while it executes: the generic arm below would
        # read it as an error nothing expected, exit 1.
        _fail_workspace_definition(exc)
    except ASHConfigValidationError as exc:
        # The prewarm's refusal of a plugin module outside ASH's namespace,
        # made before anything is imported: an invalid configuration, exit 3,
        # in the real run, and reported here as the plan's own config
        # refusal is. Uncaught, it ended the dry run with exit 1 and
        # nothing printed.
        _fail_workspace_config(exc)
    except Exception as exc:  # noqa: BLE001 -- answered as the real run answers it
        # A plugin module in the namespace whose top-level code raises
        # something other than ImportError when the prewarm imports it. The
        # real run answers that as an unexpected failure, exit 1, naming the
        # exception; uncaught here, the dry run exited 1 with no reason
        # printed. The same sentence, so the operator reads one failure.
        # Redacted as the real run's handler is, with the values the prewarm
        # recorded on the error, which error_text reads off it; and logged
        # with its traceback first, as the real run logs it, so the one
        # printed sentence is not all there is to debug a crashing plugin.
        from automated_security_helper.utils.error_text import (
            error_text,
            log_unexpected_error,
        )
        from automated_security_helper.utils.log import ASH_LOGGER

        log_unexpected_error(ASH_LOGGER, exc)
        _fail_workspace(
            shown_on_one_line(
                f"Exiting due to exception during ASH workspace scan: {error_text(exc)}"
            ),
            code=WorkspaceExitCode.INTERNAL_ERROR,
        )
    # Line by line: a line can quote a path, whose newline is shown as
    # \x0a so the path stays on its line of the plan.
    for line in plan.render_lines():
        echo(shown_on_one_line(line))
    raise typer.Exit(WorkspaceExitCode.SUCCESS)


def run_ash_scan_cli_command(
    ctx: typer.Context,
    source_dir: Annotated[
        str | None,
        typer.Option(
            rich_help_panel="Scan",
            help="The source directory to scan",
            envvar="ASH_SOURCE_DIR",
            writable=False,
        ),
    ] = None,
    output_dir: Annotated[
        str | None,
        typer.Option(
            rich_help_panel="Reports",
            help="The directory to output results to",
            envvar="ASH_OUTPUT_DIR",
            writable=True,
        ),
    ] = None,
    scanners: Annotated[
        Optional[List[str]],
        typer.Option(
            rich_help_panel="Scan",
            help="Specific scanner names to run. Defaults to all scanners.",
            envvar="ASH_SCANNERS",
        ),
    ] = None,
    exclude_scanners: Annotated[
        Optional[List[str]],
        typer.Option(
            rich_help_panel="Scan",
            help="Specific scanner names to exclude from running. Takes precedence over scanners parameter.",
            envvar="ASH_EXCLUDED_SCANNERS",
        ),
    ] = None,
    ash_plugin_modules: Annotated[
        Optional[List[str]],
        typer.Option(
            rich_help_panel="Configuration and plugins",
            help="List of Python modules to import containing ASH plugins and/or event subscribers. These are loaded in addition to the default modules.",
            envvar="ASH_PLUGIN_MODULES",
        ),
    ] = None,
    config_overrides: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config-overrides",
            rich_help_panel="Configuration and plugins",
            help="Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2'). "
            "Supports lists with [item1,item2], append mode with key+=[value], and JSON syntax. See https://awslabs.github.io/automated-security-helper/latest/how-to/configure/",
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            rich_help_panel="Execution",
            help="Run scan in offline/airgapped mode. npm-audit does not run offline, because npm, yarn and pnpm audit by asking the registry: a project with a lockfile reports it MISSING, and one without reports it SKIPPED. IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage.",
        ),
    ] = False,
    sandbox: Annotated[
        Optional[SandboxMode],
        typer.Option(
            "--sandbox",
            rich_help_panel="Execution",
            help="Run every scanner subprocess in an OS-level sandbox: read-only source, writable results directory only, private home and temporary directory, no network unless the scanner needs one (never under --offline). 'auto' picks the best available (Linux: bwrap, firejail, landlock; macOS: sandbox-exec). A scanner whose sandbox cannot be set up is graded by the refusal: under 'auto' no working backend is a missing dependency and the scanner is reported MISSING; a named backend that is unavailable, or any other refusal (such as a results path that is a symlink), is reported ERROR. Overrides the config file's sandbox.mode; default off. Refused with --mode container (exit 5), which runs the scanners unsandboxed inside the container. See docs/content/docs/scanner-sandbox.md",
            case_sensitive=False,
        ),
    ] = None,
    offline_semgrep_rulesets: Annotated[
        str,
        typer.Option(
            "--offline-semgrep-rulesets",
            rich_help_panel="Execution",
            help="Specify Semgrep rulesets for use in ASH offline mode",
        ),
    ] = "p/ci",
    strategy: Annotated[
        ExecutionStrategy,
        typer.Option(
            rich_help_panel="Execution",
            help="Whether to run scanners in parallel or sequential",
        ),
    ] = ExecutionStrategy.PARALLEL.value,
    progress: Annotated[
        bool,
        typer.Option(
            "--progress/--no-progress",
            "-p/-P",
            rich_help_panel="Output and logging",
            help="Show progress of each job live in the console. Defaults to True.",
        ),
    ] = True,
    output_formats: Annotated[
        Optional[List[str]],
        typer.Option(
            "--output-formats",
            "--output-format",
            "--formats",
            "--format",
            "-f",
            rich_help_panel="Reports",
            help=(
                "The output formats to use (comma-separated). Available formats: "
                f"{', '.join(f.value for f in ExportFormat if f not in FORMATS_NO_REPORTER_WRITES and f not in AWS_PLUGIN_MODULE_FORMATS)}. "
                "With the AWS plugin module (ash_aws_plugins) in "
                "ash_plugin_modules, also, once enabled: "
                f"{', '.join(f.value for f in ExportFormat if f in AWS_PLUGIN_MODULE_FORMATS)}. "
                "Also accepted, though no reporter writes them: "
                f"{', '.join(f.value for f in ExportFormat if f in FORMATS_NO_REPORTER_WRITES)}."
            ),
        ),
    ] = None,
    cleanup: Annotated[
        bool,
        typer.Option(
            rich_help_panel="Execution",
            help="Clean up 'converted' directory and other temporary files after scan completes. Defaults to False. Note: Scans will always clean up existing files in the output directory before a new scan starts. This parameter only affects the cleanup of the temporary work directory after a scan has completed, typically for inspection of temporary artifacts.",
        ),
    ] = False,
    phases: Annotated[
        Optional[List[ExecutionPhase]],
        typer.Option(
            rich_help_panel="Execution",
            help="The phases to run. Defaults to all phases except inspect.",
        ),
    ] = None,
    inspect: Annotated[
        bool,
        typer.Option(
            rich_help_panel="Reports",
            help="Enable inspection of SARIF fields after running. This adds the inspect phase to the execution.",
        ),
    ] = False,
    use_existing: Annotated[
        bool,
        typer.Option(
            rich_help_panel="Reports",
            help="Use an existing ash_aggregated_results.json file in the output-dir. If True, the scan phase will be skipped and reports will be generated from this file.",
        ),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Prints version number",
        ),
    ] = False,
    mode: Annotated[
        Optional[RunMode],
        typer.Option(
            rich_help_panel="Scan",
            help=(
                "Execution mode preset. 'local' (default) runs the scan in this "
                "process with the scanner tools installed on this machine. "
                "'precommit' is a local scan that runs only "
                f"{', '.join(PRECOMMIT_MODE_SCANNERS)}, plus any --scanners, with "
                "simplified output and no progress display; in workspace mode it "
                "changes only the output. 'container' builds the ASH container "
                "image and runs the scan inside it. 'nix' runs the scan inside "
                "`nix develop`, whose shell supplies pinned scanner versions, and "
                "always offline."
            ),
            envvar="ASH_MODE",
        ),
    ] = RunMode.local,
    python_based_plugins_only: Annotated[
        bool,
        typer.Option(
            "--python-only/--full",
            "--python-based-scanners-only/--all-enabled-scanners",
            "--python-based-plugins-only/--all-enabled-plugins",
            rich_help_panel="Execution",
            help="Exclude execution of any plugins or tools that have depencies external to Python.",
        ),
    ] = False,
    show_summary: Annotated[
        bool,
        typer.Option(
            rich_help_panel="Reports", help="Show metrics table and results summary"
        ),
    ] = True,
    quiet: Annotated[
        bool,
        typer.Option(rich_help_panel="Output and logging", help="Hide all log output"),
    ] = False,
    log_level: Annotated[
        AshLogLevel,
        typer.Option(
            "--log-level",
            rich_help_panel="Output and logging",
            help="Set the log level.",
        ),
    ] = AshLogLevel.INFO,
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            rich_help_panel="Scan",
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_SOURCES_DESCRIPTION}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            rich_help_panel="Output and logging",
            help="Enable verbose logging. Any log flag on the command line overrides ASH_VERBOSE.",
            envvar="ASH_VERBOSE",
        ),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option(
            "--debug",
            "-d",
            rich_help_panel="Output and logging",
            help="Enable debug logging. Any log flag on the command line overrides ASH_DEBUG.",
            envvar="ASH_DEBUG",
        ),
    ] = False,
    color: Annotated[
        bool,
        typer.Option(
            rich_help_panel="Output and logging", help="Enable/disable colorized output"
        ),
    ] = True,
    fail_on_findings: Annotated[
        bool | None,
        typer.Option(
            rich_help_panel="Exit policy",
            help="Enable/disable throwing non-successful exit codes if any actionable findings are found. Defaults to unset, which prefers the configuration value. If this is set directly, it takes precedence over the configuration value.",
        ),
    ] = None,
    fail_on_incomplete_scanners: Annotated[
        bool | None,
        typer.Option(
            rich_help_panel="Exit policy",
            help=(
                "Exit 1 when a selected scanner did not complete -- ERROR (ran and "
                "failed) or MISSING (dependencies unavailable, so it never ran). "
                "On by default: under --no-fail-on-incomplete-scanners, a run where "
                "nothing ran exits 0, the same code as a clean scan, because no "
                "scanner produced any finding. A SKIPPED scanner, one you did not "
                "select or one with nothing of its kind "
                "to scan, does not trip it by itself, so --scanners and "
                "--exclude-scanners both narrow what is gated; but a run in which "
                "every scanner is SKIPPED, such as one where no selected scanner "
                "had a file to scan, exits 1. "
                "Independent of --fail-on-findings, and takes precedence over it "
                "when both would fail: a partial scan's findings are real but its "
                "clean bill of health is not. Defaults to unset, which prefers the "
                "configuration value and then on. Pass "
                "--no-fail-on-incomplete-scanners to accept a partial scan's exit "
                "code, or --exclude-scanners for a tool you do not have, which "
                "records it SKIPPED and says so in the report."
            ),
        ),
    ] = None,
    allow_stale_content_db: Annotated[
        bool | None,
        typer.Option(
            rich_help_panel="Exit policy",
            help=(
                "Let the scan pass when a scanner's content database (grype's or "
                "trivy's vulnerability database, the offline semgrep/opengrep "
                "rulesets) is older than its declared bound -- for grype, "
                f"{go_duration(get_content_database('grype-db').max_age)} after the "
                "database was built. Without it such a scan exits 1, except for "
                "trivy's database in an image built with OFFLINE=YES, which warns by "
                "default. With it the scan proceeds and the warning is recorded in the "
                "log and in the reports. --no-allow-stale-content-db forces the "
                "failure, for that database too. "
                "Defaults to unset, which prefers the `content_db_staleness` config "
                "value and then 'fail'; either form of the flag takes precedence over "
                "the config."
            ),
        ),
    ] = None,
    simple: Annotated[
        bool,
        typer.Option(
            rich_help_panel="Output and logging",
            help="Simplified output mode with minimal logging",
        ),
    ] = False,
    ignore_suppressions: Annotated[
        bool,
        typer.Option(
            rich_help_panel="Exit policy",
            help="Ignore all suppression rules and report all findings regardless of suppression status.",
        ),
    ] = False,
    honor_ignore_files: Annotated[
        bool | None,
        typer.Option(
            help=(
                "Whether the .gitignore and .ignore files in the scanned tree decide "
                "which files are left out of ASH's scan set (the files "
                "detect-secrets, cfn-nag, cdk-nag, cfn-lint, cfn-guard, actionlint, "
                "zizmor, npm-audit and the converters read). --no-honor-ignore-files scans the files they match too; "
                "ASH's own exclusions such as .git still apply. Defaults to unset, "
                "which prefers the operator's `honor_ignore_files` config value and "
                "then honoring them. Either form takes precedence over the config. "
                "A config file inside the scanned tree cannot set it. The results "
                "and summaries record whether the ignore files were honored and how "
                "many files they excluded."
            )
        ),
    ] = None,
    min_severity: Annotated[
        MinSeverity,
        typer.Option(
            rich_help_panel="Exit policy",
            help="Minimum severity to trigger non-zero exit code (critical, high, medium, low, none). 'critical' and 'high' are equivalent because SARIF does not distinguish them. Findings below this threshold are still reported but don't affect the exit code.",
            case_sensitive=False,
        ),
    ] = MinSeverity.LOW,
    compact_report: Annotated[
        bool,
        typer.Option(
            "--compact-report",
            rich_help_panel="Reports",
            help="Produce a shorter markdown report suitable for PR comments. Omits the severity legend, scan metadata, footer, and rows for scanners that were skipped or had zero findings.",
        ),
    ] = False,
    changed_files_only: Annotated[
        bool,
        typer.Option(
            "--changed-files-only",
            rich_help_panel="CI and sharding",
            help="Report only findings in files changed between --base-ref and HEAD, for example on a pull request. Scanners still scan every file; findings located in other files are dropped from every report, the summary counts and the exit code. Findings with no file location are kept. When git cannot list the changes, everything is reported; when nothing changed inside --source-dir, nothing is. Not supported with --mode container, which refuses it (exit 5).",
            envvar="ASH_CHANGED_FILES_ONLY",
        ),
    ] = False,
    base_ref: Annotated[
        str,
        typer.Option(
            "--base-ref",
            rich_help_panel="CI and sharding",
            help="Git ref to diff against when --changed-files-only is set.",
            envvar="ASH_BASE_REF",
        ),
    ] = "origin/main",
    allow_in_tree_tools: Annotated[
        bool,
        typer.Option(
            "--allow-in-tree-tools",
            help="Let ASH start scanners and other tools found inside the scanned directory, such as an activated in-repo .venv/bin or node_modules/.bin. Off by default: a tool inside the scanned directory is treated as missing. Only this flag (also the allow_in_tree_tools key of --cli-json-input) and the ASH_ALLOW_IN_TREE_TOOLS environment variable (1, true, yes or on) turn it on, never a config file, and `ash mcp` never does.",
        ),
    ] = False,
    shard_index: Annotated[
        Optional[int],
        typer.Option(
            "--shard-index",
            rich_help_panel="CI and sharding",
            help="Zero-based index of this shard when one scan is split across several executors. Requires --shard-count. A 3-way split uses indices 0, 1 and 2. Each shard runs a disjoint subset of the scanners and records which ones in its results; recombine them with 'ash merge'.",
            envvar="ASH_SHARD_INDEX",
        ),
    ] = None,
    shard_count: Annotated[
        Optional[int],
        typer.Option(
            "--shard-count",
            rich_help_panel="CI and sharding",
            help="Total number of shards this scan is split across. Requires --shard-index. Balance is by scanner count rather than scanner cost, so counts above about four buy little: wall clock is bounded by the slowest single scanner.",
            envvar="ASH_SHARD_COUNT",
        ),
    ] = None,
    config_from_scanned_repository: Annotated[
        bool,
        typer.Option(
            "--config-from-scanned-repository",
            hidden=True,
            help="Apply the limits ASH puts on a repository-written config file to the --config file and every file it extends, wherever they are. Container mode passes this to the scan inside the container when the config is a file the scanned repository wrote (judged by its resolved path and by the name that reached it) but outside --source-dir, where that scan cannot see it. In a workspace scan it marks the --config file that is layered over every project's own config and used alone by a project without one, from planning on.",
        ),
    ] = False,
    config_file_from_scanned_repository: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config-file-from-scanned-repository",
            hidden=True,
            help="Apply the limits ASH puts on a repository-written config file to this one file of the extends chain of the --config file or of the file ASH_CONFIG names. Container mode passes it, once per file, for each file of those chains the scanned repository wrote; the bases of a --config whose whole chain carries --config-from-scanned-repository are passed individually as well, so a mounted base judged on its own is still a marked file. Refused for a file that is in neither chain.",
        ),
    ] = None,
    config_file_from_another_checkout: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config-file-from-another-checkout",
            hidden=True,
            help="Apply the limits ASH puts on a config file inside a git checkout other than the scanned one to this one file of the extends chain of the --config file or of the file ASH_CONFIG names. The file cannot grant, and still sets what only restricts, as it does on the host: a lowered archive extraction limit, a scanner option that sends no usage data, and a network_scanners list as a limit. Container mode passes it, once per file, for each file of those chains that is in such a checkout, by its path inside the container, where the scan inside cannot see the checkout. Refused for a file that is in neither chain.",
        ),
    ] = None,
    ash_config_from_host: Annotated[
        Optional[str],
        typer.Option(
            "--ash-config-from-host",
            hidden=True,
            help="Read this file as the file ASH_CONFIG names, for the whole command. Container mode passes it to the scan inside the container, with the path there of the file the host's ASH_CONFIG names, which a local scan reads as its base whatever names the config. Not --config, whose environment variable ASH_CONFIG is.",
        ),
    ] = None,
    ### WORKSPACE-RELATED OPTIONS
    workspace: Annotated[
        str | None,
        typer.Option(
            "--workspace",
            rich_help_panel="Workspace",
            help="Path to a '.code-workspace' file whose folders are scanned as separate, independently-scoped projects. Pass 'auto' to use the single '*.code-workspace' file in the current directory. Mutually exclusive with --source-dir.",
            envvar="ASH_WORKSPACE",
        ),
    ] = None,
    workspace_config: Annotated[
        str | None,
        typer.Option(
            "--workspace-config",
            rich_help_panel="Workspace",
            help="Path to the workspace policy file (severity ceiling, workspace-wide suppressions and ignore paths, additional scanners). Without this, ASH looks for 'ash-workspace.{yaml,yml,json}' in the workspace root or its '.ash' directory; finding none is not an error. Must not be any project's own ASH config: workspace policy governs every project, so reading one project's config as policy would apply its settings to its siblings.",
            envvar="ASH_WORKSPACE_CONFIG",
        ),
    ] = None,
    allow_missing_projects: Annotated[
        bool,
        typer.Option(
            "--allow-missing-projects",
            rich_help_panel="Workspace",
            help="In workspace mode, skip project folders that are absent or unreadable instead of failing. Skipped projects are recorded in the plan. Without this, a missing project fails the whole workspace, so a typo or an un-cloned repository cannot pass as a clean scan.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            rich_help_panel="Workspace",
            help="In workspace mode, print the resolved execution plan and exit without scanning anything.",
        ),
    ] = False,
    ### CONTAINER-RELATED OPTIONS
    build: Annotated[
        bool,
        typer.Option(
            "--build/--no-build",
            "-b/-B",
            rich_help_panel="Container",
            help="Whether to build the ASH container image",
        ),
    ] = True,
    run: Annotated[
        bool,
        typer.Option(
            "--run/--no-run",
            "-r/-R",
            rich_help_panel="Container",
            help="Whether to run the ASH container image",
        ),
    ] = True,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            rich_help_panel="Container",
            help="Force rebuild of the ASH container image",
        ),
    ] = False,
    oci_runner: Annotated[
        Optional[str],
        typer.Option(
            "--oci-runner",
            "--oci",
            "--runner",
            "-o",
            rich_help_panel="Container",
            help="Use the specified OCI runner instead of docker to run the containerized tools",
            envvar="OCI_RUNNER",
        ),
    ] = None,
    build_target: Annotated[
        BuildTarget | None,
        typer.Option(
            "--build-target",
            rich_help_panel="Container",
            help="The ASH image stage to build and run: 'non-root' (an unprivileged user, the default) or 'ci' (root, the default on Windows). CI environment variables do not change it; --custom-containerfile builds on 'ci'.",
            case_sensitive=False,
        ),
    ] = None,
    container_uid: Annotated[
        Optional[str],
        typer.Option(
            "--container-uid",
            "-u",
            rich_help_panel="Container",
            help="UID to use for the container user",
        ),
    ] = None,
    container_gid: Annotated[
        Optional[str],
        typer.Option(
            "--container-gid",
            "-g",
            rich_help_panel="Container",
            help="GID to use for the container user",
        ),
    ] = None,
    ash_revision_to_install: Annotated[
        str | None,
        typer.Option(
            rich_help_panel="Container",
            help="ASH branch, tag or full commit id to install in the container image for usage during containerized scans",
        ),
    ] = None,
    custom_containerfile: Annotated[
        str | None,
        typer.Option(
            rich_help_panel="Container",
            help="Path to a custom container definition (e.g. Dockerfile) that you would like to build *after* the ASH container image builds. This is typically used when building a custom container image for ASH and including custom tooling that ASH does not come with by default. The fully qualified image name for the ASH image is passed in as the `ASH_BASE_IMAGE` build-arg so you can use it as a base. IMPORTANT: When a custom_containerfile path is provided, the build-target is set to `ci` so the container run-as configuration is not shifted to the non-root user. If you are using this parameter, you are responsible for securing your final container as appropriate.",
        ),
    ] = None,
    custom_build_arg: Annotated[
        Optional[List[str]],
        typer.Option(
            rich_help_panel="Container",
            help="Custom build arguments to pass to the container build",
        ),
    ] = None,
):
    """Scan code, infrastructure, secrets, and dependencies.

    Start with: ash --mode container --source-dir .

    Review the result with: ash inspect findings

    Options are grouped by workflow below. Running ash without a subcommand starts a scan.
    """
    # Skip if this is tab completion or if a subcommand was invoked
    # When invoked_subcommand is not None, it means we're in the callback and a subcommand
    # (like 'scan') will handle the actual execution with the correct arguments
    if ctx.resilient_parsing or ctx.invoked_subcommand is not None:
        return

    if version:
        echo(f"awslabs/automated-security-helper v{get_ash_version()}")
        raise typer.Exit

    # envvar= above documents ASH_VERBOSE/ASH_DEBUG in --help, but click would
    # also let the variable set the flag outright, so ASH_DEBUG=true would beat
    # an explicit --quiet or --log-level. A value that came from the environment
    # is dropped here and run_ash_scan reads the variable itself, below every
    # CLI flag -- one precedence rule for the CLI, MCP and library callers alike.
    #
    # Compared by name: typer vendors its own click, so click.core.ParameterSource
    # is a different enum from the one this context returns.
    if _from_environment(ctx, "verbose"):
        verbose = False
    if _from_environment(ctx, "debug"):
        debug = False

    # --mode precommit asks for minimal output without naming a log flag, and
    # --log-level SIMPLE spells simple as a level, so both are folded into the
    # one simple value here, before anything reads it: the gate below and the
    # run_ash_scan call receive the same flags, or a pre-commit run's gate
    # would sit at INFO while the scan's console sat at ERROR.
    precommit_mode = mode == RunMode.precommit or str(mode).lower() == "precommit"
    simple = (
        simple
        or precommit_mode
        or log_level == AshLogLevel.SIMPLE
        or str(log_level).lower() == "simple"
    )

    # The process-wide last-resort gate, set once at the command's start: the
    # level the one precedence rule resolves from the flags the scan receives.
    # A name logging does not know would fall back to ASH_LOG_LEVEL (WARNING
    # by default), though none arises here: ERROR and INFO are stdlib names,
    # utils/log registers VERBOSE and TRACE at import, and QUIET/SIMPLE --
    # the pre-commit fold above included -- resolve to ERROR before the gate.
    # run_ash_scan never calls the gate itself: the MCP server hosts it
    # in-process for every hosted scan, and the server's own entry point
    # already set the gate.
    configure_last_resort_level(
        resolved_console_log_level(
            log_level=log_level,
            verbose=verbose,
            debug=debug,
            quiet=quiet,
            simple=simple,
        ).value
    )

    _validate_shard_options(shard_index, shard_count, workspace)
    _refuse_sandbox_in_container_mode(sandbox, mode)
    _refuse_changed_files_only_in_container_mode(
        changed_files_only,
        mode,
        from_environment=_from_environment(ctx, "changed_files_only"),
    )

    # Container mode's marks for the scan inside, which cannot see where the host
    # found the --config it mounted at /ash-config: --config-from-scanned-repository
    # for a --config the scanned repository wrote, with every file it extends, and
    # --config-file-from-scanned-repository for each file of the chain the
    # repository wrote, the bases of a chain-marked --config included, each listed
    # on its own; and --config-file-from-another-checkout for each file of either
    # chain that is in a git checkout other than the scanned one, which is not the
    # scanned tree's but is not the operator's either. Every scan holds them,
    # one-directory and workspace alike, for the whole command, from planning on
    # (sandbox_grants.marked_repository_written, marked_files_repository_written,
    # marked_files_in_another_checkout).
    # None is resolve_config's untrusted_config, which is for a file an MCP
    # client delivered and holds it to the client's rules. The scan inside runs in
    # local mode with a --config; any other scan cannot apply them, so they are a
    # usage error with exit 3 rather than run_ash_scan's ValueError.
    #
    # --ash-config-from-host is the file the host's ASH_CONFIG names, mounted at
    # /ash-env-config: set as ASH_CONFIG here, after click has read --config, so
    # it is the base the scan reads (default_config.get_default_config), as on the
    # host, and not the --config it would be as the option's environment variable.
    # A file of its chain the host counts as repository-written comes marked with
    # --config-file-from-scanned-repository, and one in another checkout with
    # --config-file-from-another-checkout.
    marked_files = list(config_file_from_scanned_repository or [])
    elsewhere_files = list(config_file_from_another_checkout or [])
    if (
        config_from_scanned_repository
        or marked_files
        or elsewhere_files
        or ash_config_from_host
    ):
        if (mode or RunMode.local) != RunMode.local:
            _fail_config_mark(
                "--config-from-scanned-repository, "
                "--config-file-from-scanned-repository, "
                "--config-file-from-another-checkout and --ash-config-from-host "
                "are passed by container mode to the scan inside the container and "
                "apply only to a scan in local mode. Leave them out: container mode "
                "decides them on the host."
            )
        from automated_security_helper.config.sandbox_grants import (
            marked_files_in_another_checkout,
            marked_files_repository_written,
            marked_repository_written,
        )
        from automated_security_helper.utils.process_env import environ_overrides

        marks = contextlib.ExitStack()
        ctx.call_on_close(marks.close)
        if ash_config_from_host is not None:
            marks.enter_context(environ_overrides({"ASH_CONFIG": ash_config_from_host}))
        chains = [Path(path) for path in (config, ash_config_from_host) if path]
        if (
            config_from_scanned_repository or marked_files or elsewhere_files
        ) and not chains:
            _fail_config_mark(
                "--config-from-scanned-repository, "
                "--config-file-from-scanned-repository and "
                "--config-file-from-another-checkout mark the --config file and the "
                "files it extends, and this scan has none. Leave them out: container "
                "mode decides them on the host."
            )
        if config_from_scanned_repository and config is None:
            _fail_config_mark(
                "--config-from-scanned-repository marks the --config file and every "
                "file it extends, and this scan has none. Leave it out: container "
                "mode decides it on the host."
            )
        # Each chain is read once for both file marks, and one refusal names every
        # option that names a file outside them.
        if marked_files or elsewhere_files:
            chain_files = _chain_files(chains)
            if chain_files is not None:
                outside = _marks_outside_the_chain(
                    chain_files,
                    [
                        ("--config-file-from-scanned-repository", marked_files),
                        ("--config-file-from-another-checkout", elsewhere_files),
                    ],
                )
                if outside:
                    _fail_config_mark(" ".join(outside))
        if config_from_scanned_repository and config is not None:
            marks.enter_context(marked_repository_written(Path(config)))
        if marked_files:
            marks.enter_context(
                marked_files_repository_written(Path(path) for path in marked_files)
            )
        if elsewhere_files:
            marks.enter_context(
                marked_files_in_another_checkout(Path(path) for path in elsewhere_files)
            )

    # Through the environment rather than a parameter, so that every lookup in this
    # process and in the processes it starts (the cdk-nag worker, a container, a
    # nix shell) sees the same answer; see utils/subprocess_utils.in_tree_tools_allowed.
    if allow_in_tree_tools:
        from automated_security_helper.utils.process_env import (
            apply_environ_overrides,
        )
        from automated_security_helper.utils.subprocess_utils import (
            ALLOW_IN_TREE_TOOLS_ENV,
        )

        apply_environ_overrides({ALLOW_IN_TREE_TOOLS_ENV: "1"})

    # With --changed-files-only the base ref goes to `git diff`, so it is refused
    # here, before any git process starts, when git could read it as anything but
    # a revision. Without the flag no diff runs and the value is not used.
    if changed_files_only:
        try:
            validate_base_ref(base_ref)
        except InvalidBaseRefError as exc:
            _fail_usage(f"{exc} The value comes from --base-ref or ASH_BASE_REF.")

    # Workspace mode is handled before any cwd-based default is applied, because
    # --workspace and --source-dir are mutually exclusive and defaulting
    # source_dir first would make every invocation look like it had both.
    if workspace is None and (
        dry_run or allow_missing_projects or workspace_config is not None
    ):
        # None of these flags mean anything outside workspace mode. Silently
        # ignoring --dry-run would run a full scan for someone who asked for
        # none; silently ignoring --workspace-config would scan with no policy
        # for someone who believes a severity ceiling is in force. The policy
        # file is the one option here with an environment variable, so the
        # refusal names the source the value came from, which click records
        # (_from_environment): with ASH_WORKSPACE_CONFIG exported, every scan
        # outside workspace mode was refused for a flag the command line did
        # not carry, and naming both sources at once told the operator who
        # passed the flag to look for a variable that was not set.
        policy_from_environment = _from_environment(ctx, "workspace_config")
        offending = [
            flag
            for flag, given in (
                ("--dry-run", dry_run),
                ("--allow-missing-projects", allow_missing_projects),
                (
                    "ASH_WORKSPACE_CONFIG in the environment",
                    workspace_config is not None and policy_from_environment,
                ),
                (
                    "--workspace-config",
                    workspace_config is not None and not policy_from_environment,
                ),
            )
            if given
        ]
        _fail_workspace(
            f"{' and '.join(offending)} only applies in workspace mode; pass "
            f"'--workspace <file>' or '--workspace auto' as well."
        )

    # Built HERE, above the workspace block, rather than with the other
    # None-to-empty normalisations below. Workspace resolution needs the COMPLETE
    # override list, because a threshold override changes what each project
    # declares and therefore what --dry-run must print. Normalising afterwards
    # would hand resolution an empty list and the plan would report a threshold
    # the scan does not enforce.
    #
    # --compact-report is why this is not just a None check: it synthesises an
    # override, so config_overrides is non-empty for an operator who never passed
    # --config-overrides. Leaving that below the workspace block would omit it
    # from the plan while the scan applied it.
    if config_overrides is None:
        config_overrides = []
    if compact_report:
        config_overrides.append("reporters.markdown.options.compact=true")
    # The same route as --compact-report, for the same reason and one more: as a config
    # override it reaches every mode unchanged -- local, nix, workspace, and the container,
    # which is handed config_overrides verbatim -- and overrides are applied after the
    # config file, which is what makes the flag win over `content_db_staleness` there.
    if allow_stale_content_db is not None:
        config_overrides.extend(
            content_db_staleness_flag_overrides(allow_stale=allow_stale_content_db)
        )

    # A config override for the same reasons as the two above: it reaches local, nix
    # and workspace runs unchanged and wins over the config file's sandbox.mode.
    if sandbox is not None:
        config_overrides.append(f"sandbox.mode={SandboxMode(sandbox).value}")

    # The same route again. As an override it is operator input, which a config
    # file inside the scanned tree cannot outvote (resolve_config's
    # confine_honor_ignore_files), and the container runs it unchanged.
    if honor_ignore_files is not None:
        config_overrides.append(
            f"honor_ignore_files={'true' if honor_ignore_files else 'false'}"
        )

    # Parsed above the workspace block, so a workspace dry run refuses a format the
    # real run refuses instead of exiting 0 for it. Comma-separated.
    if output_formats is None:
        output_formats = []
    parsed_output_formats = []
    for item in output_formats:
        for fmt in item.split(","):
            fmt = fmt.strip()
            if fmt:
                try:
                    parsed_output_formats.append(ExportFormat(fmt))
                except ValueError:
                    valid_formats = [f.value for f in ExportFormat]
                    raise typer.BadParameter(
                        f"'{fmt}' is not a valid format. Valid formats are: {', '.join(valid_formats)}"
                    )

    workspace_plan: WorkspacePlan | None = None
    if workspace is not None:
        workspace_plan = _handle_workspace_mode(
            workspace=workspace,
            source_dir=source_dir,
            allow_missing_projects=allow_missing_projects,
            workspace_config=workspace_config,
            config_overrides=tuple(config_overrides),
            config=config,
        )
        # The workspace root is the scan root: it is what container mode mounts at
        # /src, and what every workspace-relative finding path is relative to.
        # Individual projects get their own source_dir inside the executor.
        source_dir = workspace_plan.workspace_root

    # Rebind list defaults to fresh empty lists at call time so each CLI
    # invocation gets its own collection (typer will populate them if the
    # user supplies --scanners etc., but we guard against reusing aliases).
    if scanners is None:
        scanners = []
    if exclude_scanners is None:
        exclude_scanners = []
    if ash_plugin_modules is None:
        ash_plugin_modules = []
    # "a_ash_plugins, b_ash_plugins", from the flag or ASH_PLUGIN_MODULES, names two
    # modules, as the same entry does in a config file.
    from automated_security_helper.config.plugin_module_trust import (
        split_plugin_modules,
    )

    ash_plugin_modules = split_plugin_modules(ash_plugin_modules)
    # config_overrides and output_formats are normalised above the workspace
    # block; see the comments there for why neither can happen here.
    if phases is None:
        phases = [ExecutionPhase.CONVERT, ExecutionPhase.SCAN, ExecutionPhase.REPORT]
    if custom_build_arg is None:
        custom_build_arg = []

    # Resolve cwd-based defaults at call time (not import time).
    if source_dir is None:
        source_dir = Path.cwd().as_posix()
    # Refused before anything else uses it. A missing --source-dir used to run a
    # real scan of nothing -- every scanner finds no files -- and could exit 0,
    # which reads exactly like a clean scan of the directory the operator named.
    # The text is the one every surface gives (utils/directory_refusals.py), on one
    # line: a newline in the path made a line of its own, which could read as another
    # message.
    source_refusal = source_dir_refusal(source_dir)
    if source_refusal is not None:
        _fail_usage(shown_on_one_line(source_refusal))
    # The output directory's default, the collision adjustment, its refusals and
    # --use-existing, in one place for the real run and the workspace dry run.
    output_dir, existing_results = _settle_output_dir(
        source_dir, output_dir, use_existing, ignore_suppressions
    )
    if workspace_plan is not None and dry_run:
        # After the preflight above, in the real run's order, so the dry run
        # refuses what the run refuses and names the same first problem.
        _exit_with_workspace_dry_run(
            workspace_plan,
            scanners=tuple(scanners),
            exclude_scanners=tuple(exclude_scanners),
            ash_plugin_modules=tuple(ash_plugin_modules),
        )

    # Apply mode presets if specified (precommit_mode is folded into simple
    # above, before the last-resort gate is set)
    if precommit_mode:
        print(
            "[green]-------------- Running ASH in pre-commit mode with minimal output --------------[/green]"
        )

    cli_final_show_progress = (
        progress
        and not verbose
        and not precommit_mode
        and os.environ.get("CI", None) is None
        and os.environ.get("ASH_IN_CONTAINER", "NO").upper()
        not in [
            "YES",
            "1",
            "TRUE",
        ]
    )

    # --compact-report is translated into its config override above the workspace
    # block, so that workspace resolution sees it. Appending here as well would
    # apply it twice.

    # The output formats were parsed above the workspace block
    # (parsed_output_formats).

    # Call run_ash_scan with all parameters, as a scan the entry point's SIGTERM
    # handler cancels (core/cancellation.py, "SIGTERM on the CLI"). The scope is
    # entered here and not inside run_ash_scan because the MCP runner calls
    # run_ash_scan inside a scope of its own, whose event its registry stops; a
    # scope installed below the shared frame would shadow it.
    cancel_event = CancelEvent()
    try:
        with shutdown_cancels(cancel_event), cancel_scope(cancel_event):
            run_ash_scan(
                source_dir=source_dir,
                output_dir=output_dir,
                config=config,
                config_overrides=config_overrides,
                offline=offline,
                strategy=strategy,
                scanners=scanners,
                exclude_scanners=exclude_scanners,
                progress=cli_final_show_progress,
                output_formats=parsed_output_formats,
                cleanup=cleanup,
                phases=phases,
                inspect=inspect,
                existing_results=existing_results,
                python_based_plugins_only=python_based_plugins_only,
                log_level=log_level,
                quiet=quiet,
                verbose=verbose,
                debug=debug,
                color=color,
                fail_on_findings=fail_on_findings,
                fail_on_incomplete_scanners=fail_on_incomplete_scanners,
                ignore_suppressions=ignore_suppressions,
                min_severity=MinSeverity(min_severity).value,
                changed_files_only=changed_files_only,
                base_ref=base_ref,
                shard_index=shard_index,
                shard_count=shard_count,
                mode=mode or RunMode.local,
                show_summary=show_summary,
                simple=simple,
                # Pass the ash_plugin_modules parameter
                ash_plugin_modules=ash_plugin_modules,
                # Container-specific params
                build=build,
                run=run,
                force=force,
                oci_runner=oci_runner,
                build_target=build_target,
                offline_semgrep_rulesets=offline_semgrep_rulesets,
                container_uid=container_uid,
                container_gid=container_gid,
                ash_revision_to_install=ash_revision_to_install,
                custom_containerfile=custom_containerfile,
                custom_build_arg=custom_build_arg,
                workspace_plan=workspace_plan,
                allow_missing_projects=allow_missing_projects,
                workspace_config_as_named=workspace_config,
            )
    except KeyboardInterrupt:
        # Ctrl-C, in every mode. A container runtime has been passed the interrupt and
        # given its grace to stop (run_cmd_direct), and the scan printed no completion
        # line and no results table, so this is the only word on how the run ended.
        # The interrupt landed in ONE frame; a workspace pool's project events chain
        # to this scan-wide one (link_parent) and a cancellable spawn still running
        # in another thread polls it, so cancel it before exiting or those keep
        # running a scan the operator stopped. This is a normal thread frame, so the
        # real set calls are safe here where the signal handler's are not.
        cancel_event.stop_promptly = True
        cancel_event.set()
        echo(
            "ASH scan interrupted before it finished: there is no verdict, and the "
            "output directory may hold partial results.",
            err=True,
        )
        raise typer.Exit(ASH_EXIT_INTERRUPTED) from None
    except ScanCancelled as error:
        if not shutdown_requested():
            # Not this frame's stop: nothing on the CLI sets the scan's event but
            # the SIGTERM handler, so an unexplained cancel is a defect to report
            # as one, not to dress up as a shutdown.
            raise
        # The handler printed nothing (a signal frame must not take the logger's
        # locks), so this is the only word on how the run ended. The executors'
        # stop path has already run on the way up here.
        message = (
            "ASH scan stopped by SIGTERM before it finished: there is no verdict, "
            "and the output directory may hold partial results."
        )
        survivors = getattr(error, "could_not_stop", ())
        if survivors:
            # The stop path recorded each kill that did not end its tool, as
            # data on the cancel (ScanCancelled.could_not_stop), and this
            # line is all the operator reads: without it the ending reads as
            # a clean stop and the surviving tools go unlooked-for. Named by
            # shown argv0 and pid, so the operator knows what to look for.
            names = "; ".join(f"{tool} (pid {pid})" for tool, pid in survivors)
            message += f" A tool the stop could not end may still be running: {names}."
        echo(message, err=True)
        raise typer.Exit(ASH_EXIT_TERMINATED) from None
