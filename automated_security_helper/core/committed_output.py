# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Stopping a run that would delete or overwrite a file git tracks in its output.

Why this exists
---------------
A scan deletes the previous run's output in its output directory and writes its
own there (``utils/scan_output_dirs.committed_files_at_results_paths`` lists those
paths). A file a repository committed to one of them, with the default output
directory ``.ash/ash_output``, would be deleted or overwritten by every scan, so
a run that would do that refuses before it changes anything, with exit 3 and a
message naming the files (:func:`committed_output_files_error`).

Code that runs before the orchestrator can delete or write first, so every entry
point checks before its own first write:

* the CLI (``run_ash_scan``), before its logger truncates ``ash.log`` and before
  container and Nix mode clear the output directory, the previous results an MCP
  scan set aside included, on the host. In container mode the inner scan cannot
  ask the host's git at all, so the host checks everything the container writes;
* the MCP scan tools, before a scan is started and before ``clean_output`` sets
  the previous results aside (core/previous_results.py), which moves them; the
  MCP workspace tool, before it sets each project's aside;
* ``ASHScanOrchestrator.initialize``, for a caller that reaches it directly,
  before it sets the previous results aside or removes a held set.

What a run writes
-----------------
A scan starting fresh deletes and writes every results path. A report over
existing results (``--use-existing``) writes fewer
(:func:`report_over_existing_results_writes`). A workspace scan writes the
unified results file and ``reports/`` at the root of its output directory
(:data:`WORKSPACE_ROOT_FILES`, :data:`WORKSPACE_ROOT_DIRECTORIES`), spools each
project's run under :data:`WORKSPACE_SPOOL_DIR_NAME` there and removes it, and
scans each project into ``projects/<key>/`` as a fresh scan
(:func:`committed_entries_in_a_workspace_output`). A container-mode run that only
builds the image writes the log files alone. The CLI's logger writes the log
files in every one of them. Each run is refused only for committed entries where
it writes, so that a committed file it never touches does not stop it.

When git cannot answer
----------------------
When the output directory is in a repository and git could not list its index
(git is not installed, it timed out, or it exited with an error: a corrupt
index, a ``.git`` file naming a directory that is not there, a repository format
it does not read), nothing tells a committed file there from a previous run's.
So whatever is on disk where the run writes refuses the run, with exit 3
(:class:`UnverifiedOutputFilesError`): the message names the entries, git's
error, and the two ways out, letting git read the repository or removing the old
results. Nothing on disk there, nothing could be lost, and the run goes on. The
ownership check git applies to a repository it finds by itself
(``safe.directory``) is not among the causes: the repository is named on git's
command line, and git does not check the owner of one named that way.

Known limitations: outside a git checkout nothing is refused. In a repository
git cannot read, a run is refused whenever its output paths hold anything,
including a report over existing results, since the results file it reads is
one of them. A file committed between the check and the write is not seen.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Collection, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import CommittedOutputFilesError
from automated_security_helper.utils.inner_run_outcome import INNER_RUN_OUTCOME_FILE
from automated_security_helper.utils.scan_output_dirs import (
    RESULTS_FILE_NAME,
    SCAN_SET_RUN_FILE_NAME,
    SCAN_START_FILE_NAMES,
    GitIndexAnswer,
    GitIndexUnavailable,
    _an_enclosing_repository_tracks_the_root,
    _repository_root_of,
    _where_git_is_asked,
    entries_at_results_paths,
    entries_on_disk,
    git_index_below,
    output_name_key,
    results_path_names,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line

#: The log files the CLI's logger writes in the output directory
#: (``utils/log.get_logger``): truncated when a scan starts, appended to by a
#: report over existing results. ``committed_files_at_results_paths`` counts them
#: among the results paths.
LOG_FILE_NAMES: Tuple[str, ...] = ("ash.log", "ash.log.jsonl")

#: The files at the root of the output directory that a scan starting fresh removes
#: before it writes its own: ``ASHScanOrchestrator.initialize`` locally, and
#: ``run_ash_scan._discard_prior_run_artifacts`` on the host before container and Nix
#: mode start. The inner run's outcome record (``utils/inner_run_outcome.py``) is
#: one of them: both removed it, but it was listed by neither this tuple nor
#: ``scan_output_dirs.results_path_names``, so a committed one was deleted by every
#: fresh scan without the refusal below (:func:`_found_in_the_way` covers the
#: difference between the two lists).
PREVIOUS_RUN_FILE_NAMES: Tuple[str, ...] = (
    RESULTS_FILE_NAME,
    *SCAN_START_FILE_NAMES,
    SCAN_SET_RUN_FILE_NAME,
    INNER_RUN_OUTCOME_FILE,
)

#: What a workspace scan writes at the root of its output directory, besides the
#: CLI's log files: the unified results file and the workspace reports.
WORKSPACE_ROOT_FILES: Tuple[str, ...] = (RESULTS_FILE_NAME,)
WORKSPACE_ROOT_DIRECTORIES: Tuple[str, ...] = ("reports",)

#: Where a workspace scan writes each project's output, ``projects/<key>/``,
#: under the workspace's output directory. The same spelling as
#: ``workspace/execution.PROJECTS_DIR_NAME`` and ``workspace/reporting
#: .PROJECTS_DIR_NAME``, repeated here rather than imported: those modules
#: import the orchestrator, which imports this one. A test holds the three equal.
#: Checked as an entry of its own (:func:`_found_tracked_entry`): the per-project
#: checks look inside each project's directory, and the per-project orchestrators
#: refuse a linked output directory of their own, but nothing looked at
#: ``projects`` itself, so a committed link there let a workspace scan clear and
#: write every project's output through it.
WORKSPACE_PROJECTS_DIR_NAME = "projects"

#: Where a workspace scan spools each project's run, at the root of its output
#: directory, until it writes the unified results file; it then removes the
#: directory (workspace/aggregation.py). Not one of the results paths
#: ``committed_files_at_results_paths`` counts, so it is checked on its own
#: (:func:`committed_entries_under`).
WORKSPACE_SPOOL_DIR_NAME = ".workspace-spool"

#: How many committed entries the refusal names before it counts the rest.
NAMED_IN_THE_MESSAGE = 10

#: The exit code of a scan this check refuses, for committed files or for files
#: git cannot account for: a refused input (``ASH_EXIT_CODES``). The CLI exits
#: with it (``run_ash_scan._refuse_committed_output``), and the MCP scan tools
#: report it as ``exit_code``.
COMMITTED_OUTPUT_REFUSED_EXIT_CODE = 3


class UnverifiedOutputFilesError(CommittedOutputFilesError):
    """git could not say what is committed where a run writes, and files are there.

    A ``CommittedOutputFilesError``, so that every entry point refuses it as it
    refuses committed files: exit 3, labeled "Scan refused". *entries* are what
    is on disk where the run deletes or writes, absolute; *answer* is git's
    (``scan_output_dirs.GitIndexAnswer``), with the repository and git's error.
    """

    def __init__(
        self,
        message: str,
        *,
        entries: Sequence[Path] = (),
        answer: Optional[GitIndexAnswer] = None,
    ) -> None:
        super().__init__(message)
        self.entries = list(entries)
        self.answer = answer


def report_over_existing_results_writes(
    *, inspect: bool, cleanup: bool
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """The root files and the directories a report over existing results writes.

    The results file, which the CLI rewrites after the report phase, and the log
    files, appended to; ``reports/``; ``analysis/`` when the inspect phase runs;
    and the work directory, ``converted/``, which ``--cleanup`` removes when the
    run ends. A report over existing results (``--use-existing``) removes none of
    the previous run's files, clears no other working directory
    (``ASHScanOrchestrator.ensure_directories``) and neither sets the previous
    results aside nor removes a held set or its marker (core/previous_results.py),
    so a committed ``scanners/``, scan-set list or held set does not stop it.
    """
    directories = ["reports"]
    if inspect:
        directories.append("analysis")
    if cleanup:
        directories.append(ASH_WORK_DIR_NAME)
    return (RESULTS_FILE_NAME, *LOG_FILE_NAMES), tuple(directories)


class _Found(NamedTuple):
    """What one check found: committed entries, or, where git could not answer,
    the entries on disk and git's answer."""

    committed: List[Path]
    unverified: List[Path]
    answer: Optional[GitIndexAnswer]


def _absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


class _GitFailures:
    """What git has answered during one composite check.

    A workspace check asks git about the output root, the spool, the projects
    entry and every project's directory, each with a call of its own that may
    take :data:`scan_output_dirs.GIT_INDEX_TIMEOUT_SECONDS`. Once git has not
    answered for a repository, the next directory in it gets the same answer
    without another call, so a hung git costs one wait and not one per project.
    A directory in another repository (a nested checkout) is still asked.

    A listing git DID give is kept too, by the directory it was asked for: the
    root's spool check and its projects-entry check ask about the same
    directory, and asked git once each, so a workspace check ran ``git
    ls-files`` for the root three times and derived three answers from one
    listing. The second ask for a directory now reads the first's answer. Every
    check of a directory, the results-path check included, asks through
    :func:`_index_below`, so a directory costs one ``git ls-files`` however many
    checks read it.
    """

    def __init__(self) -> None:
        self._answers: dict[Path, GitIndexAnswer] = {}
        self._listed: dict[Path, GitIndexAnswer] = {}

    def remember(self, answer: GitIndexAnswer) -> None:
        if answer.unanswered and answer.repository is not None:
            self._answers.setdefault(answer.repository, answer)
        elif answer.names is not None:
            self._listed.setdefault(_absolute(answer.base), answer)

    def known_for(self, directory: str | Path) -> Optional[GitIndexAnswer]:
        """The answer remembered for *directory*: the listing git gave for it
        earlier in this check, else the failure remembered for the repository
        holding it, spelled for *directory*; None when neither."""
        if not self._answers and not self._listed:
            return None
        base = _absolute(directory)
        listed = self._listed.get(base)
        if listed is not None:
            return listed
        if not self._answers:
            return None
        # Path.is_dir lets a PermissionError through on CPython 3.10-3.12 when a
        # parent cannot be searched; a directory that cannot be looked up is
        # one git is not asked about (git_index_below answers it as not there),
        # so there is nothing remembered for it.
        try:
            is_dir = base.is_dir()
        except OSError:
            return None
        if not is_dir:
            return None
        # The repository is found where git_index_below finds it, from where
        # the directory really is and, for a directory that is itself a link,
        # from its parent: the root the failure was remembered under is that
        # one, and the resolved target of a link can lie in another repository
        # (or in none).
        asked, _tail = _where_git_is_asked(base)
        root = _repository_root_of(asked)
        remembered = self._answers.get(root) if root is not None else None
        if remembered is None:
            return None
        return GitIndexAnswer(
            base,
            repository=remembered.repository,
            error=remembered.error,
            could_not_run=remembered.could_not_run,
        )


def _index_below(
    directory: str | Path, failures: Optional[_GitFailures]
) -> GitIndexAnswer:
    """:func:`git_index_below`, answered from *failures* where git already failed."""
    if failures is not None:
        known = failures.known_for(directory)
        if known is not None:
            return known
    answer = git_index_below(directory)
    if failures is not None:
        failures.remember(answer)
    return answer


def _scoped(
    output_dir: str | Path,
    entries: Iterable[Path],
    files: Optional[Collection[str]],
    directories: Optional[Collection[str]],
) -> List[Path]:
    """The *entries* that are one of *files* at the root, or under one of
    *directories*; all of them when neither is given. Names are compared as
    ``scan_output_dirs.output_name_key`` says."""
    entries = list(entries)
    if files is None and directories is None:
        return entries
    base = _absolute(output_dir)
    root_files = {output_name_key(name) for name in files or ()}
    under = {output_name_key(name) for name in directories or ()}
    kept = []
    for path in entries:
        parts = path.relative_to(base).parts
        if not parts:
            # The output directory itself: what it holds could not be read.
            kept.append(path)
            continue
        first = output_name_key(parts[0])
        if (len(parts) == 1 and first in root_files) or first in under:
            kept.append(path)
    return kept


def _previous_run_files_outside_the_results_paths() -> Tuple[str, ...]:
    """The previous-run files a fresh scan removes that ``results_path_names`` does
    not list, compared as the filesystem compares names. Empty once the two
    lists agree; until then the fresh-scan check looks for these on its own."""
    root_files, _directories = results_path_names()
    listed = {output_name_key(name) for name in root_files}
    return tuple(
        name for name in PREVIOUS_RUN_FILE_NAMES if output_name_key(name) not in listed
    )


def _found_in_the_way(
    output_dir: str | Path,
    files: Optional[Collection[str]],
    directories: Optional[Collection[str]],
    not_on_disk: Collection[str],
    failures: Optional[_GitFailures] = None,
) -> _Found:
    # A fresh scan (neither files nor directories given) also removes the
    # previous-run files results_path_names does not list.
    unlisted = (
        _previous_run_files_outside_the_results_paths()
        if files is None and directories is None
        else ()
    )
    # One listing answers both questions below, the results paths and the
    # previous-run files outside them: asked separately they were two spawns of
    # ``git ls-files`` of the same directory, each allowed its own timeout. The
    # results paths are read from it as committed_files_at_results_paths reads
    # them from its own.
    answer = _index_below(output_dir, failures)
    unanswered: Optional[GitIndexAnswer] = None
    committed: List[Path] = []
    if answer.unanswered:
        unanswered = answer
    elif answer.names is not None:
        # The superproject question can fail the same way
        # committed_files_at_results_paths' own call fails (GitIndexUnavailable,
        # a listing the enclosing repository could not give), and is folded the
        # same way: the directory is unanswered, and what is on disk is
        # reported instead.
        try:
            root_tracked = (
                "" in answer.names or _an_enclosing_repository_tracks_the_root(answer)
            )
        except GitIndexUnavailable as unavailable:
            unanswered = unavailable.answer
            if failures is not None:
                failures.remember(unanswered)
        else:
            committed = entries_at_results_paths(answer.base, answer.names)
            if root_tracked:
                committed.insert(0, answer.base)
    if unanswered is not None:
        root_files, cleared = results_path_names()
        skipped = {output_name_key(name) for name in not_on_disk}
        base = _absolute(output_dir)
        on_disk = [
            path
            for path in entries_on_disk(output_dir, (*root_files, *unlisted), cleared)
            if not (path.parent == base and output_name_key(path.name) in skipped)
        ]
        return _Found([], _scoped(output_dir, on_disk, files, directories), unanswered)
    found = _Found(_scoped(output_dir, committed, files, directories), [], None)
    if unlisted:
        found = _combined([found, _entries_named(answer, unlisted)])
    return found


def _found_under(
    output_dir: str | Path,
    names: Collection[str],
    failures: Optional[_GitFailures] = None,
) -> _Found:
    answer = _index_below(output_dir, failures)
    if answer.unanswered:
        return _Found([], entries_on_disk(output_dir, (), names), answer)
    return _entries_named(answer, names)


def _entries_named(answer: GitIndexAnswer, names: Collection[str]) -> _Found:
    """The entries of git's listing *answer* that are, or are under, one of *names*
    at its directory's root. *answer* is one git gave: a directory outside a
    repository has no entries."""
    if answer.names is None:
        return _Found([], [], None)
    base = answer.base
    wanted = {output_name_key(name) for name in names}
    found = []
    for name in answer.names:
        path = Path(os.path.normpath(base.joinpath(*name.split("/"))))
        if path == base or not path.is_relative_to(base):
            continue
        if output_name_key(path.relative_to(base).parts[0]) in wanted:
            found.append(path)
    return _Found(sorted(found), [], None)


def _found_tracked_entry(
    output_dir: str | Path,
    name: str,
    failures: Optional[_GitFailures] = None,
) -> _Found:
    """Whether git tracks ``output_dir/<name>`` ITSELF, which for a directory name
    means a link (git tracks no directories). Nothing under it is counted here;
    :func:`_found_under` is for that. Where git could not answer and a link is on
    disk at the name, the link is the unverified entry."""
    answer = _index_below(output_dir, failures)
    path = _absolute(output_dir) / name
    if answer.unanswered:
        on_disk = [path] if os.path.islink(path) else []
        return _Found([], on_disk, answer)
    if answer.names is None:
        return _Found([], [], None)
    wanted = output_name_key(name)
    for entry in answer.names:
        parts = [part for part in entry.split("/") if part]
        if len(parts) == 1 and output_name_key(parts[0]) == wanted:
            return _Found([path], [], None)
    return _Found([], [], None)


def _combined(found: Iterable[_Found]) -> _Found:
    committed: List[Path] = []
    unverified: List[Path] = []
    answer: Optional[GitIndexAnswer] = None
    for item in found:
        committed.extend(item.committed)
        unverified.extend(item.unverified)
        # The answer the refusal quotes is git's for the entries it names. A check
        # that found nothing on disk carries an answer too (git could not list
        # its directory), and it may be another repository's.
        if answer is None and item.unverified:
            answer = item.answer
    return _Found(sorted(committed), sorted(unverified), answer)


def _settled(found: _Found, output_dir: str | Path) -> List[Path]:
    """The committed entries *found*; or, when there are none and git could not
    answer where entries are on disk, the refusal of those."""
    if found.committed:
        return found.committed
    if found.unverified:
        raise unverified_output_files_error(output_dir, found.unverified, found.answer)
    return []


def committed_entries_in_the_way(
    output_dir: str | Path,
    *,
    files: Optional[Collection[str]] = None,
    directories: Optional[Collection[str]] = None,
    not_on_disk: Collection[str] = (),
) -> List[Path]:
    """The entries git tracks where a run into *output_dir* writes, sorted.

    Every results path (``committed_files_at_results_paths``) when neither
    *files* nor *directories* is given. Otherwise only those among them that are
    one of *files* at the root of *output_dir*, or under one of *directories*
    there (the directory itself included, when git tracks it as a link).

    Raises :class:`UnverifiedOutputFilesError` when *output_dir* is in a
    repository git could not list and anything is on disk at those paths, scoped
    the same way. *not_on_disk* names root files that are then not counted: the
    orchestrator passes the log files, which the CLI's logger has opened by the
    time it runs, and which the CLI counted before opening them.
    """
    return _settled(
        _found_in_the_way(output_dir, files, directories, not_on_disk), output_dir
    )


def committed_entries_in_project_outputs(
    project_output_dirs: Iterable[str | Path],
) -> List[Path]:
    """Every committed results path in each workspace project's own directory.

    A workspace scans each project into ``projects/<key>/`` under its output
    directory as a scan starting fresh, so every results path there counts.
    Checked before the workspace starts, where its projects' own orchestrators
    would refuse one project at a time: the MCP workspace tool sets each
    project's previous results aside before any of them starts, and in container
    mode the inner orchestrators cannot ask the host's git. Raises
    :class:`UnverifiedOutputFilesError` as :func:`committed_entries_in_the_way`
    does, naming the entries of every project at once.
    """
    directories = list(project_output_dirs)
    if not directories:
        return []
    failures = _GitFailures()
    found = _combined(
        _found_in_the_way(directory, None, None, (), failures)
        for directory in directories
    )
    common = Path(
        os.path.commonpath([os.fspath(_absolute(path)) for path in directories])
    )
    return _settled(found, common)


def committed_entries_under(
    output_dir: str | Path, names: Collection[str]
) -> List[Path]:
    """The entries git tracks at ``output_dir/<name>`` or below it, sorted.

    For each of *names*, the directory itself when git tracks it (as a link) and
    every entry under it, of any kind, a link as much as a regular file, as for
    the results paths. For what a run writes outside those paths, such as the
    workspace spool. Asks git as ``committed_files_at_results_paths`` does
    (``scan_output_dirs.git_index_below``); empty outside git. Raises
    :class:`UnverifiedOutputFilesError` when git could not answer and anything is
    there on disk.
    """
    return _settled(_found_under(output_dir, names), output_dir)


def committed_entries_in_a_workspace_output(
    output_dir: str | Path,
    project_output_dirs: Iterable[str | Path],
    *,
    root_files: Collection[str] = WORKSPACE_ROOT_FILES,
    every_results_path_at_the_root: bool = False,
) -> List[Path]:
    """The committed entries a workspace scan into *output_dir* would touch.

    At the root, *root_files* and :data:`WORKSPACE_ROOT_DIRECTORIES`, or every
    results path with *every_results_path_at_the_root* (container mode clears
    them on the host); the spool, :data:`WORKSPACE_SPOOL_DIR_NAME`, and anything
    under it; and every results path in each of *project_output_dirs*. One check
    for the CLI and the MCP workspace tool, so that they refuse the same
    workspaces. When git could not answer, one :class:`UnverifiedOutputFilesError`
    names what is on disk in all of those places.
    """
    failures = _GitFailures()
    if every_results_path_at_the_root:
        root = _found_in_the_way(output_dir, None, None, (), failures)
    else:
        root = _found_in_the_way(
            output_dir, root_files, WORKSPACE_ROOT_DIRECTORIES, (), failures
        )
    found = _combined(
        [
            root,
            _found_under(output_dir, (WORKSPACE_SPOOL_DIR_NAME,), failures),
            # The projects directory itself: a committed link there would have
            # every project's output cleared and written through it.
            _found_tracked_entry(output_dir, WORKSPACE_PROJECTS_DIR_NAME, failures),
            *(
                _found_in_the_way(directory, None, None, (), failures)
                for directory in project_output_dirs
            ),
        ]
    )
    return _settled(found, output_dir)


def _named(output: Path, entries: Sequence[Path], *, git_tracks_it: bool = True) -> str:
    """The first :data:`NAMED_IN_THE_MESSAGE` of *entries*, relative to *output*,
    and a count of the rest. *output* itself is named as such: for committed
    entries, which git can track as a link, with "which git tracks"; for entries
    git could not account for (*git_tracks_it* False), without that claim."""
    itself = "the output directory itself" + (
        ", which git tracks" if git_tracks_it else ""
    )
    shown = [
        itself if path == output else path.relative_to(output).as_posix()
        for path in entries[:NAMED_IN_THE_MESSAGE]
    ]
    more = f" and {len(entries) - len(shown)} more" if len(entries) > len(shown) else ""
    return f"{', '.join(shown)}{more}"


def _file_count(entries: Sequence[Path]) -> str:
    return f"{len(entries)} {'file' if len(entries) == 1 else 'files'}"


def committed_output_files_error(
    output_dir: str | Path, committed: Sequence[Path]
) -> CommittedOutputFilesError:
    """The refusal for *committed*, entries git tracks under *output_dir*.

    Names the first :data:`NAMED_IN_THE_MESSAGE` of them, relative to
    *output_dir*, and counts the rest. One message for every entry point, so that
    the CLI, the MCP tools and the orchestrator say the same thing.
    """
    output = _absolute(output_dir)
    return CommittedOutputFilesError(
        f"ASH's output directory {output.as_posix()} holds {_file_count(committed)} "
        f"committed to git where a scan deletes or writes its own output: "
        f"{_named(output, committed)}. "
        # "This run", not "the scan": a report over existing results
        # (--use-existing) is refused the same way and starts no scan.
        "ASH does not delete or overwrite committed files, so this run did not "
        "start. Move them out of the output directory, or write ASH's output "
        "elsewhere with --output-dir."
    )


def _letting_git_read(answer: Optional[GitIndexAnswer], repository: str) -> str:
    """The way out that lets git answer, for what git said.

    The safe.directory way out shows a command to copy, so the path in it is
    shell-quoted (shlex.quote): unquoted, a path with a space split the command.
    A path the message's sinks show other than as written (shown_on_one_line: a
    control character or a line break, a lone surrogate for a byte that is not
    UTF-8, a backslash before text that reads as an escape) cannot survive a paste
    at all once it is shown as an escape, so the command is left out and the
    message says the path cannot be written here as plain text.
    """
    error = (answer.error if answer is not None else None) or ""
    if "dubious ownership" in error or "safe.directory" in error:
        if shown_on_one_line(repository) != repository:
            return (
                "mark the repository safe for git with git config --global "
                "--add safe.directory and the repository's path, which cannot "
                "be written here as plain text"
            )
        return (
            "mark the repository safe for git "
            f"(git config --global --add safe.directory {shlex.quote(repository)})"
        )
    if answer is not None and answer.could_not_run:
        return "make git available on PATH"
    return "fix what stops git from reading the repository"


def unverified_output_files_error(
    output_dir: str | Path,
    entries: Sequence[Path],
    answer: Optional[GitIndexAnswer],
) -> UnverifiedOutputFilesError:
    """The refusal for *entries*, on disk where a run into *output_dir* writes,
    when git could not say whether they are committed (*answer*).

    Names the entries as :func:`committed_output_files_error` does, git's error,
    and both ways out: let git read the repository, or remove the old results.
    """
    output = _absolute(output_dir)
    repository = (
        answer.repository.as_posix()
        if answer is not None and answer.repository is not None
        else "(unknown)"
    )
    error = (answer.error if answer is not None else None) or "no answer"
    return UnverifiedOutputFilesError(
        f"ASH's output directory {output.as_posix()} holds {_file_count(entries)} "
        "where a scan deletes or writes its own output: "
        f"{_named(output, entries, git_tracks_it=False)}. "
        f"It is in the git repository at {repository}, and git could not list "
        f"what is committed there ({error}), so ASH cannot tell whether those "
        "files are committed. ASH did not delete or overwrite anything, and this "
        f"run did not start. To run it, {_letting_git_read(answer, repository)}, "
        "or remove the old results from the output directory.",
        entries=entries,
        answer=answer,
    )


def refusal_label(error: BaseException) -> str:
    """How an exit-3 refusal is labeled wherever it is printed or recorded.

    "Scan refused" for committed files in the way (``CommittedOutputFilesError``),
    which are not a configuration problem, and "Invalid configuration" for any
    other ``ASHConfigValidationError``. The single-directory CLI prints it before
    the message (``run_ash_scan._config_refusal_text``); a workspace records it
    on a refused project.
    """
    if isinstance(error, CommittedOutputFilesError):
        return "Scan refused"
    return "Invalid configuration"


def refuse_committed_entries(
    output_dir: str | Path,
    *,
    files: Optional[Collection[str]] = None,
    directories: Optional[Collection[str]] = None,
    not_on_disk: Collection[str] = (),
) -> None:
    """Raise ``CommittedOutputFilesError`` when git tracks an entry in the way.

    *files*, *directories* and *not_on_disk* as for
    :func:`committed_entries_in_the_way`, which raises
    :class:`UnverifiedOutputFilesError` itself when git cannot answer.
    """
    committed = committed_entries_in_the_way(
        output_dir, files=files, directories=directories, not_on_disk=not_on_disk
    )
    if committed:
        raise committed_output_files_error(output_dir, committed)
