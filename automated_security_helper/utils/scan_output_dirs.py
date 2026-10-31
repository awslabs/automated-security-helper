# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The directories under a scan root that hold ASH's own output.

Why this exists
---------------
ASH writes its output inside the tree it scans by default (``.ash/ash_output``),
and CI commonly points ``--output-dir`` at a visible directory in the checkout as
well. Every later scan of that tree then read the earlier reports back in:
measured on a two-file project, a second run with ``--output-dir shard-1``
reported 21 findings where the first reported 4, the other 17 being
detect-secrets matches in ``.ash/ash_output/reports/``. The only protection was a
``.gitignore`` entry, and only for the scanners that honor one.

What counts as ASH output
-------------------------
Directories ASH names, never directories it recognizes:

* the output directory of the scan in progress, and inside ASH's container the
  host's output directory as the mounted tree holds it;
* ``.ash/ash_output`` under the scan root and under the working directory, the
  two places ASH's default output directory resolves to, when git can say which
  of its files are committed (see below).

Each only when it sits strictly inside the scan root, with both resolved, so that
a root or an output directory given through a link above the tree (``/var`` on
macOS) is still matched; each is spelled under the scan root as given, the
spelling every scanner sees. The scan root itself is never one, since excluding
it would leave nothing to scan.

Why not recognize ASH output by the files in it
-----------------------------------------------
A first version also left out any directory holding ``ash_aggregated_results.json``
or both scan-start files (``ash-ignore-report.txt`` and
``ash-scan-set-files-list.txt``), so that another shard's output or an interrupted
run's would be skipped too. Those are files a scanned repository can commit. A
``src/ash_aggregated_results.json`` holding ``{}`` took ``src/`` away from every
scanner, including the ones that do not read ``.gitignore``, and the executor
dropped what was left before suppressions were applied; measured, 14 result
locations became 2. So such a directory is scanned, and :func:`holds_ash_output`
only decides whether to warn about it. Write shard output outside the scanned
tree, or list it in ``.gitignore``.

Files a repository committed there
----------------------------------
A named directory is a fixed path a repository can commit to, and leaving it out
hid what was committed: a B602 and an AWS key under ``.ash/ash_output/hidden/``,
reported before ASH named its output directories, went unreported with
``--output-dir`` outside the tree, as container mode runs. In a git checkout, the
scan-set walk lists the files git tracks in a named directory
(:func:`tracked_files_in`) and warns. git is asked about the repository found
from the directory's ancestors, named on its command line, so content inside the
directory cannot change which repository answers. Only regular files are listed,
each inside the directory and reached without a link (:func:`committed_file_under`):
a committed link is left out, wherever it points. Everything after the walk reads
that from this run's scan-set list, or from git when the run wrote none, as in
``ash merge``: a scanner's tool is told to skip the named directories holding none
of its files, and ASH's own directories in the others
(:func:`output_dirs_to_exclude`), and both the drop and the suppression step's
exclusion of this run's output directory keep the results located in them
(:func:`committed_output_files`). Those two once dropped them when the committed
files were in this run's output directory, the default ``.ash/ash_output``, and so
did detect-secrets' own file filter: a key committed there was reported by no
scanner.

Where git cannot say what is committed, outside a checkout or for a repository git
gives no list for, nothing tells ASH's files from the repository's. This run's
output directory is then left out whole. An earlier run's ``.ash/ash_output`` used
to be left out whole too, which hid every file in it from every scanner; it is
scanned like the rest of the tree instead, with a warning naming it
(:func:`classified_output_dirs`).

Known limitations: a committed file still passes through the ignore files like any
other, so one an ignore file lists is not scanned; where git gives no list, the
committed files in this run's output directory are left out with the rest of it,
and an earlier run's reports in a ``.ash/ash_output`` are scanned. Ownership is not
a cause: git checks it only for a repository it finds itself, and ASH names the
repository on git's command line (:func:`git_index_below`).
"""

from __future__ import annotations

import enum
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import unquote

from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import ScanSetUnreadableError
from automated_security_helper.utils.error_text import redact_then_split
from automated_security_helper.utils.git_command import decode_git_output, git_argv
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_dir_links import same_by_identity
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.undecodable_text import (
    path_in_record_form,
    resolve_uri_reading,
    undecodable_of_text,
)

#: Written at the root of every ASH output directory once a run completes.
RESULTS_FILE_NAME = "ash_aggregated_results.json"

#: Written at the root of the output directory before any scanner starts.
SCAN_START_FILE_NAMES: Tuple[str, ...] = (
    "ash-ignore-report.txt",
    "ash-scan-set-files-list.txt",
)

#: Written beside the scan-start files by the run that wrote them: its run ID and the
#: SHA-256 of each, so that only that run reads them back (``get_scan_set``).
SCAN_SET_RUN_FILE_NAME = "ash-scan-set-run.json"

#: The directories under the output directory that a scan clears when it starts and
#: fills with its own output (``ASHScanOrchestrator.ensure_directories``).
WORKING_DIR_NAMES: Tuple[str, ...] = ("analysis", "reports", "scanners", "converted")

#: ASH's default output directory, relative to the directory it resolves from.
DEFAULT_OUTPUT_RELATIVE = Path(".ash", "ash_output")


class PatternSyntax(enum.Enum):
    """The pattern syntaxes ASH writes a path into, to tell a tool to skip it.

    ``GLOB``: grype and syft (doublestar ``Match``), semgrep and opengrep
    (``--exclude``, gitignore-style), ferret-scan (Go ``filepath.Match``).
    ``FNMATCH``: Python's ``fnmatch``, which bandit's ``-x`` uses.
    ``REGEX``: Python's ``re``, which checkov's ``--skip-path`` uses.
    """

    GLOB = "glob"
    FNMATCH = "fnmatch"
    REGEX = "regex"


#: Characters a glob reads as syntax that ASH puts in a character class.
_GLOB_CLASS_ESCAPED = frozenset("*?[{")
#: The same for fnmatch, which has no braces.
_FNMATCH_CLASS_ESCAPED = frozenset("*?[")


def escape_for_pattern(
    text: str, syntax: PatternSyntax, *, separator: str = os.sep
) -> str:
    """*text*, a path or path component, as a *syntax* pattern matching exactly it.

    For the globs each of ``*``, ``?``, ``[`` and (``GLOB`` only) ``{`` is put in a
    one-character class, ``[*]``, which every tool above reads as that character on
    every platform: no backslash is involved, and Go's ``filepath.Match`` treats a
    backslash as the separator on Windows. ``]``, ``}`` and ``,`` are literal once
    nothing opens a class or an alternation. A backslash in a POSIX name is doubled
    for ``GLOB``, the one place a backslash escape is needed; when *separator* is a
    backslash it is a separator and left as it is. A space that ends a ``GLOB``
    pattern on a POSIX name is escaped with a backslash too: the gitignore-style
    syntax semgrep and opengrep read trims an unescaped trailing space, so a
    directory named with one was matched by the name without it. ``fnmatch``
    reads a backslash as itself. ``REGEX`` is :func:`re.escape`.

    Measured, as ``--exclude`` values naming a directory such as ``out[1]`` beside a
    real ``out1``, offline, on grype 0.120.1 and syft 1.54.1 (both linking doublestar
    v4.10.2), semgrep 1.180.0, opengrep 1.30.2 and ferret-scan 2.4.5 and 2.5.2; and on
    bandit 1.9.4's and checkov 3.3.26's own matching functions, called directly. The
    unescaped names skipped the look-alike directories and missed their own.

    The caller still has to keep *text* out of any separator the tool's option uses
    between values, such as a comma, which no syntax here can escape.
    """
    if syntax is PatternSyntax.REGEX:
        return re.escape(text)
    escaped = (
        _GLOB_CLASS_ESCAPED if syntax is PatternSyntax.GLOB else _FNMATCH_CLASS_ESCAPED
    )
    out = []
    for char in text:
        if char in escaped:
            out.append(f"[{char}]")
        elif char == "\\" and syntax is PatternSyntax.GLOB and separator != "\\":
            out.append("\\\\")
        else:
            out.append(char)
    if syntax is PatternSyntax.GLOB and separator != "\\" and out and out[-1] == " ":
        out[-1] = "\\ "
    return "".join(out)


def holds_ash_output(file_names: Iterable[str]) -> bool:
    """Whether a directory whose files are *file_names* looks like ASH output.

    Used to warn, never to exclude: see the module docstring.
    """
    names = set(file_names)
    return RESULTS_FILE_NAME in names or all(
        name in names for name in SCAN_START_FILE_NAMES
    )


def warn_about_look_alike(directory: str | Path) -> None:
    """Say that *directory* looks like ASH output and is scanned anyway.

    Said during the walk, before the ignore files are applied, so it says "as far
    as the ignore files allow": an ignore file other than the root ``.gitignore``
    can still leave the directory out, and the warning once said it was scanned
    without that qualification.
    """
    ASH_LOGGER.warning(
        f"{Path(directory).as_posix()} holds files ASH writes to its output "
        "directory, but it is not this scan's output directory or .ash/ash_output, "
        "so it is scanned like the rest of the tree, as far as the ignore files "
        "allow. If it is the output of another ASH run, such as another shard's, "
        "write that output outside the scanned tree or list it in .gitignore."
    )


def warn_about_committed_files(directory: str | Path, count: int) -> None:
    """Say that ASH's output directory *directory* holds *count* committed files.

    Said during the walk, before the ignore files are applied: a committed file an
    ignore file lists (the ``.ash/.gitignore`` that ``ash config init`` writes, say)
    is still left out, so the warning says the files are scanned as far as the
    ignore files allow.
    """
    ASH_LOGGER.warning(
        f"ASH's output directory {Path(directory).as_posix()} holds {count} "
        f"{'file' if count == 1 else 'files'} committed to git. They are scanned, as "
        "far as the ignore files allow; the rest of the directory is ASH's own "
        "output and is not. Move committed files out of it, or write ASH's output "
        "elsewhere with --output-dir."
    )


def tracked_files_in(directory: str | Path) -> Optional[List[Path]]:
    """The files git tracks under *directory*, spelled under it, or None.

    The index entries below *directory* (:func:`git_index_below`): what is
    committed or staged, whatever ``.gitignore`` says. Only the entries that are
    regular files inside *directory*, reached without a link, are returned
    (:func:`committed_file_under`).

    None when git cannot answer: *directory* does not exist or is not in a git
    checkout, or git could not list the index of the repository it is in (git is
    not installed, it timed out, or it exited with an error, as for a corrupt
    index or a ``.git`` file naming a directory that is not there). The caller
    then treats the directory as holding no committed file. In the last case
    that leaves committed files out unseen, so it is logged as a warning naming
    git's error. Ownership is not among the causes: git checks it, and honors
    ``safe.directory``, only for a repository it finds by itself, and this one is
    named on its command line.
    """
    answer = git_index_below(directory)
    if answer.names is None:
        if answer.repository is not None:
            ASH_LOGGER.warning(
                f"git could not list the files committed under "
                f"{answer.base.as_posix()}, in the repository at "
                f"{answer.repository.as_posix()}: {answer.error}. ASH treats the "
                "directory as holding none, so a file committed there is left out "
                "with the rest of ASH's output."
            )
        return None
    tracked: List[Path] = []
    for name in answer.names:
        path = committed_file_under(answer.base, name)
        if path is not None:
            tracked.append(path)
    return tracked


def _repository_root_of(directory: Path) -> Optional[Path]:
    """The nearest of *directory* and its ancestors holding a ``.git`` entry.

    Found on the filesystem, not by git's own search, which from inside
    *directory* takes a directory that only looks like a repository (a ``HEAD``,
    ``objects`` and ``refs``) for one, and whose config can then name another work
    tree: committed files can lay that out, and a ``.git`` entry they cannot (git
    refuses the name). ``GIT_CEILING_DIRECTORIES`` is honored as git honors it:
    *directory* itself is always looked at, listed or not, and the search stops
    before it would move up into a listed directory. Measured on git 2.50.1: a
    repository whose root is listed is found from that root, and from a listed
    directory git goes on up into its unlisted parent. Each entry is compared
    with its links resolved, as git resolves them (setup.c,
    ``canonicalize_ceiling_entry``) and as *directory* is given here (every link
    resolved, by :func:`git_index_below`): compared as written, a ceiling spelled
    through a link never matched the resolved walk and did not stop it.

    Deliberately a third rule beside the other two ``.git`` judgments. The
    nesting walk (``scan_source._marks_a_checkout``) takes the shapes git's
    own discovery reads, erring toward "nested" on a near miss (a dangling
    link, a bare ``HEAD``), and the checkout boundary
    (``sandbox_grants._git_shaped``) takes shape plus ownership; here ANY
    ``.git`` entry marks the nearest root, because the answer only chooses
    which repository ``git_index_below`` names on git's own command line.
    Pointing git at a stray entry fails loud -- git errors and the answer
    records why -- never open, and skipping a shaped-but-unusable entry
    would instead hand the question to an enclosing repository the entry's
    directory never belonged to.
    """
    # Each entry both as spelled and resolved, as *directory* is by its caller
    # and as git resolves a listed entry: a ceiling spelled through a link stops
    # the walk at the directory it names, compared where the walk really is.
    ceilings = set()
    for entry in os.environ.get("GIT_CEILING_DIRECTORIES", "").split(os.pathsep):
        if entry and os.path.isabs(entry):
            ceilings.add(_absolute(entry))
            ceilings.add(_resolved(_absolute(entry)))
    candidate = directory
    while True:
        if os.path.lexists(candidate / ".git"):
            return candidate
        parent = candidate.parent
        if parent == candidate or parent in ceilings:
            return None
        candidate = parent


def _index_entries_under(directory: str | Path) -> Optional[Tuple[Path, List[str]]]:
    """*directory*, absolute, and the index entries below it, or None.

    :func:`git_index_below` without the reason: None whenever git gave no list.
    """
    answer = git_index_below(directory)
    if answer.names is None:
        return None
    return answer.base, answer.names


def committed_file_under(base: Path, name: str) -> Optional[Path]:
    """*name*, an entry git lists below *base*, as a path, when it is a regular file.

    The entry, ``/``-separated as git writes it, is joined onto *base* and
    normalized. None when that path is not strictly inside *base*, when a component
    between *base* and it is a link or a junction, or when it is not a regular file:
    a link, a directory (a submodule is listed as one), or anything else. Each entry
    left out is logged at debug level with its name.

    Every place that takes a path from git's index, or from a scan set holding
    such paths, goes through this, so a committed link is never taken as a
    committed file, whatever it points at. On Windows a reparse point that is
    neither a link nor a junction is resolved by ``os.lstat`` and reads as the
    file it resolves to; a git checkout creates none, only files, directories and
    links.
    """
    path = Path(os.path.normpath(base.joinpath(*name.split("/"))))
    reason = None
    if not _strictly_inside(path, base):
        reason = "it is not inside that directory"
    elif _reached_through_a_link(path.parent, base):
        reason = "it is reached through a link"
    else:
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            reason = "it does not exist"
        else:
            if not stat.S_ISREG(mode):
                reason = "it is not a regular file"
    if reason is not None:
        ASH_LOGGER.debug(
            f"Not taking {name!r}, listed under {base.as_posix()}, as a committed "
            f"file: {reason}"
        )
        return None
    return path


def committed_files_at_results_paths(output_dir: str | Path) -> List[Path]:
    """The entries git tracks where a scan into *output_dir* deletes and writes its own.

    The results file, the scan-start files and the record of the run that wrote
    them, and the CLI's log files (``ash.log``, ``ash.log.jsonl``), which its
    logger truncates, at the root of *output_dir*; the working directories with
    anything under them, which a scan clears when it starts and fills again; and
    the previous results an MCP scan set aside, with the marker a restore leaves,
    which a scan removes when it starts (``core/previous_results.py``;
    :func:`results_path_names`). Every kind of entry counts, a link or a
    submodule as much as a regular file, since the scan would remove any of them
    from the working tree; only what goes into the scan set is limited to regular
    files (:func:`tracked_files_in`). Names are compared as the filesystem
    compares them (:func:`output_name_key`): without regard to case on macOS and
    Windows. *output_dir* itself is among them when git tracks it, as a link or a
    submodule: every results path is then reached through it, and a scan would
    clear and write wherever it leads (``.ash/ash_output`` committed as a link to
    the repository's ``src`` had ``src/reports`` cleared). Absolute, sorted.
    Empty when git tracks none of them, and outside git.

    Raises :class:`GitIndexUnavailable` when *output_dir* is in a repository and
    git could not list its index. Nothing then tells a committed file there from
    a previous run's, and the refusal counts what is at those paths on disk
    instead (:func:`entries_on_disk`, ``core/committed_output.py``).

    A scan never deletes or overwrites such an entry: it refuses to start instead
    (``ASHScanOrchestrator``). Writing this run's results under another name was
    the alternative, and every reader of ``ash_aggregated_results.json`` (``ash
    report``, ``--use-existing``, container mode, the MCP progress readers) would
    then have read the committed file as this run's results.
    """
    answer = git_index_below(output_dir)
    if answer.names is None:
        if answer.unanswered:
            raise GitIndexUnavailable(answer)
        return []
    found = entries_at_results_paths(answer.base, answer.names)
    if "" in answer.names or _an_enclosing_repository_tracks_the_root(answer):
        found.insert(0, answer.base)
    return found


def _an_enclosing_repository_tracks_the_root(answer: GitIndexAnswer) -> bool:
    """Whether *answer*'s directory is itself a repository's root that an enclosing
    repository tracks as an entry: a checked-out submodule.

    A submodule holds a ``.git`` file of its own, so :func:`_repository_root_of`
    names the submodule itself and its index says nothing about the gitlink the
    superproject tracks at its path; only when the directory is below the root
    does the listing come back with the ``""`` entry that marks the directory
    itself as tracked. So when the answer's repository is the directory itself,
    the repository above it is asked once whether it lists the directory's path
    exactly. A scan would clear and write inside the submodule's checkout.

    Raises :class:`GitIndexUnavailable` when the repository above gives no
    list: git not answering is not "it does not track the directory", and read
    as that it let the scan clear and write inside a submodule whose
    superproject tracks it. The caller then counts what is on disk instead, as
    it does when the directory's own repository gives no list.
    """
    if answer.repository is None or answer.repository != _resolved(answer.base):
        return False
    outer = _repository_root_of(answer.repository.parent)
    if outer is None:
        return False
    relative = answer.repository.relative_to(outer).as_posix()
    # An entry at the listed path itself (the gitlink) comes back as "".
    listed, error, could_not_run = _index_listing(outer, relative)
    if listed is None:
        raise GitIndexUnavailable(
            GitIndexAnswer(
                answer.base, repository=outer, error=error, could_not_run=could_not_run
            )
        )
    return "" in listed


@dataclass(frozen=True)
class GitIndexAnswer:
    """What git said about the index entries below a directory.

    *base* is the directory, absolute. *names* are the entries below it,
    ``/``-separated under it, when git listed them, and None when it did not; an
    entry at *base* itself, a link or a submodule, is listed as ``""``.
    *repository* is the repository *base* is in (:func:`_repository_root_of`),
    None when there is none. *error*, for a repository git gave no list for, is
    why: its exit status and the first lines it wrote to stderr, or why it could
    not be run; *could_not_run* is whether git could not be started at all.
    """

    base: Path
    names: Optional[List[str]] = None
    repository: Optional[Path] = None
    error: Optional[str] = None
    could_not_run: bool = False

    @property
    def unanswered(self) -> bool:
        """Whether *base* is in a repository and git gave no list for it."""
        return self.names is None and self.repository is not None


class GitIndexUnavailable(Exception):
    """git could not list the index of the repository a directory is in.

    Raised by :func:`committed_files_at_results_paths`, so that no caller reads
    "git did not answer" as "nothing is committed". *answer* says where and why.
    """

    def __init__(self, answer: GitIndexAnswer) -> None:
        super().__init__(
            f"git could not list the files under {answer.base.as_posix()}: "
            f"{answer.error}"
        )
        self.answer = answer


#: How long git may take to list the index below a directory.
GIT_INDEX_TIMEOUT_SECONDS = 30

#: Environment variables left out of git's environment when it lists the index: the
#: ones that point git at another repository or index (``--git-dir`` and
#: ``--work-tree`` name the repository on the command line; GIT_INDEX_FILE is a
#: hook's temporary index), and the ones that change what a pathspec matches, which
#: make git refuse ``--literal-pathspecs`` outright (GIT_ICASE_PATHSPECS or
#: GIT_GLOB_PATHSPECS together with it is exit 128) or match something other than
#: the path as spelled.
_GIT_ENV_LEFT_OUT = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_GLOB_PATHSPECS",
        "GIT_NOGLOB_PATHSPECS",
        "GIT_ICASE_PATHSPECS",
        "GIT_LITERAL_PATHSPECS",
    }
)


def _git_index_environ() -> Dict[str, str]:
    """ASH's environment without :data:`_GIT_ENV_LEFT_OUT`, for the index listing."""
    return {
        key: value
        for key, value in snapshot_environ().items()
        if key not in _GIT_ENV_LEFT_OUT
    }


def _pathspec_options() -> Tuple[str, ...]:
    """git's global options that make the index pathspec match the directory as named.

    Literal where the filesystem compares names exactly, so no character of the
    path is read as a glob or as pathspec magic: ``--literal-pathspecs``. Where it
    compares names without regard to case (:func:`output_name_key`: macOS and
    Windows) the match must ignore case too (the index keeps the spelling the file
    was committed with, and an output directory spelled ``Out`` is the committed
    ``out`` there, so a case-exact pathspec listed nothing and the committed-output
    refusal never fired), and no global option gives both: ``--literal-pathspecs``
    refuses every magic, and ``--icase-pathspecs`` with ``--noglob-pathspecs``
    still read a leading ``:`` of the name as magic (``:out`` matched ``out``;
    ``:!x`` excluded). There the element carries the readings itself
    (:func:`_pathspec_element`), and no global option is passed.
    """
    if output_name_key("A") == "A":
        return ("--literal-pathspecs",)
    return ()


def _pathspec_element(relative: str) -> str:
    """The pathspec that names *relative* literally, and without regard to case
    where the filesystem compares names that way: ``:(literal,icase)<relative>``
    there, whose long-form magic ends at ``)`` and leaves the rest a name whatever
    it starts with; ``.`` and, under ``--literal-pathspecs``, *relative* itself
    elsewhere."""
    if relative == "." or output_name_key("A") == "A":
        return relative
    return f":(literal,icase){relative}"


def _names_below(listed: str, relative: str) -> List[str]:
    """The entries of *listed* (NUL-separated) below *relative*, spelled under it.

    Compared component by component with :func:`output_name_key`, as the prefix
    was matched: an entry whose directory prefix differs from *relative* only in
    case is below it where the filesystem compares names that way. An entry at
    *relative* itself (git tracks it as a link or a submodule) is ``""``.
    """
    if relative == ".":
        return [name for name in listed.split("\0") if name]
    prefix_keys = [output_name_key(part) for part in relative.split("/")]
    depth = len(prefix_keys)
    names: List[str] = []
    for name in listed.split("\0"):
        if not name:
            continue
        parts = name.split("/")
        if len(parts) < depth:
            continue
        if [output_name_key(part) for part in parts[:depth]] != prefix_keys:
            continue
        names.append("/".join(parts[depth:]))
    return names


#: How much of git's stderr a refusal or a warning quotes.
_GIT_ERROR_LINES = 2
_GIT_ERROR_CHARACTERS = 300


def git_index_below(
    directory: str | Path, *, values: Iterable[str] = ()
) -> GitIndexAnswer:
    """The index entries below *directory*, as git lists them, and why not if not.

    ``values`` are the run's environment-read values when the caller knows
    them, for the stderr line the error can quote; defaulted empty for the
    callers that run before a configuration is loaded.

    Every entry, whatever its type: a regular file, a link, a submodule. git is
    asked once, about the repository :func:`_repository_root_of` finds from where
    *directory* really is (every link resolved; for a *directory* that is itself
    a link, from where its parent really is, :func:`_where_git_is_asked`), named
    on the command line (``--git-dir`` and ``--work-tree``), so nothing inside
    *directory* decides which repository answers; *directory* is the pathspec,
    taken literally, and without regard to case where the filesystem compares
    names that way (:func:`_pathspec_options`, :func:`_pathspec_element`). A
    *directory* that git tracks as
    a link or a submodule is listed as the entry ``""``. ``core.fsmonitor`` is turned off and
    ``core.hooksPath`` pointed at ``/dev/null`` for the call (:func:`git_argv`),
    so the repository's own config cannot start a program, and the variables that
    would point git elsewhere or change what the pathspec matches are left out of
    its environment (:data:`_GIT_ENV_LEFT_OUT`).

    No names and no repository when *directory* does not exist or no repository
    holds it. No names, the repository and git's error when git could not list
    the index: git is not installed or could not be started, it took longer than
    :data:`GIT_INDEX_TIMEOUT_SECONDS`, or it exited with an error. Naming the
    repository on the command line also means git does not check its owner:
    ``safe.directory`` and "dubious ownership" apply only to a repository git
    finds by itself (measured on git 2.50.1 with
    ``GIT_TEST_ASSUME_DIFFERENT_OWNER``).
    """
    base = _absolute(directory)
    # Path.is_dir lets a PermissionError through on CPython 3.10-3.12 when a
    # parent cannot be searched; a directory that cannot be looked up is one git
    # cannot be asked about, so it is answered as one that is not there.
    try:
        is_dir = base.is_dir()
    except OSError:
        is_dir = False
    if not is_dir:
        return GitIndexAnswer(base)
    # The repository is found from where the directory really is, every link
    # resolved, as git would find it: a directory reached through a link that
    # lands inside a repository (``/alias`` to ``<repo>/sub``) is that
    # repository's, and one reached through a link in the repository that leads
    # out of it is not. The answer's base stays the directory as spelled, since
    # its callers join the names onto it, and the two are one directory.
    asked, tail = _where_git_is_asked(base)
    root = _repository_root_of(asked)
    if root is None:
        return GitIndexAnswer(base)
    relative = PurePosixPath(*asked.relative_to(root).parts, *tail).as_posix()
    names, error, could_not_run = _index_listing(root, relative, values=values)
    if names is None:
        return GitIndexAnswer(
            base, repository=root, error=error, could_not_run=could_not_run
        )
    return GitIndexAnswer(base, names=names, repository=root)


def _where_git_is_asked(base: Path) -> Tuple[Path, Tuple[str, ...]]:
    """Where the repository holding *base* is looked for, and the pathspec's tail.

    *base* with every link resolved, and no tail, for a directory in its own
    right. For a *base* that is itself a link or a junction: its parent with
    every link resolved, and *base*'s own name as the tail. git tracks such a
    link as an entry of the repository holding the link's directory, listed as
    ``""`` below the link's own path, which is how a committed link at the output
    directory is reported (:func:`committed_files_at_results_paths`); resolving
    the link first asked git about the target's files and lost that entry, and
    for a link leading out of the repository answered "no repository" where the
    link itself is the repository's.
    """
    # Imported here, as in _reached_through_a_link.
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    try:
        if _is_link_stat(os.lstat(base)):
            return _resolved(base.parent), (base.name,)
    except OSError:
        pass
    return _resolved(base), ()


def _index_listing(
    root: Path, relative: str, *, values: Iterable[str] = ()
) -> Tuple[Optional[List[str]], Optional[str], bool]:
    """The index entries of the repository at *root* below *relative*, or why not.

    *relative* is ``/``-separated under *root*, ``.`` for the root itself. The
    names come back spelled under *relative* (:func:`_names_below`), an entry at
    *relative* itself as ``""``. When git gave no list the names are None, the
    second value says why (its exit status and first stderr lines, or why it could
    not be run) and the third whether git could not be started at all.
    """
    # Through the spawn helper every ASH subprocess uses. The scan set is built by
    # the orchestrator before any scanner runs, outside a scanner's sandbox.
    from automated_security_helper.utils.subprocess_utils import spawn_run

    pathspec = _pathspec_element(relative)
    try:
        result = spawn_run(
            git_argv(
                f"--git-dir={root / '.git'}",
                f"--work-tree={root}",
                *_pathspec_options(),
                "ls-files",
                "-z",
                "--",
                pathspec,
            ),
            cwd=root,
            capture_output=True,
            # The files the git dir names are the repository's, and one linked
            # to /dev/stdin made git wait on ASH's stdin.
            stdin=subprocess.DEVNULL,
            timeout=GIT_INDEX_TIMEOUT_SECONDS,
            env=_git_index_environ(),
        )
    except subprocess.TimeoutExpired:
        return (
            None,
            f"git did not answer within {GIT_INDEX_TIMEOUT_SECONDS} seconds",
            False,
        )
    except OSError as error:  # git missing, not executable, or not startable
        return None, f"git could not be run: {_quoted_for_a_message(str(error))}", True
    except Exception as error:  # a refused sandbox, or anything else spawning
        return None, f"git could not be run: {_quoted_for_a_message(str(error))}", False
    if result.returncode != 0:
        said = _first_lines(result.stderr, values=values)
        return (
            None,
            f"git exited with status {result.returncode}"
            + (f": {said}" if said else ""),
            False,
        )
    # Decoded as Python decodes a file name, so each name matches the directory
    # entry it is compared with: GIT_OUTPUT_ENCODING (UTF-8 on Windows, whatever
    # the filesystem encoding is there) with surrogateescape, so a byte that does
    # not decode is kept as a surrogate and never raises. An entry at *relative*
    # itself (git tracks it as a link or a submodule, which a filesystem walk
    # follows into) comes back as "".
    listed = decode_git_output(result.stdout)
    return _names_below(listed, relative), None, False


def _first_lines(stderr: Optional[bytes], *, values: Iterable[str]) -> str:
    """The first non-empty lines git wrote to stderr, joined, bounded, printable.

    ``values`` are the run's environment-read values when the caller knows
    them; ``git_index_below`` forwards what its caller passes, defaulted
    empty. Redacted whole BEFORE the strip-and-join (redact_then_split): a
    value holding a line break would otherwise come back joined with one
    space, a spelling the downstream whole-value redaction cannot match."""
    text = (stderr or b"").decode("utf-8", "replace")
    lines = [line.strip() for line in redact_then_split(text, values) if line.strip()]
    said = " ".join(lines[:_GIT_ERROR_LINES])
    if len(said) > _GIT_ERROR_CHARACTERS:
        said = said[: _GIT_ERROR_CHARACTERS - 3] + "..."
    return _quoted_for_a_message(said)


def _quoted_for_a_message(text: str) -> str:
    """*text* with each character a terminal would act on written as an escape."""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in text
    )


def output_name_key(name: str) -> str:
    """*name*, an entry's name in an output directory, as its filesystem compares it.

    Every comparison of a name with a results path, git's names and the names on
    disk alike, goes through this. Casefolded on macOS and Windows, whose default
    filesystems (APFS, HFS+, NTFS) compare names without regard to case: there a
    committed ``Reports/x.md`` is inside the ``reports`` a scan removes with
    ``shutil.rmtree``, and ``ASH.LOG`` is the ``ash.log`` the logger truncates.
    Exact anywhere else: on Linux ``Reports`` is a directory of its own, which a
    scan never touches. A case-sensitive volume on macOS is then compared as if
    it were not, which can only refuse more.
    """
    if sys.platform in ("darwin", "win32"):
        return name.casefold()
    return name


def results_path_names() -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """The names a scan deletes and writes at the root of its output directory.

    The files: the results file, the scan-start files, the record of the run that
    wrote them, the marker a restore leaves, and the CLI's log files. The
    directories it clears whole when it starts: the working directories, and
    where an MCP scan sets the previous results aside (``core/previous_results.py``).
    """
    # Imported here: core.previous_results is above this module.
    from automated_security_helper.core.previous_results import (
        RESTORED_MARKER_NAME,
    )

    return (
        (
            RESULTS_FILE_NAME,
            *SCAN_START_FILE_NAMES,
            SCAN_SET_RUN_FILE_NAME,
            RESTORED_MARKER_NAME,
            "ash.log",
            "ash.log.jsonl",
        ),
        ash_own_dir_names(),
    )


def entries_at_results_paths(base: Path, names: Iterable[str]) -> List[Path]:
    """The entries of *names* that are at a results path of *base*. Absolute, sorted.

    *names* are ``/``-separated under *base*, as git lists them. An entry counts
    when it is one of the root files of :func:`results_path_names` at the root of
    *base*, or is one of its directories or anything under one; names are compared
    with :func:`output_name_key`. Depends on the names alone.
    """
    root_files, directories = results_path_names()
    root_keys = {output_name_key(name) for name in root_files}
    directory_keys = {output_name_key(name) for name in directories}
    found = []
    for name in names:
        path = Path(os.path.normpath(base.joinpath(*name.split("/"))))
        parts = _parts_below(path, base)
        if not parts:
            continue
        first = output_name_key(parts[0])
        if (len(parts) == 1 and first in root_keys) or first in directory_keys:
            found.append(path)
    return sorted(found)


def entries_on_disk(
    output_dir: str | Path,
    files: Iterable[str],
    directories: Iterable[str],
) -> List[Path]:
    """What is at *files* and in *directories* at the root of *output_dir*, on disk.

    For when git cannot say what is committed there (:class:`GitIndexUnavailable`).
    Each entry at the root whose name is one of *files*, of whatever kind; each
    one whose name is one of *directories*, when it is a link, a junction or not a
    directory at all; and every entry that is not a directory under each of those
    that is one, found without following a link, a link or a junction counting
    as an entry. A directory that cannot be read counts as an entry, since what
    it holds cannot be told. Names are compared with :func:`output_name_key`.
    Absolute, sorted; empty when *output_dir* does not exist.
    """
    base = _absolute(output_dir)
    file_keys = {output_name_key(name) for name in files}
    directory_keys = {output_name_key(name) for name in directories}
    try:
        children = sorted(os.listdir(base))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError:
        return [base]
    found: List[Path] = []
    for name in children:
        key = output_name_key(name)
        path = base / name
        if key in file_keys:
            found.append(path)
        elif key in directory_keys:
            found.extend(_entries_under(path))
    return sorted(found)


def _entries_under(directory: Path) -> List[Path]:
    """*directory* when it is not a directory, else every non-directory below it.

    Links and junctions are entries, never followed (``os.lstat``). A directory
    that cannot be listed is itself an entry.
    """
    # Imported here, as in _reached_through_a_link.
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    def _real_directory(path: Path) -> Optional[bool]:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError:
            return False
        return stat.S_ISDIR(info.st_mode) and not _is_link_stat(info)

    found: List[Path] = []
    pending = [directory]
    while pending:
        current = pending.pop()
        kind = _real_directory(current)
        if kind is None:
            continue
        if not kind:
            found.append(current)
            continue
        try:
            names = os.listdir(current)
        except OSError:
            found.append(current)
            continue
        pending.extend(current / name for name in names)
    return found


def _absolute(path: str | Path) -> Path:
    # absolute() and not resolve(): a tool sees the tree as it was given,
    # symlinked prefix and all, so every directory named here is spelled under
    # the source as the operator gave it. Whether one is inside the source is
    # decided with both resolved (_spelled_under).
    return Path(os.path.abspath(os.fspath(path)))


def _resolved(path: Path) -> Path:
    return Path(os.path.realpath(path))


def _strictly_inside(candidate: Path, root: Path) -> bool:
    """Whether *candidate* is below *root*, component by component.

    Each name as its filesystem compares it (:func:`output_name_key`): on macOS and
    Windows an output directory spelled ``Out`` is the ``out`` under the source,
    and a text comparison of the paths said it was outside the tree.
    """
    candidate_keys = [output_name_key(part) for part in candidate.parts]
    root_keys = [output_name_key(part) for part in root.parts]
    return (
        len(candidate_keys) > len(root_keys)
        and candidate_keys[: len(root_keys)] == root_keys
    )


def _parts_below(path: Path, root: Path) -> Optional[Tuple[str, ...]]:
    """*path*'s components below *root* when *path* is *root* or below it, each
    name compared as its filesystem compares it (:func:`output_name_key`); None
    when it is not.

    The companion of :func:`_strictly_inside`, and the only way a path placed
    inside by that comparison is taken apart: ``relative_to`` compares by text,
    so for a candidate spelled in another case than the root (``repo/out`` under
    ``Repo`` on macOS) it raised ``ValueError`` right after ``_strictly_inside``
    had said "inside". The components keep *path*'s own spelling; a caller that
    joins them onto *root* spells the result under *root*.
    """
    keys, prefix = _name_keys(path), _name_keys(root)
    if keys[: len(prefix)] != prefix:
        return None
    return path.parts[len(root.parts) :]


def _reached_through_a_link(directory: Path, base: Path) -> bool:
    """Whether a component of *directory* below *base* is a symlink or a junction.

    Each component is ``lstat``-ed from *base* down. A component that does not
    exist ends the check: nothing is behind it. A *directory* that is not at or
    below *base* (:func:`_parts_below`) has no component below it: False.
    """
    # Imported here: scanned_tree is the one place that says what a link is,
    # Windows junctions included.
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    below = _parts_below(directory, base)
    if below is None:
        return False
    current = base
    for part in below:
        current = current / part
        try:
            if _is_link_stat(os.lstat(current)):
                return True
        except OSError:
            return False
    return False


def _through_a_link_in_the_tree(
    candidate: Path, root: Path, root_resolved: Optional[Path] = None
) -> bool:
    """Whether a component of *candidate*, as given, is a link placed in the tree.

    A link whose own directory resolves to the tree's root (*root_resolved*) or
    below it is the tree's: its author chose where it leads. A link above the
    tree, such as ``/var`` on macOS, is the operator's path and is followed, and
    so are the components of *root*'s own spelling: when the source directory is
    itself spelled through a link inside the tree (``<repo>/self`` to ``.``), that
    link is the operator's path too, and examining it rejected every candidate,
    this run's output directory included. A candidate spelled under *root* is
    walked from *root* down; any other from the top. Each component is
    ``lstat``-ed; one that does not exist ends the check.

    *root_resolved* is *root* with its links resolved; left out, it is resolved
    here, so the one-root form this function had before *root* and
    *root_resolved* were told apart still answers (``get_scan_set._own_output_of``
    passed the source's real path alone for a while): a resolved root has no link
    component of its own, so the two forms answer alike for it.
    """
    # Imported here, as in _reached_through_a_link.
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    if root_resolved is None:
        root_resolved = _resolved(root)
    if _strictly_inside(candidate, root):
        current = root
        parts = candidate.parts[len(root.parts) :]
    else:
        current = Path(candidate.anchor)
        parts = candidate.parts[1:]
    for part in parts:
        parent, current = current, current / part
        try:
            info = os.lstat(current)
        except OSError:
            return False
        if _is_link_stat(info):
            if _at_or_below(_resolved(parent), root_resolved):
                return True
    return False


def _spelled_under(candidate: Path, root: Path, root_resolved: Path) -> Optional[Path]:
    """*candidate* spelled under *root*, when it is strictly inside the tree.

    *root*'s own spelling, then the candidate's components below it, when it is
    spelled under *root* (names compared as the filesystem compares them, so on
    macOS and Windows ``repo/out`` is under ``Repo`` and comes back as
    ``Repo/out``, one path with everything else named under *root*). Otherwise,
    when it is inside with both resolved, *root* joined with the rest of its
    resolved path: the source or the output directory given through a link above
    the tree is still the same tree, and on macOS ``/var`` is a link to
    ``/private/var``. None when it is outside the tree either way.
    """
    below = _parts_below(candidate, root)
    if below:
        return root.joinpath(*below)
    below = _parts_below(_resolved(candidate), root_resolved)
    if below:
        return root.joinpath(*below)
    return None


def _same_directory(first: Path, second: Path) -> bool:
    if first == second or _resolved(first) == _resolved(second):
        return True
    return same_by_identity(first, second)


#: Set by ASH's container launcher (``run_ash_container``): the host's source and
#: output directories, mounted at ``/src`` and ``/out``.
CONTAINER_HOST_SOURCE_ENV = "ASH_ACTUAL_SOURCE_DIR"
CONTAINER_HOST_OUTPUT_ENV = "ASH_ACTUAL_OUTPUT_DIR"

#: Where the launcher mounts the host's source directory inside the container
#: (``scan_source._CONTAINER_SOURCE_MOUNT`` names the same place).
CONTAINER_SOURCE_MOUNT = "/src"


def _host_output_dir_in_the_tree(root: Path) -> Optional[Path]:
    """Inside ASH's container, the host's output directory as the tree holds it.

    The container scans the host's source at ``/src`` and writes to ``/out``,
    the host's output directory. When that directory is inside the host's
    source, the tree holds it too, at the same relative path: the same directory,
    which this run writes. Worked out from the host's paths, in their own
    flavor (a Windows host's compare without case), so that it does not depend
    on the two mounts reporting one file identity. The relative path is joined
    onto the mount, which is what the host's source became: in a workspace scan
    *root* is one project's directory below the mount, and joining it there
    named a directory inside the project that is nobody's output while this
    run's went unnamed. A *root* that is not the mount or below it (another
    mount point) is taken as the host's source itself. None outside the
    container, and when the host's output directory is not strictly inside its
    source.
    """
    host_source = os.environ.get(CONTAINER_HOST_SOURCE_ENV)
    host_output = os.environ.get(CONTAINER_HOST_OUTPUT_ENV)
    if not host_source or not host_output:
        return None
    for flavor in (PurePosixPath, PureWindowsPath):
        source, output = flavor(host_source), flavor(host_output)
        if not (source.is_absolute() and output.is_absolute()):
            continue
        try:
            relative = output.relative_to(source)
        except ValueError:
            return None
        if not relative.parts or ".." in relative.parts:
            return None
        return _container_source_mount_of(root).joinpath(*relative.parts)
    return None


def _container_source_mount_of(root: Path) -> Path:
    """The directory the host's source is mounted at, for a scan rooted at *root*.

    ``/src`` when *root* is it or below it; otherwise *root* itself.
    """
    mount = PurePosixPath(CONTAINER_SOURCE_MOUNT)
    posix_root = PurePosixPath(root.as_posix())
    if posix_root == mount or posix_root.is_relative_to(mount):
        return Path(CONTAINER_SOURCE_MOUNT)
    return root


def _output_dir_candidates_with_owner(
    source_dir: str | Path,
    output_dir: Optional[str | Path] = None,
    workspace_output_dir: Optional[str | Path] = None,
) -> List[Tuple[Path, bool]]:
    """Each :func:`output_dir_candidates` entry, and whether it is this run's.

    This run's: *output_dir*; *workspace_output_dir*, in a workspace scan the
    workspace's output directory, which holds every project's output directory
    and the unified results; and inside ASH's container the host's output
    directory as the tree holds it (:func:`_host_output_dir_in_the_tree`). A
    ``.ash/ash_output`` is this run's when it is the same directory as one of
    those; otherwise it is an earlier run's, or the repository's.
    """
    root = _absolute(source_dir)
    root_resolved = _resolved(root)
    # Each candidate with the directory its link check starts from.
    this_run: List[Tuple[Path, Path]] = []
    if output_dir is not None:
        this_run.append((_absolute(output_dir), root))
    if workspace_output_dir is not None:
        this_run.append((_absolute(workspace_output_dir), root))
    in_the_tree = _host_output_dir_in_the_tree(root)
    if in_the_tree is not None:
        this_run.append((in_the_tree, root))
    defaults: List[Tuple[Path, Path]] = []
    for base in (root, Path.cwd()):
        default = _absolute(base / DEFAULT_OUTPUT_RELATIVE)
        if default.is_dir():
            defaults.append((default, base))
    found: List[Tuple[Path, bool]] = []
    for candidate, base in [*this_run, *defaults]:
        checked_from = root if _strictly_inside(candidate, root) else base
        if _reached_through_a_link(
            candidate, checked_from
        ) or _through_a_link_in_the_tree(candidate, root, root_resolved):
            ASH_LOGGER.debug(
                f"Not treating {candidate} as ASH's output directory: it is reached "
                "through a link inside the scanned tree"
            )
            continue
        owned = any(_same_directory(candidate, mine) for mine, _ in this_run)
        found.append((candidate, owned))
    return found


def output_dir_candidates(
    source_dir: str | Path,
    output_dir: Optional[str | Path] = None,
    workspace_output_dir: Optional[str | Path] = None,
) -> List[Path]:
    """The directories ASH names as its own output, absolute, wherever they are.

    *output_dir*, which is this scan's output directory and is named whether or
    not it exists yet; *workspace_output_dir*, in a workspace scan the workspace's
    output directory; inside ASH's container, the host's output directory as the
    scanned tree holds it; and ``.ash/ash_output`` under *source_dir* and under
    the working directory when they exist. Reads no file in the tree.

    :func:`named_output_dirs` keeps the ones inside *source_dir*, with both sides
    resolved, and of those not this run's only the ones git can answer for.

    A name reached through a link inside the tree is not one of them, and neither
    is a ``.ash`` or ``ash_output`` that is a link, however the path to it is
    spelled. The tree's author chose where such a link points, and the findings
    under a named directory are dropped: ``.ash/ash_output`` committed as a link
    to the root dropped every finding of every scanner. A link the operator's own
    path goes through, above the tree or to an output directory outside it, is
    followed as usual.
    """
    return [
        candidate
        for candidate, _ in _output_dir_candidates_with_owner(
            source_dir, output_dir, workspace_output_dir
        )
    ]


def classified_output_dirs(
    source_dir: str | Path,
    output_dir: Optional[str | Path] = None,
    workspace_output_dir: Optional[str | Path] = None,
) -> Tuple[List[Path], List[Path]]:
    """The named output directories, and earlier runs' ones scanned instead.

    Both strictly inside *source_dir*, spelled under it as given
    (:func:`_spelled_under`). This run's output directory is always named. One
    that is not this run's is named only when git can say which of its files are
    committed: then those are scanned and the rest, ASH's own output, is not.
    Where git cannot say, outside a checkout or for a repository git gives no list
    for, nothing tells a file the repository put there from ASH's, and leaving
    the whole directory out hid any file in it from every scanner; it is scanned
    like the rest of the tree instead, and is in the second list. The walk
    records each one it reaches, and ``get_scan_set.scan_set`` warns about it
    (:func:`warn_about_scanned_output_dir`) once the ignore files have been
    applied, if the scan set still holds a file in it. The cost: there, an
    earlier run's reports left in the tree are scanned too.
    """
    named, scanned = _classified_output_dirs(
        source_dir, output_dir, workspace_output_dir
    )
    outermost = sorted(
        path
        for path in named
        if not any(other != path and _at_or_below(path, other) for other in named)
    )
    return outermost, sorted(
        path
        for path in scanned
        if not any(_at_or_below(path, other) for other in named)
    )


def _classified_output_dirs(
    source_dir: str | Path,
    output_dir: Optional[str | Path] = None,
    workspace_output_dir: Optional[str | Path] = None,
) -> Tuple[Set[Path], Set[Path]]:
    """Every named output directory, nested ones included, and the scanned ones.

    :func:`classified_output_dirs` without the reduction to the outermost: what
    :func:`output_dirs_to_exclude` needs, since a named directory nested inside
    another that holds a committed file is excluded on its own.

    A directory that is not this run's is named only when git lists the index of
    a repository ABOVE it. A ``.git`` entry inside the directory itself makes it
    a repository of its own, whose index says nothing about the tree being
    scanned: an earlier run's ``.ash/ash_output`` holding one answered "nothing
    committed" and was left out whole, every file in it hidden from every
    scanner, where it is scanned with a warning like any other directory git
    cannot speak for.
    """
    root = _absolute(source_dir)
    root_resolved = _resolved(root)
    named: Set[Path] = set()
    scanned: Set[Path] = set()
    for candidate, owned in _output_dir_candidates_with_owner(
        source_dir, output_dir, workspace_output_dir
    ):
        spelled = _spelled_under(candidate, root, root_resolved)
        if spelled is None:
            continue
        if owned or _an_enclosing_repository_lists(spelled):
            named.add(spelled)
        else:
            scanned.add(spelled)
    # One entry per directory: where names compare without case, this run's
    # output directory spelled in one case and the earlier run's on disk in
    # another are one directory, and two spellings of it each read as below
    # the other, so the reduction to the outermost directories dropped both and
    # named nothing.
    named = _one_spelling_each(named)
    named_keys = {_name_keys(path) for path in named}
    scanned = {
        path
        for path in _one_spelling_each(scanned)
        if _name_keys(path) not in named_keys
    }
    return named, scanned


def _one_spelling_each(paths: Set[Path]) -> Set[Path]:
    """*paths* with one entry for each directory, where two spellings name one
    (:func:`_name_keys`): the first in sorted order is kept."""
    kept: Dict[Tuple[str, ...], Path] = {}
    for path in sorted(paths):
        kept.setdefault(_name_keys(path), path)
    return set(kept.values())


def _an_enclosing_repository_lists(directory: Path) -> bool:
    """Whether git listed the index below *directory* for a repository above it."""
    answer = git_index_below(directory)
    if answer.names is None or answer.repository is None:
        return False
    return answer.repository != _resolved(answer.base)


def named_output_dirs(
    source_dir: str | Path,
    output_dir: Optional[str | Path] = None,
    workspace_output_dir: Optional[str | Path] = None,
) -> List[Path]:
    """ASH's own output directories strictly inside *source_dir*, absolute.

    This run's output directory, and in a workspace scan the workspace's
    (*workspace_output_dir*), when inside the tree; and an earlier run's
    ``.ash/ash_output`` when git can say which of its files are committed
    (:func:`classified_output_dirs`). Spelled under *source_dir* as given, the
    spelling each scanner's exclusion is built from, though either may be
    reached through a link above the tree. Sorted, with no entry inside another,
    so each can become one exclusion.
    """
    return classified_output_dirs(source_dir, output_dir, workspace_output_dir)[0]


def named_output_dirs_of(context: Any) -> List[Path]:
    """:func:`named_output_dirs` for the run a plugin *context* belongs to."""
    return named_output_dirs(
        context.source_dir,
        getattr(context, "output_dir", None),
        getattr(context, "workspace_output_dir", None),
    )


def warn_about_scanned_output_dir(relative: str, file_count: int) -> None:
    """Say that *relative*, an earlier run's output directory, is scanned.

    *relative* is ``/``-separated under the source, the form
    ``global_settings.ignore_paths`` takes. *file_count* is how many of its files
    the scan set holds once the ignore files have been applied; the caller warns
    only when that is more than none (``get_scan_set.scan_set``).

    The suggested override is built as JSON and quoted for a POSIX shell, so it
    adds exactly *relative* whatever its name holds: a quote in it broke the
    pasted command. ``ignore_paths`` applies to findings, after the scan set is
    built, so with it alone the warning comes back on every scan; an ignore file
    that lists the directory, or deleting it, stops it. The message says so.
    """
    entry = json.dumps([{"path": f"{relative}/", "reason": "earlier ASH output"}])
    override = shlex.quote(f"global_settings.ignore_paths+={entry}")
    held = (
        "whether the 1 file the scan set holds in it is committed, so it is"
        if file_count == 1
        else f"which of the {file_count} files the scan set holds in it are "
        "committed, so they are"
    )
    ASH_LOGGER.warning(
        f"{relative} is not this scan's output directory, and git cannot say "
        f"{held} scanned like the rest of the tree, any earlier ASH run's reports "
        "included. To leave it out, delete it "
        "or list it in an ignore file such as .gitignore. Adding it to "
        "global_settings.ignore_paths in the ASH config leaves its findings out, "
        "but the scan still reads the directory, so this warning repeats until "
        "the directory is deleted or an ignore file lists it. For example: "
        f"--config-overrides {override}."
    )


def scanned_files_in(
    dirs: Sequence[Path], scanned_files: Iterable[str | Path]
) -> Dict[Path, List[Path]]:
    """The files of *scanned_files* (a scan set) inside each of *dirs*, absolute.

    The scan set holds a named directory's files only when git tracks them (see
    ``get_scan_set``), so this is how the scanners and the drop learn which named
    directories hold committed files without asking git again. Compared component
    by component after ``os.path.abspath``, the spelling :func:`named_output_dirs`
    uses, each name as its filesystem compares it (:func:`output_name_key`):
    without regard to case on macOS and Windows, where a prefix test on the text
    missed ``.ASH/Ash_Output`` for ``.ash/ash_output``. An entry is kept only
    when it is a regular file reached without a link
    (:func:`committed_file_under`), whichever list it came from.
    """
    prefixes = [
        (directory, tuple(output_name_key(part) for part in Path(directory).parts))
        for directory in dirs
    ]
    found: Dict[Path, List[Path]] = {directory: [] for directory in dirs}
    if not prefixes:
        return found
    for entry in scanned_files:
        parts = Path(os.path.abspath(os.fspath(entry))).parts
        keys = tuple(output_name_key(part) for part in parts)
        # Every directory holding the entry, not only the first: *dirs* may hold
        # one named directory nested inside another.
        for directory, prefix in prefixes:
            if len(keys) > len(prefix) and keys[: len(prefix)] == prefix:
                relative = "/".join(parts[len(prefix) :])
                path = committed_file_under(Path(directory), relative)
                if path is not None:
                    found[directory].append(path)
    return found


def output_dirs_to_exclude(
    source_dir: str | Path,
    output_dir: Optional[str | Path] = None,
    scanned_files: Iterable[str | Path] = (),
    workspace_output_dir: Optional[str | Path] = None,
) -> List[Path]:
    """The :func:`named_output_dirs` a scanner's tool may be told to skip, or parts of them.

    Each named directory that holds none of *scanned_files*, the scan set, whole.
    One whose committed files are in the scan set cannot be skipped but for those
    files, which no tool here can be told; ASH's own directories in it are
    skipped instead, each that holds no committed file (:func:`ash_own_dir_names`).
    So one committed file, a README say, does not turn off every exclusion for the
    whole directory, and the tools do not read ASH's reports and scanner results there.

    What is left, the files at the root of such a directory and a working
    directory holding a committed file, reaches the tool. The executor's drop
    removes the SARIF results located in ASH's files there; a tool that writes
    something else, syft's SBOM, keeps what it found in them.

    A named directory nested inside another (this run's output directory, or a
    workspace project's, under an earlier run's ``.ash/ash_output`` that holds a
    committed file) is excluded on its own, whole when it holds no committed
    file: the outer directory's committed file does not open the inner one, and
    ASH's in-progress output there was read by every directory-walking tool.
    """
    named, _ = _classified_output_dirs(source_dir, output_dir, workspace_output_dir)
    dirs = sorted(named)
    held = scanned_files_in(dirs, scanned_files)
    workspace = (
        None if workspace_output_dir is None else _absolute(workspace_output_dir)
    )
    excluded: List[Path] = []
    for directory in dirs:
        if any(_at_or_below(directory, done) for done in excluded):
            continue
        committed = held[directory]
        if not committed:
            excluded.append(directory)
            continue
        own_names = ash_own_dir_names()
        if workspace is not None and _same_directory(directory, workspace):
            own_names += _workspace_own_dir_names()
        for name in own_names:
            own = directory / name
            # Compared as the filesystem compares names (output_name_key): on
            # macOS a committed Reports/x.md is inside the reports/ a scan
            # clears, and an exact comparison excluded the directory over it.
            if not any(_at_or_below(path, own) for path in committed):
                excluded.append(own)
    return excluded


def _workspace_own_dir_names() -> Tuple[str, ...]:
    """The directories a workspace scan fills under its own output directory:
    every project's output and the aggregator's spool (``output_dir_links``).

    Only for the workspace's output directory, when it holds a committed file: the
    directory is then not excluded whole, and without these every project's
    reports and scanner outputs under ``projects/`` reached the tools. Not among
    :func:`ash_own_dir_names`, since a single-directory scan neither clears nor
    writes them, so a committed ``projects/`` in its output directory is no reason
    to refuse the scan.
    """
    # Imported here: output_dir_links imports this module lazily for its git read.
    from automated_security_helper.utils.output_dir_links import WORKSPACE_OUTPUT_DIRS

    return WORKSPACE_OUTPUT_DIRS


def _name_keys(path: Path) -> Tuple[str, ...]:
    """*path*'s parts, each as its filesystem compares it (:func:`output_name_key`)."""
    return tuple(output_name_key(part) for part in path.parts)


def _at_or_below(path: Path, directory: Path) -> bool:
    """Whether *path* is *directory* or below it, each name compared as the
    filesystem compares it (:func:`output_name_key`)."""
    keys, prefix = _name_keys(path), _name_keys(directory)
    return keys[: len(prefix)] == prefix


def ash_own_dir_names() -> Tuple[str, ...]:
    """The directories ASH creates in its output directory and fills with its own files.

    The working directories a scan clears and fills (:data:`WORKING_DIR_NAMES`),
    where an MCP scan sets the previous results aside, whole or part way, and
    where a restore stages them on the way back (``core/previous_results.py``):
    every name a scan deletes or moves, so the committed-output refusal and the
    output-directory exclusions cover each one.
    """
    # Imported here: core.previous_results is above this module.
    from automated_security_helper.core.previous_results import (
        HELD_DIR_NAME,
        RESTORING_DIR_NAME,
    )

    return (
        *WORKING_DIR_NAMES,
        HELD_DIR_NAME,
        f"{HELD_DIR_NAME}.partial",
        RESTORING_DIR_NAME,
    )


def output_dirs_inside(dirs: Sequence[Path], target: str | Path) -> List[Path]:
    """The entries of *dirs* strictly inside *target*, relative to it.

    A directory that is *target* or contains it is left out. That is the converted
    target, ``work_dir``, which lives under the current output directory:
    excluding the output directory there would exclude everything the converters
    produced.
    """
    target_abs = _absolute(target)
    inside: List[Path] = []
    for directory in dirs:
        # Names compared as the filesystem compares them (_parts_below), never
        # relative_to: on macOS a directory spelled in another case than the
        # target was placed inside and then raised ValueError here.
        below = _parts_below(directory, target_abs)
        if below:
            inside.append(Path(*below))
    return inside


def output_dir_exclude_globs(relatives: Sequence[Path]) -> List[str]:
    """``--exclude`` values for grype and syft naming each of *relatives*.

    Both resolve an exclusion relative to the scanned directory only when it
    begins with ``./``, ``*/`` or ``**/``; an absolute path matches nothing in a
    directory scan. ``./out/**`` is the documented way to skip everything under
    ``out`` (syft's file selection guide; grype shares syft's file selection). The
    relative path is escaped (:func:`escape_for_pattern`): ``./out[1]/**`` skipped a
    directory ``out1`` and scanned ``out[1]``.

    Known limitation, in syft itself (1.54.1): it prepends the scanned directory's
    absolute path to the pattern without escaping it, so when that path holds a
    ``[`` or a ``{`` no exclusion matches anything. The directory is then scanned.
    grype writes SARIF, and ASH drops the findings located in it after the scan;
    syft writes an SBOM, which nothing filters, so the components syft finds in
    ASH's own files there stay in it.
    """
    return [
        f"./{escape_for_pattern(relative.as_posix(), PatternSyntax.GLOB, separator='/')}/**"
        for relative in relatives
    ]


def _result_paths(result: Any, source: Path) -> Iterable[Path]:
    """The resolved path of each of *result*'s locations that names a file.

    Expects URIs already made relative to *source*, as ``sanitize_sarif_paths``
    leaves them; a ``file://`` URI is read as the path it names, with the parser
    that function uses, and any other scheme is skipped.

    A relative URI is a URI reference, and a tool may percent-encode it: checkov
    3.3.26 writes ``out(1)/x.tf`` as ``out%281%29/x.tf``, which
    ``sanitize_sarif_paths`` leaves encoded. Read literally, that path named no
    directory, and a finding in an output directory named ``out(1)`` stayed in
    the results. The decoded path is used unless the URI names a file as it is
    written, as it does when a tool did not encode a name holding a ``%``. It is
    decoded as the filesystem decodes a name (surrogateescape), as the ``file://``
    parser decodes its path: ``unquote``'s default replaced a byte that is not
    UTF-8 with U+FFFD, so the decoded path of a committed file whose name is not
    UTF-8 matched no file and its result was placed nowhere. A ``file:`` URI with
    no authority (``file:/abs/x``, which RFC 8089 admits) is read as the path it
    names too; read as a relative path it was joined under the source.

    A URI holds a file name that is not UTF-8 in its record form, each lone
    surrogate as ``\\udcNN`` (utils/undecodable_text.py). It is resolved by the
    name the file has on disk and yielded in the record form, so callers compare
    it with their directories in that form.

    A reading that cannot be resolved -- the decoded form of a uri holding
    ``%00`` resolves a NUL (``ValueError``), a symlink loop raises
    ``RuntimeError`` on CPython 3.10-3.12 -- names no file and is skipped
    (``utils.undecodable_text.resolve_uri_reading``). Both callers run per
    scanner result inside the scan, so one such location must place the result
    nowhere rather than raise out of the loop.
    """
    # Imported here because sarif_utils imports the models, which this low-level
    # module must not.
    from automated_security_helper.utils.sarif_utils import _file_uri_to_path_text

    for location in getattr(result, "locations", None) or []:
        physical = getattr(location, "physicalLocation", None)
        root = getattr(physical, "root", physical)
        artifact = getattr(root, "artifactLocation", None)
        uri = getattr(artifact, "uri", None)
        if not uri:
            continue
        if uri.startswith("file:"):
            uri = _file_uri_to_path_text(uri)
        elif "://" in uri:
            continue
        else:
            decoded = unquote(uri, errors="surrogateescape")
            if decoded != uri and not _names_a_file(source / undecodable_of_text(uri)):
                uri = decoded
        resolved = resolve_uri_reading(uri, base=source)
        if resolved is None:
            continue
        yield path_in_record_form(resolved)


def _names_a_file(path: Path) -> bool:
    """Whether something exists at *path*; False when the question cannot be asked.

    ``Path.exists`` raises on CPython 3.10-3.12 for a name the filesystem cannot
    look up at all: a component longer than NAME_MAX (a percent-encoded name is
    up to three times its decoded length), or one holding a NUL. Such a path
    names no file, and the caller runs once per scanner result inside the scan,
    so the answer is False rather than an exception out of the loop.
    """
    try:
        return path.exists()
    except (OSError, ValueError):
        return False


def _work_dir_of(context: Any) -> Path:
    work_dir = getattr(context, "work_dir", None)
    if work_dir is None:
        work_dir = Path(context.output_dir).joinpath(ASH_WORK_DIR_NAME)
    return Path(work_dir).resolve()


def mark_converted_results(sarif_report: Any, context: Any) -> int:
    """Record, on each result located in a converted file, that file's path.

    The path relative to the converted root (``work_dir``), as the result property
    ``converted_path``: the finding's identity is keyed by it, so that its id does
    not depend on where the output directory is (measured: ``--output-dir out1``
    and ``out2`` gave a converted notebook's findings different ids). The URI is
    left as it is, since it is where the converted file is.

    Returns:
        The number of results marked.
    """
    from automated_security_helper.schemas.sarif_schema_model import PropertyBag
    from automated_security_helper.utils.finding_identity import (
        CONVERTED_PATH_PROPERTY,
    )

    runs = getattr(sarif_report, "runs", None) or []
    if not runs or getattr(context, "output_dir", None) is None:
        return 0
    source = Path(context.source_dir).resolve()
    # _result_paths yields the record form, so the work directory is compared,
    # and the recorded relative path is written, in that form.
    work = path_in_record_form(_work_dir_of(context))
    marked = 0
    for run in runs:
        for result in getattr(run, "results", None) or []:
            for candidate in _result_paths(result, source):
                if candidate == work or not candidate.is_relative_to(work):
                    continue
                relative = candidate.relative_to(work).as_posix()
                if result.properties is None:
                    result.properties = PropertyBag()
                # An extra property: PropertyBag allows them, and the workspace
                # aggregator's workspace_project is one too.
                setattr(result.properties, CONVERTED_PATH_PROPERTY, relative)
                marked += 1
                break
    return marked


#: Written by a converter beside its output, at the top of its results directory:
#: a JSON object mapping each path it wrote, relative to the work directory with
#: ``/`` (the form ``mark_converted_results`` records as ``converted_path``), to the
#: path in the scanned tree it was converted from. A key ending in ``/`` names a
#: directory, and every file below it was converted from that one source (the
#: members of an extracted archive). ``converted_sources_of`` reads every
#: converter's file back for the ``--changed-files-only`` filter, which places a
#: finding in a converted file by the source named here.
CONVERTED_SOURCES_FILE_NAME = "converted-sources.json"


def record_converted_sources(
    results_dir: str | Path, work_dir: str | Path, sources: Mapping[Path, str]
) -> Optional[Path]:
    """Write a converter's converted-path -> source mapping beside its output.

    *sources* maps each file or directory the converter wrote, as it wrote it, to
    the path in the scanned tree it was converted from (relative to the tree with
    ``/``, as ``scanned_tree.relative_display`` gives it). The file is
    :data:`CONVERTED_SOURCES_FILE_NAME` under *results_dir*; its keys are the
    written paths relative to *work_dir*, a directory's with a trailing ``/``, so
    they are the ``converted_path`` a finding in that file carries. That property
    is written in the record form (:func:`path_in_record_form`: a name that is
    not UTF-8 holds each lone surrogate as the text ``\\udcNN``), so the keys are
    too; a key holding the surrogate itself matched no finding, and the filter
    could not place a converted file whose name is not UTF-8. A path outside
    *work_dir* is left out, since no finding carries it. Nothing is written for an
    empty mapping.

    Returns:
        The file written, or None when nothing was written: an empty mapping, or a
        write that failed. A failed write is logged and never fails the
        conversion: the converted files are still scanned, and the filter then
        keeps their findings and says so, which is the behavior before this file.
    """
    from automated_security_helper.utils.sandbox.fs_guard import open_for_write

    # Both sides in the record form, as mark_converted_results compares them, so
    # the key is the converted_path it writes, byte for byte.
    work = path_in_record_form(Path(work_dir).resolve())
    recorded: Dict[str, str] = {}
    for written, source in sources.items():
        try:
            resolved = path_in_record_form(Path(written).resolve())
            relative = resolved.relative_to(work).as_posix()
        except (OSError, ValueError):
            continue
        if not relative or relative == ".":
            continue
        if Path(written).is_dir():
            relative += "/"
        recorded[relative] = source
    if not recorded:
        return None
    target = Path(results_dir).joinpath(CONVERTED_SOURCES_FILE_NAME)
    try:
        # The keys are in the record form, so the file holds text only: a name
        # that is not UTF-8 is written as the text ``\\udcNN``, never as a lone
        # surrogate, and reads back as the same text.
        data = json.dumps(recorded, sort_keys=True, indent=2).encode("utf-8")
        with open_for_write(target, binary=True, mode=0o644, make_parents=True) as out:
            out.write(data)
    except OSError as error:
        ASH_LOGGER.warning(
            f"Could not record the sources of the converted files in "
            f"{Path(results_dir).name}/{CONVERTED_SOURCES_FILE_NAME} "
            f"({type(error).__name__}: {error.strerror or error}); a "
            "--changed-files-only scan keeps their findings rather than placing "
            "them by their sources"
        )
        return None
    return target


def converted_sources_of(context: Any) -> Dict[str, str]:
    """Every converter's converted-path -> source mapping of the run, merged.

    Read from :data:`CONVERTED_SOURCES_FILE_NAME` at the top of each directory
    under the work directory (one per converter, as :func:`record_converted_sources`
    writes it). The keys are ``converted_path`` values (relative to the work
    directory, ``/``-separated, a directory's with a trailing ``/``) and the
    values paths in the scanned tree. A file that cannot be read or is not a JSON
    object of strings is skipped with a warning, and an entry that is not a pair
    of non-empty strings is left out: the filter then keeps the findings it cannot
    place and says so, rather than one bad file failing the scan.

    Empty for a context with no work directory and no output directory to derive
    one from, and for a work directory that does not exist.
    """
    if (
        getattr(context, "work_dir", None) is None
        and getattr(context, "output_dir", None) is None
    ):
        return {}
    work = _work_dir_of(context)
    try:
        converter_dirs = sorted(
            entry
            for entry in work.iterdir()
            if entry.is_dir() and not entry.is_symlink()
        )
    except OSError:
        return {}
    mapping: Dict[str, str] = {}
    for converter_dir in converter_dirs:
        file = converter_dir.joinpath(CONVERTED_SOURCES_FILE_NAME)
        if file.is_symlink() or not file.is_file():
            continue
        try:
            data = json.loads(file.read_bytes().decode("utf-8"))
        except (OSError, ValueError):
            # The failure's text is logged through logging's own exception
            # rendering, once, at DEBUG; the warning names the file and what the
            # filter does without it.
            ASH_LOGGER.warning(
                f"Skipped {converter_dir.name}/{CONVERTED_SOURCES_FILE_NAME}: it "
                "could not be read as the converter's record of what it "
                "converted; the --changed-files-only filter keeps that "
                "converter's findings rather than placing them by their sources"
            )
            ASH_LOGGER.debug(
                f"Why {converter_dir.name}/{CONVERTED_SOURCES_FILE_NAME} could not "
                "be read",
                exc_info=True,
            )
            continue
        if not isinstance(data, dict):
            ASH_LOGGER.warning(
                f"Skipped {converter_dir.name}/{CONVERTED_SOURCES_FILE_NAME}: it "
                "is not a JSON object; the --changed-files-only filter keeps that "
                "converter's findings rather than placing them by their sources"
            )
            continue
        for key, value in data.items():
            if isinstance(key, str) and key and isinstance(value, str) and value:
                mapping[key] = value
    return mapping


def scan_set_of(context: Any) -> List[str]:
    """The scan set of the run *context* belongs to; empty only for no output dir.

    The list the orchestrator wrote to the output directory before any scanner
    ran, under the run's ID (``context.run_id``), which is what every scanner that
    takes a file list reads; built here when the run wrote none (a scanner run on
    its own).

    A list that cannot be read or built raises ScanSetUnreadableError, which names
    the error. It returned an empty list, so the scanner asking was told nothing
    was in scope and scanned as though the tree were empty. The error is not an
    OSError or a ValueError, so the scanners' handlers that read those as
    "nothing to exclude" let it through: the scanner stops, and the scan exits 1
    with it incomplete.
    """
    from automated_security_helper.utils.get_scan_set import (
        honors_ignore_files,
        scan_set,
    )

    output_dir = getattr(context, "output_dir", None)
    if output_dir is None:
        return []
    try:
        workspace_output_dir = getattr(context, "workspace_output_dir", None)
        return scan_set(
            source=str(context.source_dir),
            output=str(output_dir),
            run_id=getattr(context, "run_id", None),
            honor_ignore_files=honors_ignore_files(getattr(context, "config", None)),
            workspace_output_dir=(
                None if workspace_output_dir is None else str(workspace_output_dir)
            ),
        )
    except (OSError, ValueError) as error:
        raise ScanSetUnreadableError(
            f"The scan set could not be read, so this scanner does not run on an "
            f"empty one: {type(error).__name__}: {error}"
        ) from error


def committed_output_files(
    context: Any,
    scanned_files: Optional[Iterable[str | Path]] = None,
    dirs: Optional[Sequence[Path]] = None,
) -> Set[Path]:
    """The files a repository committed to ASH's output directories, resolved.

    The files of the scan set inside *dirs*, :func:`named_output_dirs` when not
    given. In a named directory the scan set holds only the files git tracks
    (``get_scan_set``), so a result located in one of these is a finding about the
    repository, wherever the step that reads it would otherwise drop results in
    ASH's output. *scanned_files* is the scan set.

    When it is not given, the list this run wrote is read, if it is there intact:
    in a scan, that is the list every scanner reading the scan set was given.
    Otherwise git is asked which files it tracks in each directory
    (:func:`tracked_files_in`), which is what the scan-set walk asks it, so the
    same files are kept with no walk of the source tree and nothing written to the
    output directory. ``ash merge`` builds its context with no run ID, so it never
    reads a list back (``get_scan_set.scan_set_this_run_wrote``) and always asks
    git, so it neither walks its working directory nor writes list files into the
    merge output. Outside git that answer is that nothing is committed.

    Empty when the directories cannot be named; the caller then drops what it
    would have dropped before committed files were kept.
    """
    from automated_security_helper.utils.get_scan_set import scan_set_this_run_wrote

    if dirs is None:
        try:
            dirs = named_output_dirs_of(context)
        except (OSError, TypeError, ValueError):
            # The failure's text is logged through logging's own exception
            # rendering, once.
            ASH_LOGGER.debug("Could not name ASH's output directories", exc_info=True)
            return set()
    if not dirs:
        return set()
    if scanned_files is None:
        output_dir = getattr(context, "output_dir", None)
        scanned_files = (
            None
            if output_dir is None
            else scan_set_this_run_wrote(output_dir, getattr(context, "run_id", None))
        )
    if scanned_files is None:
        return {
            path.resolve()
            for directory in dirs
            for path in tracked_files_in(directory) or []
        }
    return {
        path.resolve()
        for files in scanned_files_in(dirs, scanned_files).values()
        for path in files
    }


def drop_results_in_ash_output_dirs(
    sarif_report: Any,
    context: Any,
    scanner_name: str = "scanner",
    scanned_files: Optional[Iterable[str | Path]] = None,
) -> int:
    """Remove the results of *sarif_report* located in one of ASH's output dirs.

    For a scanner whose tool cannot be told to skip a directory, or was not: the
    findings it reported about ASH's own reports are not findings about the
    scanned tree. Only the directories :func:`named_output_dirs` names, so a
    directory that merely holds ASH-like files keeps its findings, and a result in
    a file of the scan set is kept: in a named directory those are the files git
    tracks. *scanned_files* is the scan set, read with :func:`scan_set_of` when
    not given. Expects URIs already made relative to the source directory, as
    ``sanitize_sarif_paths`` leaves them; a ``file://`` URI is read as the path it
    names. Results under the current ``work_dir`` are kept, because those are the
    converted files.

    Returns:
        The number of results removed.
    """
    runs = getattr(sarif_report, "runs", None) or []
    if not runs:
        return 0
    try:
        dirs = named_output_dirs_of(context)
    except (OSError, TypeError, ValueError):
        # The failure's text is logged through logging's own exception
        # rendering, once.
        ASH_LOGGER.debug("Could not name ASH's output directories", exc_info=True)
        return 0
    if not dirs:
        return 0
    source = Path(context.source_dir).resolve()
    # _result_paths yields the record form, so the directories and the committed
    # files are compared in that form too, and each name as the filesystem
    # compares it (output_name_key): on macOS a result reported at the on-disk
    # spelling of a committed file git lists in another case is that file, and
    # a result under the output directory spelled in another case is in it.
    resolved_dirs = [path_in_record_form(directory.resolve()) for directory in dirs]
    committed = {
        _name_keys(path_in_record_form(path))
        for path in committed_output_files(context, scanned_files, dirs)
    }
    work = path_in_record_form(_work_dir_of(context))

    def in_output(result: Any) -> bool:
        # Decided by the first location that names a file: SARIF's first
        # location is the one the result is about. A result whose first location
        # is a file of the scanned tree is a finding about the tree, whatever a
        # later (related) location points at, and was dropped when that later
        # location sat in an output directory.
        for candidate in _result_paths(result, source):
            if _at_or_below(candidate, work):
                return False
            if any(_at_or_below(candidate, d) for d in resolved_dirs):
                return _name_keys(candidate) not in committed
            return False
        return False

    removed = 0
    for run in runs:
        results = getattr(run, "results", None)
        if not results:
            continue
        kept = [result for result in results if not in_output(result)]
        removed += len(results) - len(kept)
        run.results = kept
    # WARNING, as the suppression step's exclusion of the output directory is: this
    # pass can remove any number of results, and the count is what tells an
    # operator their result set shrank. It applies whatever --ignore-suppressions
    # says, because these are ASH's own reports and not suppressed findings.
    if removed:
        ASH_LOGGER.warning(
            f"Dropped {removed} {scanner_name} "
            f"{'finding' if removed == 1 else 'findings'} located in ASH's output "
            f"directories ({', '.join(d.as_posix() for d in dirs)}). These are "
            f"reports ASH wrote, not findings about the scanned tree."
        )
    return removed
