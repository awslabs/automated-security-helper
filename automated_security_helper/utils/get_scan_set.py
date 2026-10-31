#!/usr/bin/env python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import codecs
import hashlib
import io
import json
import re
import shutil
import stat
import subprocess  # nosec B404
import sys
import threading
import uuid
from typing import (
    AbstractSet,
    Any,
    Collection,
    Dict,
    Iterable,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
)
from igittigitt import IgnoreParser
from igittigitt import igittigitt as _igittigitt_module
from pathlib import Path, PurePosixPath
import argparse
import os

from automated_security_helper.utils.atomic_write import (
    write_bytes_atomically,
    write_text_atomically,
)
from automated_security_helper.utils.output_dir_links import OUTPUT_GITIGNORE
from automated_security_helper.utils.scan_output_dirs import (
    SCAN_SET_RUN_FILE_NAME,
    SCAN_START_FILE_NAMES,
    _through_a_link_in_the_tree,
    classified_output_dirs,
    holds_ash_output,
    tracked_files_in,
    warn_about_committed_files,
    warn_about_look_alike,
    warn_about_scanned_output_dir,
)
from automated_security_helper.utils.error_text import redact_then_split
from automated_security_helper.utils.git_command import git_argv, resolved_git
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.scanned_tree import (
    REASON_LINK_LEAVES_TREE,
    TreeInputRefused,
    open_in_scanned_tree,
    relative_display,
    resolves_inside,
)
from automated_security_helper.utils.terminal_text import shown_not_obeyed

ASH_INCLUSIONS = [
    ".git",
    "**/cdk.out/asset.*",
    "!**/*.template.json",  # CDK output template default path pattern
]

# Names used in the per-ignore-file exclusion report for the two sources of
# exclusions that are not a user's ignore file. Both remove files from the scan
# set, so both have to appear in the report: a count that left them out would not
# add up to the number of files actually removed.
ASH_INCLUSIONS_MARKER = "ASH_INCLUSIONS"
BUNDLED_CDK_MARKER = "node_modules/aws-cdk (ASH built-in exclusion)"

# The lines that wrap each ignore file's text in ash-ignore-report.txt, around the
# name of the file the block came from. Written and read through these constants
# only, and read exactly (prefix and suffix, nothing searched for in between): a
# directory name may contain "START CONTENTS:" or "#########" on Linux and macOS,
# and searching the line for the token read such a name as the marker's end.
MARKER_SUFFIX = " #########"
START_MARKER_PREFIX = "######### START CONTENTS: "
END_MARKER_PREFIX = "######### END CONTENTS: "
#: The line that stands in the report for an ignore file that was found and not read.
SKIPPED_MARKER_PREFIX = "######### SKIPPED: "
SOURCE_DIR_TOKEN = "${SOURCE_DIR}/"

# The file names ASH reads as ignore files when it walks the scanned tree.
IGNORE_FILE_NAMES = frozenset({".ignore", ".gitignore"})

# What compiling or matching one ignore rule can raise in igittigitt: a pattern
# its glob translation refuses. Caught per rule wherever a rule is added or
# matched, so one bad line costs that rule and not the scan.
_IGNORE_RULE_ERRORS = (ValueError, TypeError, IndexError, re.error)

# Written into ash-ignore-report.txt in place of the repository's ignore files when
# the operator turned them off, so the report says why they are missing from it.
# A comment line: get_ash_ignorespec_with_attribution skips it.
NOT_HONORED_REPORT_LINE = (
    "######### NOT HONORED: the scanned repository's .gitignore and .ignore files "
    "(honor_ignore_files: false) #########"
)

# The characters that count as a path separator when a posix-shaped literal has to
# be tested against a path ``os.walk`` built. ``os.walk`` joins with ``os.sep``, so
# every walked path on Windows is ``\``-separated, while a ``--ignorefile`` value or
# a replayed ``ash-ignore-report.txt`` may use ``/`` on the same host.
#
# Read off ``os`` rather than hardcoded to both, so the POSIX answer is unchanged:
# ``\`` is a legal character in a POSIX filename, and treating it as a separator
# there would rewrite a directory that really is named ``node_modules\aws-cdk``.
# The two functions below take it as an argument for the same reason the value is
# derived here rather than inlined -- passing the Windows set is the only way to
# measure the Windows answer from a POSIX host, and both of these were wrong on
# Windows for exactly as long as that was untestable.
_PATH_SEPARATORS = os.sep if os.altsep is None else os.sep + os.altsep


def red(msg) -> str:
    return "\033[91m{}\033[00m".format(msg)


def green(msg) -> str:
    return "\033[92m{}\033[00m".format(msg)


def yellow(msg) -> str:
    return "\033[33m{}\033[00m".format(msg)


def lightPurple(msg) -> str:
    return "\033[94m{}\033[00m".format(msg)


def purple(msg) -> str:
    return "\033[95m{}\033[00m".format(msg)


def cyan(msg) -> str:
    return "\033[96m{}\033[00m".format(msg)


def gray(msg) -> str:
    return "\033[97m{}\033[00m".format(msg)


def black(msg) -> str:
    return "\033[98m{}\033[00m".format(msg)


def debug_echo(*msg, debug: bool = False) -> str | None:
    message = " ".join(str(m) for m in msg)
    if debug:
        # NO_MARKUP, as for every line here that carries a path: a "[/" in
        # one is a closing Rich tag that raises instead of printing.
        ASH_LOGGER.debug(message, extra=NO_MARKUP)
    return message


def _with_posix_separators(path: str, separators: str) -> str:
    """*path* with each character of *separators* rewritten to ``/``."""
    for separator in separators:
        path = path.replace(separator, "/")
    return path


def _source_dir_marker(
    source_dir: str | Path,
    file_path: str,
    *,
    separators: str = _PATH_SEPARATORS,
) -> str:
    r"""Name *file_path* with the ``${SOURCE_DIR}`` token when it sits under *source_dir*.

    The token is what makes a marker mean anything to a second reader.
    :func:`get_ash_ignorespec` reads it back to derive each rule's base path, and
    :func:`report_ignore_file_exclusions` keys its per-ignore-file counts off the
    same text. A marker holding an absolute host path still compiles, but it names
    one machine's directory inside an artifact meant to be replayable against
    another checkout, and it makes the exclusion report label a temp directory
    instead of the ignore file the user wrote.

    The derivation this replaced compared ``Path(source_dir).as_posix()`` against a
    raw *file_path*. Those are the same string on POSIX and different on Windows,
    where ``os.walk`` joins with ``\``: the anchor could not match, no substitution
    happened, and every marker on Windows carried an absolute path.

    Normalizing only the subject was tried and reverted. ``PurePath`` drops a
    leading ``./``, so ``Path("./sub/.gitignore").as_posix()`` is
    ``sub/.gitignore`` and a relative scan root's anchor stopped matching; for
    ``./.gitignore`` the ``^\.`` anchor then matched the filename's own dot and
    emitted ``${SOURCE_DIR}gitignore``. Here the prefix is compared raw -- *file_path*
    was built by joining onto *source_dir*, so the two agree character for
    character whatever shape the caller passed -- and only the remainder is
    rewritten. The separator between token and remainder is written out rather
    than salvaged from the strip, so no input can lose it.

    The remainder has to begin at a separator. A bare prefix test would rewrite
    ``/project/.gitignore`` under a ``/proj`` scan root into
    ``${SOURCE_DIR}ect/.gitignore``, which an absolute ``--ignorefile`` naming a
    sibling directory reaches.

    Args:
        source_dir: The scan root, in whatever form the caller passed it --
            absolute or relative, with or without a trailing separator.
        file_path: A path built by joining onto *source_dir*, normally by
            ``os.walk``.
        separators: Characters to treat as path separators, defaulting to the
            host's.

    Returns:
        ``${SOURCE_DIR}/<posix relative path>`` for a path inside *source_dir*;
        otherwise *file_path* with posix separators, which
        :func:`get_ash_ignorespec` reads through its absolute-marker branch and
        :func:`_confine_base_path` then scopes back into the tree.
    """
    root = str(source_dir)
    if root and file_path.startswith(root):
        remainder = file_path[len(root) :]
        separator_tuple = tuple(separators)
        if remainder.startswith(separator_tuple) or root.endswith(separator_tuple):
            relative = _with_posix_separators(remainder, separators).lstrip("/")
            if relative:
                return f"${{SOURCE_DIR}}/{relative}"
    return _with_posix_separators(file_path, separators)


def _is_bundled_cdk_path(
    file_path: str,
    *,
    separators: str = _PATH_SEPARATORS,
) -> bool:
    r"""True when *file_path* sits inside the vendored ``node_modules/aws-cdk`` tree.

    ASH bundles aws-cdk so that ``cdk synth`` can run, and CDK carries
    CloudFormation templates of its own as test fixtures. Those are not the user's
    infrastructure, so they stay out of the scan set; otherwise a CDK project's
    findings are diluted by its dependency's fixtures.

    This carve-out is the *only* thing keeping those templates out, which is worth
    stating because :func:`get_files_not_matching_spec` reads as though the ignore
    spec were also involved. It is not: nothing excludes a bundled template in the
    first place, so ``spec.match`` is False for it and the forced-inclusion pass on
    ``!**/*.template.json`` is never consulted. Remove this test and the templates
    are scanned, whatever the rest of the function does.

    The check this replaced was ``"/node_modules/aws-cdk" in file_path``, against a
    path ``os.walk`` joined with ``\`` on Windows -- so it matched nothing there and
    the carve-out was dead on the one platform where it was silently dead rather
    than loudly wrong.

    Kept as a substring test rather than a path-components test so the POSIX answer
    is byte for byte what it was, including that it also covers sibling packages
    whose names merely begin with ``aws-cdk``. Narrowing that would change which
    files POSIX scans and is a separate decision from making the platforms agree.
    """
    return "/node_modules/aws-cdk" in _with_posix_separators(file_path, separators)


def _is_bundled_cdk_below(walked: str | Path, root_absolute: str) -> bool:
    """:func:`_is_bundled_cdk_path` for *walked*, judged by its path below the scan root.

    The carve-out is for the aws-cdk tree that sits inside the code being scanned.
    Tested on the whole path, a scan root that itself lies below a
    ``node_modules/aws-cdk*`` directory left every file out of the scan set, and
    the answer changed with how the source was spelled: ``.`` inside that
    directory read as outside it, the absolute path of the same directory as inside.
    *root_absolute* is the scan root, made absolute.

    The root's own last component is kept in front of the path below it: a scan
    root that is itself a ``node_modules`` directory holds ``aws-cdk/...``, which is
    the bundled tree, and without the root's name the test would never see the
    ``/node_modules`` before it. Only that one component is kept, not the ones
    above it, so a root below ``node_modules/aws-cdk-lib`` still scans.
    """
    relative = os.path.relpath(os.path.abspath(walked), root_absolute)
    return _is_bundled_cdk_path("/" + os.path.basename(root_absolute) + "/" + relative)


def _bundled_cdk_in(parts: Sequence[str], root_name: str = "") -> bool:
    """:func:`_is_bundled_cdk_path` for a path given as its components below the root.

    *root_name* is the scan root's last component, as :func:`_is_bundled_cdk_below`
    keeps it; empty when the caller has no root.
    """
    return _is_bundled_cdk_path("/" + root_name + "/" + "/".join(parts), separators="/")


#: Whether this is Windows. Read where an answer is given for Windows alone, so a
#: test can stand it in.
_WINDOWS = sys.platform == "win32"


#: The reparse tag of a mount point, which is what a junction is. ``stat`` defines
#: the name on Windows builds only, so the value is spelled here (the Windows
#: header's mount-point tag, 0xA in the top four bits and 3 in the low bits) for the
#: platforms where a test hands the check a status of its own.
_IO_REPARSE_TAG_MOUNT_POINT = getattr(
    stat, "IO_REPARSE_TAG_MOUNT_POINT", (0xA << 28) | 3
)


def _is_junction_status(status: "os.stat_result") -> bool:
    """Whether *status*, an ``lstat``, is a Windows junction: a mount-point reparse point."""
    attributes = getattr(status, "st_file_attributes", 0)
    if not attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    return getattr(status, "st_reparse_tag", 0) == _IO_REPARSE_TAG_MOUNT_POINT


def _is_junction(path: str | Path) -> bool:
    """Whether *path* is a Windows junction.

    ``os.path.isjunction`` where Python has it (3.12 and later). Before that it is
    read from the reparse tag of an ``lstat``, on Windows alone: the function is
    absent on 3.10 and 3.11, which the package supports, and it answered False for
    every junction there, so the walks documented as never following a link followed
    junctions.
    """
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None:
        return bool(isjunction(path))
    if not _WINDOWS:
        return False
    try:
        return _is_junction_status(os.lstat(path))
    except (OSError, ValueError):
        return False


def _is_link_to_directory(path: str | Path) -> bool:
    """Whether *path* is a symlink, or a Windows junction, rather than a real directory.

    ``os.walk`` lists such an entry among the directories and does not descend it,
    so nothing behind it is ever in the scan set.
    """
    return bool(os.path.islink(path) or _is_junction(path))


def _entry_is_link_to_directory(entry: "os.DirEntry[str]") -> bool:
    """:func:`_is_link_to_directory` for a ``scandir`` entry, from what it holds.

    ``entry.is_symlink()`` answers from the listing's cached ``lstat``, where
    ``os.path.islink`` runs one ``lstat`` per entry: for a tree of regular files
    that was one system call per file, repeated by every scanner that walks the
    tree through :func:`file_links_leaving_tree`. The junction test is
    ``os.path.isjunction``, read off ``os.path`` when called as
    :func:`_is_link_to_directory` reads it (a test stands one in); on POSIX it
    answers without a system call. Where Python has none (3.10 and 3.11) the
    entry's own status gives the answer, on Windows only, where a listing holds it.
    """
    if entry.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None:
        return bool(isjunction(entry.path))
    if not _WINDOWS:
        return False
    try:
        return _is_junction_status(entry.stat(follow_symlinks=False))
    except OSError:
        return False


def _warn_directory_not_listed(error: OSError) -> None:
    """``os.walk``'s *onerror*: say that a directory could not be listed.

    Without one ``os.walk`` goes on without a word, so a directory the scanning
    user cannot list was left out of the scan set with nothing logged.
    """
    ASH_LOGGER.warning(
        "Not scanning the contents of %r: it could not be listed (%s), so none of "
        "its files are in the scan set.",
        str(error.filename),
        error.strerror or type(error).__name__,
        extra=NO_MARKUP,
    )


def _walk_without_link_directories(top: str | Path, onerror=None):
    """``os.walk(top)`` that never descends a link or junction to a directory.

    ``os.walk`` lists a symlink to a directory among the directories without
    descending it on every interpreter, but a Windows junction is a directory to
    the ``os.walk`` of Python 3.10 and 3.11 (3.12 stopped following junctions), so
    a junction that points outside the scan root put everything behind it into
    the scan set, and one that points at an ancestor recursed. Each such entry is
    taken out of the directory list before ``os.walk`` reaches it. The lists are
    the ones ``os.walk`` yields, so a caller that prunes ``dirs`` in place still
    prunes the walk.

    *onerror* is passed to ``os.walk``: called with the ``OSError`` for a directory
    that could not be listed. The walks that build the scan set pass
    :func:`_warn_directory_not_listed`; the ones that only count files do not, since
    the walk that builds the set has said so already.
    """
    for root, dirs, files in os.walk(top, onerror=onerror):
        dirs[:] = [d for d in dirs if not _is_link_to_directory(os.path.join(root, d))]
        yield root, dirs, files


def _walk_unless_link(top: str | Path):
    """``os.walk(top)``, or nothing when *top* is a link or junction to a directory.

    ``os.walk`` lists a link to a directory below its top without descending it,
    but it follows one given as the top. Every walk that counts files ASH did not
    scan goes through here, so a link the repository placed, at any depth, is
    never followed: nothing behind it is in a scan set, honored or not, and
    following it would read wherever the link points, outside the tree included.
    Below the top, a junction is left out too (:func:`_walk_without_link_directories`).
    """
    if _is_link_to_directory(top):
        return iter(())
    return _walk_without_link_directories(top)


def _is_file_link_leaving_the_tree(full_path: str, root: str) -> bool:
    """Whether *full_path* is a link whose target, every link resolved, is outside *root*."""
    return os.path.islink(full_path) and not resolves_inside(full_path, root)


def _names_of_links_in(directory: str) -> Optional[Set[str]]:
    """The names of the symlinks directly in *directory*, from one listing of it.

    ``entry.is_symlink()`` answers from the listing itself, where
    ``os.path.islink`` runs one ``lstat`` per file: a pruned ``node_modules`` holds
    hundreds of thousands, on file systems where each call is slow. None when the
    directory cannot be listed again, and the caller asks of each file instead.
    """
    try:
        with os.scandir(directory) as entries:
            return {entry.name for entry in entries if entry.is_symlink()}
    except OSError:
        return None


def _file_link_leaves_the_tree(
    directory: str, name: str, links: Optional[Set[str]], root: str
) -> bool:
    """:func:`_is_file_link_leaving_the_tree` for *name* in *directory*, given its *links*.

    *links* is :func:`_names_of_links_in` for *directory*: a name not in it is not a
    symlink and costs no system call; None asks of the file itself.
    """
    full_path = os.path.join(directory, name)
    if links is None:
        return _is_file_link_leaving_the_tree(full_path, root)
    return name in links and not resolves_inside(full_path, root)


def _left_out_as_a_link_leaving_the_tree(
    full_path: str, root: str, links_not_scanned: Optional[List[str]]
) -> bool:
    """Whether *full_path* is a file link whose target leaves *root*; if so, say so.

    ``os.walk`` lists a link to a file among the files, and a scanner given the scan
    set opens it by name, which reads wherever the link points. A link the
    repository committed points wherever its author chose, so one whose target, every
    link resolved (:func:`~automated_security_helper.utils.scanned_tree.resolves_inside`),
    is outside the scan root is left out of the scan set. A link to a file inside the
    tree stays, as do links to directories, which the walk does not descend anyway.

    When the answer is yes, a warning names the link by its path below *root*,
    escaped with ``repr``, and not its target, which is outside the tree; and
    *full_path* is appended to *links_not_scanned* when one is given.
    """
    if not _is_file_link_leaving_the_tree(full_path, root):
        return False
    ASH_LOGGER.warning(
        f"Not scanning {relative_display(full_path, root)!r}: {REASON_LINK_LEAVES_TREE}"
    )
    if links_not_scanned is not None:
        links_not_scanned.append(full_path)
    return True


def file_links_leaving_tree(
    root: str | Path,
    all_files: Optional[List[str]] = None,
    directory_links: Optional[List[str]] = None,
) -> List[str]:
    """Every link to a file under *root* whose target leaves it, sorted.

    For scanners that hand their tool a directory to walk (bandit, checkov,
    ferret-scan) and so cannot use the scan set: each passes these to its tool's own
    exclusion option. The walk is the one those tools make, not the scan set's: it
    does not descend a link to a directory (``os.walk`` does not, and neither do
    bandit or checkov 3.3.26), and it honors no ignore file, because the tools walk
    the directories ignore files leave out as well. A link counts as leaving when its
    target, every link resolved, is not strictly below *root* (``resolves_inside``),
    so a dangling link is judged by where it points.

    Args:
        root: The directory the tool is given.
        all_files: Filled, when given, with every file the walk found, links
            included, so a caller can check that an exclusion it builds matches
            nothing else.
        directory_links: Filled, when given, with every link to a directory whose
            target leaves *root*. The walk does not enter these, so a scanner whose
            tool might (snyk-code) refuses on them.

    Returns:
        Paths below *root*, with ``/`` separators.
    """
    links: List[str] = []
    pending = [(os.fspath(root), "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as entries:
                listed = list(entries)
        except OSError:
            continue
        for entry in listed:
            relative = f"{prefix}{entry.name}"
            try:
                if entry.is_dir(
                    follow_symlinks=False
                ) and not _entry_is_link_to_directory(entry):
                    pending.append((entry.path, f"{relative}/"))
                    continue
                # A symlink to a directory, or a Windows junction: on Python 3.12
                # and later a junction is neither a symlink nor, with
                # follow_symlinks=False, a directory to DirEntry, so tested by
                # itself; otherwise it was listed among the files and never
                # recorded as a directory link. From the entry's own cached
                # lstat, not os.path.islink: that was one extra system call per
                # regular file.
                if _entry_is_link_to_directory(entry) and os.path.isdir(entry.path):
                    if directory_links is not None and not resolves_inside(
                        entry.path, root
                    ):
                        directory_links.append(relative)
                    continue
            except OSError:
                continue
            if entry.is_symlink() and not resolves_inside(entry.path, root):
                links.append(relative)
            if all_files is not None:
                all_files.append(relative)
    return sorted(links)


#: The files the running scan has already written at the top of its output directory
#: when the scan set is built: its logs, and the .gitignore it writes there when the
#: directory is inside the tree (output_dir_links.ignore_output_dir_in_git). Not
#: counted among the files found there.
_THIS_RUNS_FILES = frozenset(
    {
        "ash.log",
        "ash.log.jsonl",
        OUTPUT_GITIGNORE,
        # The scan set and ignore report a scan writes there as it starts, and the
        # record of the run that wrote them (:func:`_write_lists`). A walk made
        # while the scan runs finds them, and they are ASH's, not the repository's.
        *SCAN_START_FILE_NAMES,
        SCAN_SET_RUN_FILE_NAME,
    }
)


def _directory_identity(
    path: str | Path, follow_symlinks: bool = False
) -> Optional[tuple[int, int]]:
    """``(st_dev, st_ino)`` of the directory at *path*, or None when it is not one.

    Two spellings of one directory share it: a link in the source path, the bind
    mounts container mode uses (the output at /out and again at
    /src/.ash/ash_output), and a case-only difference on a case-insensitive
    filesystem. Comparing path strings missed all three.
    """
    try:
        status = os.stat(path, follow_symlinks=follow_symlinks)
    except (OSError, ValueError):
        return None
    if not stat.S_ISDIR(status.st_mode):
        return None
    return (status.st_dev, status.st_ino)


class _OwnOutput(NamedTuple):
    """ASH's output directory for one scan, as the walks recognize it."""

    #: :func:`_directory_identity` of the directory, followed when the way to it
    #: is the operator's (a link above the tree, such as ``/var`` on macOS: it is
    #: where ASH writes, whatever it is called). Not followed through a link the
    #: tree holds: ``.ash/ash_output`` committed as a link to the repository's own
    #: ``src`` would otherwise take ``src`` out of the scan, and such a directory
    #: is named as ASH's by nothing (``scan_output_dirs.named_output_dirs``); the
    #: orchestrator refuses a symlinked one anyway. None when it does not exist,
    #: or is such a link.
    identity: Optional[tuple[int, int]]
    #: Its absolute, case-normalized path, for when the identity cannot decide.
    path: str


def _own_output_of(
    output: Optional[str | Path], source: str | Path
) -> Optional[_OwnOutput]:
    """The output directory of the scan of *source*, or None for no output directory."""
    if not output:
        return None
    absolute = Path(os.path.abspath(output))
    root = Path(os.path.abspath(source))
    through_the_tree = _through_a_link_in_the_tree(
        absolute, root, Path(os.path.realpath(root))
    )
    return _OwnOutput(
        identity=_directory_identity(output, follow_symlinks=not through_the_tree),
        path=os.path.normcase(str(absolute)),
    )


def _is_own_output(candidate: str, own: Optional[_OwnOutput]) -> bool:
    """Whether the directory at *candidate* is ASH's output directory *own*.

    By identity, so a spelling through a link or a second mount still matches. A
    file system that reports ``st_ino`` 0 gives every directory on the device the
    same identity, which would make all of them the output directory and empty the
    scan set; there, and when the output directory does not exist, the absolute
    path decides instead (case-normalized, so a case-only difference on Windows
    still matches). A link is never the output directory.
    """
    if own is None:
        return False
    if own.identity is not None and own.identity[1] != 0:
        return _directory_identity(candidate) == own.identity
    if _is_link_to_directory(candidate):
        return False
    return os.path.normcase(os.path.abspath(candidate)) == own.path


def _count_files_in_own_output(directory: str, committed: Collection[str] = ()) -> int:
    """How many files were already in ASH's output directory, this run's own aside.

    *committed* holds the paths (as the walk spells them) of the files git tracks
    there. They are put into the scan set, so they are not among the files left out.
    """
    count = 0
    for root, _dirs, files in _walk_unless_link(directory):
        count += sum(
            1
            for name in files
            if not (root == directory and name in _THIS_RUNS_FILES)
            and os.path.join(root, name) not in committed
        )
    return count


#: The ``ASH_INCLUSIONS`` entries :func:`_excluded_by_ash_itself` restates. A change
#: to ``ASH_INCLUSIONS`` has to change that function too; a test compares them.
_RESTATED_ASH_INCLUSIONS = (".git", "**/cdk.out/asset.*", "!**/*.template.json")


def _excluded_by_ash_itself(
    walked: str, parts: Sequence[str], root_name: str = ""
) -> bool:
    """Whether ASH leaves a file out with no ignore file at all, from its path.

    *walked* is the file's path as the walk spelled it and *parts* its components
    below the scan root. The answer is :func:`get_files_not_matching_spec`'s with
    ``ASH_INCLUSIONS`` as the whole spec, worked out from names instead of by
    matching each file against the parser: a pruned ``node_modules`` holds hundreds
    of thousands of files, and a parser match per file stats each of them.

    - The bundled aws-cdk tree: a ``node_modules/aws-cdk*`` component in *parts*,
      the path below the scan root (:func:`_is_bundled_cdk_below`), as the scan set
      tests it, with *root_name*, the scan root's last component, in front.
      *walked* is not read.
    - Any ``*.template.json`` is kept otherwise, which is what the forced-inclusion
      pass does whatever else matched, unless a directory above it, below the scan
      root, is itself named ``*.template.json`` (:func:`_forced_in`).
    - A ``.git`` component, file or directory, is left out (rule ``.git``).
    - An ``asset.*`` component directly under a ``cdk.out`` component is left out
      (rule ``**/cdk.out/asset.*``).
    """
    if _bundled_cdk_in(parts, root_name):
        return True
    if (
        parts
        and parts[-1].endswith(".template.json")
        and not any(part.endswith(".template.json") for part in parts[:-1])
    ):
        return False
    for index, part in enumerate(parts):
        if part == ".git":
            return True
        if part.startswith("asset.") and index > 0 and parts[index - 1] == "cdk.out":
            return True
    return False


def _relative_parts(path: str, source: str) -> tuple[str, ...]:
    """*path*'s components below *source*, compared as the walk spelled them."""
    relative = os.path.relpath(os.path.abspath(path), os.path.abspath(source))
    return tuple(_with_posix_separators(relative, _PATH_SEPARATORS).split("/"))


def _files_removed_by_ignore_files(
    source: str, all_files: List[str], scan_set_files: List[str]
) -> int:
    """How many walked files are missing from the scan set because of an ignore file.

    The walked files that are not in the scan set, less the ones ASH leaves out on
    its own (:func:`_excluded_by_ash_itself`). Taken from the scan set rather than
    summed from the per-file attribution, so a rule the attribution credits to the
    wrong file, or to none, still counts.
    """
    kept = set(scan_set_files)
    root_name = os.path.basename(os.path.abspath(source))
    return sum(
        1
        for walked in all_files
        if walked not in kept
        and not _excluded_by_ash_itself(
            walked, _relative_parts(walked, source), root_name
        )
    )


def _count_templates(directory: str, source: Optional[str] = None) -> int:
    """``*.template.json`` files under *directory*: the forced inclusion keeps them.

    With *source*, the scan root, the bundled aws-cdk tree is judged by the path
    below it (:func:`_is_bundled_cdk_below`); without, by the whole path.

    A directory named ``*.template.json`` below the scan root (below *directory*
    without *source*) is not entered: the forced inclusion does not name a file
    below one (:func:`_forced_in`), so the scan set leaves those out and so does this.
    """
    root_absolute = None if source is None else os.path.abspath(source)
    reference = os.path.abspath(directory if source is None else source)

    def bundled(full: str) -> bool:
        if root_absolute is None:
            return _is_bundled_cdk_path(full)
        return _is_bundled_cdk_below(full, root_absolute)

    count = 0
    for root, dirs, files in _walk_unless_link(directory):
        if any(
            part.endswith(".template.json") for part in _relative_parts(root, reference)
        ):
            dirs[:] = []
            continue
        count += sum(
            1
            for name in files
            if name.endswith(".template.json") and not bundled(os.path.join(root, name))
        )
    return count


def _count_files_ash_would_scan(
    directory: Path,
    source: str,
    own_output: Optional[_OwnOutput] = None,
    own_output_counts: Optional[Dict[str, int]] = None,
    named_output_dirs: Optional[AbstractSet[Path]] = None,
) -> int:
    """How many files under *directory* stay in the scan set when no ignore file applies.

    The answer :func:`get_files_not_matching_spec` gives with ``ASH_INCLUSIONS`` as
    the whole spec, decided from names (:func:`_excluded_by_ash_itself`) and not by
    matching each file against a parser. A file ASH leaves out on its own (``.git``,
    CDK assets, the bundled aws-cdk tree, its own output directory *own_output*)
    was not removed by the ignore file that pruned *directory*, so it is not
    counted. The output directory's files go into *own_output_counts* instead, as
    they do when the scan-set walk reaches it directly: a pruned parent does not
    change what they are. So do the other output directories the walk names
    (*named_output_dirs*, as absolute paths: an earlier run's ``.ash/ash_output``,
    the workspace's output directory), which it leaves out whatever the ignore files
    say.

    ASH's own exclusions are applied a directory at a time, so a pruned
    ``node_modules`` costs a walk, one more listing of each directory that holds
    files for the names of its symlinks (:func:`_names_of_links_in`, which answers
    from the listing and not from an ``lstat`` per file), and a string test per
    file: a directory on the
    bundled aws-cdk path is not entered, and a ``.git`` directory or a CDK asset
    directory is only searched for the ``*.template.json`` files the forced
    inclusion keeps. Links to directories are not followed, as in the walk that
    pruned *directory*: neither *directory* itself nor one below it, including a
    ``.git`` or asset directory searched for templates (:func:`_walk_unless_link`).
    A link to a file whose target leaves *source* is not counted either: the scan-set
    walk never keeps one (:func:`_left_out_as_a_link_leaving_the_tree`), so the
    ignore file did not remove it.
    """
    count = 0
    root_absolute = os.path.abspath(source)
    root_name = os.path.basename(root_absolute)
    for root, dirs, files in _walk_unless_link(directory):
        parts = _relative_parts(root, source)
        kept_dirs = []
        for d in dirs:
            candidate = os.path.join(root, d)
            if _is_own_output(candidate, own_output) or (
                named_output_dirs is not None
                and Path(os.path.abspath(candidate)) in named_output_dirs
            ):
                if own_output_counts is not None:
                    own_output_counts[candidate] = _count_files_in_own_output(candidate)
                continue
            if _is_bundled_cdk_below(candidate, root_absolute):
                continue
            if d == ".git" or (
                d.startswith("asset.") and parts and parts[-1] == "cdk.out"
            ):
                count += _count_templates(candidate, source)
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs
        # A directory with no files has no link to a file to look for, and a pruned
        # ``node_modules`` is mostly such directories (``@scope/``, nested levels).
        links = _names_of_links_in(root) if files else None
        count += sum(
            1
            for name in files
            if not _excluded_by_ash_itself(
                os.path.join(root, name), parts + (name,), root_name
            )
            and not _file_link_leaves_the_tree(root, name, links, source)
        )
    return count


#: Prefix of the directories ``cdk synth`` stages assets in, inside an assembly.
_CDK_ASSET_DIR_PREFIX = "asset."

#: Files every CDK cloud assembly directory holds: the assembly version marker
#: and the manifest (aws-cdk-lib core/test/synthesis.test.ts lists both).
_CDK_ASSEMBLY_MARKER_FILES = ("cdk.out", "manifest.json")


def _is_cdk_cloud_assembly(directory: Path) -> bool:
    """Whether *directory* is a CDK cloud assembly that ``cdk synth`` wrote.

    Named ``cdk.out``, CDK's default output directory, or holding the files every
    assembly holds, which covers ``cdk synth -o <dir>``. Asked only of a
    directory the root ``.gitignore`` excludes, which is the one place a
    directory is pruned before the ``!**/*.template.json`` inclusion is applied:
    the same rule in a nested ignore file never pruned anything, so the
    templates came back there and not here.

    A directory the scanning user cannot search is not an assembly: before
    Python 3.13 ``Path.is_file`` raises ``PermissionError`` for a child of such
    a directory, and one ignored directory with that mode aborted the scan.
    """
    if directory.name == "cdk.out":
        return True
    try:
        return all(
            directory.joinpath(name).is_file() for name in _CDK_ASSEMBLY_MARKER_FILES
        )
    except OSError:
        return False


def _negations_that_unprune(
    root_path: Path, extra_ignorefiles: List[str], honor_ignore_files: bool
) -> List[Tuple[str, Path]]:
    """The negation rules of the root ``.ignore`` and the caller's ignore files,
    each with the base it compiles against, for the pruning pre-pass.

    The pre-pass is compiled from the root ``.gitignore`` alone, and git never
    descends a directory it excludes, so a nested ignore file cannot bring one
    back. But ASH's full spec compiles the root ``.ignore`` after the root
    ``.gitignore``, and a caller-named ignore file after both, with the last
    matching rule deciding: a ``!vendor/`` in either re-includes ``vendor/`` in
    the full spec, while the pre-pass, which never saw it, had already pruned the
    directory, so its files were missing from the scan set. The negations are
    added to the pre-pass parser, where they take effect the same way, so such a
    directory is walked and the full spec has the last word on each file.

    Only negations: a positive rule in these files is left to the full spec, so
    whatever the pre-pass prunes is still the root ``.gitignore``'s doing and is
    counted to it. A file that cannot be opened contributes nothing here, and the
    pre-pass goes on; the full spec then meets the same file and raises, since an
    unreadable ignore file in the tree is an error by design (only a refused one
    is skipped; ``test_tree_readers_scanned_tree`` pins it), so the tolerance here
    never widens a scan set. A caller-named file outside the scan root compiles
    against the root, as the full spec compiles it (:func:`_confine_base_path`).
    """
    sources: List[Tuple[List[str], Path]] = []
    if honor_ignore_files:
        root_ignore = root_path / ".ignore"
        if root_ignore.is_file():
            try:
                with io.TextIOWrapper(
                    open_in_scanned_tree(root_ignore, root_path),
                    errors=IGNORE_FILE_ERRORS,
                    newline=IGNORE_FILE_NEWLINE,
                ) as handle:
                    sources.append((ignore_file_lines(handle), root_path))
            except (TreeInputRefused, OSError):
                pass
    root_absolute = Path(os.path.abspath(root_path))
    for extra in extra_ignorefiles:
        extra_path = os.path.join(root_path, extra)
        if not os.path.isfile(extra_path):
            continue
        base = Path(os.path.dirname(os.path.abspath(extra_path)))
        if not base.is_relative_to(root_absolute):
            base = root_path
        try:
            with open(
                extra_path, errors=IGNORE_FILE_ERRORS, newline=IGNORE_FILE_NEWLINE
            ) as handle:
                sources.append((ignore_file_lines(handle), base))
        except OSError:
            continue
    negations: List[Tuple[str, Path]] = []
    for lines, base in sources:
        for line in lines:
            rule = gitignore_rule_for_igittigitt(ignore_file_line(line))
            if rule.lstrip().startswith("!"):
                negations.append((rule, base))
    return negations


def _warn_about_scanned_earlier_output_dirs(
    reached: List[Tuple[str, Path]], scan_set_files: List[str]
) -> None:
    """Warn about each earlier run's output directory the scan set still reads.

    Counted over *scan_set_files*, after the ignore files have been applied: an
    ignore file that lists the directory leaves none of its files in the scan
    set, and then the warning that it "is scanned like the rest of the tree"
    was not true. A directory with no file left gets no warning.
    """
    for relative, directory in reached:
        kept = sum(
            1
            for name in scan_set_files
            if Path(os.path.abspath(name)).is_relative_to(directory)
        )
        if kept:
            warn_about_scanned_output_dir(relative, kept)


def _collect_ignorefiles_and_all_files(
    path: str,
    extra_ignorefiles: List[str] | None = None,
    debug: bool = False,
    honor_ignore_files: bool = True,
    pruned_counts: Optional[Dict[str, int]] = None,
    own_output: Optional[str] = None,
    own_output_counts: Optional[Dict[str, int]] = None,
    output_dir: str | Path | None = None,
    workspace_output_dir: str | Path | None = None,
    earlier_output_dirs_reached: Optional[List[Tuple[str, Path]]] = None,
    links_not_scanned: Optional[List[str]] = None,
) -> tuple[List[str], List[str]]:
    """Walk the directory tree once to collect ignore files and all file paths.

    Respects .gitignore hierarchy: if a directory is ignored by a parent
    .gitignore, its contents (including nested .gitignore files) are skipped.
    This prevents rules like ``*`` inside ``.venv/.gitignore`` from being
    applied globally and accidentally ignoring all project files. The one
    ignored directory still walked is a CDK cloud assembly, for its templates;
    see :func:`_is_cdk_cloud_assembly`.

    ASH's own output is skipped whether or not an ignore file names it: the
    directory *output_dir* names and the default ``.ash/ash_output``
    (``utils/scan_output_dirs.named_output_dirs``). Without that, a scan read the
    reports of the previous scan back in as source. A directory that only holds
    files like ASH's output is walked like any other, with a warning naming it.
    In a git checkout, the files git tracks in a skipped output directory are
    listed anyway, with a warning: a repository can commit files there, and they
    were scanned before ASH named its output directories. Their ignore files are
    not collected; they are ASH's directory's. Where git cannot say what is
    committed, only this run's output directory is skipped: an earlier run's
    ``.ash/ash_output`` is walked like the rest of the tree
    (``utils/scan_output_dirs.classified_output_dirs``). Each one the walk
    reaches is appended to *earlier_output_dirs_reached*, as its ``/``-separated
    path under the source and its absolute path, so that :func:`scan_set` warns
    about it once the ignore files have been applied, and only when a file below
    it is still in the scan set.

    *links_not_scanned* is filled, when given, with each file link the walk left
    out because its target leaves *path*
    (:func:`_left_out_as_a_link_leaving_the_tree`). A file git tracks in a skipped
    output directory is never one: ``tracked_files_in`` returns only regular files
    reached without a link. Such a link is not in the file paths returned, so
    nothing counts it as removed by an ignore file. An ignore file that is such a
    link is still returned among the ignore files, where reading it is refused and
    reported.

    Args:
        honor_ignore_files: False when the operator turned the scanned
            repository's ignore files off. They are then not collected and prune
            nothing: every directory is walked, and only the ignore files the
            caller named in *extra_ignorefiles* are returned.
        pruned_counts: Filled, when given, with the root ``.gitignore`` (as
            walked, the same string :func:`get_ash_ignorespec_lines` builds its
            marker from) mapped to the number of files under the directories it
            pruned that ASH would have scanned without it. Those files are in
            neither list returned, so :func:`report_ignore_file_exclusions` adds
            them to that file's count.
        own_output: ASH's output directory for this scan. When it sits inside
            *path* it is not walked, whatever the ignore files say: ASH's own
            log and reports are not part of the code being scanned. Without
            this, only a ``.gitignore`` kept them out (``ash config init``
            writes ``.ash/.gitignore`` for it), so turning the ignore files off
            put ASH's log into the scan set. Recognized by
            :func:`_is_own_output`, not by its spelling, and also below a
            directory the root ``.gitignore`` prunes.
        own_output_counts: Filled, when given, with the output directory (as
            walked) mapped to the number of files already in it when the walk
            reached it, this run's log files aside
            (:func:`_count_files_in_own_output`). They are left out like the rest
            of the directory, and the caller reports them.
        links_not_scanned: Filled, when given, with each file link the walk left
            out because its target leaves *path*
            (:func:`_left_out_as_a_link_leaving_the_tree`). Such a link is not in
            the file paths returned, so nothing counts it as removed by an ignore
            file. An ignore file that is such a link is still returned among the
            ignore files, where reading it is refused and reported as before.

    Returns a tuple of (ignore_file_paths, all_file_paths).
    """
    if extra_ignorefiles is None:
        extra_ignorefiles = []

    ignore_files: List[str] = []
    all_files: List[str] = []

    root_absolute = Path(os.path.abspath(path))
    named, scanned_earlier = classified_output_dirs(
        path, output_dir, workspace_output_dir
    )
    own_output_dirs = set(named)
    # Earlier runs' output directories git cannot say anything about: walked like
    # the rest of the tree, and recorded when the walk reaches them, for
    # scan_set's warning once the ignore files have been applied.
    earlier_output_dirs = set(scanned_earlier)
    skipped_output_dirs: List[str] = []
    kept_assemblies: List[Path] = []

    # Build an initial ignore spec from the root .gitignore (if it exists)
    # so we can skip walking into ignored directories.
    root_ignore_parser = IgnoreParser()
    root_path = Path(path)
    root_gitignore = root_path / ".gitignore"
    # Read under the same scanned-tree rule get_ash_ignorespec_lines uses, and parsed
    # from the text that was checked rather than reopened by name, so a link is not
    # used here either. That function is the one that warns about a refused file.
    # add_rule per line is what parse_rule_file does with each line it reads.
    # Parsed into a parser of its own and adopted only once every line has parsed,
    # so a file that fails part way prunes nothing rather than some directories.
    if honor_ignore_files and root_gitignore.is_file():
        try:
            candidate_parser = IgnoreParser()
            with io.TextIOWrapper(
                open_in_scanned_tree(root_gitignore, root_path),
                errors=IGNORE_FILE_ERRORS,
                newline=IGNORE_FILE_NEWLINE,
            ) as rule_lines:
                for rule_line in ignore_file_lines(rule_lines):
                    candidate_parser.add_rule(
                        gitignore_rule_for_igittigitt(ignore_file_line(rule_line)),
                        base_path=root_path,
                    )
            root_ignore_parser = candidate_parser
        except TreeInputRefused:
            pass
        except (OSError, *_IGNORE_RULE_ERRORS):
            # If the root .gitignore can't be read or parsed (malformed patterns,
            # encoding issues, etc.), proceed without directory pruning. The full
            # ignore spec reads the same file later: a rule it cannot compile is
            # skipped with a warning, one rule at a time
            # (get_ash_ignorespec_with_attribution), so the files are still
            # filtered by every rule that does compile; a file it cannot OPEN is
            # an error there, by design (an unreadable ignore file in the tree
            # ends the scan set; only a refused one is skipped), so skipping it
            # here only decides whether directories are pruned, never what the
            # scan set holds.
            debug_echo(
                f"Could not parse root .gitignore for directory pruning: {root_gitignore}",
                debug=debug,
            )
    for negation, base in _negations_that_unprune(
        root_path, extra_ignorefiles, honor_ignore_files
    ):
        try:
            root_ignore_parser.add_rule(negation, base_path=base)
        except _IGNORE_RULE_ERRORS:
            # The full spec reports the rule it cannot compile; here it merely
            # brings nothing back.
            pass

    pruned_key = os.path.join(path, ".gitignore")
    # The output directory is followed if it is reached through a link above the
    # tree: it is where ASH writes, whatever it is called. A link the tree holds is
    # not followed (_OwnOutput); the orchestrator refuses a symlinked one anyway.
    own = _own_output_of(own_output, path)

    # A link or junction to a directory below the root is not descended, on any
    # interpreter (_walk_without_link_directories); the root itself is walked as
    # given, as before.
    for root, dirs, files in _walk_without_link_directories(
        path, onerror=_warn_directory_not_listed
    ):
        root_path = Path(os.path.abspath(root))
        kept_dirs = []
        for d in dirs:
            candidate = root_path.joinpath(d)
            walked = os.path.join(root, d)
            if candidate not in own_output_dirs and not _is_own_output(walked, own):
                kept_dirs.append(d)
                continue
            skipped_output_dirs.append(walked)
            # tracked_files_in returns regular files reached without a link only,
            # so no link, leaving the tree or not, is among them.
            committed = [
                os.path.join(walked, *tracked.relative_to(candidate).parts)
                for tracked in tracked_files_in(candidate) or []
            ]
            # The committed files are listed below, so they are not among the files
            # left out: counted as both they were warned about as left out and
            # reported in output_dir_file_count while sitting in the scan set.
            if own_output_counts is not None:
                own_output_counts[walked] = _count_files_in_own_output(
                    walked, frozenset(committed)
                )
            if committed:
                all_files.extend(committed)
                warn_about_committed_files(
                    _source_dir_marker(path, walked), len(committed)
                )
        dirs[:] = kept_dirs
        if root_path in earlier_output_dirs and earlier_output_dirs_reached is not None:
            earlier_output_dirs_reached.append(
                (root_path.relative_to(root_absolute).as_posix(), root_path)
            )
        inside_an_earlier_output_dir = any(
            root_path == earlier or root_path.is_relative_to(earlier)
            for earlier in earlier_output_dirs
        )
        if (
            root_path != root_absolute
            and holds_ash_output(files)
            and not inside_an_earlier_output_dir
        ):
            warn_about_look_alike(_source_dir_marker(path, root))

        # Inside a cloud assembly the root .gitignore excludes, kept only for the
        # templates the forced-inclusion pass brings back (see
        # _is_cdk_cloud_assembly). Its asset directories hold bundled code, not
        # templates, and are not walked; nothing else here is re-tested, because
        # every path below the assembly matches the rule that matched it.
        inside_kept_assembly = any(
            root_path == kept or root_path.is_relative_to(kept)
            for kept in kept_assemblies
        )
        if inside_kept_assembly:
            asset_dirs = [d for d in dirs if d.startswith(_CDK_ASSET_DIR_PREFIX)]
            dirs[:] = [d for d in dirs if not d.startswith(_CDK_ASSET_DIR_PREFIX)]
            # Not walked, so their files are in neither list: they are missing from
            # the scan set because the root .gitignore excludes the assembly, and
            # counted to it like the files of a pruned directory. An assembly not
            # named cdk.out has no rule of ASH's own for its assets, so uncounted
            # they were missing from the exclusion count; the count leaves out
            # what ASH excludes on its own.
            if pruned_counts is not None:
                for d in asset_dirs:
                    removed = _count_files_ash_would_scan(
                        Path(root) / d, path, own, own_output_counts, own_output_dirs
                    )
                    pruned_counts[pruned_key] = (
                        pruned_counts.get(pruned_key, 0) + removed
                    )
        else:
            # Prune directories that are ignored by the root .gitignore.
            # This prevents descending into .venv/, node_modules/, etc.
            # and picking up their internal .gitignore files.
            dirs_to_remove = []
            for d in dirs:
                dir_path = Path(root) / d
                # The directory itself, as git decides whether to descend: a
                # directory-only rule ("lib/") matches it, since igittigitt reads a
                # path that is not a file as a directory. Asking about a file inside
                # it instead pruned a directory whose children alone are excluded
                # ("vendor/*"), so a later "!vendor/keep.js" could not bring keep.js
                # back, as git does.
                # Absolute, because igittigitt runs os.path.expanduser over the
                # path it is asked about: under a root given as ".", a directory
                # named "~" was asked about as "~", which is the home directory.
                try:
                    if root_ignore_parser.match(Path(os.path.abspath(dir_path))):
                        if _is_cdk_cloud_assembly(dir_path):
                            kept_assemblies.append(Path(os.path.abspath(dir_path)))
                            debug_echo(
                                f"Walking ignored CDK cloud assembly for its "
                                f"templates: {dir_path}",
                                debug=debug,
                            )
                            continue
                        dirs_to_remove.append(d)
                        debug_echo(
                            f"Skipping ignored directory: {dir_path}", debug=debug
                        )
                except _IGNORE_RULE_ERRORS:
                    # If matching fails for a specific directory (e.g. due to a
                    # malformed pattern), skip pruning for that directory only.
                    pass
            for d in dirs_to_remove:
                dirs.remove(d)
                # The pruned files are still counted: they are missing from the
                # scan set because of the root .gitignore, and a count that left
                # them out would report less than the file removed. Counted, not
                # listed, so a pruned node_modules costs a walk and no memory. A
                # link counts nothing: the count walks through _walk_unless_link,
                # as every count does.
                if pruned_counts is None:
                    continue
                removed = _count_files_ash_would_scan(
                    Path(root) / d, path, own, own_output_counts, own_output_dirs
                )
                pruned_counts[pruned_key] = pruned_counts.get(pruned_key, 0) + removed

        for f in files:
            full_path = os.path.join(root, f)
            # An ignore file under an ignored directory is not read: git does
            # not read one there either.
            if (
                honor_ignore_files
                and f in IGNORE_FILE_NAMES
                and not inside_kept_assembly
            ):
                ignore_files.append(full_path)
            if _left_out_as_a_link_leaving_the_tree(full_path, path, links_not_scanned):
                continue
            all_files.append(full_path)

    # Append any user-specified ignore files
    for extra in extra_ignorefiles:
        extra_path = os.path.join(path, extra)
        if extra_path not in ignore_files:
            ignore_files.append(extra_path)

    if skipped_output_dirs:
        ASH_LOGGER.info(
            "Left %d ASH output %s out of the scan set: %s",
            len(skipped_output_dirs),
            "directory" if len(skipped_output_dirs) == 1 else "directories",
            ", ".join(
                _source_dir_marker(path, directory) for directory in skipped_output_dirs
            ),
            extra=NO_MARKUP,
        )

    return ignore_files, all_files


def _skip_ignore_file(
    lines: List[str], clean: str, reason: str, shown: Optional[str] = None
) -> None:
    """Say that an ignore file was found and not applied: a warning and a report line.

    The line is a comment, which every reader of the report already skips, so the
    skip is visible next to the rules that were applied. *clean* is the report's
    spelling of the file (:func:`_source_dir_marker`); *shown* is how the warning
    names it, *clean* when not given.
    """
    ASH_LOGGER.warning(
        f"Skipped ignore file '{clean if shown is None else shown}': {reason}, so its "
        "rules were not applied",
        extra=NO_MARKUP,
    )
    lines.append(f"{SKIPPED_MARKER_PREFIX}{clean}: {reason} #########")
    lines.append("")


def get_ash_ignorespec_lines(
    path,
    ignorefiles: List[str] | None = None,
    debug: bool = False,
    _discovered_ignore_files: List[str] | None = None,
) -> List[str]:
    if ignorefiles is None:
        ignorefiles = []

    if _discovered_ignore_files is not None:
        all_ignores = _discovered_ignore_files
    else:
        # Fallback: collect ignore files via a walk (used when called standalone)
        all_ignores, _ = _collect_ignorefiles_and_all_files(path, ignorefiles, debug)

    # Ignore files named by the caller are the operator's choice and are read as
    # named. Every other one was found in the tree, and its text is copied into
    # ash-ignore-report.txt, so it is read under the scanned-tree rule: a link would
    # otherwise copy whatever it points at into the report. Git itself stopped
    # following a symlinked .gitignore in 2.32.
    named_by_caller = {os.path.join(path, extra) for extra in ignorefiles}

    # Shallowest ignore file first, so that a deeper one's rules are added to the
    # spec last and therefore win: igittigitt lets the last matching rule decide,
    # and git gives precedence to the ignore file closest to the file being
    # tested. The order has to be stated rather than taken from a set, because a
    # set of strings iterates in hash order, which is randomized per process --
    # a "!keep.tmp" in sub/deep/.gitignore would override "*.tmp" from
    # sub/.gitignore on some runs of the same scan and lose on others.
    #
    # Depth is counted below the scan root, not from the filesystem root: counted
    # by the path as spelled, an ignore file outside the tree sorted by its own
    # absolute depth against tree files whose depth followed how --source was
    # written, so whether its rules overrode a nested file's negation depended on
    # a relative or an absolute source. A file outside the tree has its rules
    # applied from the scan root (_confine_base_path), so it counts as a file at the
    # root, after the tree's own files of that depth; a file the caller names in the
    # tree sorts by its depth there, likewise after the tree's own files of that depth.
    root_absolute = os.path.abspath(path)

    def precedence(ignorefile: str) -> Tuple[int, bool, str]:
        absolute = os.path.abspath(ignorefile)
        try:
            inside = os.path.commonpath([absolute, root_absolute]) == root_absolute
        except ValueError:  # another drive
            inside = False
        depth = (
            len(Path(os.path.relpath(absolute, root_absolute)).parts) if inside else 1
        )
        return depth, ignorefile in named_by_caller, ignorefile

    all_ignores = sorted(set(all_ignores), key=precedence)

    lines = []
    for ignorefile in all_ignores:
        clean = _source_dir_marker(path, ignorefile)
        if ignorefile in named_by_caller:
            if not os.path.isfile(ignorefile):
                # Named by the operator and not there (or not a file): said, like the
                # tree-found file that is refused, with a line in the report. It was
                # skipped with neither, so a mistyped --ignorefile excluded nothing
                # and nothing said why.
                _skip_ignore_file(
                    lines,
                    clean,
                    "it is not a regular file"
                    if os.path.exists(ignorefile)
                    else "it does not exist",
                )
                continue
            try:
                with open(
                    ignorefile, errors=IGNORE_FILE_ERRORS, newline=IGNORE_FILE_NEWLINE
                ) as f:
                    content = ignore_file_lines(f)
            except FileNotFoundError:
                # Gone between the check above and the open. Said, with a warning and
                # a SKIPPED line, because the operator named it; a file found in the
                # tree below that is gone by its open is skipped without a word.
                # A file that is there and cannot be read still raises, for both: an
                # unreadable ignore file is an error.
                _skip_ignore_file(lines, clean, "it does not exist")
                continue
        else:
            try:
                handle = open_in_scanned_tree(ignorefile, path)
            except TreeInputRefused as refused:
                _skip_ignore_file(lines, clean, refused.reason, shown=refused.path)
                continue
            except FileNotFoundError:
                # Gone since the walk: what the isfile() check here used to skip. Any
                # other OSError propagates, as it did from the open() this replaced.
                continue
            # TextIOWrapper with no encoding decodes exactly as open() does.
            with io.TextIOWrapper(
                handle, errors=IGNORE_FILE_ERRORS, newline=IGNORE_FILE_NEWLINE
            ) as f:
                content = ignore_file_lines(f)
        debug_echo(f"Found .ignore file: {clean}", debug=debug)
        lines.append(f"{START_MARKER_PREFIX}{clean}{MARKER_SUFFIX}")
        # Comment lines are left out. They hold no rule (git reads a line as a
        # comment only when "#" is its first character, and the compiler below
        # skips every such line). A line shaped like this function's own markers
        # is left out too, indented or not: the marker reader strips each line,
        # so it would be read back as one, and the rules after it would be
        # credited to another file and compiled against that file's directory.
        # Any other indented "#" line is a pattern to git (" #y.py" ignores the
        # file " #y.py") and is kept.
        lines.extend(line for line in content if not _comment_or_marker_shaped(line))
        lines.append(f"{END_MARKER_PREFIX}{clean}{MARKER_SUFFIX}")
        lines.append("")
    # Only the line ending comes off: a pattern's leading whitespace and an
    # escaped trailing space are part of it (gitignore_rule_for_igittigitt).
    lines = [ignore_file_line(line) for line in lines]
    lines.append(f"{START_MARKER_PREFIX}{ASH_INCLUSIONS_MARKER}{MARKER_SUFFIX}")
    lines.extend(ASH_INCLUSIONS)
    lines.append(f"{END_MARKER_PREFIX}{ASH_INCLUSIONS_MARKER}{MARKER_SUFFIX}")
    return lines


#: How an ignore file is split into lines: on LF alone, as git splits it. Text
#: mode's universal newlines also split on a lone CR, so ``a<CR>b.py`` became
#: the two patterns ``a`` and ``b.py``, which git reads as one.
IGNORE_FILE_NEWLINE = "\n"

#: How an ignore file's bytes are decoded: with the locale's encoding, and
#: surrogateescape for a byte it does not decode. git reads the file as bytes, so
#: a line that is not UTF-8 is a pattern there, matching the file whose name holds
#: the same bytes; os.walk gives that name back as the same surrogates. Decoded
#: strictly, the line raised UnicodeDecodeError out of scan_set.
IGNORE_FILE_ERRORS = "surrogateescape"

#: A UTF-8 byte order mark as it decodes, U+FEFF. Spelled with chr() so the
#: source holds no invisible character.
_UTF8_BOM = chr(0xFEFF)


def _byte_order_marks(handle: Iterable[str]) -> Tuple[str, ...]:
    """A UTF-8 byte order mark as *handle* decodes it, and as U+FEFF.

    Ignore files are read with the locale's encoding, and on Windows without
    UTF-8 mode that is the ANSI code page, where the mark's three bytes decode as
    "\\xef\\xbb\\xbf" (cp1252). An encoding that cannot decode them adds nothing: a
    file read with it cannot hold the mark.
    """
    marks = [_UTF8_BOM]
    encoding = getattr(handle, "encoding", None)
    errors = getattr(handle, "errors", None)
    if isinstance(encoding, str):
        try:
            # With the handle's own error handler: under cp932 the mark's bytes
            # do not decode strictly, and surrogateescape gives "\udcef" plus two
            # half-width katakana, which is what the handle read.
            decoded = codecs.BOM_UTF8.decode(
                encoding, errors if isinstance(errors, str) else "strict"
            )
        except (LookupError, UnicodeDecodeError):
            decoded = ""
        if decoded and decoded not in marks:
            marks.append(decoded)
    return tuple(marks)


def ignore_file_lines(handle: Iterable[str]) -> List[str]:
    """The lines of an ignore file opened with :data:`IGNORE_FILE_NEWLINE`.

    A UTF-8 byte order mark before the first line is skipped, as git skips its
    bytes (``skip_utf8_bom`` in dir.c), however the handle decoded them; kept,
    it made the first pattern start with the mark, which matches no file. Only
    that one is skipped: a mark on a later line, or a second one, is part of its
    pattern for git too. Line endings are left for :func:`ignore_file_line`.
    """
    marks = _byte_order_marks(handle)
    lines = list(handle)
    if lines:
        for mark in marks:
            if lines[0].startswith(mark):
                lines[0] = lines[0][len(mark) :]
                break
    return lines


#: What every marker line ASH writes into the ignore report starts with: START
#: CONTENTS, END CONTENTS and SKIPPED.
_MARKER_LEAD = "#########"


def _comment_or_marker_shaped(line: str) -> bool:
    """Whether an ignore-file *line* is left out of the report's copy of the file.

    A git comment ("#" in the first column), or a line that reads as one of the
    report's own marker lines once stripped, as the marker reader strips it.
    """
    return line.startswith("#") or line.strip().startswith(_MARKER_LEAD)


def ignore_file_line(line: str) -> str:
    """*line*, read with :data:`IGNORE_FILE_NEWLINE`, without its line ending.

    The LF, and one CR before it, as git drops it (``add_patterns_from_buffer``
    in dir.c); a last line with no LF loses a trailing CR the same way, because
    git ends the buffer with an LF first. Any other CR is part of the pattern.
    """
    return line.removesuffix("\n").removesuffix("\r")


def _git_trim_trailing_spaces(text: str) -> str:
    """*text* without its trailing spaces, as git trims an ignore-file line.

    git's ``trim_trailing_spaces`` (dir.c): only spaces, not tabs, and not a space
    a backslash escapes. A backslash escapes whatever follows it.
    """
    last_space: Optional[int] = None
    index = 0
    while index < len(text):
        char = text[index]
        if char == " ":
            if last_space is None:
                last_space = index
        elif char == "\\":
            index += 1
            if index >= len(text):
                return text
            last_space = None
        else:
            last_space = None
        index += 1
    return text if last_space is None else text[:last_space]


def _bracket_expression_end(tokens: Sequence[str], start: int) -> Optional[int]:
    """The index of the token that closes the bracket expression opened at *start*.

    ``[``, an optional ``!`` or ``^``, an optional first ``]`` that is a member, then
    everything up to the next ``]``: how a glob reads a class. None when there is no
    closing ``]``, which makes the ``[`` an ordinary character.
    """
    index = start + 1
    if index < len(tokens) and tokens[index] in ("!", "^"):
        index += 1
    if index < len(tokens) and tokens[index] == "]":
        index += 1
    while index < len(tokens):
        if tokens[index] == "]":
            return index
        index += 1
    return None


def _escaped_spaces_made_literal(tokens: Sequence[str]) -> List[str]:
    """*tokens* with each escaped space (``\\ ``) written so igittigitt keeps it.

    Outside a bracket expression an escaped space becomes the one-character class
    ``[ ]``. Inside one it becomes a plain space, a member of that class:
    ``[a\\ b]`` was rewritten to ``[a[ ]b]``, whose first ``]`` closes the class
    early, so the rule named something else. igittigitt splits a pattern on an escaped
    space and strips the parts; a plain space in a class is left alone.
    """
    result: List[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "[":
            end = _bracket_expression_end(tokens, index)
            if end is not None:
                result.extend(
                    " " if member == "\\ " else member
                    for member in tokens[index : end + 1]
                )
                index = end + 1
                continue
        result.append("[ ]" if token == "\\ " else token)
        index += 1
    return result


def gitignore_rule_for_igittigitt(line: str) -> str:
    """One ignore-file line, newline removed, as igittigitt must get it to read it as git does.

    git keeps a pattern's leading whitespace, drops only the trailing spaces no
    backslash escapes, keeps a trailing tab, and reads a line as a comment only
    when ``#`` is its first character. igittigitt 2.2.3 strips the pattern's
    leading whitespace, and the whitespace around every escaped space, so
    `` lead.py`` ignored ``lead.py`` and ``tab.py<TAB>`` ignored ``tab.py``.
    So git's trailing-space rule is applied here, and every escaped space and
    every whitespace character left at either end of the pattern is written as a
    one-character class (``[ ]``): it matches the same character, and igittigitt
    neither strips nor splits on it. Measured against ``git check-ignore`` 2.50.1
    (tests/unit/utils/test_ignore_file_whitespace_follows_git.py).

    Returns an empty string for a blank line or a comment.
    """
    text = _git_trim_trailing_spaces(line)
    if not text or text.startswith("#"):
        return ""
    prefix = ""
    if text.startswith("!"):
        prefix, text = "!", text[1:]
    tokens: List[str] = []
    index = 0
    while index < len(text):
        if text[index] == "\\" and index + 1 < len(text):
            tokens.append(text[index : index + 2])
            index += 2
        else:
            tokens.append(text[index])
            index += 1
    tokens = _escaped_spaces_made_literal(tokens)
    start = 0
    while start < len(tokens) and tokens[start].isspace():
        tokens[start] = f"[{tokens[start]}]"
        start += 1
    end = len(tokens)
    while end > start and tokens[end - 1].isspace():
        tokens[end - 1] = f"[{tokens[end - 1]}]"
        end -= 1
    return prefix + "".join(tokens)


def _confine_base_path(candidate: Path, root_base_path: Path, marker: str) -> Path:
    """Return *candidate* if it sits inside the scan root, else the scan root.

    A rule's base is derived from a marker line, and both derivations can leave
    the tree: ``${SOURCE_DIR}/../elsewhere/.gitignore`` joins a ``..`` onto the
    scan root, and an absolute marker can name any directory on the host. Neither
    escape announces itself, because igittigitt normalizes a base through
    ``os.path.abspath`` when it compiles the rule. A base that escapes sideways
    then matches nothing in the tree, so the ignore file the user asked for
    becomes a no-op; one that escapes *upward* to an ancestor compiles to
    ``<ancestor>/**/<pattern>``, which reaches every file in the tree and applies
    that file's rules from the wrong anchor.

    Normalization mirrors igittigitt's own ``_expand_base_path``: ``abspath``
    after ``expanduser``, and deliberately not ``Path.resolve()``, so the
    decision is made about the same path igittigitt will compile. Resolving
    symlinks would answer a different question than the parser asks.
    ``is_relative_to`` rather than ``os.path.commonpath`` because it is total --
    ``commonpath`` raises on two Windows paths that share no drive, which is
    exactly one of the cases that has to be answered "not contained".

    The caller passes an absolute *root_base_path* and a *candidate* joined onto
    it, so the ``expanduser`` here (and igittigitt's) has nothing to expand: a
    directory named ``~`` in the tree is a directory, not a home.
    """
    root_absolute = Path(os.path.abspath(os.path.expanduser(str(root_base_path))))
    candidate_absolute = Path(os.path.abspath(os.path.expanduser(str(candidate))))
    if candidate_absolute.is_relative_to(root_absolute):
        return candidate

    ASH_LOGGER.warning(
        "Ignore rules from %s resolve to a base outside the scan root, at %s. "
        "Applying them from the scan root instead, so an explicitly supplied "
        "ignore file is not silently discarded.",
        marker,
        candidate_absolute,
        extra=NO_MARKUP,
    )
    return root_base_path


def _forced_inclusion_spec(source_dir: str | Path) -> IgnoreParser:
    """Compile the negated ``ASH_INCLUSIONS`` entries into a parser of their own.

    Each entry is stripped of its leading ``!`` and added as an ordinary rule, so
    a match against this parser means "ASH wants this file in the scan set no
    matter what the ignore files said".

    Separate from the main spec because a negation inside that spec cannot do the
    job: git -- and igittigitt implementing it -- will not let a negation
    re-include a path underneath an excluded *directory*, on the grounds that git
    never descends into one. ``!**/*.template.json`` is not a preference that may
    lose to a user's ``out/``; it is there to force CloudFormation templates into
    the scan set that ``cdk_nag_scanner`` and ``cfn_nag_scanner`` read.
    """
    parser = IgnoreParser()
    base_path = Path(source_dir)
    for entry in ASH_INCLUSIONS:
        if entry.startswith("!"):
            parser.add_rule(entry[1:], base_path=base_path)
    return parser


def get_ash_ignorespec(
    lines: List[str],
    source_dir: str | Path,
    debug: bool = False,
) -> IgnoreParser:
    """Compile collected ignorespec lines into an ``IgnoreParser``.

    Args:
        lines: Output of :func:`get_ash_ignorespec_lines`: ignore file contents
            wrapped in ``START/END CONTENTS`` markers naming the file each block
            came from.
        source_dir: The directory being scanned. Every rule's base path is
            derived from it, which is also what makes the ``${SOURCE_DIR}`` token
            in the markers resolvable -- and what lets a persisted
            ``ash-ignore-report.txt`` be replayed against a different checkout.
        debug: Enable debug logging.

    Returns:
        A parser whose rules match paths underneath *source_dir*.
    """
    parser, _rule_ids_by_marker = get_ash_ignorespec_with_attribution(
        lines, source_dir, debug=debug
    )
    return parser


def _start_marker_path(stripped: str) -> Optional[str]:
    """The path a START CONTENTS marker line names, or None for any other line.

    Read as the text between :data:`START_MARKER_PREFIX` and :data:`MARKER_SUFFIX`,
    so an END or SKIPPED line, and a path holding either token, are not mistaken
    for the start of a block.
    """
    if not (
        stripped.startswith(START_MARKER_PREFIX) and stripped.endswith(MARKER_SUFFIX)
    ):
        return None
    if len(stripped) < len(START_MARKER_PREFIX) + len(MARKER_SUFFIX):
        return None
    return stripped[len(START_MARKER_PREFIX) : len(stripped) - len(MARKER_SUFFIX)]


def _check_rule_compiles(rule: str, base_path: str | Path) -> None:
    """Raise what igittigitt raises when it cannot compile *rule*, as it would at match.

    ``add_rule`` only builds the rule. igittigitt compiles the rule's glob the first
    time a path is matched against it, so a pattern wcmatch refuses passed
    ``add_rule`` and then raised out of the first match that reached it, out of the
    scan set, though the pruning pass tolerates the same pattern. A parser holding
    only this rule builds its rules, and each built rule's glob goes through the
    function igittigitt matches with, so every rule it holds is compiled, directory
    only rules and negations included, and the real parser never holds a rule it
    cannot match. No path is asked about, so the answer does not depend on what the
    tree holds: asking a parser to match ``<base>/probe`` skipped the directory-only
    rules when a file of that name existed.

    The check leans on igittigitt internals (its ``_globmatch``, the parser's
    ``rules`` and each rule's ``pattern_glob``), and the pin allows any 2.x. When
    they are not what this is written for, it asks about a path that is not a file,
    as before, instead of reading the difference as a rule that cannot compile: a
    changed signature raises ``TypeError``, which the caller counts as a bad rule,
    and every rule would be skipped, ``.git`` among them.
    """
    probe = IgnoreParser()
    probe.add_rule(rule, base_path=base_path)
    glob_match = _igittigitt_glob_function()
    built_rules = getattr(probe, "rules", None)
    if (
        glob_match is None
        or built_rules is None
        or not all(hasattr(built, "pattern_glob") for built in built_rules)
    ):
        _warn_once_that_the_rule_check_is_degraded()
        probe.match(Path(os.path.abspath(base_path)) / "probe")
        return
    for built in built_rules:
        glob_match("", built.pattern_glob)


_RULE_CHECK_DEGRADED_WARNED = False


def _warn_once_that_the_rule_check_is_degraded() -> None:
    """Say once per process that the installed igittigitt is not the one the rule
    check is written for, so the check asks about a path instead.

    That path-based check skips a directory-only rule when a file of the probe's
    name exists, so a rule igittigitt cannot compile can get through. One line,
    not one per rule: the check runs for every rule of every ignore file.
    """
    global _RULE_CHECK_DEGRADED_WARNED
    if _RULE_CHECK_DEGRADED_WARNED:
        return
    _RULE_CHECK_DEGRADED_WARNED = True
    ASH_LOGGER.warning(
        "The installed igittigitt does not match what the ignore-rule check is "
        "written for; checking rules by matching a path instead, which can miss a "
        "directory-only rule that cannot be compiled",
        extra=NO_MARKUP,
    )


def _igittigitt_glob_function():
    """igittigitt's glob-compiling match function, or None when it is not the one
    :func:`_check_rule_compiles` is written for.

    Called once with a glob that compiles, which tells a changed signature (a
    ``TypeError`` or ``AttributeError`` here) from a rule that cannot compile (what
    the caller's own call raises). Looked up on each call and not once at import, so
    a test that stands a function in its place is read.
    """
    glob_match = getattr(_igittigitt_module, "_globmatch", None)
    if glob_match is None:
        return None
    try:
        glob_match("", "*")
    except (TypeError, AttributeError):
        return None
    return glob_match


def get_ash_ignorespec_with_attribution(
    lines: list[str],
    source_dir: str | Path,
    debug: bool = False,
) -> tuple[IgnoreParser, dict[str, list[int]]]:
    """:func:`get_ash_ignorespec`, plus a record of which ignore file each rule came from.

    The parser compiles every rule into one ordered list, because that ordering
    *is* git's precedence and splitting it per file would break it. That leaves no
    way to ask a matched rule which ignore file it came from, which is what
    :func:`report_ignore_file_exclusions` needs to attribute an exclusion to the
    ignore file responsible for it.

    So the mapping is recorded here, while the answer is still known. It is keyed
    by ``id()`` of the rule object rather than the rule itself because
    ``IgnoreRule`` defines ``__eq__``/``__hash__`` over its string form: two
    ignore files carrying the same pattern produce rules that are equal and hash
    alike, so a dict keyed on the rules would merge them and attribute both to
    whichever was inserted last. Identity is the only thing that separates them.
    ``add_rule`` also extends by a slice rather than appending one rule, so the
    whole added range is recorded rather than a presumed single rule.

    Keying on ``id()`` is sound only while the rules are alive, and they are: the
    returned parser holds every one of them for as long as the mapping is used.

    Returns:
        The parser, and an insertion-ordered mapping of marker to the ids of the
        rules its block contributed. Markers whose block contributed no rules are
        present with an empty list, so that "this ignore file excluded nothing"
        stays distinguishable from "there was no such ignore file".
    """
    debug_echo("Generating spec from collected ignorespec lines", debug=debug)
    parser = IgnoreParser()
    rule_ids_by_marker: dict[str, list[int]] = {}
    current_marker = ASH_INCLUSIONS_MARKER

    # Rules have to compile against the real scan root, not a synthetic "/"
    # prefix. igittigitt resolves a rule's base through os.path.abspath and then
    # matches it against the absolute paths os.walk produced, so a rule from
    # sub/.gitignore given the base "/sub" becomes "/sub/**/<pattern>" and can
    # never match "<source_dir>/sub/<file>" -- nested ignore files matched
    # nothing at all. Root-level rules survived that only by accident: the base
    # "/" compiles to "//**/<pattern>", whose leading ** swallows any prefix.
    # Deriving every base from source_dir also keeps base and subject on the same
    # Windows drive, which a rootless "/" cannot: abspath binds it to the drive
    # of the current working directory, so an interpreter on D: compiled rules
    # that could not match a tree on C:.
    #
    # Made absolute here, before any directory name is joined onto it. igittigitt
    # runs every base through os.path.expanduser before abspath, and so does
    # _confine_base_path, and expanduser rewrites a path that STARTS with "~":
    # under a scan root given as ".", a top-level directory named "~" (or
    # "~user") gave the ignore file inside it the base "~/", which both turned
    # into a home directory, outside the root, so its rules were re-anchored at
    # the scan root and applied to the whole tree. "<absolute root>/~" starts
    # with no tilde and is left alone.
    root_base_path = Path(os.path.abspath(source_dir))

    # Track the current base directory from section markers.
    # Lines like "######### START CONTENTS: ${SOURCE_DIR}/.ruff_cache/.gitignore #########"
    # indicate that subsequent rules should be scoped to that directory.
    current_base_path = root_base_path

    for line in lines:
        if not line:
            continue
        stripped = line.strip()

        # Detect section markers to determine the base path for rules
        content_path = _start_marker_path(stripped)
        if content_path is not None:
            # The path between the exact prefix and suffix:
            #   "######### START CONTENTS: ${SOURCE_DIR}/subdir/.gitignore #########"
            #   "######### START CONTENTS: ${SOURCE_DIR}/.gitignore #########"
            #   "######### START CONTENTS: ASH_INCLUSIONS #########"
            try:
                if content_path == ASH_INCLUSIONS_MARKER:
                    current_base_path = root_base_path
                elif content_path.startswith(SOURCE_DIR_TOKEN):
                    # Extract the directory containing the .gitignore/.ignore
                    # file. The marker is written with "/" separators, so it is
                    # read back as a posix path regardless of host platform. Only
                    # the leading token stands for the scan root: the same text
                    # later in the path is part of a directory name.
                    relative_path = content_path[len(SOURCE_DIR_TOKEN) :].lstrip("/")
                    parent_dir = PurePosixPath(relative_path).parent
                    if str(parent_dir) == ".":
                        current_base_path = root_base_path
                    else:
                        current_base_path = root_base_path / parent_dir
                else:
                    marker_path = Path(content_path)
                    if marker_path.is_absolute():
                        # A marker naming a real path rather than the
                        # ${SOURCE_DIR} token. _source_dir_marker emits one for
                        # any ignore file that is not under the scan root as the
                        # caller spelled it: an absolute --ignorefile outside the
                        # tree, or -- under a relative --source -- an absolute
                        # --ignorefile inside it. A persisted
                        # ash-ignore-report.txt written by an ASH whose
                        # substitution never fired on Windows carries one for
                        # every ignore file, and replaying it has to keep working.
                        # Scope such a rule to the ignore file's own directory:
                        # falling back to the scan root would quietly widen a
                        # nested rule to the whole tree and drop files from the
                        # scan set. _confine_base_path pulls it back if that
                        # directory turns out to be outside the tree.
                        current_base_path = marker_path.parent
                    else:
                        current_base_path = root_base_path
            except (IndexError, ValueError):
                current_base_path = root_base_path
            # Gated here rather than in each branch above, so a derivation added
            # later cannot reach the parser unchecked.
            current_base_path = _confine_base_path(
                current_base_path, root_base_path, content_path
            )
            # Registered on sight rather than on first rule, so an ignore file
            # whose rules exclude nothing still gets a line in the report.
            current_marker = content_path
            rule_ids_by_marker.setdefault(current_marker, [])
            continue

        # Read as git reads the line, not as stripped: a comment only with "#" in
        # its first column, and leading whitespace and an escaped trailing space
        # kept as part of the pattern.
        rule = gitignore_rule_for_igittigitt(line)
        if not rule:
            continue

        added_from = len(parser.rules)
        try:
            _check_rule_compiles(rule, current_base_path)
            parser.add_rule(rule, base_path=current_base_path)
        except _IGNORE_RULE_ERRORS as error:
            # One pattern the parser refuses used to raise out of here and abort
            # the scan, while the pruning pre-pass tolerated the same pattern.
            # Skipped and said: the rule applies to nothing, so the scan set is
            # larger, never smaller. The rule is the repository's text, shown and
            # not obeyed.
            ASH_LOGGER.warning(
                f"Skipped ignore rule {shown_not_obeyed(rule)!r} from {current_marker}: "
                f"it could not be compiled ({error})",
                extra=NO_MARKUP,
            )
            continue
        rule_ids_by_marker.setdefault(current_marker, []).extend(
            id(rule) for rule in parser.rules[added_from:]
        )
    return parser, rule_ids_by_marker


def report_ignore_file_exclusions(
    path: str | Path,
    spec: IgnoreParser,
    scan_set_files: list[str],
    rule_ids_by_marker: dict[str, list[int]],
    all_files: list[str],
    debug: bool = False,
    pruned_counts: Optional[Dict[str, int]] = None,
    honored: bool = True,
    skipped_ignore_files: int = 0,
) -> dict[str, int]:
    """Log how many files each ignore file removed from the scan set.

    Making nested ignore files work means ASH scans *less* than it used to: a
    vendored directory that ships its own ``.gitignore`` now takes its own source
    out of the scan set. That is correct by gitignore semantics and matches what a
    root-level ``.gitignore`` already did, but a security scanner that quietly
    scans less after an upgrade is the worst outcome available, and vendored
    dependencies very commonly ship ignore files. So the reduction is reported
    rather than left silent.

    The count is per ignore file, because that is what a user can act on -- a
    single total says the scan set shrank without saying which file to go read.
    It is a count and not a list of paths: the list is unbounded and would bury
    the line that matters. The paths are available at debug level.

    Counts are taken over the files that are missing from *scan_set_files*, not
    over what the spec matched. Those differ, and the difference is the honest
    one: ``ASH_INCLUSIONS`` re-adds ``*.template.json`` after the spec has
    excluded it, and a file that came back is not a file this ignore file
    removed. Counting spec matches would print a number that contradicts the
    artifact it describes.

    A directory the root ``.gitignore`` prunes in
    :func:`_collect_ignorefiles_and_all_files` is not walked for the scan set, so
    its files are in neither *all_files* nor the scan set. That walk counts them
    instead, leaving out files ASH would exclude on its own, and they arrive here
    as *pruned_counts*, keyed by the ignore file that pruned them. They are added
    to that file's count, so the root ``.gitignore`` reports every file it removed
    and not only the ones walked.

    *honored* is False when the operator turned the repository's ignore files off,
    so none were read; the "no ignore files were found" line is then not logged.
    *skipped_ignore_files* is how many ignore files were found and not read (refused,
    or named by the caller and not there): when every one found was skipped, the
    line says none could be applied, not that none were found.

    Returns:
        Marker to number of files removed, for every marker seen -- including
        zeros. Callers get the data; the log line is the product of it.
    """
    excluded = set(all_files) - set(scan_set_files)
    marker_by_rule_id = {
        rule_id: marker
        for marker, rule_ids in rule_ids_by_marker.items()
        for rule_id in rule_ids
    }

    counts: dict[str, int] = dict.fromkeys(rule_ids_by_marker, 0)
    counts[BUNDLED_CDK_MARKER] = 0
    paths_by_marker: dict[str, list[str]] = {}
    unattributed: list[str] = []
    root_absolute = os.path.abspath(path)

    for excluded_file in sorted(excluded):
        # The bundled aws-cdk tree first, because get_files_not_matching_spec drops it
        # before it consults the spec: an ignore rule that also matches one of its
        # files did not remove it.
        if _is_bundled_cdk_below(excluded_file, root_absolute):
            marker = BUNDLED_CDK_MARKER
            counts[marker] = counts.get(marker, 0) + 1
            paths_by_marker.setdefault(marker, []).append(excluded_file)
            continue
        # Absolute: igittigitt expands a leading "~" in the path it is asked about.
        _ignored, rule = spec.match_with_rule(Path(os.path.abspath(excluded_file)))
        if rule is not None and id(rule) in marker_by_rule_id:
            marker = marker_by_rule_id[id(rule)]
        else:
            # No ignore rule owns this exclusion. Reaching here means the
            # attribution mapping and the parser disagree, which would otherwise
            # surface as every count reading zero -- the same absent-reads-as-zero
            # ambiguity this report exists to remove. Say so instead.
            unattributed.append(excluded_file)
            continue
        counts[marker] = counts.get(marker, 0) + 1
        paths_by_marker.setdefault(marker, []).append(excluded_file)

    for ignorefile, pruned in (pruned_counts or {}).items():
        marker = _source_dir_marker(path, ignorefile)
        counts[marker] = counts.get(marker, 0) + pruned

    ignore_file_markers = [
        marker for marker in rule_ids_by_marker if marker != ASH_INCLUSIONS_MARKER
    ]
    # With the repository's ignore files not honored, none were read, so "none were
    # found" would be untrue; scan_set says why they were not read instead.
    if not ignore_file_markers and honored and skipped_ignore_files:
        ASH_LOGGER.info(
            "None of the %d ignore file(s) found or named for %s could be applied (see "
            "the warnings above), so no ignore rules removed anything from the scan "
            "set.",
            skipped_ignore_files,
            path,
            extra=NO_MARKUP,
        )
    elif not ignore_file_markers and honored:
        ASH_LOGGER.info(
            "No ignore files were found under %s, so no ignore rules removed "
            "anything from the scan set.",
            path,
            extra=NO_MARKUP,
        )

    for marker, count in counts.items():
        if count == 0 and marker == BUNDLED_CDK_MARKER:
            # Not a file the user wrote, and there is nothing to go look at when
            # it excluded nothing.
            continue
        ASH_LOGGER.info(
            "%s excluded %d %s from the scan set",
            marker,
            count,
            "file" if count == 1 else "files",
            extra=NO_MARKUP,
        )
        if debug and paths_by_marker.get(marker):
            for excluded_file in paths_by_marker[marker]:
                debug_echo(f"  excluded by {marker}: {excluded_file}", debug=debug)

    if unattributed:
        ASH_LOGGER.warning(
            "%d files left the scan set without any ignore rule accounting for "
            "them, so the per-ignore-file counts above are incomplete. First: %s",
            len(unattributed),
            unattributed[0],
            extra=NO_MARKUP,
        )

    return counts


def ignore_file_exclusion_record(
    counts: Dict[str, int],
    honored: bool,
    excluded_file_count: int,
    output_dir_file_count: int = 0,
) -> Dict[str, Any]:
    """The ``metadata.ignore_file_exclusions`` record of one scan set.

    ``by_ignore_file`` is :func:`report_ignore_file_exclusions`'s counts, without
    the two entries that are not an ignore file (``ASH_INCLUSIONS`` and the bundled
    aws-cdk tree): what ASH leaves out on its own is not something an ignore file
    removed. Each ignore file is named by its path relative to the scan root, the
    ``${SOURCE_DIR}/`` token dropped, and keeps its count when that is zero.

    Args:
        counts: Marker to number of files removed.
        honored: Whether the scanned repository's own ignore files were applied.
            False when the operator turned them off; *counts* then holds only the
            ignore files the caller named, which is nothing for ``ash scan``.
        excluded_file_count: The total, from the scan set itself
            (:func:`_files_removed_by_ignore_files` plus the pruned files), not
            from *counts*: the attribution names a file for each removal, and the
            total must not depend on it naming the right one.
        output_dir_file_count: Files already in ASH's own output directory inside
            the tree, left out whatever the ignore files say.
    """
    by_ignore_file: Dict[str, int] = {}
    for marker, count in counts.items():
        if marker in (ASH_INCLUSIONS_MARKER, BUNDLED_CDK_MARKER):
            continue
        key = marker.removeprefix(SOURCE_DIR_TOKEN)
        by_ignore_file[key] = by_ignore_file.get(key, 0) + count
    return {
        "honored": honored,
        "excluded_file_count": excluded_file_count,
        "by_ignore_file": by_ignore_file,
        "output_dir_file_count": output_dir_file_count,
    }


def _forced_in(
    forced_inclusions: IgnoreParser,
    root_absolute: str,
    file_path: Path,
    forced_directories: Dict[Path, bool],
) -> bool:
    """Whether a forced inclusion names *file_path* itself.

    A rule that names a file also names a directory of that name, and the
    parser then reports everything below the directory as matched. A directory
    called ``x.template.json`` made every file in it, ``.git`` internals and
    user-ignored files among them, forced into the scan set. A file counts when
    no directory above it, below the scan root, is matched by a forced rule.

    *forced_directories* remembers each directory's answer between calls. At module
    level so that the test of :func:`_excluded_by_ash_itself`, which restates this
    from names, can compare against it.
    """
    if not forced_inclusions.match(file_path):
        return False
    for parent in file_path.parents:
        if str(parent) == root_absolute or not parent.is_relative_to(root_absolute):
            break
        matched = forced_directories.get(parent)
        if matched is None:
            matched = forced_directories[parent] = forced_inclusions.match(parent)
        if matched:
            return False
    return True


def get_files_not_matching_spec(
    path,
    spec,
    debug: bool = False,
    _all_files: List[str] | None = None,
    links_not_scanned: Optional[List[str]] = None,
):
    """The files under *path* that *spec* does not leave out, sorted.

    A file link whose target leaves *path* is never returned, whether the walk here
    found it or the caller passed it in *_all_files*; each one is warned about and
    appended to *links_not_scanned* when given
    (:func:`_left_out_as_a_link_leaving_the_tree`). :func:`scan_set` passes the
    files its own walk already filtered, so it sees each link once.
    """
    if _all_files is None:
        # Fallback: walk again if called standalone without pre-collected files.
        # The same walk as scan_set's, so a link or junction to a directory is
        # never descended here either (os.walk of 3.10 and 3.11 follows a junction).
        _all_files = []
        for root, _dirs, files in _walk_without_link_directories(path):
            for f in files:
                _all_files.append(os.path.join(root, f))

    # Applied as a pass of its own after *spec* has had its say, because a
    # negation inside that spec loses to an excluded ancestor directory: a nested
    # "out/" in src/cdk/.gitignore beat "!**/*.template.json" and took
    # src/cdk/out/Stack.template.json out of the scan set that cdk_nag_scanner and
    # cfn_nag_scanner read, so CloudFormation analysis of that template stopped
    # with nothing logged to say so.
    forced_inclusions = _forced_inclusion_spec(path)
    root_absolute = os.path.abspath(path)
    forced_directories: Dict[Path, bool] = {}

    included = []
    for inc_full in _all_files:
        # inc_full stays native throughout, because callers use it to open files.
        # Both helpers below normalize internally and only for their own comparison.
        if _is_bundled_cdk_below(inc_full, root_absolute):
            continue
        if _left_out_as_a_link_leaving_the_tree(inc_full, path, links_not_scanned):
            continue
        # Absolute for the parsers, which run os.path.expanduser over the path they
        # are asked about: under a root given as ".", "~/inside.py" (a top-level
        # directory named "~") was asked about as a file in the home directory, so
        # no rule of that directory's ignore file matched it and it stayed in the
        # scan set. abspath, not resolve: the rules are anchored on abspath bases.
        file_path = Path(os.path.abspath(inc_full))
        if spec.match(file_path) and not _forced_in(
            forced_inclusions, root_absolute, file_path, forced_directories
        ):
            continue
        clean = _source_dir_marker(path, inc_full)
        debug_echo(f"Matched file for scan set: {clean}", debug=debug)
        included.append(inc_full)
    included = sorted(set(included))
    return included


def child_environ():
    """The environment git is started with; see subprocess_utils.child_environ."""
    from automated_security_helper.utils.subprocess_utils import (
        child_environ as _child_environ,
    )

    return _child_environ()


def _git_executable() -> Optional[str]:
    """The git to run, as an absolute path, or None when there is none.

    Not the bare name: on Windows a program started by name is looked for in the
    working directory before PATH, and ASH usually runs from the repository it scans.
    Every git spawn in this module starts the path this returns
    (``git_command.resolved_git``), the repository-root lookup and the diff as well
    as the common-dir, git-dir, worktree and ls-files lookups the nesting check
    makes; none passes the bare name to ``subprocess``.
    """
    return resolved_git()


#: Variables that point git at a repository whatever its working directory is.
_GIT_LOCATION_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")

#: Variables that replace a repository's own state: the index the diff reads the
#: working tree through, and the object stores. ``git diff --name-only <commit>``
#: lists the index's entries, not the directory's files, so a foreign
#: GIT_INDEX_FILE (a pre-commit hook's temporary index, a stale export, a path
#: that is gone) made the diff name another set of files, or none at all and at
#: exit 0, and the scan then kept or discarded findings by that set. A foreign
#: GIT_OBJECT_DIRECTORY makes the named revision unreadable ("bad revision").
_GIT_STATE_ENV = (
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
)


def _git_environ(*, without: Iterable[str] = ()) -> Dict[str, str]:
    """The environment every git command in this module is started with.

    ``child_environ`` (a copy, never the live environ; PATH reduced to its anchored
    entries, so a program git starts by name, a credential helper or a textconv
    driver, cannot be found through the working directory), less GIT_DIR and its
    siblings (:data:`_GIT_LOCATION_ENV`), so that git discovers the repository
    from the directory it is started in and answers about that one, and less the
    index and object-store overrides (:data:`_GIT_STATE_ENV`), so that it reads
    that repository's own index and objects. *without* names more variables to
    leave out.

    The repository-root lookup and the diff drop them too. A git hook exports
    GIT_DIR and not GIT_WORK_TREE, and with that pair git takes its working
    directory for the top of the work tree: ``rev-parse --show-toplevel`` in a
    subdirectory then named that subdirectory, while ``diff --name-only`` kept
    naming the changed files from the real root, so a ``--source-dir src
    --changed-files-only`` scan started by a pre-commit hook joined ``src/app.py``
    onto ``<tree>/src``, matched no finding, and reported nothing at exit 0; a
    workspace project below a larger repository became a root of its own the same
    way. With discovery the root is the real one for the hook's own tree and for a
    subdirectory alike, and the nesting check reads the same root.
    """
    dropped = set(_GIT_LOCATION_ENV).union(_GIT_STATE_ENV, without)
    return {key: value for key, value in child_environ().items() if key not in dropped}


def _core_worktree_names_a_tree(git_dir: str, started_in: str) -> bool:
    """Whether the repository at *git_dir* sets ``core.worktree`` to a directory
    that holds *started_in*.

    With ``core.worktree`` set, GIT_DIR alone describes the layout in full: git
    takes its working directory for the top of the tree only when none of
    ``--work-tree``, GIT_WORK_TREE and ``core.worktree`` is given. Read with ``git
    --git-dir <dir> config --get core.worktree``, which exits 0 and prints the
    value as written when it is set and 1 when it is not (128 when the value
    names a directory that is gone: git enters the configured tree before it
    answers). A relative value is relative to the git directory itself, not to
    the directory git is started in, so it is joined onto *git_dir* before the
    check. A git that cannot be started, is missing or times out, an answer that
    is not text, a value naming no directory, and a value naming a directory that
    does not hold *started_in* all read as False, which drops the variable and
    lets discovery answer.

    The containment check is the same one the GIT_DIR and GIT_WORK_TREE pair gets
    in :func:`_layout_environ`, for the same reason: a GIT_DIR left exported for
    another repository (a hook's, a dotfiles checkout's) whose config names its
    own tree would otherwise make the root lookup and the diff describe that
    tree while the scan reads this one, and the changed set would intersect the
    scanned directory to nothing. git honors such a GIT_DIR from any directory;
    the scan honors it only where git's and the scan's trees are the same.
    """
    git = _git_executable()
    if git is None:
        return False
    try:
        result = subprocess.run(
            # git_argv: the repository's config names no program git runs here.
            git_argv(  # nosec B603 B607
                "--git-dir", git_dir, "config", "--get", "core.worktree", program=git
            ),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            env=_git_environ(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    try:
        work_tree = _git_text(result.stdout).strip()
    except UnicodeDecodeError:
        return False
    if not work_tree:
        return False
    if not os.path.isabs(work_tree):
        work_tree = os.path.join(git_dir, work_tree)
    return os.path.isdir(work_tree) and _is_at_or_below(started_in, work_tree)


def _layout_environ(cwd: "str | os.PathLike[str] | None") -> Dict[str, str]:
    """The environment of the repository-root lookup and the diff started in *cwd*.

    :func:`_git_environ`, unless the caller names the layout: with GIT_DIR set and
    GIT_WORK_TREE set to an existing directory that holds *cwd*, the location
    variables are passed through, each relative one made absolute first. GIT_DIR
    is required because GIT_WORK_TREE alone makes git discover the repository from
    *cwd* and still report the named directory as the top, so the root and the
    diff's names would describe two trees; *cwd* must be at or below the named
    tree because a pair left exported for another checkout (``GIT_DIR=~/.cfg
    GIT_WORK_TREE=~/other``) would otherwise make the scan of an unrelated
    directory read that checkout's root and changes, intersect to nothing, and
    discard every finding at exit 0. A relative value means "relative to the
    directory of the process that exported it", and that is this process's own
    directory: receive-pack starts a post-receive hook inside the repository with
    ``GIT_DIR=.`` exported, and a hook that then exports ``GIT_WORK_TREE=/srv/app``
    and scans ``/srv/app`` means the repository it runs in. Passed on as written to
    a git started in *cwd*, the scanned directory, ``.`` named that directory
    instead and git answered "not a git repository", so the scan lost its
    changed-file filter in the very shape this passthrough is for. Made absolute
    against this process's directory, the value keeps the exporter's meaning
    wherever git is started.
    A bare repository driven as ``GIT_DIR=<bare> GIT_WORK_TREE=<tree>`` (a
    post-receive hook deploying a checkout) has no ``.git`` entry in the tree for
    git to discover, so dropping the pair there turned the scan's root lookup into
    "not a repository", and dropping GIT_DIR alone would let discovery bind
    GIT_WORK_TREE to whatever repository holds the tree's ancestors. With
    GIT_WORK_TREE unset, GIT_DIR alone is the hook shape where git takes its
    working directory for the top of the tree, and the variables are dropped so
    that git discovers the repository (the docstring above); unless that
    repository sets ``core.worktree`` to a directory that holds *cwd*
    (:func:`_core_worktree_names_a_tree`), in which case GIT_DIR alone describes
    the layout in full and is kept, as it was before the drop. The containment
    rule is the pair's: a GIT_DIR left exported for another repository whose
    config names its own tree is as stale as a stale pair, and honored from
    outside that tree it would make the root and the diff describe a tree the
    scan is not reading. A GIT_WORK_TREE that names no directory is not honored
    either: git would answer with that name unchecked, and the lookup would join
    the diff's paths onto a path that does not exist. A location variable
    exported with an empty value is read as unset (and left out of the copy):
    git itself refuses the empty string as a path.

    A kept copy never carries GIT_INDEX_FILE: the diff lists the index's entries,
    and the index of the layout the caller names is the named repository's own,
    never one exported for another purpose (a pre-commit hook's temporary index
    names the files being committed, not the tree). The object-store overrides
    (GIT_OBJECT_DIRECTORY, GIT_ALTERNATE_OBJECT_DIRECTORIES) are kept with a kept
    layout: a pre-receive hook's quarantine puts the pushed objects in a directory
    only those two variables name, and dropping them there made the named
    revision unreadable; when the variables are dropped to discovery instead,
    :func:`_git_environ` drops these too.
    """
    environ = child_environ()
    environ.pop("GIT_INDEX_FILE", None)
    # os.path.abspath reads a relative value against this process's directory, the
    # exporter's, and keeps an absolute one as it is; git started in *cwd* then
    # reads the same directory the exporter meant. A variable exported EMPTY is
    # dropped from the copy: git refuses "" as a path ("The empty string is not a
    # valid path" for GIT_WORK_TREE, "not a git repository: ''" for GIT_DIR), so
    # passed through it would turn a layout git honors with GIT_DIR alone into a
    # failed lookup, and unset is what such an export means.
    for name in _GIT_LOCATION_ENV:
        value = environ.get(name)
        if value is None:
            continue
        if not value:
            del environ[name]
        elif not os.path.isabs(value):
            environ[name] = os.path.abspath(value)
    work_tree = environ.get("GIT_WORK_TREE")
    git_dir = environ.get("GIT_DIR")
    started_in = os.getcwd() if cwd is None else os.path.abspath(cwd)
    if (
        git_dir
        and work_tree
        and os.path.isdir(work_tree)
        and _is_at_or_below(started_in, work_tree)
    ):
        return environ
    if git_dir and not work_tree and _core_worktree_names_a_tree(git_dir, started_in):
        return environ
    return _git_environ()


def _is_at_or_below(path: str, root: str) -> bool:
    """Whether *path* is *root* or inside it, both read through their real paths.

    ``os.path.normcase`` on both, so a volume that ignores case compares as git
    does there; ``is_relative_to`` rather than ``os.path.commonpath``, which
    raises on two Windows paths with no drive in common.
    """
    real_path = Path(os.path.normcase(os.path.realpath(path)))
    real_root = Path(os.path.normcase(os.path.realpath(root)))
    return real_path == real_root or real_path.is_relative_to(real_root)


def git_repository_root(path: Path, *, values: Iterable[str] = ()) -> Optional[Path]:
    """Return the root of the git repository containing *path*, or None.

    Needed because ``git diff --name-only`` prints paths relative to the
    repository root, not to the directory it was run from. Resolving those paths
    against the scan directory is only correct when the two coincide -- true for a
    single-directory scan of a checkout, and not true for a workspace project that
    sits below a larger repository. Callers that need to turn a diff into absolute
    paths must join against this, not against their own source directory.

    Also the discriminator for "is this a git repository at all", which
    ``get_changed_files`` cannot answer: it returns ``None`` both for "git is
    missing" and for "the ref does not exist", and a non-repository is a third
    thing that needs a different response.

    Args:
        path: Any directory. Its containing repository is returned, which may be
            an ancestor.

        values: The run's environment-read values when the caller knows them,
            for the stderr line a problem clause can quote.

    Returns:
        The absolute repository root, or ``None`` when *path* is not inside a git
        repository, git is not on ``PATH``, or the command times out.
        :func:`git_repository_root_problem` says which.
    """
    root, problem = _rev_parse_toplevel(path, values=values)
    key = _problem_key(path)
    with _root_problems_lock:
        if problem is None:
            _root_problems.pop(key, None)
        else:
            _root_problems[key] = problem
    return root


#: The clause a warning uses when git itself is absent.
GIT_NOT_INSTALLED = "git is not installed or not on PATH"

# What the last failed git_repository_root of each directory found, kept until
# git_repository_root_problem reads it or the next lookup of that directory
# replaces it. Asking git again for the reason cost a second 30-second timeout
# when git hangs. Locked because a workspace scans its projects in threads.
_root_problems: Dict[str, str] = {}
_root_problems_lock = threading.Lock()


def _problem_key(path: Path) -> str:
    return os.path.abspath(os.fspath(path))


def git_repository_root_problem(path: Path, *, values: Iterable[str] = ()) -> str:
    """Why :func:`git_repository_root` has no answer for *path*, as a clause.

    Asked after a ``None``. The cause is the one that lookup found; git is run
    again only when there was no such lookup (a caller that substituted
    ``git_repository_root``, or asked first). The warnings this feeds said "is
    not inside a git repository" for every ``None``, including when git itself
    was missing, which sent the reader to check a repository that was there.
    ``values`` as for :func:`git_repository_root`; a remembered clause was
    already redacted with the values that lookup carried.
    """
    with _root_problems_lock:
        remembered = _root_problems.pop(_problem_key(path), None)
    if remembered is not None:
        return remembered
    root, problem = _rev_parse_toplevel(path, values=values)
    if problem is not None:
        return problem
    # The second run found a root the first did not, or a caller substituted
    # the lookup. Nothing more specific is known.
    return f"the git repository root of {path.as_posix()} could not be read"


def _why_git_did_not_start(error: OSError, cwd: Optional[Path]) -> str:
    """The cause of a FileNotFoundError from starting git in *cwd*, as a clause.

    subprocess raises the same FileNotFoundError for a missing working directory
    as for a missing program, so the two are told apart here rather than every
    one being reported as git missing.
    """
    if cwd is not None and not Path(cwd).is_dir():
        return f"{Path(cwd).as_posix()} does not exist"
    if shutil.which("git") is None:
        return GIT_NOT_INSTALLED
    where = f" in {Path(cwd).as_posix()}" if cwd is not None else ""
    return f"git could not be started{where}: {error}"


# Every git command here runs with no stdin. git reads the files a repository
# names (a worktree's commondir, a .git file's gitdir), and one linked to
# /dev/stdin made it read ASH's: a silent terminal held it for the 30-second
# timeout, and what someone typed went to git.
#
# They run through plain subprocess.run, not run_ended_with_the_server: each is a
# query bounded by that timeout, so one running when an MCP server stops ends on
# its own soon after.
#
# Their output is read as bytes and decoded by _git_text. git prints a path as the
# bytes of its name, and Python reads a file name with the filesystem encoding, so
# the output is decoded the way ``os.fsdecode`` decodes a name: the host's
# filesystem encoding on POSIX, which a legacy locale (ISO-8859-1, EUC-JP) makes
# something other than UTF-8, and a byte that does not decode is kept as a
# surrogate, as Python keeps it in a name. On Windows the codec is UTF-8 outright
# and not ``sys.getfilesystemencoding()``: git for Windows prints UTF-8, and
# PYTHONLEGACYWINDOWSFSENCODING=1 (the PEP 529 opt-out) makes the filesystem
# encoding "mbcs", a code page that turns a non-ASCII name into one that names no
# file.


def _git_output_codec() -> "tuple[str, str]":
    """The (encoding, errors) git's output is decoded with on this host.

    UTF-8 on Windows whatever ``sys.getfilesystemencoding()`` says there, with the
    handler ``os.fsdecode`` uses there by default (``surrogatepass``): output that
    is not UTF-8 raises ``UnicodeDecodeError``. The git-directory, worktree and
    listing lookups catch it and answer None; the stdout decode in
    ``_rev_parse_toplevel`` and the one in ``get_changed_files`` sit outside a
    ``try`` and let it propagate, as they did with ``os.fsdecode`` in the default
    mode (under ``PYTHONLEGACYWINDOWSFSENCODING=1`` that decode used the ``replace``
    handler and never raised). Elsewhere the filesystem's own encoding and error
    handler.
    """
    if sys.platform == "win32":
        return "utf-8", "surrogatepass"
    return sys.getfilesystemencoding(), sys.getfilesystemencodeerrors()


def _git_text(output: bytes | str) -> str:
    """git's output as the text a file name would be: see :func:`_git_output_codec`.

    A ``str`` is returned as it is, for the callers that are handed text.
    """
    if isinstance(output, str):
        return output
    encoding, errors = _git_output_codec()
    return output.decode(encoding, errors)


def _git_message_text(output: bytes | str) -> str:
    """git's stderr as text for a message: the codec of :func:`_git_text`, never raising.

    The text is quoted in a problem clause, never matched against a file name, so
    it must not raise out of the lookup that quotes it. Where the codec's handler
    keeps a byte it cannot decode (``surrogateescape`` on POSIX) that handler is
    used, so a value with such a byte still reads back as the needle a redaction
    looks for. Where it raises (``surrogatepass`` on Windows, or ``strict``) the
    byte becomes a replacement character. With ``PYTHONLEGACYWINDOWSFSENCODING=1``
    the decode used to be a code page with the ``replace`` handler, which cannot
    fail; the UTF-8 codec must not make a message that is not UTF-8 raise.
    """
    if isinstance(output, str):
        return output
    encoding, errors = _git_output_codec()
    if errors in ("strict", "surrogatepass"):
        errors = "replace"
    return output.decode(encoding, errors)


def _rev_parse_toplevel(
    path: Path, *, values: Iterable[str]
) -> "tuple[Optional[Path], Optional[str]]":
    """``git rev-parse --show-toplevel`` in *path*: (root, None) or (None, problem).

    ``values`` are the run's environment-read values when the caller knows
    them, for the stderr line a problem clause can quote; the public entries
    forward what their callers pass, defaulted empty."""
    git = _git_executable()
    if git is None:
        return None, GIT_NOT_INSTALLED
    try:
        result = subprocess.run(
            # git_argv: the repository's config names no program git runs here.
            git_argv("rev-parse", "--show-toplevel", program=git),  # nosec B603 B607
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            cwd=path,
            env=_layout_environ(path),
        )
    except FileNotFoundError as error:
        return None, _why_git_did_not_start(error, path)
    except subprocess.TimeoutExpired:
        return None, "git rev-parse --show-toplevel timed out after 30 seconds"
    except (NotADirectoryError, OSError) as error:
        return None, f"git could not be started in {Path(path).as_posix()}: {error}"

    if result.returncode != 0:
        stderr = _git_message_text(result.stderr or b"")
        # Redacted whole BEFORE the first-line cut (redact_then_split) and
        # before any strip: a value holding a line break would otherwise leave
        # its first line in the problem clause, and a value whose own edge is
        # whitespace at stderr's edge would lose that edge to a whole-text
        # strip and stop matching. Each line is stripped only after the
        # redaction, so no needle is shaved first.
        lines = [line.strip() for line in redact_then_split(stderr, values)]
        first_line = next((line for line in lines if line), "")
        if "not a git repository" in stderr.lower():
            return None, f"{Path(path).as_posix()} is not inside a git repository"
        detail = f" ({first_line})" if first_line else ""
        return None, (
            f"git could not read the repository root of {Path(path).as_posix()}{detail}"
        )
    top = _git_path_line(result.stdout)
    if not os.path.isabs(top):
        return None, f"git printed no repository root for {Path(path).as_posix()}"
    return Path(top).resolve(), None


def git_common_dir(path: Path) -> Optional[Path]:
    """The ``git rev-parse --git-common-dir`` of the repository at *path*, resolved.

    Two worktrees of one repository share it, and a submodule or an unrelated
    clone has its own. utils/scan_source.py exempts a linked worktree inside its
    checkout from the nesting check only when this matches the outer
    repository's, ``git_worktree_paths`` lists it, and its admin dir records it
    (``git_absolute_git_dir``): a listed path that now holds another repository
    fails this check, and a planted ``.git`` file that names the outer git dir
    passes it. GIT_DIR and its siblings are left out of git's environment, so
    the answer is about *path*.

    Returns:
        The absolute common git directory, or ``None`` when *path* is not inside
        a git repository, git is missing or refuses it (safe.directory), the
        command times out, or the path it prints is not a file name here
        (:func:`_git_path_line`).
    """
    git = _git_executable()
    if git is None:
        return None
    try:
        result = subprocess.run(
            git_argv("rev-parse", "--git-common-dir", program=git),  # nosec B603 B607
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            cwd=path,
            env=_git_environ(),
        )
        common = _git_path_line(result.stdout)
    except (
        FileNotFoundError,
        NotADirectoryError,
        subprocess.TimeoutExpired,
        OSError,
        UnicodeDecodeError,
    ):
        return None
    if result.returncode != 0 or not common:
        return None
    # Relative to *path* for a main checkout (".git"), absolute otherwise.
    return (Path(path) / common).resolve()


def git_absolute_git_dir(path: Path) -> Optional[Path]:
    """The ``git rev-parse --absolute-git-dir`` of the repository at *path*, resolved.

    For a linked worktree, its admin dir under the common git dir's
    ``worktrees/``. utils/scan_source.py checks that a directory exempted as a
    linked worktree has one, and that the admin dir's ``gitdir`` names that
    directory. GIT_DIR and its siblings are left out of git's environment, so
    the answer is about *path*.

    Returns:
        The absolute git directory, or ``None`` when *path* is not inside a git
        repository, git is missing or refuses it (safe.directory), the command
        times out, or the path it prints is not a file name here
        (:func:`_git_path_line`).
    """
    git = _git_executable()
    if git is None:
        return None
    try:
        result = subprocess.run(
            git_argv("rev-parse", "--absolute-git-dir", program=git),  # nosec B603 B607
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            cwd=path,
            env=_git_environ(),
        )
        git_dir = _git_path_line(result.stdout)
    except (
        FileNotFoundError,
        NotADirectoryError,
        subprocess.TimeoutExpired,
        OSError,
        UnicodeDecodeError,
    ):
        return None
    if result.returncode != 0 or not git_dir:
        return None
    return Path(git_dir).resolve()


def git_worktree_paths(path: Path) -> Optional[Set[Path]]:
    """The worktrees ``git worktree list`` names for the repository at *path*.

    The main worktree and every linked one, as git prints them, not resolved
    here. By default git records a linked worktree's real absolute path when it
    adds one, and prints the main worktree's real path, so resolving would only
    follow a symlink that later replaced a listed path (or one of its parents)
    to whatever it points at now, a nested clone or a planted ``.git`` file. A
    worktree added with ``--relative-paths`` or ``worktree.useRelativePaths``
    (git 2.48 and later) is recorded relative to its admin dir instead, and git
    resolves that path when it lists it, so it follows such a symlink itself:
    for those, this list says nothing about the directory now at the path, and
    scan_source.py checks the admin dir's record too.

    utils/scan_source.py uses this with ``git_common_dir`` and
    ``git_absolute_git_dir`` to tell a linked worktree inside its checkout from
    a nested repository. GIT_DIR and its siblings are left out of git's
    environment, so the answer is about *path*.

    Returns:
        The absolute worktree paths, or ``None`` when *path* is not inside a git
        repository, git is missing or refuses it (safe.directory), the command
        times out, or its output is not file names here (:func:`_git_paths`).
    """
    git = _git_executable()
    if git is None:
        return None
    try:
        result = subprocess.run(
            git_argv(  # nosec B603 B607
                "worktree", "list", "--porcelain", "-z", program=git
            ),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            cwd=path,
            env=_git_environ(),
        )
        fields = _git_paths(result.stdout)
    except (
        FileNotFoundError,
        NotADirectoryError,
        subprocess.TimeoutExpired,
        OSError,
        UnicodeDecodeError,
    ):
        return None
    if result.returncode != 0:
        return None
    # -z ends every attribute line with NUL; a "worktree <path>" line opens each
    # entry, so a path with a newline in it is read whole.
    paths = {
        Path(field[len("worktree ") :])
        for field in fields
        if field.startswith("worktree ")
    }
    return paths or None


#: Variables that change what a pathspec matches. They are left out of the
#: environment of the listings below, which set GIT_LITERAL_PATHSPECS themselves
#: or spell their own magic: a path is matched as written, never as a glob or
#: ignoring case.
_GIT_PATHSPEC_ENV = (
    "GIT_GLOB_PATHSPECS",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
    "GIT_LITERAL_PATHSPECS",
)


def _git_listing(
    repository: Path, args: List[str], literal: bool = True
) -> Optional[List[str]]:
    """``git ls-files -z`` *args* in *repository*: its paths, or None.

    Paths are relative to *repository*, as ``ls-files`` prints them from there,
    and matched literally; with *literal* False, the pathspecs in *args* carry
    their own magic instead. GIT_DIR and its siblings, GIT_INDEX_FILE (a hook's
    temporary index, say) and the pathspec variables are left out, so the
    answer is about the repository at *repository* and the paths as given.

    Returns:
        The paths, or None when git is missing, refuses the repository
        (safe.directory), fails, times out, or prints something that is not a
        file name here (:func:`_git_paths`).
    """
    git = _git_executable()
    if git is None:
        return None
    environ = _git_environ(without=(*_GIT_PATHSPEC_ENV, "GIT_INDEX_FILE"))
    if literal:
        environ["GIT_LITERAL_PATHSPECS"] = "1"
    try:
        result = subprocess.run(
            git_argv("ls-files", "-z", *args, program=git),  # nosec B603 B607
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            cwd=repository,
            env=environ,
        )
        fields = _git_paths(result.stdout)
    except (
        FileNotFoundError,
        NotADirectoryError,
        subprocess.TimeoutExpired,
        OSError,
        UnicodeDecodeError,
    ):
        return None
    if result.returncode != 0:
        return None
    return [field for field in fields if field]


def _pathspec_for_exactly(path: str) -> str:
    """A pathspec that matches *path* and nothing below it.

    A plain pathspec, literal or not, also matches every path below the one it
    names. A ``:(glob)`` pathspec with a wildcard in it is matched against the
    whole path instead, and a backslash-escaped character counts as one, so the
    last character is escaped (every glob character before it is too).
    """
    escaped = "".join("\\" + char if char in "*?[\\" else char for char in path[:-1])
    return f":(glob){escaped}\\{path[-1]}"


def _pathspecs_below_and_exactly(
    relative: str, exactly: Sequence[str], suffix: str = ""
) -> List[str]:
    """Pathspecs for *relative* and everything below it, plus one per path in
    *exactly* (with *suffix* after it) for that path alone; the listing that
    takes them runs with ``literal=not exactly``."""
    if not exactly:
        return [relative]
    return [
        f":(literal){relative}",
        *(_pathspec_for_exactly(path) + suffix for path in exactly),
    ]


def git_index_paths_below(
    repository: Path, relative: str, exactly: Sequence[str] = ()
) -> Optional[List[str]]:
    """The index entries of the repository at *repository* at or below *relative*,
    and at each path in *exactly*.

    One ``git ls-files`` with *relative* (``/``-separated, from *repository*)
    as a literal pathspec: a gitlink is listed as its own path, and nothing
    below it is. Each path in *exactly* gets a pathspec that matches it alone
    (:func:`_pathspec_for_exactly`), since one that named it plainly would list
    everything below it too, which for the top directory of a monorepo is most
    of the index. ls-files answers from the index alone, so a gitlink there is
    listed whether or not its commit is in the repository (``git cat-file
    --batch-check`` calls such a gitlink missing), and so is an entry a merge
    left unmerged. utils/scan_source.py uses it to ask whether a repository
    that a GIT_CEILING_DIRECTORIES entry hides tracks a directory below it, or
    a path between them.

    Returns:
        The paths, relative to *repository*, or None when git could not answer.
    """
    return _git_listing(
        repository,
        ["--", *_pathspecs_below_and_exactly(relative, exactly)],
        literal=not exactly,
    )


def git_untracked_paths_below(
    repository: Path, relative: str, exactly: Sequence[str] = ()
) -> Optional[List[str]]:
    """What the repository at *repository* lists as untracked at or below *relative*,
    and which of the directories in *exactly* it lists as untracked.

    ``git ls-files --others --exclude-standard --directory`` with *relative* as a
    literal pathspec: untracked and not ignored, by the repository's ignore files,
    ``info/exclude`` and ``core.excludesFile``. A directory git does not descend
    into (another repository, a linked worktree, a directory with nothing
    tracked) is listed once, with a trailing ``/``. Nothing below a gitlink is
    listed. Each directory in *exactly* gets a pathspec that matches it alone
    and is listed, as ``<path>/``, only when git lists the directory itself.
    utils/scan_source.py uses it with ``git_index_paths_below``.

    Returns:
        The paths, relative to *repository*, or None when git could not answer.
    """
    return _git_listing(
        repository,
        [
            "--others",
            "--exclude-standard",
            "--directory",
            "--",
            *_pathspecs_below_and_exactly(relative, exactly, suffix="/"),
        ],
        literal=not exactly,
    )


def _git_path_line(output: bytes | str) -> str:
    """The path git printed on a line of its own, spelled as Python spells a file name.

    Only the newline git ends the line with is removed: a strip took a trailing
    space off the name of a repository root, and every changed path was then
    joined onto a directory that is not the repository. Decoded as a file name
    (:func:`_git_text`), not in text mode, which raised ``UnicodeDecodeError``
    for a root that is not UTF-8. On Windows, where no file name holds a carriage
    return, one before the newline is removed too.
    """
    text = _git_text(output)
    if text.endswith("\n"):
        text = text[:-1]
        if sys.platform == "win32" and text.endswith("\r"):
            text = text[:-1]
    return text


def _git_paths(output: bytes) -> List[str]:
    """The NUL-separated fields git printed with ``-z``, each spelled as Python
    spells a file name.

    git prints a path as the bytes of its name, and in UTF-8 on Windows. Each
    path read here is compared with a name on disk, so the output is decoded as
    :func:`_git_text` decodes it, the way :func:`os.fsdecode` decodes that name:
    on Linux a byte that is not UTF-8 is kept as a surrogate. Text mode would
    decode with the locale's encoding, which on Windows is a code page (cp1252,
    say), not UTF-8. On Windows the output is read as UTF-8 even when
    ``PYTHONLEGACYWINDOWSFSENCODING=1`` makes the filesystem encoding a code
    page, and output that is not UTF-8 raises ``UnicodeDecodeError``, which the
    callers take as no answer.
    """
    return _git_text(output).split("\0")


#: The characters a base ref may hold. Narrower than git's own ref name rules,
#: which also allow shell metacharacters, quotes and non-ASCII text.
_BASE_REF_CHARACTERS = re.compile(r"[a-zA-Z0-9._/~^@{}\-]+")

#: ``~<n>`` and ``^<n>`` steps after a ref name (gitrevisions(7)): ``HEAD~1`` is
#: the commit before ``HEAD``, ``HEAD^2`` its second parent.
_ANCESTRY_STEPS = re.compile(r"(?:[~^][0-9]*)+\Z")


class InvalidBaseRefError(ValueError):
    """A base ref ASH does not pass to git, so the changed-files scan is refused."""


def _breaks_ref_name_rules(name: str) -> bool:
    """Whether ``git check-ref-format --allow-onelevel`` refuses *name*.

    The rules of git-check-ref-format(1), checked here so that no git process
    starts for a value git would refuse: no ``..``, ``//``, ``@{`` or ``\\``; no
    space, ``~``, ``^``, ``:``, ``?``, ``*``, ``[`` or ASCII control character; no
    leading or trailing ``/``, no trailing ``.``; not ``@`` alone; and no
    ``/``-separated component that starts with ``.`` or ends with ``.lock``.
    ``tests/unit/utils/test_base_ref.py`` compares this with git itself.
    """
    if name in ("", "@") or name.startswith("/") or name.endswith(("/", ".")):
        return True
    if any(sequence in name for sequence in ("..", "//", "@{")):
        return True
    if any(ch in " ~^:?*[\\" or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        return True
    return any(
        component.startswith(".") or component.endswith(".lock")
        for component in name.split("/")
    )


def validate_base_ref(base_ref: str) -> str:
    """Return *base_ref* when git can read it only as a revision; raise otherwise.

    A base ref goes to ``git diff`` as ``<base_ref>...HEAD``, and git reads any
    argument that starts with ``-`` as an option, whatever follows it:
    ``--output=<file>`` makes git write the diff into that file, and ``-O<file>``
    turns the command into a different diff that exits 0 and names no files. So
    a base ref is accepted only when it is a ref name that ``git check-ref-format
    --allow-onelevel`` accepts (a branch, a tag, a remote-tracking branch,
    ``HEAD`` or a commit id), in the characters :data:`_BASE_REF_CHARACTERS`
    allows, optionally followed by ``~<n>`` or ``^<n>`` steps. Reflog forms such
    as ``main@{1}`` are refused, since ``@{`` breaks the ref name rules.

    Called by every entry point before it starts any git process: the CLI, the
    ``run_ash_scan`` library call, a workspace run, and :func:`get_changed_files`.

    Raises:
        InvalidBaseRefError: naming the value (escaped with ``repr``) and why.
    """
    if not base_ref:
        reason = "it is empty"
    elif base_ref.startswith("-"):
        reason = "it starts with '-', which git reads as an option"
    elif not _BASE_REF_CHARACTERS.fullmatch(base_ref):
        reason = "it holds a character other than letters, digits and . _ / ~ ^ @ { } -"
    elif _breaks_ref_name_rules(_ANCESTRY_STEPS.sub("", base_ref)):
        reason = "it is not a ref name git accepts (see git check-ref-format)"
    else:
        return base_ref
    raise InvalidBaseRefError(
        f"Refusing --base-ref {base_ref!r}: {reason}. Name a branch, a tag or a "
        "commit, optionally followed by ~<n> or ^<n>: for example origin/main, "
        "v1.2.0 or HEAD~1."
    )


def get_changed_files(
    base_ref: str = "origin/main", cwd: Optional[Path] = None
) -> Optional[List[Path]]:
    """Return files changed between *base_ref* and HEAD using ``git diff``.

    Falls back to ``None`` (meaning "report every finding") when:
    * ``git`` is not available on ``PATH``, or
    * *base_ref* does not exist in the local repository.

    Args:
        base_ref: The git ref to diff against.  Defaults to ``origin/main``.
        cwd: Directory to run git from (must be inside the target repo).
             Defaults to the current working directory.

    Returns:
        A list of :class:`~pathlib.Path` objects relative to the repo root,
        or ``None`` if the diff could not be computed.

    The names are read as git stores them: ``-z`` separates them with NUL and
    prints each verbatim, and ``core.quotePath=false`` keeps git from quoting
    one. Read line by line and stripped, with the default ``core.quotePath``, a
    name holding a byte above 0x7f, a control character, a double quote or a
    backslash came back C-quoted, and a leading or trailing space was lost; such
    a name matched no file, and the findings in it were dropped. Each name is
    decoded as Python decodes a file name (:func:`_git_text`).

    Raises:
        InvalidBaseRefError: when :func:`validate_base_ref` refuses *base_ref*.
            No git process is started for it.
    """
    validate_base_ref(base_ref)

    git = _git_executable()
    if git is None:
        ASH_LOGGER.warning(f"{GIT_NOT_INSTALLED}; reporting every finding")
        return None
    try:
        # -z and core.quotepath=false, because git otherwise quotes a name holding a
        # non-ASCII byte, a quote, a backslash or a control character
        # ("\303\274.py"), and that string names no file: those changes never
        # matched a finding. -z separates names with NUL and prints them raw, so a
        # name is never split or stripped either. Each name is decoded as Python
        # decodes a file name (_git_text), so the Path still names the file on
        # disk. git_argv: the repository's config names no program git runs here.
        #
        # The trailing "--" makes git read the range only as revisions. Without
        # it, when the base ref is missing here (origin/main in a shallow clone)
        # and the checkout has a file named "origin/main...HEAD", git reads the
        # argument as that path, diffs it between the working tree and the index,
        # and exits 0. With it, git exits 128 on the missing ref and the full-scan
        # fallback applies.
        #
        # diff.relative=false, because the names are joined onto the repository
        # root (git_repository_root), which is what git prints by default. With
        # diff.relative set in the repository's or the user's config, git prints
        # them relative to *cwd* and leaves out every change above it, so a scan
        # of a subdirectory or a workspace project joined cwd-relative names onto
        # the root, matched no finding, and reported nothing.
        result = subprocess.run(
            git_argv(  # nosec B603 B607
                "-c",
                "core.quotepath=false",
                "-c",
                "diff.relative=false",
                "diff",
                "--name-only",
                "-z",
                f"{base_ref}...HEAD",
                "--",
                program=git,
            ),
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            cwd=cwd,
            # The same environment as the root lookup's (_layout_environ), so the
            # diff and the root its names are joined onto describe one repository:
            # the one git discovers from cwd, or the one GIT_DIR and GIT_WORK_TREE
            # name together.
            env=_layout_environ(cwd),
        )
    except FileNotFoundError as error:
        ASH_LOGGER.warning(
            f"{_why_git_did_not_start(error, cwd)}; reporting every finding",
            extra=NO_MARKUP,
        )
        return None
    except subprocess.TimeoutExpired:
        ASH_LOGGER.warning(
            f"git diff against {base_ref} timed out after 30 seconds; reporting "
            "every finding",
            extra=NO_MARKUP,
        )
        return None
    except OSError as error:
        # NotADirectoryError (a working directory that is a file), PermissionError and
        # the rest of what starting git can raise: the same answer as a git that is not
        # there, as the repository-root lookup gives for the same errors.
        shown = Path(cwd).as_posix() if cwd is not None else "the working directory"
        ASH_LOGGER.warning(
            f"git could not be started in {shown}: {error}; reporting every finding",
            extra=NO_MARKUP,
        )
        return None

    if result.returncode != 0:
        ASH_LOGGER.warning(
            "git diff against %s failed (rc=%d); reporting every finding",
            base_ref,
            result.returncode,
            extra=NO_MARKUP,
        )
        return None

    # Every name ends in NUL, so the last entry is empty; nothing is stripped, since
    # a leading or trailing space is part of a name.
    return [Path(_git_text(name)) for name in result.stdout.split(b"\0") if name]


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        Parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Get list of files not matching .gitignore underneath SourceDir arg path"
    )
    parser.add_argument("--source", help="path to scan", default=os.getcwd(), type=str)
    parser.add_argument(
        "--output",
        help="output path to save the ash-ignore-report.txt and ash-scan-set-files-list.txt files to",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--filter-pattern",
        help="Filter results against a regular expression pattern, searched for anywhere in each path as listed: the --source value as given, then the file's path below it (anchor it with ^ or $). Defaults to returning empty which returns the full list of files to be included in the scan.",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--ignorefile",
        help=(
            "ignore file to use in addition to the standard gitignore. A path "
            "outside the scan root is allowed; its rules are applied from the "
            "scan root, since a base outside the tree would match nothing in it"
        ),
        default=[],
        type=str,
        nargs="*",
    )
    parser.add_argument(
        "--honor-ignore-files",
        help=(
            "Whether the .gitignore and .ignore files in the scanned tree decide "
            "what is left out (default). --no-honor-ignore-files lists every file "
            "but the ones ASH leaves out on its own"
        ),
        default=True,
        action=argparse.BooleanOptionalAction,
    )
    parser.add_argument(
        "--debug", help="Enables debug logging", action=argparse.BooleanOptionalAction
    )
    return parser.parse_args()


def honors_ignore_files(config: Any) -> bool:
    """The ``honor_ignore_files`` setting of *config*, True when it has none.

    For callers holding a plugin context's config, which tests build from mocks:
    anything but a real ``False`` reads as the default.
    """
    return getattr(config, "honor_ignore_files", True) is not False


def new_run_id() -> str:
    """An ID for one scan: the run :func:`scan_set` records its lists under."""
    return uuid.uuid4().hex


#: How a list's names become bytes, and back. UTF-8, with the filesystem's error
#: handler: a name that is not UTF-8 is a str with surrogate escapes from
#: ``os.walk`` on POSIX, written as the bytes the filesystem holds, and a
#: strict encode made the write raise for any tree holding one.
_LIST_ENCODING = "utf-8"
_LIST_ERRORS = sys.getfilesystemencodeerrors()


def _list_bytes(lines: List[str]) -> bytes:
    return "\n".join(lines).encode(_LIST_ENCODING, _LIST_ERRORS)


def _list_lines(data: bytes) -> List[str]:
    """The names :func:`_list_bytes` wrote, split on ``\\n`` alone.

    ``str.splitlines`` also splits on ``\\r``, ``\\x0b``, ``\\x0c``,
    ``\\x1c``-``\\x1e``, ``\\x85``, U+2028 and U+2029, every one of which a file
    name can hold: ``a\\x0cb.py`` came back as two names. An empty file is an
    empty list.

    Only the separator is removed, never other whitespace: a name may end in a
    space, a tab or, on POSIX, a carriage return. On Windows, where no file name
    holds a carriage return, one at the end of a record is part of a ``\\r\\n``
    separator and is removed too.
    """
    text = data.decode(_LIST_ENCODING, _LIST_ERRORS)
    records = text.split("\n") if text else []
    if sys.platform == "win32":
        records = [record.removesuffix("\r") for record in records]
    return records


def _without_dot_segments(path: str) -> str:
    """*path* with ``.`` segments and repeated separators removed; ``..`` kept.

    ``os.path.abspath`` and ``os.path.normpath`` fold ``a/../b`` to ``b`` by
    string manipulation. The walk does not: it opens the path as spelled. On
    POSIX the kernel resolves the component before ``..`` -- a symlink, or nothing
    at all -- so ``sub/../rules.txt`` can be another file than ``rules.txt``, or
    no file. Windows folds ``sub\\..`` away before the file system sees it, and
    there keeping ``..`` only costs a second walk. Only spellings every host reads
    as one name are made to compare equal: a ``.`` segment and a repeated
    separator never change what a path names.
    """
    sep = os.sep
    if os.altsep:
        path = path.replace(os.altsep, sep)
    drive, rest = os.path.splitdrive(path)
    segments = [segment for segment in rest.split(sep) if segment not in ("", ".")]
    collapsed = sep.join(segments)
    if rest.startswith(sep):
        collapsed = sep + collapsed
    elif not collapsed:
        # Nothing but "." segments and separators: the path names its own directory.
        collapsed = "."
    if rest.endswith(sep) and not collapsed.endswith(sep):
        # A trailing separator asks for a directory -- the system refuses it on a
        # regular file -- so it is kept apart from the plain spelling.
        collapsed += sep
    return drive + collapsed


def _scan_set_inputs(
    source: str | Path, ignorefile: Sequence[str | Path]
) -> Dict[str, Any]:
    """Which tree a scan set lists, as its run record holds it.

    Two calls of one run that share an output directory reuse one pair only when
    these match: another source, or other ignore files, lists other files. The
    source is kept two ways, and both must match: as the caller spelled it
    (``source``) and made absolute against the working directory at the time of
    the call (``source_abs``). The saved list holds paths joined onto the source
    as the first caller spelled it, so a caller that spells the same directory
    another way (``.`` and its absolute path) walks its own tree and gets paths
    in its own spelling, rather than reading names in the writer's. The absolute
    form keeps a relative spelling from matching another tree after the working
    directory changes: ``a`` under two directories is two sources.

    Each ignore file is joined below the absolute source when relative, as the
    walk joins it below the source, then its ``.`` segments and repeated
    separators are removed, so ``./rules.txt`` and ``rules.txt`` match. ``..`` is
    kept (:func:`_without_dot_segments`): on POSIX the kernel resolves the
    component before it, a symlink or nothing at all, so ``sub/../rules.txt`` is
    not the same name as ``rules.txt`` and the two do not share a pair. The files
    are compared sorted and without duplicates: the ignore report orders ignore
    files itself, shallowest first, and a file's rules are the same however often
    or in whatever order it is named, so neither changes the list the walk builds.

    The run's own settings are not compared. A list read back is the run's,
    whatever ``honor_ignore_files`` the reader passes (see :func:`scan_set`), and
    ``workspace_output_dir`` is named by the run's writers and not by the
    scanners that read its list, so comparing it would have every reader in a
    workspace scan walk the tree again with the workspace output left in.
    ``debug``, ``print_results`` and ``filter_pattern`` change what a call prints
    or returns, not the list it builds.
    """
    root = os.path.abspath(os.fspath(source))
    resolved = sorted(
        {
            _without_dot_segments(os.path.join(root, os.fspath(entry)))
            for entry in ignorefile
        }
    )
    return {"source": os.fspath(source), "source_abs": root, "ignorefile": resolved}


#: The keys :func:`_scan_set_inputs` returns, which a run record's ``inputs`` must hold.
_SCAN_SET_INPUT_KEYS = frozenset({"source", "source_abs", "ignorefile"})


def _record_this_run_wrote(output_path: Path, run_id: str) -> Optional[Dict[str, Any]]:
    """The run record in *output_path*, if run *run_id* wrote it.

    The record alone, read without touching the pair beside it: whether that
    pair is intact is the digest check in :func:`_lists_this_run_wrote`, so a
    caller can tell "the run wrote a pair here", however the pair looks now,
    apart from "the pair can be read back". None for no record, a damaged one,
    or another run's. Damaged includes a record that parses but is not the shape
    :func:`_write_lists` writes (an ``inputs`` object holding the keys
    :func:`_scan_set_inputs` returns, and ``sha256`` as a map or null): it names
    no owner, so the next call writes the pair again. A record
    whose ``sha256`` is null marks a pair the run wrote but no call may read back
    (a name with a newline in it).
    """
    try:
        record = json.loads(
            (output_path / SCAN_SET_RUN_FILE_NAME).read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict) or record.get("run_id") != run_id:
        return None
    inputs = record.get("inputs")
    digests = record.get("sha256", False)
    if not isinstance(inputs, dict) or not _SCAN_SET_INPUT_KEYS.issubset(inputs):
        return None
    if digests is not None and not isinstance(digests, dict):
        return None
    return record


def _lists_this_run_wrote(
    output_path: Path,
    run_id: str,
    inputs: Optional[Mapping[str, Any]] = None,
) -> Optional[tuple[list[str], list[str]]]:
    """The ignore report and the scan-set list in *output_path*, if run *run_id* wrote them.

    Read only when ``SCAN_SET_RUN_FILE_NAME`` there names *run_id* and the SHA-256
    of each file as it is now, and, when *inputs* is given
    (:func:`_scan_set_inputs`), records the same inputs. None for a pair with no
    record, another run's, one built from other inputs, one recorded as not
    reusable (``sha256`` null, a name with a newline in it), a damaged record, or
    a file changed since it was written: a pair an earlier run left, or one a
    repository committed to its ``.ash/ash_output``, is not read.
    """
    record = _record_this_run_wrote(output_path, run_id)
    if record is None:
        return None
    digests = record.get("sha256")
    if not isinstance(digests, dict):
        return None
    if inputs is not None and record.get("inputs") != dict(inputs):
        ASH_LOGGER.debug(
            "Not reusing the scan set in %s: this run wrote it for another source "
            "or other ignore files.",
            output_path.as_posix(),
            extra=NO_MARKUP,
        )
        return None
    contents: list[list[str]] = []
    for name in SCAN_START_FILE_NAMES:
        try:
            data = (output_path / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != digests.get(name):
                return None
            contents.append(_list_lines(data))
        except (OSError, UnicodeDecodeError):
            return None
    return contents[0], contents[1]


def _record_names_other_inputs(
    output_path: Path, run_id: str, inputs: Mapping[str, Any]
) -> bool:
    """Whether *output_path* holds a record of run *run_id* built from other inputs.

    True only for a readable record that names *run_id* and whose inputs differ
    from *inputs* (:func:`_scan_set_inputs`). The pair beside such a record is the
    run's, written by its first call, and a call for another tree leaves it as it
    is. The decision is the record's alone (:func:`_record_this_run_wrote`): a pair
    changed since it was written, or recorded as not reusable, is still the run's
    own and is never replaced by a call for other inputs. False for no record, a
    damaged one, another run's, or one with the same inputs (a pair changed since
    it was written is then written again).
    """
    record = _record_this_run_wrote(output_path, run_id)
    return record is not None and record.get("inputs") != dict(inputs)


def scan_set_this_run_wrote(output: str | Path, run_id: object) -> Optional[List[str]]:
    """The scan set run *run_id* wrote to *output*, as :func:`scan_set` returns it.

    None when *run_id* is not a string or that run's list is not there intact
    (:func:`_lists_this_run_wrote`). Walks nothing and writes nothing, for a caller
    that has another way to answer when the run wrote no list: ``ash merge`` has
    no run ID, so it never reads one.
    """
    if not isinstance(run_id, str):
        return None
    reread = _lists_this_run_wrote(Path(output), run_id)
    if reread is None:
        return None
    # As written, not stripped: a name that ends in whitespace keeps it.
    return reread[1]


#: Held while :func:`scan_set` checks for a run's record and writes the pair, so
#: threads of one process that finish their walks together for different inputs
#: cannot both find no record and both write: the first writes, and the other
#: finds its record and leaves the pair. Threads with the same inputs may both
#: write, each the pair of its own walk. Another process is not covered: each
#: replaces a file atomically, and the record it writes names its own inputs.
_PAIR_WRITE_LOCK = threading.Lock()


def _run_settings(output_path: Path, run_id: str) -> Dict[str, Any]:
    """The settings the run recorded beside its scan set, or ``{}``.

    ``honor_ignore_files`` and ``workspace_output_dir``, as the call that wrote the
    pair had them (:func:`_write_lists`). A later call of the run that does not state
    its own takes these (:func:`scan_set`), so a scan set built again because the
    first could not be read back is the one the run asked for.
    """
    record = _record_this_run_wrote(output_path, run_id)
    settings = record.get("settings") if record is not None else None
    return dict(settings) if isinstance(settings, dict) else {}


def _write_lists(
    output_path: Path,
    ignore_lines: list[str],
    scan_set_lines: list[str],
    run_id: Optional[str],
    inputs: Optional[Mapping[str, Any]] = None,
    settings: Optional[Mapping[str, Any]] = None,
) -> None:
    """Write the ignore report and the scan-set list, and, for a run, its record.

    Each file is replaced atomically, the record last, so no reader trusts a pair
    that is half written. Without *run_id* no record is written, and no caller
    reads the pair back. The record holds *inputs* (:func:`_scan_set_inputs`),
    which a later call of the run must match to reuse the pair, and *settings*
    (:func:`_run_settings`), which a later call that states none takes as its own.

    Each list is encoded once, and the record holds the digest of those bytes, not
    of the file as it is after the replace: another run writing to the same output
    directory can replace the file in between, and its list was then recorded, and
    read back, as this run's.

    A scan set holding a name with a ``\\n`` in it, which no newline-separated
    list can give back whole, gets a record whose ``sha256`` is null: the run
    still owns the pair, so a later call of the run with other inputs leaves it,
    but no call reads it back, and every later call walks.
    """
    output_path.mkdir(parents=True, exist_ok=True)
    digests = {}
    # root=output_path: the pair may be written where no PluginContext registered
    # the output directory (the command line, a scanner run on its own), and a
    # link at a list's name is refused there too, never replaced or written
    # through (fs_guard.open_for_write's root argument names these lists).
    for name, lines in zip(SCAN_START_FILE_NAMES, (ignore_lines, scan_set_lines)):
        data = _list_bytes(lines)
        write_bytes_atomically(output_path / name, data, root=output_path)
        digests[name] = hashlib.sha256(data).hexdigest()
    if run_id is not None:
        reusable = not any("\n" in line for line in scan_set_lines)
        if not reusable:
            ASH_LOGGER.debug(
                "Not recording the scan set for reuse: a file name in it holds a "
                "newline, so each scanner that reads the scan set builds it again."
            )
        write_text_atomically(
            output_path / SCAN_SET_RUN_FILE_NAME,
            json.dumps(
                {
                    "run_id": run_id,
                    "inputs": None if inputs is None else dict(inputs),
                    "settings": None if settings is None else dict(settings),
                    "sha256": digests if reusable else None,
                },
                indent=2,
            ),
            root=output_path,
        )


def scan_set(
    source: Optional[str] = None,
    output: Optional[str] = None,
    ignorefile: Optional[list[str]] = None,
    debug: bool = False,
    print_results: bool = False,
    filter_pattern: Optional[re.Pattern] = None,
    honor_ignore_files: Optional[bool] = None,
    exclusions: Optional[Dict[str, Any]] = None,
    run_id: Optional[str] = None,
    write_lists: bool = False,
    workspace_output_dir: Optional[str] = None,
    links_not_scanned: Optional[List[Dict[str, str]]] = None,
    filter_anywhere: bool = False,
) -> list[str]:
    """Get list of files not matching .gitignore underneath source path.

    *output* is the scan's output directory, which the walk leaves out. With
    *run_id* too, the ignore report and the scan set are written there as
    ``ash-ignore-report.txt`` and ``ash-scan-set-files-list.txt``, a record of the
    run that wrote them goes beside them, and a later call with the same *run_id*,
    *source* and *ignorefile* reads the pair back instead of walking the tree. A
    call with another source or other ignore files walks it, returns what it
    found, and leaves the pair and the record as the run's first call wrote them,
    whether or not the pair is still intact. A scan set reused that way is
    returned as it was written, whatever *honor_ignore_files* says. Nothing else
    is read back, so a pair an earlier run left, or one a repository committed to
    its output directory, never decides what a scanner reading the scan set is
    given.

    Without *run_id* nothing is written unless *write_lists* asks for the pair,
    which then has no record. So a call with neither, such as a scanner run on
    its own, leaves the pair in the output directory as it is, a pair the
    repository committed there included.

    Args:
        source: Path to scan. Defaults to current working directory.
        output: The output directory: left out of the walk, and where the
            ash-ignore-report.txt and ash-scan-set-files-list.txt files are saved.
        ignorefile: List of ignore files to use in addition to the standard gitignore.
        debug: Enable debug logging.
        print_results: Print results to stdout. Defaults to False for library usage.
        filter_pattern: Filter results against a re.Pattern, matched from the start of
            each path as listed (``re.match``: *source* as given, then the file's path
            below it), so a pattern that leans on that start, such as a leading negative
            lookahead, keeps its meaning. Defaults to returning the full scan set.
        filter_anywhere: Search *filter_pattern* for anywhere in each path instead
            (``re.search``; anchor it with ``^`` or ``$``). The command line sets it, so
            that an end-anchored ``--filter-pattern`` means what it reads as; a library
            caller gets the match from the start unless it asks.
        honor_ignore_files: Whether the scanned repository's ``.gitignore`` and
            ``.ignore`` files decide what is left out. False scans every file but
            the ones ASH leaves out on its own (``.git``, CDK assets, the bundled
            aws-cdk tree, and *output* when it is inside *source*). The
            ``honor_ignore_files`` config key and
            ``--no-honor-ignore-files`` set it; see :func:`honors_ignore_files`.
            Left unstated (None), a call of a run that has a record in *output*
            takes the run's setting, True when it has none: a scanner that builds
            the scan set again, because the run's could not be read back, builds the
            run's, not one that honors ignore files the run turned off.
        exclusions: When given, filled with the record of what the ignore files
            removed (:func:`ignore_file_exclusion_record`), which the orchestrator
            stores as ``metadata.ignore_file_exclusions``. Left empty when the
            scan set was reused from *output*, since nothing was matched then.
        run_id: The scan's ID (``PluginContext.run_id``, :func:`new_run_id`). None
            walks the tree on every call.
        write_lists: Write the pair to *output* without a *run_id*, as the
            command line does.
        workspace_output_dir: In a workspace scan, the workspace's output
            directory, which holds every project's output and is left out of the
            walk like *output*: a project at the workspace root holds it
            (``PluginContext.workspace_output_dir``). Left unstated (None), a call
            of a run that has a record in *output* takes the run's, as for
            *honor_ignore_files*.
        links_not_scanned: When given, extended with ``{"path", "reason"}`` for
            each file link left out of the scan set because its target leaves
            *source* (:func:`_left_out_as_a_link_leaving_the_tree`): the path below
            *source* with ``/`` separators, and the reason
            ``REASON_LINK_LEAVES_TREE``, sorted by path. Left empty when the scan set
            was read back from *output*, whose list already leaves them out. Every
            such link is also warned about, whether or not this is given.

    Returns:
        List of files not matching ignore specifications.
    """
    if source is None:
        source = os.getcwd()
    if ignorefile is None:
        ignorefile = []

    # Read back below, or computed by the walk.
    ashignore_content: List[str] = []
    ashscanset_list: List[str] = []
    imported = False
    if not isinstance(run_id, str):
        # A context a test or another plugin builds may carry anything in run_id;
        # only a string is a run's ID, and anything else reads nothing back.
        run_id = None
    inputs = _scan_set_inputs(source, ignorefile)

    # What this call leaves unstated is the run's, when the run recorded it: the
    # orchestrator states them, and the scanners that read the scan set do not.
    recorded = _run_settings(Path(output), run_id) if output and run_id else {}
    if honor_ignore_files is None:
        was = recorded.get("honor_ignore_files")
        honor_ignore_files = was if isinstance(was, bool) else True
    if workspace_output_dir is None and isinstance(
        recorded.get("workspace_output_dir"), str
    ):
        workspace_output_dir = recorded["workspace_output_dir"]
    settings = {
        "honor_ignore_files": honor_ignore_files,
        "workspace_output_dir": None
        if workspace_output_dir is None
        else os.fspath(workspace_output_dir),
    }

    if output and run_id is not None:
        reread = _lists_this_run_wrote(Path(output), run_id, inputs)
        if reread is not None:
            ashignore_content, ashscanset_list = reread
            imported = True
            debug_echo(
                f"Imported this run's {', '.join(SCAN_START_FILE_NAMES)} from {output}",
                debug=debug,
            )

    pruned_counts: Dict[str, int] = {}
    own_output_counts: Dict[str, int] = {}
    if not imported:
        # Single os.walk pass collects both ignore files and the full file list
        earlier_output_dirs: List[Tuple[str, Path]] = []
        walked_links: List[str] = []
        discovered_ignores, all_files = _collect_ignorefiles_and_all_files(
            source,
            ignorefile,
            debug=debug,
            honor_ignore_files=honor_ignore_files,
            pruned_counts=pruned_counts,
            own_output=output,
            own_output_counts=own_output_counts,
            output_dir=output,
            workspace_output_dir=workspace_output_dir,
            earlier_output_dirs_reached=earlier_output_dirs,
            links_not_scanned=walked_links,
        )
        for directory, found in own_output_counts.items():
            if found:
                ASH_LOGGER.warning(
                    "%d %s already in ASH's output directory %s, and %s left out "
                    "of the scan set: ASH does not scan its own output directory, "
                    "whatever the ignore files say. Files from an earlier run are "
                    "expected there. If these belong to the repository, write "
                    "ASH's output outside the scanned tree with --output-dir.",
                    found,
                    "file was" if found == 1 else "files were",
                    _source_dir_marker(source, directory),
                    "it was" if found == 1 else "they were",
                )
        ashignore_content = get_ash_ignorespec_lines(
            source,
            ignorefile,
            debug=debug,
            _discovered_ignore_files=discovered_ignores,
        )
        if not honor_ignore_files:
            ashignore_content.insert(0, NOT_HONORED_REPORT_LINE)
            ASH_LOGGER.info(
                "The scanned repository's .gitignore and .ignore files are not "
                "honored for this scan (honor_ignore_files: false), so they remove "
                "nothing from the scan set."
            )
        spec, rule_ids_by_marker = get_ash_ignorespec_with_attribution(
            ashignore_content, source, debug=debug
        )
        ashscanset_list = get_files_not_matching_spec(
            source,
            spec,
            debug=debug,
            _all_files=all_files,
            links_not_scanned=walked_links,
        )
        if links_not_scanned is not None:
            links_not_scanned.extend(
                {
                    "path": relative_display(link, source),
                    "reason": REASON_LINK_LEAVES_TREE,
                }
                for link in sorted(
                    walked_links, key=lambda link: relative_display(link, source)
                )
            )
        _warn_about_scanned_earlier_output_dirs(earlier_output_dirs, ashscanset_list)
        counts = report_ignore_file_exclusions(
            source,
            spec,
            ashscanset_list,
            rule_ids_by_marker,
            all_files,
            debug=debug,
            pruned_counts=pruned_counts,
            honored=honor_ignore_files,
            skipped_ignore_files=sum(
                1
                for line in ashignore_content
                if line.startswith(SKIPPED_MARKER_PREFIX)
            ),
        )
        if exclusions is not None:
            removed = _files_removed_by_ignore_files(
                source, all_files, ashscanset_list
            ) + sum(pruned_counts.values())
            exclusions.update(
                ignore_file_exclusion_record(
                    counts,
                    honored=honor_ignore_files,
                    excluded_file_count=removed,
                    output_dir_file_count=sum(own_output_counts.values()),
                )
            )
    else:
        # The scan set came off disk, so nothing was matched this run and there is
        # no attribution to report. Say that rather than printing nothing, which
        # would read as "no ignore file removed anything".
        ASH_LOGGER.info(
            "Scan set was reused from %s, so per-ignore-file exclusion counts "
            "were not recomputed this run.",
            output,
            extra=NO_MARKUP,
        )

    if output and not imported and (run_id is not None or write_lists):
        # One step: scanners that run in threads each reach this point with their
        # own walk done. Checking for the run's record and writing the pair under
        # one lock lets the first call write and every other call for other inputs
        # find its record.
        #
        # The first call to reach the output directory owns the pair. That holds
        # for the callers that pass run_id today: the orchestrator's two calls, the
        # archive and jupyter converters, detect-secrets, npm-audit, snyk-code,
        # scan_output_dirs.scan_set_of and cfn_template_model. Each passes the
        # context's source directory, as the Path or its str (one spelling), and
        # no ignore file, so their inputs are identical and ownership changes no
        # outcome.
        # The command line passes no run_id and writes a pair with no record to
        # own. A caller that needs to pass run_id with another source or other
        # ignore files needs an explicit owns_lists parameter on scan_set first
        # (there is none yet), so that it does not take the pair from, or leave it
        # to, a call for other inputs by call order alone.
        with _PAIR_WRITE_LOCK:
            owned_by_another_call = run_id is not None and _record_names_other_inputs(
                Path(output), run_id, inputs
            )
            if not owned_by_another_call:
                debug_echo(
                    f"Writing {', '.join(SCAN_START_FILE_NAMES)} to {output}",
                    debug=debug,
                )
                _write_lists(
                    Path(output),
                    ashignore_content,
                    ashscanset_list,
                    run_id,
                    inputs,
                    settings,
                )
        if owned_by_another_call:
            # The run's first call wrote this pair for its own tree. This call
            # answers for another source or other ignore files, so it returns
            # its list and leaves the pair, and the record naming it, as written.
            debug_echo(
                f"Not replacing this run's {', '.join(SCAN_START_FILE_NAMES)} in "
                f"{output}: they were written for another source or other ignore "
                "files.",
                debug=debug,
            )

    # Filtered before it is printed, so what is shown is what is returned. The pair
    # written above is the whole scan set, as before.
    if filter_pattern:
        matcher = re.search if filter_anywhere else re.match
        ashscanset_list = [
            file
            for file in ashscanset_list
            if matcher(pattern=filter_pattern, string=file)
        ]

    if print_results:
        # The names are the repository's: a control or a CI command form in one
        # is shown, not obeyed.
        for file in ashscanset_list:
            print(shown_not_obeyed(file), file=sys.stdout)

    # Each name exactly as the walk found it, or as _list_lines read it back. A
    # strip took the whitespace off a name that ends in a space, a tab or a
    # carriage return, and off a relative source directory that starts with a
    # space, so the scan set named files that do not exist.
    return ashscanset_list


def main() -> int:
    """Main entry point for CLI usage.

    Returns:
        Exit code (0 for success).
    """
    args = parse_args()

    # --filter-pattern was parsed and never passed on, so it filtered nothing.
    filter_pattern = None
    if args.filter_pattern:
        try:
            filter_pattern = re.compile(args.filter_pattern)
        except re.error as error:
            # The error quotes the pattern the operator typed: shown, not obeyed.
            print(
                shown_not_obeyed(
                    f"--filter-pattern is not a regular expression: {error}"
                ),
                file=sys.stderr,
            )
            return 2

    file_list = scan_set(
        source=args.source,
        output=args.output,
        ignorefile=args.ignorefile,
        debug=args.debug,
        print_results=True,
        filter_pattern=filter_pattern,
        filter_anywhere=True,
        honor_ignore_files=args.honor_ignore_files,
        write_lists=True,
    )
    print(shown_not_obeyed(str(file_list)), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
