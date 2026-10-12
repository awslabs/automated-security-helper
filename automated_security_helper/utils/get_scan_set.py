#!/usr/bin/env python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import io
import re
import stat
import subprocess  # nosec B404
import sys
from typing import Any, Dict, List, NamedTuple, Optional, Sequence
from igittigitt import IgnoreParser
from pathlib import Path, PurePosixPath
import argparse
import os

from automated_security_helper.utils.git_command import git_argv
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_dir_links import open_no_follow
from automated_security_helper.utils.scanned_tree import (
    REASON_LINK_LEAVES_TREE,
    TreeInputRefused,
    open_in_scanned_tree,
    relative_display,
    resolves_inside,
)

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
SOURCE_DIR_TOKEN = "${SOURCE_DIR}/"

# The file names ASH reads as ignore files when it walks the scanned tree.
IGNORE_FILE_NAMES = frozenset({".ignore", ".gitignore"})

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
        ASH_LOGGER.debug(message)
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


def _is_link_to_directory(path: str | Path) -> bool:
    """Whether *path* is a symlink, or a Windows junction, rather than a real directory.

    ``os.walk`` lists such an entry among the directories and does not descend it,
    so nothing behind it is ever in the scan set.
    """
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction is not None and isjunction(path))


def _walk_unless_link(top: str | Path):
    """``os.walk(top)``, or nothing when *top* is a link or junction to a directory.

    ``os.walk`` lists a link to a directory below its top without descending it,
    but it follows one given as the top. Every walk that counts files ASH did not
    scan goes through here, so a link the repository placed, at any depth, is
    never followed: nothing behind it is in a scan set, honored or not, and
    following it would read wherever the link points, outside the tree included.
    """
    if _is_link_to_directory(top):
        return iter(())
    return os.walk(top)


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
    if not os.path.islink(full_path) or resolves_inside(full_path, root):
        return False
    ASH_LOGGER.warning(
        f"Not scanning {relative_display(full_path, root)!r}: {REASON_LINK_LEAVES_TREE}"
    )
    if links_not_scanned is not None:
        links_not_scanned.append(full_path)
    return True


def file_links_leaving_tree(
    root: str | Path, all_files: Optional[List[str]] = None
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
                if entry.is_dir(follow_symlinks=False) and not _is_link_to_directory(
                    entry.path
                ):
                    pending.append((entry.path, f"{relative}/"))
                    continue
                if entry.is_symlink() and os.path.isdir(entry.path):
                    continue
            except OSError:
                continue
            if entry.is_symlink() and not resolves_inside(entry.path, root):
                links.append(relative)
            if all_files is not None:
                all_files.append(relative)
    return sorted(links)


#: The log files the running scan has already opened in its output directory when
#: the scan set is built. Not counted among the files found there.
_THIS_RUNS_LOG_FILES = frozenset({"ash.log", "ash.log.jsonl"})


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

    #: :func:`_directory_identity` of the directory, followed if it is a link (it
    #: is where ASH writes, whatever it is called; the orchestrator refuses a
    #: symlinked one anyway). None when it does not exist.
    identity: Optional[tuple[int, int]]
    #: Its absolute, case-normalized path, for when the identity cannot decide.
    path: str


def _own_output_of(output: Optional[str | Path]) -> Optional[_OwnOutput]:
    if not output:
        return None
    return _OwnOutput(
        identity=_directory_identity(output, follow_symlinks=True),
        path=os.path.normcase(os.path.abspath(output)),
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


def _count_files_in_own_output(directory: str) -> int:
    """How many files were already in ASH's output directory, this run's logs aside."""
    count = 0
    for root, _dirs, files in _walk_unless_link(directory):
        count += sum(
            1
            for name in files
            if not (root == directory and name in _THIS_RUNS_LOG_FILES)
        )
    return count


#: The ``ASH_INCLUSIONS`` entries :func:`_excluded_by_ash_itself` restates. A change
#: to ``ASH_INCLUSIONS`` has to change that function too; a test compares them.
_RESTATED_ASH_INCLUSIONS = (".git", "**/cdk.out/asset.*", "!**/*.template.json")


def _excluded_by_ash_itself(walked: str, parts: Sequence[str]) -> bool:
    """Whether ASH leaves a file out with no ignore file at all, from its path.

    *walked* is the file's path as the walk spelled it and *parts* its components
    below the scan root. The answer is :func:`get_files_not_matching_spec`'s with
    ``ASH_INCLUSIONS`` as the whole spec, worked out from names instead of by
    matching each file against the parser: a pruned ``node_modules`` holds hundreds
    of thousands of files, and a parser match per file stats each of them.

    - The bundled aws-cdk tree: :func:`_is_bundled_cdk_path` on *walked*, the path
      the scan set tests, so a scan root that is itself inside that tree counts as
      inside it here too.
    - Any ``*.template.json`` is kept otherwise, which is what the forced-inclusion
      pass does whatever else matched.
    - A ``.git`` component, file or directory, is left out (rule ``.git``).
    - An ``asset.*`` component directly under a ``cdk.out`` component is left out
      (rule ``**/cdk.out/asset.*``).
    """
    if _is_bundled_cdk_path(walked):
        return True
    if parts and parts[-1].endswith(".template.json"):
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
    return sum(
        1
        for walked in all_files
        if walked not in kept
        and not _excluded_by_ash_itself(walked, _relative_parts(walked, source))
    )


def _count_templates(directory: str) -> int:
    """``*.template.json`` files under *directory*: the forced inclusion keeps them."""
    return sum(
        1
        for root, _dirs, files in _walk_unless_link(directory)
        for name in files
        if name.endswith(".template.json")
        and not _is_bundled_cdk_path(os.path.join(root, name))
    )


def _count_files_ash_would_scan(
    directory: Path,
    source: str,
    own_output: Optional[_OwnOutput] = None,
    own_output_counts: Optional[Dict[str, int]] = None,
) -> int:
    """How many files under *directory* stay in the scan set when no ignore file applies.

    The answer :func:`get_files_not_matching_spec` gives with ``ASH_INCLUSIONS`` as
    the whole spec, decided from names (:func:`_excluded_by_ash_itself`) and not by
    matching each file against a parser. A file ASH leaves out on its own (``.git``,
    CDK assets, the bundled aws-cdk tree, its own output directory *own_output*)
    was not removed by the ignore file that pruned *directory*, so it is not
    counted. The output directory's files go into *own_output_counts* instead, as
    they do when the scan-set walk reaches it directly: a pruned parent does not
    change what they are.

    ASH's own exclusions are applied a directory at a time, so a pruned
    ``node_modules`` costs a walk and a string test per file: a directory on the
    bundled aws-cdk path is not entered, and a ``.git`` directory or a CDK asset
    directory is only searched for the ``*.template.json`` files the forced
    inclusion keeps. Links to directories are not followed, as in the walk that
    pruned *directory*: neither *directory* itself nor one below it, including a
    ``.git`` or asset directory searched for templates (:func:`_walk_unless_link`).
    """
    count = 0
    for root, dirs, files in _walk_unless_link(directory):
        parts = _relative_parts(root, source)
        kept_dirs = []
        for d in dirs:
            candidate = os.path.join(root, d)
            if _is_own_output(candidate, own_output):
                if own_output_counts is not None:
                    own_output_counts[candidate] = _count_files_in_own_output(candidate)
                continue
            if _is_bundled_cdk_path(candidate):
                continue
            if d == ".git" or (
                d.startswith("asset.") and parts and parts[-1] == "cdk.out"
            ):
                count += _count_templates(candidate)
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs
        count += sum(
            1
            for name in files
            if not _excluded_by_ash_itself(os.path.join(root, name), parts + (name,))
        )
    return count


def _collect_ignorefiles_and_all_files(
    path: str,
    extra_ignorefiles: List[str] | None = None,
    debug: bool = False,
    honor_ignore_files: bool = True,
    pruned_counts: Optional[Dict[str, int]] = None,
    own_output: Optional[str] = None,
    own_output_counts: Optional[Dict[str, int]] = None,
    links_not_scanned: Optional[List[str]] = None,
) -> tuple[List[str], List[str]]:
    """Walk the directory tree once to collect ignore files and all file paths.

    Respects .gitignore hierarchy: if a directory is ignored by a parent
    .gitignore, its contents (including nested .gitignore files) are skipped.
    This prevents rules like ``*`` inside ``.venv/.gitignore`` from being
    applied globally and accidentally ignoring all project files.

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
                open_in_scanned_tree(root_gitignore, root_path)
            ) as rule_lines:
                for rule_line in rule_lines:
                    candidate_parser.add_rule(
                        rule_line.rstrip("\n"), base_path=root_path
                    )
            root_ignore_parser = candidate_parser
        except TreeInputRefused:
            pass
        except (OSError, ValueError, TypeError, IndexError, re.error):
            # If the root .gitignore can't be parsed (malformed patterns,
            # encoding issues, etc.), proceed without directory pruning.
            # All files will still be filtered by the full ignore spec later.
            debug_echo(
                f"Could not parse root .gitignore for directory pruning: {root_gitignore}",
                debug=debug,
            )

    pruned_key = os.path.join(path, ".gitignore")
    # The output directory is followed if it is a link: it is where ASH writes,
    # whatever it is called. The orchestrator refuses a symlinked one anyway.
    own = _own_output_of(own_output)

    for root, dirs, files in os.walk(path):
        if own is not None:
            kept_dirs = []
            for d in dirs:
                candidate = os.path.join(root, d)
                if not _is_own_output(candidate, own):
                    kept_dirs.append(d)
                elif own_output_counts is not None:
                    own_output_counts[candidate] = _count_files_in_own_output(candidate)
            dirs[:] = kept_dirs
        # Prune directories that are ignored by the root .gitignore.
        # This prevents descending into .venv/, node_modules/, etc.
        # and picking up their internal .gitignore files.
        dirs_to_remove = []
        for d in dirs:
            dir_path = Path(root) / d
            # igittigitt.match expects a Path; directories need trailing separator
            # to match directory-specific patterns. We check both the dir path
            # and a fake file inside it.
            try:
                if root_ignore_parser.match(dir_path / "placeholder"):
                    dirs_to_remove.append(d)
                    debug_echo(f"Skipping ignored directory: {dir_path}", debug=debug)
            except (ValueError, TypeError, IndexError, re.error):
                # If matching fails for a specific directory (e.g. due to a
                # malformed pattern), skip pruning for that directory only.
                pass
        for d in dirs_to_remove:
            dirs.remove(d)
            # The pruned files are still counted: they are missing from the scan set
            # because of the root .gitignore, and a count that left them out would
            # report less than the file removed. Counted, not listed, so a pruned
            # node_modules costs a walk and no memory. A link counts nothing: the
            # count walks through _walk_unless_link, as every count does.
            if pruned_counts is None:
                continue
            removed = _count_files_ash_would_scan(
                Path(root) / d, path, own, own_output_counts
            )
            pruned_counts[pruned_key] = pruned_counts.get(pruned_key, 0) + removed

        for f in files:
            full_path = os.path.join(root, f)
            if honor_ignore_files and f in IGNORE_FILE_NAMES:
                ignore_files.append(full_path)
            if _left_out_as_a_link_leaving_the_tree(full_path, path, links_not_scanned):
                continue
            all_files.append(full_path)

    # Append any user-specified ignore files
    for extra in extra_ignorefiles:
        extra_path = os.path.join(path, extra)
        if extra_path not in ignore_files:
            ignore_files.append(extra_path)

    return ignore_files, all_files


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

    # Shallowest ignore file first, so that a deeper one's rules are added to the
    # spec last and therefore win: igittigitt lets the last matching rule decide,
    # and git gives precedence to the ignore file closest to the file being
    # tested. The order has to be stated rather than taken from a set, because a
    # set of strings iterates in hash order, which is randomized per process --
    # a "!keep.tmp" in sub/deep/.gitignore would override "*.tmp" from
    # sub/.gitignore on some runs of the same scan and lose on others.
    all_ignores = sorted(set(all_ignores), key=lambda p: (len(Path(p).parts), p))

    # Ignore files named by the caller are the operator's choice and are read as
    # named. Every other one was found in the tree, and its text is copied into
    # ash-ignore-report.txt, so it is read under the scanned-tree rule: a link would
    # otherwise copy whatever it points at into the report. Git itself stopped
    # following a symlinked .gitignore in 2.32.
    named_by_caller = {os.path.join(path, extra) for extra in ignorefiles}

    lines = []
    for ignorefile in all_ignores:
        clean = _source_dir_marker(path, ignorefile)
        if ignorefile in named_by_caller:
            if not os.path.isfile(ignorefile):
                continue
            with open(ignorefile) as f:
                content = f.readlines()
        else:
            try:
                handle = open_in_scanned_tree(ignorefile, path)
            except TreeInputRefused as refused:
                ASH_LOGGER.warning(
                    f"Skipped ignore file '{refused.path}': {refused.reason}, so its "
                    "rules were not applied"
                )
                # Recorded in the report as a comment, which every reader of the
                # report already skips, so the skip is visible next to the rules
                # that were applied.
                lines.append(f"######### SKIPPED: {clean}: {refused.reason} #########")
                lines.append("")
                continue
            except FileNotFoundError:
                # Gone since the walk: what the isfile() check here used to skip. Any
                # other OSError propagates, as it did from the open() this replaced.
                continue
            # TextIOWrapper with no encoding decodes exactly as open() does.
            with io.TextIOWrapper(handle) as f:
                content = f.readlines()
        debug_echo(f"Found .ignore file: {clean}", debug=debug)
        lines.append(f"{START_MARKER_PREFIX}{clean}{MARKER_SUFFIX}")
        # Comment lines are left out. They hold no rule (git reads a line starting
        # with "#" as a comment, and the compiler below skips every such line), and
        # a comment shaped like this function's own START CONTENTS marker would be
        # read back as one: the rules after it would be credited to another file
        # and compiled against that file's directory. Compared stripped, because
        # every line is stripped below before the compiler sees it.
        lines.extend(line for line in content if not line.strip().startswith("#"))
        lines.append(f"{END_MARKER_PREFIX}{clean}{MARKER_SUFFIX}")
        lines.append("")
    lines = [line.strip() for line in lines]
    lines.append(f"{START_MARKER_PREFIX}{ASH_INCLUSIONS_MARKER}{MARKER_SUFFIX}")
    lines.extend(ASH_INCLUSIONS)
    lines.append(f"{END_MARKER_PREFIX}{ASH_INCLUSIONS_MARKER}{MARKER_SUFFIX}")
    return lines


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
    root_base_path = Path(source_dir)

    # Track the current base directory from section markers.
    # Lines like "######### START CONTENTS: ${SOURCE_DIR}/.ruff_cache/.gitignore #########"
    # indicate that subsequent rules should be scoped to that directory.
    current_base_path = root_base_path

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

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

        if stripped.startswith("#"):
            continue

        added_from = len(parser.rules)
        parser.add_rule(stripped, base_path=current_base_path)
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

    for excluded_file in sorted(excluded):
        # The bundled aws-cdk tree first, because get_files_not_matching_spec drops it
        # before it consults the spec: an ignore rule that also matches one of its
        # files did not remove it.
        if _is_bundled_cdk_path(excluded_file):
            marker = BUNDLED_CDK_MARKER
            counts[marker] = counts.get(marker, 0) + 1
            paths_by_marker.setdefault(marker, []).append(excluded_file)
            continue
        _ignored, rule = spec.match_with_rule(Path(excluded_file))
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
    if not ignore_file_markers and honored:
        ASH_LOGGER.info(
            "No ignore files were found under %s, so no ignore rules removed "
            "anything from the scan set.",
            path,
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
        # Fallback: walk again if called standalone without pre-collected files
        _all_files = []
        for root, _dirs, files in os.walk(path):
            for f in files:
                _all_files.append(os.path.join(root, f))

    # Applied as a pass of its own after *spec* has had its say, because a
    # negation inside that spec loses to an excluded ancestor directory: a nested
    # "out/" in src/cdk/.gitignore beat "!**/*.template.json" and took
    # src/cdk/out/Stack.template.json out of the scan set that cdk_nag_scanner and
    # cfn_nag_scanner read, so CloudFormation analysis of that template stopped
    # with nothing logged to say so.
    forced_inclusions = _forced_inclusion_spec(path)

    included = []
    for inc_full in _all_files:
        # inc_full stays native throughout, because callers use it to open files.
        # Both helpers below normalize internally and only for their own comparison.
        if _is_bundled_cdk_path(inc_full):
            continue
        if _left_out_as_a_link_leaving_the_tree(inc_full, path, links_not_scanned):
            continue
        file_path = Path(inc_full)
        if spec.match(file_path) and not forced_inclusions.match(file_path):
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
    """
    from automated_security_helper.utils.subprocess_utils import find_executable

    return find_executable("git")


def git_repository_root(path: Path) -> Optional[Path]:
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

    Returns:
        The absolute repository root, or ``None`` when *path* is not inside a git
        repository, git is not on ``PATH``, or the command times out.
    """
    git = _git_executable()
    if git is None:
        return None
    try:
        result = subprocess.run(
            # git_argv: the repository's config names no program git runs here.
            git_argv("rev-parse", "--show-toplevel", program=git),  # nosec B603 B607
            capture_output=True,
            text=True,
            timeout=30,
            cwd=path,
            env=child_environ(),
        )
    except (FileNotFoundError, NotADirectoryError, subprocess.TimeoutExpired, OSError):
        return None

    if result.returncode != 0:
        return None
    top = result.stdout.strip()
    if not top:
        return None
    return Path(top).resolve()


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

    Falls back to ``None`` (meaning "scan everything") when:
    * ``git`` is not available on ``PATH``, or
    * *base_ref* does not exist in the local repository.

    Args:
        base_ref: The git ref to diff against.  Defaults to ``origin/main``.
        cwd: Directory to run git from (must be inside the target repo).
             Defaults to the current working directory.

    Returns:
        A list of :class:`~pathlib.Path` objects relative to the repo root,
        or ``None`` if the diff could not be computed.

    Raises:
        InvalidBaseRefError: when :func:`validate_base_ref` refuses *base_ref*.
            No git process is started for it.
    """
    validate_base_ref(base_ref)

    git = _git_executable()
    if git is None:
        ASH_LOGGER.warning("git not available; falling back to full scan")
        return None
    try:
        # -z and core.quotepath=false, because git otherwise quotes a name holding a
        # non-ASCII byte, a quote, a backslash or a control character
        # ("\303\274.py"), and that string names no file: those changes never
        # matched a finding. -z separates names with NUL and prints them raw, so a
        # name is never split or stripped either. Decoded as UTF-8, which is how git
        # stores paths; surrogateescape keeps any other byte, so the Path still
        # names the file on disk. git_argv: the repository's config names no
        # program git runs here.
        #
        # The trailing "--" makes git read the range only as revisions. Without
        # it, when the base ref is missing here (origin/main in a shallow clone)
        # and the checkout has a file named "origin/main...HEAD", git reads the
        # argument as that path, diffs it between the working tree and the index,
        # and exits 0. With it, git exits 128 on the missing ref and the full-scan
        # fallback applies.
        result = subprocess.run(
            git_argv(  # nosec B603 B607
                "-c",
                "core.quotepath=false",
                "diff",
                "--name-only",
                "-z",
                f"{base_ref}...HEAD",
                "--",
                program=git,
            ),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=30,
            cwd=cwd,
            env=child_environ(),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        ASH_LOGGER.warning("git not available or timed out; falling back to full scan")
        return None

    if result.returncode != 0:
        ASH_LOGGER.warning(
            "git diff against %s failed (rc=%d); falling back to full scan",
            base_ref,
            result.returncode,
        )
        return None

    # Every name ends in NUL, so the last entry is empty; nothing is stripped, since
    # a leading or trailing space is part of a name.
    return [Path(name) for name in result.stdout.split("\0") if name]


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
        help="Filter results against a regular expression pattern. Defaults to returning empty which returns the full list of files to be included in the scan.",
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


def scan_set(
    source: Optional[str] = None,
    output: Optional[str] = None,
    ignorefile: Optional[list[str]] = None,
    debug: bool = False,
    print_results: bool = False,
    filter_pattern: Optional[re.Pattern] = None,
    honor_ignore_files: bool = True,
    exclusions: Optional[Dict[str, Any]] = None,
    links_not_scanned: Optional[List[Dict[str, str]]] = None,
) -> list[str]:
    """Get list of files not matching .gitignore underneath source path.

    A scan set reused from *output* is returned as it was written, whatever
    *honor_ignore_files* says. The orchestrator removes both files before it
    computes the scan set, so within one scan the scanners and converters that call
    this later reuse the list it wrote.

    Args:
        source: Path to scan. Defaults to current working directory.
        output: Output path to save the ash-ignore-report.txt and ash-scan-set-files-list.txt files.
        ignorefile: List of ignore files to use in addition to the standard gitignore.
        debug: Enable debug logging.
        print_results: Print results to stdout. Defaults to False for library usage.
        filter_pattern: Filter results against a re.Pattern. Defaults to returning the full scan set.
        honor_ignore_files: Whether the scanned repository's ``.gitignore`` and
            ``.ignore`` files decide what is left out. False scans every file but
            the ones ASH leaves out on its own (``.git``, CDK assets, the bundled
            aws-cdk tree, and *output* when it is inside *source*). The
            ``honor_ignore_files`` config key and
            ``--no-honor-ignore-files`` set it; see :func:`honors_ignore_files`.
        exclusions: When given, filled with the record of what the ignore files
            removed (:func:`ignore_file_exclusion_record`), which the orchestrator
            stores as ``metadata.ignore_file_exclusions``. Left empty when the
            scan set was reused from *output*, since nothing was matched then.
        links_not_scanned: When given, extended with ``{"path", "reason"}`` for
            each file link left out of the scan set because its target leaves
            *source* (:func:`_left_out_as_a_link_leaving_the_tree`): the path below
            *source* with ``/`` separators, and the reason
            ``REASON_LINK_LEAVES_TREE``, sorted by path. Left empty when the scan set
            was reused from *output*, whose list already leaves them out. Every
            such link is also warned about, whether or not this is given.

    Returns:
        List of files not matching ignore specifications.
    """
    if source is None:
        source = os.getcwd()
    if ignorefile is None:
        ignorefile = []

    ashignore_content = None
    ashscanset_list = None
    ashignore_imported = False
    ashscanset_imported = False

    if output:
        # Ensure output is a Path object
        output_path = Path(output)
        ashignore_path = output_path.joinpath("ash-ignore-report.txt")
        ashscanset_path = output_path.joinpath("ash-scan-set-files-list.txt")
        if ashignore_path.exists():
            with open(ashignore_path) as f:
                ashignore_content = f.readlines()
            ashignore_imported = True
            debug_echo(f"Imported ash-ignore-report.txt from {output}", debug=debug)
        if ashscanset_path.exists():
            with open(ashscanset_path) as f:
                ashscanset_list = f.readlines()
            ashscanset_imported = True
            debug_echo(
                f"Imported ash-scan-set-files-list.txt from {output}", debug=debug
            )

    pruned_counts: Dict[str, int] = {}
    own_output_counts: Dict[str, int] = {}
    walked_links: List[str] = []
    if not ashignore_content or not ashscanset_list:
        # Single os.walk pass collects both ignore files and the full file list
        discovered_ignores, all_files = _collect_ignorefiles_and_all_files(
            source,
            ignorefile,
            debug=debug,
            honor_ignore_files=honor_ignore_files,
            pruned_counts=pruned_counts,
            own_output=output,
            own_output_counts=own_output_counts,
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

    if not ashignore_content:
        ashignore_content = get_ash_ignorespec_lines(
            source,
            ignorefile,
            debug=debug,
            _discovered_ignore_files=discovered_ignores,
        )
        if not honor_ignore_files:
            ashignore_content.insert(0, NOT_HONORED_REPORT_LINE)

    if not ashscanset_list:
        if not honor_ignore_files:
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
        counts = report_ignore_file_exclusions(
            source,
            spec,
            ashscanset_list,
            rule_ids_by_marker,
            all_files,
            debug=debug,
            pruned_counts=pruned_counts,
            honored=honor_ignore_files,
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
        )

    if output:
        # Ensure output is a Path object
        output_path = Path(output)
        ashignore_path = output_path.joinpath("ash-ignore-report.txt")
        ashscanset_path = output_path.joinpath("ash-scan-set-files-list.txt")

        if not ashignore_imported:
            debug_echo(f"Writing ash-ignore-report.txt to {output}", debug=debug)
            if not ashignore_path.parent.exists():
                ashignore_path.parent.mkdir(parents=True)
            with open_no_follow(ashignore_path) as f:
                f.write("\n".join(ashignore_content))

        if not ashscanset_imported:
            debug_echo(
                f"Writing ash-scan-set-files-list.txt to {output}",
                debug=debug,
            )
            if not ashscanset_path.parent.exists():
                ashscanset_path.parent.mkdir(parents=True)
            with open_no_follow(ashscanset_path) as f:
                f.write("\n".join(ashscanset_list))

    if print_results:
        for file in ashscanset_list:
            print(file, file=sys.stdout)

    if filter_pattern:
        ashscanset_list = [
            file
            for file in ashscanset_list
            if re.match(pattern=filter_pattern, string=file)
        ]

    return [item.strip() for item in ashscanset_list]


def main() -> int:
    """Main entry point for CLI usage.

    Returns:
        Exit code (0 for success).
    """
    args = parse_args()

    file_list = scan_set(
        source=args.source,
        output=args.output,
        ignorefile=args.ignorefile,
        debug=args.debug,
        print_results=True,
        honor_ignore_files=args.honor_ignore_files,
    )
    print(file_list, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
