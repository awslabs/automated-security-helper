#!/usr/bin/env python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re
import subprocess  # nosec B404
import sys
from typing import List, Optional
from igittigitt import IgnoreParser
from pathlib import Path, PurePosixPath
import argparse
import os

from automated_security_helper.utils.log import ASH_LOGGER

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


def _collect_ignorefiles_and_all_files(
    path: str,
    extra_ignorefiles: List[str] | None = None,
    debug: bool = False,
) -> tuple[List[str], List[str]]:
    """Walk the directory tree once to collect ignore files and all file paths.

    Respects .gitignore hierarchy: if a directory is ignored by a parent
    .gitignore, its contents (including nested .gitignore files) are skipped.
    This prevents rules like ``*`` inside ``.venv/.gitignore`` from being
    applied globally and accidentally ignoring all project files.

    Returns a tuple of (ignore_file_paths, all_file_paths).
    """
    if extra_ignorefiles is None:
        extra_ignorefiles = []

    _ignore_names = {".ignore", ".gitignore"}
    ignore_files: List[str] = []
    all_files: List[str] = []

    # Build an initial ignore spec from the root .gitignore (if it exists)
    # so we can skip walking into ignored directories.
    root_ignore_parser = IgnoreParser()
    root_path = Path(path)
    root_gitignore = root_path / ".gitignore"
    if root_gitignore.is_file():
        try:
            root_ignore_parser.parse_rule_file(root_gitignore, base_dir=root_path)
        except (OSError, ValueError, TypeError, IndexError, re.error):
            # If the root .gitignore can't be parsed (malformed patterns,
            # encoding issues, etc.), proceed without directory pruning.
            # All files will still be filtered by the full ignore spec later.
            debug_echo(
                f"Could not parse root .gitignore for directory pruning: {root_gitignore}",
                debug=debug,
            )

    for root, dirs, files in os.walk(path):
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

        for f in files:
            full_path = os.path.join(root, f)
            if f in _ignore_names:
                ignore_files.append(full_path)
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

    lines = []
    for ignorefile in all_ignores:
        if os.path.isfile(ignorefile):
            clean = _source_dir_marker(path, ignorefile)
            debug_echo(f"Found .ignore file: {clean}", debug=debug)
            lines.append(f"######### START CONTENTS: {clean} #########")
            with open(ignorefile) as f:
                lines.extend(f.readlines())
            lines.append(f"######### END CONTENTS: {clean} #########")
            lines.append("")
    lines = [line.strip() for line in lines]
    lines.append("######### START CONTENTS: ASH_INCLUSIONS #########")
    lines.extend(ASH_INCLUSIONS)
    lines.append("######### END CONTENTS: ASH_INCLUSIONS #########")
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
        if stripped.startswith("#########") and "START CONTENTS:" in stripped:
            # Extract the path from the marker
            # Format: "######### START CONTENTS: ${SOURCE_DIR}/subdir/.gitignore #########"
            # or:     "######### START CONTENTS: ${SOURCE_DIR}/.gitignore #########"
            # or:     "######### START CONTENTS: ASH_INCLUSIONS #########"
            content_path = stripped
            try:
                content_path = (
                    stripped.split("START CONTENTS:")[1].strip().rstrip("#").strip()
                )
                if content_path == "ASH_INCLUSIONS":
                    current_base_path = root_base_path
                elif "${SOURCE_DIR}" in content_path:
                    # Extract the directory containing the .gitignore/.ignore
                    # file. The marker is written with "/" separators, so it is
                    # read back as a posix path regardless of host platform.
                    relative_path = content_path.replace("${SOURCE_DIR}", "").lstrip(
                        "/"
                    )
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

    Known limitation: the counts cover files that were walked and then dropped.
    A directory the root ``.gitignore`` prunes in
    :func:`_collect_ignorefiles_and_all_files` is never descended into, so its
    contents are in neither *all_files* nor the scan set and cannot be counted --
    the report says nothing about them rather than guessing. The root
    ``.gitignore`` therefore reads lower than the files it truly accounts for.

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

    counts: dict[str, int] = {marker: 0 for marker in rule_ids_by_marker}
    counts[BUNDLED_CDK_MARKER] = 0
    paths_by_marker: dict[str, list[str]] = {}
    unattributed: list[str] = []

    for excluded_file in sorted(excluded):
        _ignored, rule = spec.match_with_rule(Path(excluded_file))
        if rule is not None and id(rule) in marker_by_rule_id:
            marker = marker_by_rule_id[id(rule)]
        elif "/node_modules/aws-cdk" in excluded_file:
            marker = BUNDLED_CDK_MARKER
        else:
            # No ignore rule owns this exclusion. Reaching here means the
            # attribution mapping and the parser disagree, which would otherwise
            # surface as every count reading zero -- the same absent-reads-as-zero
            # ambiguity this report exists to remove. Say so instead.
            unattributed.append(excluded_file)
            continue
        counts[marker] = counts.get(marker, 0) + 1
        paths_by_marker.setdefault(marker, []).append(excluded_file)

    ignore_file_markers = [
        marker for marker in rule_ids_by_marker if marker != ASH_INCLUSIONS_MARKER
    ]
    if not ignore_file_markers:
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


def get_files_not_matching_spec(
    path,
    spec,
    debug: bool = False,
    _all_files: List[str] | None = None,
):
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
        if "/node_modules/aws-cdk" in inc_full:
            continue
        file_path = Path(inc_full)
        if spec.match(file_path) and not forced_inclusions.match(file_path):
            continue
        clean = _source_dir_marker(path, inc_full)
        debug_echo(f"Matched file for scan set: {clean}", debug=debug)
        included.append(inc_full)
    included = sorted(set(included))
    return included


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
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],  # nosec B603 B607
            capture_output=True,
            text=True,
            timeout=30,
            cwd=path,
        )
    except (FileNotFoundError, NotADirectoryError, subprocess.TimeoutExpired, OSError):
        return None

    if result.returncode != 0:
        return None
    top = result.stdout.strip()
    if not top:
        return None
    return Path(top).resolve()


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
    """
    if not re.match(r"^[a-zA-Z0-9._/~^@{}\-]+$", base_ref):
        ASH_LOGGER.warning(f"Invalid base_ref '{base_ref}'; falling back to full scan")
        return None

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_ref}...HEAD"],  # nosec B603 B607
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd,
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

    paths: List[Path] = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if line:
            paths.append(Path(line))
    return paths


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
        "--debug", help="Enables debug logging", action=argparse.BooleanOptionalAction
    )
    return parser.parse_args()


def scan_set(
    source: Optional[str] = None,
    output: Optional[str] = None,
    ignorefile: Optional[list[str]] = None,
    debug: bool = False,
    print_results: bool = False,
    filter_pattern: Optional[re.Pattern] = None,
) -> list[str]:
    """Get list of files not matching .gitignore underneath source path.

    Args:
        source: Path to scan. Defaults to current working directory.
        output: Output path to save the ash-ignore-report.txt and ash-scan-set-files-list.txt files.
        ignorefile: List of ignore files to use in addition to the standard gitignore.
        debug: Enable debug logging.
        print_results: Print results to stdout. Defaults to False for library usage.
        filter_pattern: Filter results against a re.Pattern. Defaults to returning the full scan set.

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

    if not ashignore_content or not ashscanset_list:
        # Single os.walk pass collects both ignore files and the full file list
        discovered_ignores, all_files = _collect_ignorefiles_and_all_files(
            source, ignorefile, debug=debug
        )

    if not ashignore_content:
        ashignore_content = get_ash_ignorespec_lines(
            source,
            ignorefile,
            debug=debug,
            _discovered_ignore_files=discovered_ignores,
        )

    if not ashscanset_list:
        spec, rule_ids_by_marker = get_ash_ignorespec_with_attribution(
            ashignore_content, source, debug=debug
        )
        ashscanset_list = get_files_not_matching_spec(
            source,
            spec,
            debug=debug,
            _all_files=all_files,
        )
        report_ignore_file_exclusions(
            source,
            spec,
            ashscanset_list,
            rule_ids_by_marker,
            all_files,
            debug=debug,
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
            with open(ashignore_path, mode="w", encoding="utf-8") as f:
                f.write("\n".join(ashignore_content))

        if not ashscanset_imported:
            debug_echo(
                f"Writing ash-scan-set-files-list.txt to {output}",
                debug=debug,
            )
            if not ashscanset_path.parent.exists():
                ashscanset_path.parent.mkdir(parents=True)
            with open(ashscanset_path, mode="w", encoding="utf-8") as f:
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
    )
    print(file_list, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
