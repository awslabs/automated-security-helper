# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exclusion values that keep a tree-walking scanner off links leaving its target.

ASH's scan set leaves out every link to a file whose target, with every link
resolved, leaves the scanned tree. Scanners that walk the directory they are given
do not read the scan set, so each is also given, in its own exclusion option, every
such link under its target (``get_scan_set.file_links_leaving_tree``). bandit,
checkov and ferret-scan read such a link, so their scanners build their values
themselves and refuse a target whose link cannot be written. The scanners here do
not read one (measured, see each function), so the values are a second guard: a
link that cannot be written exactly is left out of the option rather than the
target refused, because a pattern that also matched other paths would hide files
the scan should read.

semgrep and opengrep get no such value: they follow no link either, and their
``--exclude`` cannot name one path (see ``_grep_scanner_base._execute_scan``).

The same goes for the operator's ``global_settings.ignore_paths``
(``ignored_entries``): ASH drops the findings in those paths after the scan, but a
scanner that walks the tree still reads the files unless its own option leaves
them out.
"""

from __future__ import annotations

import os
from bisect import bisect_left
from pathlib import Path
from typing import Callable, Collection, Dict, Iterable, List, Mapping, Sequence

from automated_security_helper.utils.get_scan_set import file_links_leaving_tree
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scanned_tree import resolves_inside
from automated_security_helper.utils.suppression_matcher import ignore_path_matches

#: The characters doublestar (the glob library syft, grype and trivy match with)
#: reads as pattern syntax, each escaped with a backslash to stand for itself.
_DOUBLESTAR_SPECIAL = frozenset("\\*?[]{}")

#: The characters trivy's ``--skip-files`` cannot carry: its value is read as one
#: line of CSV, so a comma splits it and a quote or a line break changes it.
_TRIVY_UNSAFE = frozenset(',"\r\n')


def doublestar_literal(text: str) -> str:
    """``text`` as a doublestar pattern that matches ``text`` and nothing else."""
    return "".join(
        f"\\{character}" if character in _DOUBLESTAR_SPECIAL else character
        for character in text
    )


def syft_excludes(
    target: str | Path,
    source_dir: str | Path | None = None,
    ignore_paths: Iterable[object] | None = None,
) -> List[str]:
    """``--exclude`` values for syft and grype: the links leaving ``target``, and
    the paths ``ignore_paths`` ignore.

    syft 1.54.1 and grype 0.120.1 list no file behind a link to a file or a
    directory whose target leaves the directory they scan (measured). Each value is
    ``./`` and the path below ``target``, glob characters escaped: syft anchors a
    ``./`` pattern at the scanned directory, whatever ``--base-path`` says, and
    matches the whole path, so ``./x/requirements.txt`` left out that file and not
    ``sub/x/requirements.txt`` (measured, with brackets, braces, ``*``, ``?``, a
    backslash, a space and a comma in the path). A directory whose every file is
    ignored is ``./<dir>/**``. None on Windows, where the paths it matches are not
    ``/``-joined.
    """
    if os.sep != "/":
        return []
    files, links = walked_files(target)
    values = [f"./{doublestar_literal(relative)}" for relative in links]
    # syft follows a link to a directory inside the tree, which the walk does not
    # enter. A directory holding a link to scanned files is never written as
    # ``./<dir>/**``, which would hide what syft reaches through the link; a link
    # to a directory whose every file is ignored is written as ``./<link>/**``
    # itself, since syft would otherwise catalog the ignored files under the
    # link's name (``ignored_entries``).
    directory_links = (
        inside_tree_directory_links(target)
        if source_dir is not None and ignore_paths
        else {}
    )
    for entry in _ignore_entries(
        target, source_dir, ignore_paths, files, directory_links=directory_links
    ):
        if entry.endswith("/"):
            values.append(f"./{doublestar_literal(entry[:-1])}/**")
        else:
            values.append(f"./{doublestar_literal(entry)}")
    return values


def trivy_skip_dirs(
    target: str | Path,
    source_dir: str | Path | None = None,
    ignore_paths: Iterable[object] | None = None,
) -> List[str]:
    """``--skip-dirs`` values for trivy: each directory whose every file is ignored.

    The directory's path below ``target``, glob characters escaped, which trivy
    matches against the whole path, as for ``--skip-files``. One with a comma, a
    double quote or a line break is left out, since trivy reads the value as CSV;
    trivy then reads its files and ASH drops their findings. None on Windows.
    """
    if os.sep != "/":
        return []
    files, _ = walked_files(target)
    values = []
    for entry in _ignore_entries(target, source_dir, ignore_paths, files):
        if entry.endswith("/") and not any(c in _TRIVY_UNSAFE for c in entry):
            values.append(doublestar_literal(entry[:-1]))
    return values


def trivy_skip_files(
    target: str | Path,
    source_dir: str | Path | None = None,
    ignore_paths: Iterable[object] | None = None,
) -> List[str]:
    """``--skip-files`` values for trivy: the links leaving ``target``, and the
    files ``ignore_paths`` ignore outside the directories ``trivy_skip_dirs`` names.

    trivy 0.75.0 skips every link, inside the tree or not (measured). A value is the
    path below ``target`` with glob characters escaped, which trivy matches against
    the whole path: ``x.txt`` left out ``x.txt`` and not ``sub/x.txt`` (measured). A
    link with a comma, a double quote or a line break is left out of the option,
    since trivy reads the value as CSV, and named in one debug record; an ignored
    file with one is left out too, and ASH drops its findings. None on Windows.
    """
    if os.sep != "/":
        return []
    files, links = walked_files(target)
    values: List[str] = []
    left_out: List[str] = []
    for relative in links:
        if any(character in _TRIVY_UNSAFE for character in relative):
            left_out.append(relative)
        else:
            values.append(doublestar_literal(relative))
    for entry in _ignore_entries(target, source_dir, ignore_paths, files):
        if not entry.endswith("/") and not any(c in _TRIVY_UNSAFE for c in entry):
            values.append(doublestar_literal(entry))
    if left_out:
        ASH_LOGGER.debug(
            "trivy: %d link(s) leaving %s not given in --skip-files, since a comma, "
            "a double quote or a line break would change the value (trivy skips "
            "every link itself): %s",
            len(left_out),
            target,
            ", ".join(repr(relative) for relative in left_out),
        )
    return values


def walked_files(target: str | Path) -> tuple[List[str], List[str]]:
    """Every file below ``target`` as the tree-walking tools list it, and the links
    among them whose target leaves it, both relative to ``target`` and sorted.

    One walk (``file_links_leaving_tree``): links to directories are not entered,
    and ignore files are not read, as the tools do not read them.
    """
    files: List[str] = []
    links = file_links_leaving_tree(target, all_files=files)
    return sorted(files), links


def inside_tree_directory_links(target: str | Path) -> Dict[str, str]:
    """Every link to a directory below ``target`` whose target stays inside it, and
    where each leads, sorted by the link.

    The same walk as ``walked_files`` makes (links to directories are not entered,
    ignore files are not read), listing what that walk steps over: the links a
    tool that follows inside-tree directory links (syft) reads files behind. Each
    key is the link and its value the directory it leads to, with every link
    resolved; both relative to ``target`` and ``/``-joined.
    """
    real_target = os.path.realpath(target)
    found: Dict[str, str] = {}
    pending = [(os.fspath(target), "")]
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
                if entry.is_symlink():
                    if os.path.isdir(entry.path) and resolves_inside(
                        entry.path, target
                    ):
                        leads_to = os.path.relpath(
                            os.path.realpath(entry.path), real_target
                        )
                        found[relative] = leads_to.replace(os.sep, "/")
                elif entry.is_dir(follow_symlinks=False):
                    pending.append((entry.path, f"{relative}/"))
            except OSError:
                continue
    return dict(sorted(found.items()))


def ignored_entries(
    target: str | Path,
    source_dir: str | Path,
    ignore_paths: Iterable[object],
    files: Sequence[str],
    matches: Callable[[str, str], bool] = ignore_path_matches,
    directory_links: Mapping[str, str] | None = None,
) -> List[str]:
    """The paths below ``target`` that ``ignore_paths`` ignore, as few as possible.

    Each ignore path's pattern is matched as ASH matches it when it drops findings
    (``matches``, by default ``ignore_path_matches``), against each file's path below
    ``source_dir``. A directory whose every walked file is ignored is returned once,
    with a trailing ``/``, and the files below it are not; any other ignored file is
    returned itself. Paths are relative to ``target`` and ``/``-joined.

    ``directory_links`` are the links to directories the walk did not enter, each
    with the directory it leads to (``inside_tree_directory_links``), relative to
    ``target``; none when omitted. The files behind such a link are not among
    ``files`` under the link's name, and a tool that follows the link (syft) reads
    them there. A link
    leading to a directory that holds a walked file the patterns do not ignore
    keeps every directory holding the link, at any depth, from being returned
    whole, since ``./<dir>/**`` would tell the tool to skip those files with the
    rest; the ignored files there are returned one by one instead. So does a link
    leading to a directory the walk found no file in: nothing behind it is proven
    ignored, and such a directory can hold a further link to scanned files, which
    the walk does not enter. A link leading to a directory whose walked files are
    all ignored (a pnpm ``node_modules/foo`` leading into ``node_modules/.pnpm``)
    is itself returned with a trailing ``/``, unless a directory holding it is, so
    the tool skips the ignored files under the link's name as well as under their
    own. A link that is not returned whole still leads to the ignored files and
    directories in its destination, which the tool reads under the link's name
    too; each is returned under that name as well (``_names_behind_links``), so
    the link is not hidden and its ignored entries are.

    Empty when ``target`` is not ``source_dir`` or a directory below it (ASH's work
    directory for converted files): the patterns name paths below the source
    directory, and a converted file's path there is not its path in the work
    directory. ASH still drops such a file's findings after the scan.

    Args:
        target: The directory the tool is given.
        source_dir: The scan's source directory.
        ignore_paths: The scan's ``global_settings.ignore_paths`` entries (each with
            a ``path``).
        files: ``target``'s walked files, from ``walked_files``.
        matches: ``(path, pattern) -> bool``.
    """
    patterns = [
        str(getattr(entry, "path", "") or "")
        for entry in ignore_paths or []
        if getattr(entry, "path", None)
    ]
    if not patterns or not files:
        return []
    try:
        below = Path(os.path.realpath(target)).relative_to(
            Path(os.path.realpath(source_dir))
        )
    except ValueError:
        return []
    prefix = "" if below.as_posix() in ("", ".") else f"{below.as_posix()}/"

    ignored = {
        relative
        for relative in files
        if any(matches(f"{prefix}{relative}", pattern) for pattern in patterns)
    }
    if not ignored:
        return []
    total: dict[str, int] = {}
    hit: dict[str, int] = {}
    for relative in files:
        parts = relative.split("/")
        for depth in range(1, len(parts)):
            directory = "/".join(parts[:depth])
            total[directory] = total.get(directory, 0) + 1
            if relative in ignored:
                hit[directory] = hit.get(directory, 0) + 1
    whole = {
        directory for directory, count in total.items() if hit.get(directory) == count
    }
    # A link whose destination is not whole (it holds a walked file that is not
    # ignored, or no walked file at all: nothing proven ignored, and a nested link
    # to scanned files may sit there, unentered) unmakes every directory holding
    # the link. That can unmake another link's destination, so the discard runs
    # to a fixpoint: a chain of links (src/vendored -> third_party/lib, which holds
    # bridge -> third_party/hub, which holds a link on to scanned files) is
    # followed back link by link, where one pass judged each link by its
    # destination's own counts and left the first link's name hiding files
    # reached three hops down. The links are indexed by destination once, so a
    # directory that stops being whole queues the links that lead to it and no
    # others: a scan of every link per discarded link was P x L steps.
    links = dict(directory_links or {})
    by_destination: dict[str, list[str]] = {}
    for link, leads_to in links.items():
        by_destination.setdefault(leads_to, []).append(link)
    pending = [link for link, leads_to in links.items() if leads_to not in whole]
    queued = set(pending)
    while pending:
        link = pending.pop()
        parts = link.split("/")
        for depth in range(1, len(parts)):
            discarded = "/".join(parts[:depth])
            if discarded not in whole:
                continue
            whole.discard(discarded)
            for other in by_destination.get(discarded, ()):
                if other not in queued:
                    queued.add(other)
                    pending.append(other)

    def _under_whole(relative: str) -> bool:
        parts = relative.split("/")
        return any("/".join(parts[:depth]) in whole for depth in range(1, len(parts)))

    # A link whose destination is still whole is skipped under its own name.
    links_to_ignored = [link for link, leads_to in links.items() if leads_to in whole]
    entries = [f"{directory}/" for directory in whole if not _under_whole(directory)]
    entries += [f"{link}/" for link in links_to_ignored if not _under_whole(link)]
    entries += [relative for relative in ignored if not _under_whole(relative)]
    # A link that is not returned whole still leads to the ignored entries behind
    # it, and a tool that follows it reads them under the link's name.
    entries += [
        alias
        for alias in _names_behind_links(entries, links, whole)
        if not _under_whole(alias.rstrip("/"))
    ]
    return sorted(entries)


#: How many links deep ``_names_behind_links`` follows an ignored entry, which
#: also ends a chain of links that leads back to itself.
_LINK_HOPS = 4

#: The most names ``_names_behind_links`` adds. Past it the rest are left out:
#: the tool then reads them, and ASH drops their findings, as before.
_MAX_NAMES_BEHIND_LINKS = 10000


def _names_behind_links(
    entries: Sequence[str], links: Mapping[str, str], whole: Collection[str]
) -> List[str]:
    """The names, under links, of *entries* that sit in a link's destination.

    A link to a directory inside the tree is followed by syft, so an ignored file
    under the link's destination is also read as ``<link>/<rest>``. A link whose
    destination is hidden whole is returned itself and needs none. For the rest
    (*links* whose destination is not in *whole*, because it holds a link to
    scanned files and so cannot be hidden whole) each entry under the destination
    is repeated under the link's name, directories keeping their trailing ``/``.
    A name is itself repeated under any link whose destination holds it (a link
    to a directory holding a link), up to ``_LINK_HOPS`` links deep.
    """
    open_links = {
        link: leads_to for link, leads_to in links.items() if leads_to not in whole
    }
    known = set(entries)
    frontier = sorted(known)
    found: List[str] = []
    for _ in range(_LINK_HOPS):
        added: List[str] = []
        for link, leads_to in open_links.items():
            low = bisect_left(frontier, f"{leads_to}/")
            high = bisect_left(frontier, f"{leads_to}0")
            for entry in frontier[low:high]:
                alias = f"{link}/{entry[len(leads_to) + 1 :]}"
                if alias not in known:
                    known.add(alias)
                    added.append(alias)
                    if len(found) + len(added) >= _MAX_NAMES_BEHIND_LINKS:
                        return found + added
        if not added:
            break
        found += added
        frontier = sorted(known)
    return found


def _ignore_entries(
    target: str | Path,
    source_dir: str | Path | None,
    ignore_paths: Iterable[object] | None,
    files: Sequence[str],
    directory_links: Mapping[str, str] | None = None,
) -> List[str]:
    """``ignored_entries``, or none when no source directory or ignore path is given."""
    if source_dir is None or not ignore_paths:
        return []
    return ignored_entries(
        target, source_dir, ignore_paths, files, directory_links=directory_links
    )


#: Characters a semgrep or opengrep ``--exclude`` reads as pattern syntax.
_GREP_PATTERN_CHARACTERS = frozenset("*?[]{}!\\")


def grep_ignore_names(
    target: str | Path,
    source_dir: str | Path | None,
    ignore_paths: Iterable[object] | None,
) -> List[str]:
    """``--exclude`` names for semgrep and opengrep that leave out only ignored paths.

    Their ``--exclude`` cannot name one path: semgrep matches a pattern against
    paths below the git work tree's root, and opengrep a name at every depth. A bare
    name leaves out every file or directory of that name at any depth. So the name
    of an ignored file, or of a directory whose every file is ignored, is passed
    only when nothing else could match it: no path below ``target`` that is not
    ignored has a part of that name, ``target``'s own path has none in either
    spelling, as given or with its links resolved (a part above it could be below
    the work tree's root, and then the name would leave out the whole target), and
    it holds no pattern character. Any other
    ignored path is still read, and ASH drops its findings. None on Windows.
    """
    if os.sep != "/":
        return []
    files, _ = walked_files(target)
    entries = _ignore_entries(target, source_dir, ignore_paths, files)
    if not entries:
        return []
    ignored_dirs = [entry for entry in entries if entry.endswith("/")]
    ignored_files = {entry for entry in entries if not entry.endswith("/")}

    def _ignored(relative: str) -> bool:
        return relative in ignored_files or any(
            relative.startswith(directory) for directory in ignored_dirs
        )

    taken = {
        part
        for relative in files
        if not _ignored(relative)
        for part in relative.split("/")
    }
    # Both spellings of the target's own path: a bare --exclude name is matched at
    # every depth of the path the tool sees, and semgrep's is the real one below the
    # git work tree's root, so a component of either spelling leaves out the
    # whole target.
    taken.update(Path(os.path.abspath(target)).parts)
    taken.update(Path(os.path.realpath(target)).parts)
    names = []
    for entry in entries:
        name = entry.rstrip("/").rsplit("/", 1)[-1]
        if (
            name
            and name not in taken
            and name not in names
            and not any(character in _GREP_PATTERN_CHARACTERS for character in name)
            and not any(character in name for character in "\r\n")
        ):
            names.append(name)
    return names


def ignoring_patterns(
    paths: Iterable[str | Path],
    source_dir: str | Path,
    ignore_paths: Iterable[object] | None,
    matches: Callable[[str, str], bool] = ignore_path_matches,
) -> dict[str, str]:
    """``{path: pattern}`` for each of ``paths`` an ignore path ignores, with the
    first pattern that matches it.

    Each path is matched as ASH matches it when it drops findings: its path below
    ``source_dir`` against each pattern. A path not below ``source_dir`` is not
    ignored.

    ``source_dir`` is tried as spelled first and with its links resolved second,
    in that order: a path below both (the source directory spelled through a
    link to its own parent, say) is matched below the spelling the scan set
    uses. The two roots were a set, iterated in hash order, so which relative
    path such a path was matched by, and so whether it was ignored, varied from
    one process to the next.
    """
    patterns = [
        str(getattr(entry, "path", "") or "")
        for entry in ignore_paths or []
        if getattr(entry, "path", None)
    ]
    if not patterns:
        return {}
    roots = list(
        dict.fromkeys(
            (Path(os.path.abspath(source_dir)), Path(os.path.realpath(source_dir)))
        )
    )

    def _below(path: str) -> str | None:
        for root in roots:
            try:
                return Path(os.path.abspath(path)).relative_to(root).as_posix()
            except ValueError:
                continue
        return None

    ignored: dict[str, str] = {}
    for path in (str(path) for path in paths):
        relative = _below(path)
        if relative is None:
            continue
        for pattern in patterns:
            if matches(relative, pattern):
                ignored[path] = pattern
                break
    return ignored


def drop_ignored(
    paths: Iterable[str | Path],
    source_dir: str | Path,
    ignore_paths: Iterable[object] | None,
    matches: Callable[[str, str], bool] = ignore_path_matches,
) -> List[str]:
    """``paths`` without the ones ``ignore_paths`` ignore, for a scan-set reader.

    Matched as ``ignoring_patterns`` matches them; a path not below
    ``source_dir`` is kept.
    """
    kept = [str(path) for path in paths]
    ignored = ignoring_patterns(kept, source_dir, ignore_paths, matches)
    return [path for path in kept if path not in ignored]
