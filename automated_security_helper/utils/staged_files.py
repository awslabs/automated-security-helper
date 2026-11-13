# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The staged-file scope of ``ash --mode precommit --staged``.

Why this exists
---------------
``--changed-files-only`` scans everything and filters the REPORTS against a
``<base_ref>...HEAD`` diff, so it saves no scan time and cannot see the staged
content a pre-commit hook is called about (``utils/changed_files.py`` and
``workspace/execution.py`` both record this). ``--staged`` is the scan-time
scope: the files ``git diff --cached`` lists become the scanner target set, so
a one-file commit pays for one file, not for the whole repository.

What lives here is the mapping from the repository-root-relative names git
prints (:func:`automated_security_helper.utils.get_scan_set.get_staged_files`)
to the source-directory-relative POSIX paths the rest of the scan speaks in,
plus the per-scanner matching used to decide that a scanner has nothing staged
to scan. Suppressions, ignore paths and SARIF post-processing are untouched by
the scope: scanners keep the same scan root, so every path they report resolves
exactly as it does in a whole-repository run.
"""

from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import List, Optional, Sequence

from automated_security_helper.utils.log import ASH_LOGGER


def staged_files_for_source(source_dir: Path) -> Optional[List[str]]:
    """The staged files inside ``source_dir``, source-relative, as POSIX text.

    git prints staged names relative to the repository root, and ``source_dir``
    may sit below it (a project inside a monorepo), so each name is kept only
    when it falls under ``source_dir`` and is then respelled relative to it.

    Returns:
        The sorted list (empty when nothing staged falls inside ``source_dir``),
        or ``None`` when the staged list could not be read at all: not a git
        repository, git missing, or the diff failed. The caller refuses the scan
        in that case rather than silently scanning everything; the specific
        cause was already logged by the reader.
    """
    from automated_security_helper.utils.get_scan_set import (
        get_staged_files,
        git_repository_root,
        git_repository_root_problem,
    )

    # resolve(), not absolute(): git prints the repository root and the staged
    # names as real paths, so under a checkout reached through a symlink (a
    # symlinked home or worktree, macOS /tmp -> /private/tmp) an unresolved
    # source never contains them, every relative_to below raises, and the list
    # came back [] -- which the CLI read as "nothing staged" and exited 0 with
    # no scanner run. changed_paths_within resolves for the same reason.
    source = Path(source_dir).resolve()
    repo_root = git_repository_root(source)
    if repo_root is None:
        ASH_LOGGER.warning(
            f"--staged needs the staged file list of a git repository, and "
            f"{git_repository_root_problem(source)}."
        )
        return None
    staged = get_staged_files(cwd=repo_root)
    if staged is None:
        return None

    inside: List[str] = []
    for name in staged:
        # The root git prints is already resolved; resolved again so the
        # containment test below can never depend on how the caller spelled it.
        absolute = repo_root.resolve() / name
        try:
            relative = absolute.relative_to(source)
        except ValueError:
            # Staged, but outside the scanned directory: a monorepo sibling's
            # file is not this scan's to report on.
            continue
        inside.append(relative.as_posix())
    return sorted(set(inside))


def matching_staged_files(
    staged: Sequence[str], patterns: Optional[Sequence[str]]
) -> List[str]:
    """The entries of ``staged`` a scanner with ``patterns`` would scan.

    ``patterns`` are ``fnmatch`` globs, matched case-insensitively (fnmatch's
    own normalization on Windows is case-insensitive already; scanners name
    suffixes, and ``A.PY`` is a Python file to bandit) against the whole
    source-relative POSIX path and against the file's base name, so ``*.py``
    matches ``pkg/app.py`` and ``package-lock.json`` matches at any depth.
    ``None`` means the scanner reads any file, so everything matches.
    """
    if patterns is None:
        return list(staged)
    matched: List[str] = []
    for entry in staged:
        name = PurePosixPath(entry).name
        lowered_entry = entry.lower()
        lowered_name = name.lower()
        if any(
            fnmatch(lowered_entry, pattern.lower())
            or fnmatch(lowered_name, pattern.lower())
            for pattern in patterns
        ):
            matched.append(entry)
    return matched
