# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tool config and plugin paths are honored only from outside the scanned tree.

Some scanner options name a file the scanner's tool reads as its own configuration,
or a file it loads as a plugin. A path that resolves inside the scanned tree names
a file the repository being scanned wrote, so it is not passed to the tool, whether
an option set it or ASH found it by name in the source directory. A path outside
the tree is passed as before. "The scanned tree" is
any tree ``config.sandbox_grants.scanned_trees`` returns for the scan root: the
outermost checkout above the source directory, under each name it has.
Containment uses ``sandbox_grants.is_within``, so symlinks and ``..`` are resolved
first.

Each refusal logs one warning naming the option, however many times the scanner
asks.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple, Union

from automated_security_helper.utils.log import ASH_LOGGER

_WARNED: Set[Tuple[str, str]] = set()
_WARNED_LOCK = threading.Lock()


def reset_path_refusal_warnings() -> None:
    """Forget which refusals were already logged (tests)."""
    with _WARNED_LOCK:
        _WARNED.clear()


def in_scanned_tree(path: Union[str, Path], scan_root: Union[str, Path]) -> bool:
    """Whether ``path`` is in a tree the repository being scanned controls.

    The one membership test this module and ``plugin_module_trust`` use, so the
    rule for which trees those are (``sandbox_grants.scanned_trees`` of the scan
    root, the same trees ``resolve_config`` checks config files against) changes
    in one place.
    """
    # Imported here: sandbox_grants imports ash_config, which imports the scanners
    # that import this module.
    from automated_security_helper.config.sandbox_grants import (
        is_within,
        scanned_trees,
    )

    return any(is_within(Path(path), tree) for tree in scanned_trees(Path(scan_root)))


#: Fallback working directories already made, by filesystem root, so a process
#: makes at most one per root (see cwd_outside_scanned_tree).
_FALLBACK_CWDS: Dict[str, Path] = {}


def _new_directory(parent: Optional[Path]) -> Optional[Path]:
    """A new empty directory under ``parent`` (the system temp dir for None)."""
    import tempfile

    try:
        return Path(tempfile.mkdtemp(prefix="ash-tool-cwd-", dir=parent))
    except OSError:
        return None


def cwd_outside_scanned_tree(
    target: Union[str, Path],
    *,
    results_dir: Union[str, Path],
    source_dir: Union[str, Path],
    config: Any = None,
) -> Path:
    """A working directory for a tool that reads its config file from its cwd.

    Normally the filesystem root of ``target``: outside the scanned tree, and with
    every path relative to it absolute, which checkov_scanner.rewrite_checkov_paths
    relies on. When that root is inside the tree itself (a source directory that
    is a drive root, such as a ``subst`` or mapped drive on Windows, or a scan of a
    whole filesystem), a new empty directory is made instead, in this order:

    1. In the system temp directory, when that is outside the tree. On Windows
       that is another drive, where checkov writes paths without the drive, so
       they still read as relative to the target's root.
    2. Directly under the target's root. checkov removes the ``/..`` its paths
       start with, so a directory one level below the root gives the same paths
       as the root.
    3. Under ``results_dir``, which a sandboxed tool can enter. checkov's paths
       can then lose directories the file shares with the results directory, so
       this is used only when 1 and 2 are not possible, and under a sandbox.

    Each is new and empty, so it holds no config file. One is made per root and
    process and reused; nothing is cleared or deleted.
    """
    root = getattr(config, "_scanned_root", None) or source_dir
    anchor = Path(Path(os.path.abspath(target)).anchor)
    if not in_scanned_tree(anchor, root):
        return anchor
    from automated_security_helper.utils.sandbox.scope import active_scope

    if active_scope() is None:
        cached = _FALLBACK_CWDS.get(anchor.as_posix())
        if cached is not None and cached.is_dir() and not any(cached.iterdir()):
            return cached
        for parent in (None, anchor):
            made = _new_directory(parent)
            if made is None:
                continue
            if parent is None and in_scanned_tree(made, root):
                made.rmdir()
                continue
            _FALLBACK_CWDS[anchor.as_posix()] = made
            return made
    directory = Path(os.path.abspath(results_dir))
    directory.mkdir(parents=True, exist_ok=True)
    made = _new_directory(directory)
    if made is None:
        raise OSError(f"cannot create a working directory under {directory}")
    ASH_LOGGER.warning(
        f"The filesystem root of {Path(target).as_posix()} is inside the scanned "
        f"tree, so the tool runs from {made.as_posix()}; paths in its findings "
        "may leave out directories they share with that location."
    )
    return made


def resolved_path(value: Union[str, Path], source_dir: Union[str, Path]) -> Path:
    """``value`` as the tool will read it: ``~`` expanded, a relative path taken from
    ``source_dir``, and symlinks and ``..`` resolved.

    ``honored_path`` checks this path and returns it, so a caller that hands the
    tool the returned value hands it exactly the file that was checked.
    """
    path = Path(os.path.expanduser(str(value)))
    if not path.is_absolute():
        path = Path(source_dir) / path
    return Path(os.path.realpath(path))


def honored_path(
    value: Union[str, Path, None],
    *,
    source_dir: Union[str, Path],
    key: str,
    config: Any = None,
) -> Optional[Path]:
    """The resolved path to hand the tool, or None when it is inside the scanned tree.

    Callers pass the tool this return value and nothing rebuilt from ``value``.

    Args:
        value: The configured or discovered path. None or blank returns None.
        source_dir: The scan's source directory. Relative paths are taken from it.
        key: The option or file name the warning names.
        config: The scan's AshConfig. When it records a wider scanned root
            (``AshConfig._scanned_root``, the workspace root in workspace mode),
            the tree is taken from that instead of from ``source_dir``.
    """
    if value is None or str(value).strip() == "":
        return None
    path = resolved_path(value, source_dir)
    root = getattr(config, "_scanned_root", None) or source_dir
    if not in_scanned_tree(path, root):
        return path
    with _WARNED_LOCK:
        first = (key, path.as_posix()) not in _WARNED
        _WARNED.add((key, path.as_posix()))
    if first:
        ASH_LOGGER.warning(
            f"Ignoring {key} ({path.as_posix()}): it is inside the scanned tree "
            "(the outermost git checkout around the source directory, or the source "
            "directory outside a checkout). A file there is not passed to the tool "
            "whoever names it; name one outside that tree."
        )
    return None
