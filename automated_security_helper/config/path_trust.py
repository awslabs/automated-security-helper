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
from typing import Any, Optional, Set, Tuple, Union

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


def cwd_outside_scanned_tree(
    target: Union[str, Path], *, source_dir: Union[str, Path], config: Any = None
) -> Path:
    """A working directory for a tool that reads its config from its cwd.

    The filesystem root of ``target``: outside the scanned tree, and with every
    path relative to it absolute. When that root is inside the tree itself (a
    source directory that is a drive root, such as a ``subst`` or mapped drive on
    Windows), a new temporary directory outside the tree is used. A tool run from
    a cwd on another drive writes paths from the drive root, so they still read as
    relative to ``target``'s root. Scanning a whole filesystem leaves no
    directory outside the tree, and the root is used.
    """
    root = getattr(config, "_scanned_root", None) or source_dir
    anchor = Path(Path(os.path.abspath(target)).anchor)
    if not in_scanned_tree(anchor, root):
        return anchor
    import tempfile

    candidate = Path(tempfile.mkdtemp(prefix="ash-tool-cwd-"))
    return anchor if in_scanned_tree(candidate, root) else candidate


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
