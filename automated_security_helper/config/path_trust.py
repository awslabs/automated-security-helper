# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tool config and plugin paths are honored only from outside the scanned tree.

Some scanner options name a file the scanner's tool reads as its own configuration,
or a file it loads as a plugin. A path that resolves inside the scanned tree names
a file the repository being scanned wrote, so it is not passed to the tool, whether
an option set it or ASH found it by name in the source directory. A path outside
the tree is passed as before. "The scanned tree" is
``config.sandbox_grants.scanned_tree``: the enclosing checkout of the source
directory. Containment uses ``sandbox_grants.is_within``, so symlinks and ``..``
are resolved first.

Each refusal logs one warning naming the option, however many times the scanner
asks.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Optional, Set, Tuple, Union

from automated_security_helper.utils.log import ASH_LOGGER

_WARNED: Set[Tuple[str, str]] = set()
_WARNED_LOCK = threading.Lock()


def reset_path_refusal_warnings() -> None:
    """Forget which refusals were already logged (tests)."""
    with _WARNED_LOCK:
        _WARNED.clear()


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
) -> Optional[Path]:
    """The resolved path to hand the tool, or None when it is inside the scanned tree.

    Callers pass the tool this return value and nothing rebuilt from ``value``.

    Args:
        value: The configured or discovered path. None or blank returns None.
        source_dir: The scan's source directory. Relative paths are taken from it.
        key: The option or file name the warning names.
    """
    # Imported here: sandbox_grants imports ash_config, which imports the scanners
    # that import this module.
    from automated_security_helper.config.sandbox_grants import (
        is_within,
        scanned_tree,
    )

    if value is None or str(value).strip() == "":
        return None
    path = resolved_path(value, source_dir)
    if not is_within(path, scanned_tree(Path(source_dir))):
        return path
    with _WARNED_LOCK:
        first = (key, path.as_posix()) not in _WARNED
        _WARNED.add((key, path.as_posix()))
    if first:
        ASH_LOGGER.warning(
            f"Ignoring {key} ({path.as_posix()}): it is inside the scanned tree. "
            "Use a file outside the tree, set with --config-overrides or a config "
            "file outside the tree."
        )
    return None
