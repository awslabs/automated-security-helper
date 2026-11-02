# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A ``Path`` predicate read as False when the stat behind it is refused.

Before Python 3.13, ``Path.is_dir()``, ``is_file()``, ``exists()`` and
``is_symlink()`` raise the stat's PermissionError for a path under an
unsearchable directory, or for a link whose target cannot be stat'ed, instead
of answering. A scanner that walks every ancestor of a workflow, or probes each
candidate input, meets paths the scan does not own, and one such path must not
end the whole selection. The actionlint and zizmor scanners each carried a copy
of this helper; one copy here keeps the two from drifting apart.
"""

from __future__ import annotations

from pathlib import Path


def probe_path(path: Path, method: str) -> bool:
    """``path.<method>()`` for ``is_dir``, ``is_file``, ``exists`` or
    ``is_symlink``, read as False when the stat is refused (any OSError)."""
    try:
        return bool(getattr(path, method)())
    except OSError:
        return False
