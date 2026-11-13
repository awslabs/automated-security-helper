# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One serialized door to ``importlib.invalidate_caches()``.

CPython's ``PathFinder.invalidate_caches`` deletes entries from
``sys.path_importer_cache`` with a plain ``del`` over a snapshot of its items
and takes no lock, so two threads that both snapshot before either deletes
race: both find the same ``None`` entry (the interpreter's absent
``pythonXY.zip`` is one on every standard install) and the loser raises
``KeyError``. ASH calls the invalidation from per-project pool workers, so
two projects resolving at once could land that race, record a correct
project FAILED with a stdlib KeyError, and exit the CLI non-zero.

Every ASH call site goes through :func:`invalidate_import_caches`, which
holds one module-level lock around the stdlib call. Nothing is caught: the
race is between ASH's own threads, and once they are serialized a KeyError
out of the stdlib is a real defect that must surface.
"""

import importlib
import threading

_INVALIDATE_LOCK = threading.Lock()


def invalidate_import_caches() -> None:
    """Call ``importlib.invalidate_caches()`` under one process-wide lock."""
    with _INVALIDATE_LOCK:
        importlib.invalidate_caches()
