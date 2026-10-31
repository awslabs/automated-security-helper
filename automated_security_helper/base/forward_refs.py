# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A once-only, thread-safe resolver for a model's forward reference.

Two models carry a forward reference to ``config.ash_config.AshConfig`` that
cannot be imported at their module's import time (``config.ash_config`` imports
them, and importing it from a half-imported module loads every built-in plugin
group): ``base.plugin_context.PluginContext`` and
``models.asharp_model.AshAggregatedResults``. Each resolves the reference on first
use, binding the class into its module and rebuilding the model once, under a
lock. The two modules each carried a byte-equivalent copy of that resolver; this
is the one copy both call.

Why the shape is what it is. ``model_rebuild()`` is not thread-safe (it clears
and regenerates the validator, serializer and core schema), so the rebuild runs
once, under the lock, with the flag set only after it: a caller that saw the flag
early would run against the still-mocked validator. The import runs OUTSIDE the
lock: the last lines of ``config/ash_config.py`` call the resolvers back as that
module finishes importing, so a thread importing it held its import lock and then
asked for this one while a thread that first used the model held this lock and
asked for the import lock. Reentrant, because ``bind`` rebuilds the model and a
rebuild that constructs one of these models on the same thread asks for the lock
again. The import is no reason for it: a model built during the import reaches
``resolve`` while ``import_target`` still raises ImportError, so it never
reaches the lock.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Generic, TypeVar

T = TypeVar("T")

# The standard library logger, not ASH_LOGGER: this module sits at the bottom of
# the import cycle described above, so it imports nothing from the package.
_LOGGER = logging.getLogger(__name__)


class OnceOnlyResolver(Generic[T]):
    """Resolve a forward reference once: import, then bind under the lock.

    ``resolve`` is cheap to call repeatedly and a no-op while the target is still
    unimportable (``import_target`` raises ImportError mid-cycle); the next call,
    once the import has finished, resolves it. ``resolved`` is set after
    ``bind`` returned, never before.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.resolved = False

    def resolve(
        self, import_target: Callable[[], T], bind: Callable[[T], None]
    ) -> None:
        if self.resolved:
            return
        # Outside the lock: see the module docstring.
        try:
            target = import_target()
        except ImportError as error:
            # Any ImportError reads as "not importable yet", so a real one, such
            # as a missing dependency of the target, is told apart only by this
            # line.
            _LOGGER.debug("forward reference not resolved yet: %s", error)
            return
        with self._lock:
            if self.resolved:
                return
            bind(target)
            self.resolved = True
