# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A held-open drop of the previous scan's results, for tests of the MCP runner.

The scan's thread settles the previous results in two steps: it decides the scan
has results of its own and marks it so, then it drops the previous scan's results
(disk work) and ends. A test that needs to land between the two holds the drop
open: the drop signals ``entered`` the moment it starts and waits for ``release``
before it runs the real drop. The restore is recorded too, and runs for real.

One copy here, used by the runner tests that need the window, so the double is
changed in one place.
"""

from __future__ import annotations

import threading
from typing import List, Tuple
from unittest.mock import patch

import pytest

from automated_security_helper.core.previous_results import PreviousResults

DEFAULT_HOLD_SECONDS = 30.0


class TheDropWindow:
    """``PreviousResults.discard`` held open, and ``restore`` recorded.

    ``entered`` is set when a drop starts; the drop then waits up to
    ``hold_seconds`` for ``release`` (far past any test, so a test that fails early
    cannot leave a thread behind for long) and runs the real drop. ``drops`` and
    ``restores`` hold the ``PreviousResults`` each call was made on.

    Use ``patches`` as context managers, or ``install(monkeypatch)``.
    """

    def __init__(self, hold_seconds: float = DEFAULT_HOLD_SECONDS) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.drops: List[PreviousResults] = []
        self.restores: List[PreviousResults] = []
        real_discard = PreviousResults.discard
        real_restore = PreviousResults.restore
        window = self

        def a_drop_held_open(this: PreviousResults) -> None:
            window.drops.append(this)
            window.entered.set()
            window.release.wait(timeout=hold_seconds)
            return real_discard(this)

        def a_restore_that_is_recorded(this: PreviousResults) -> None:
            window.restores.append(this)
            return real_restore(this)

        self._drop = a_drop_held_open
        self._restore = a_restore_that_is_recorded
        self.patches: Tuple = (
            patch.object(PreviousResults, "discard", a_drop_held_open),
            patch.object(PreviousResults, "restore", a_restore_that_is_recorded),
        )

    def install(self, monkeypatch: pytest.MonkeyPatch) -> "TheDropWindow":
        """Patch the drop and the restore for the rest of the test."""
        monkeypatch.setattr(PreviousResults, "discard", self._drop)
        monkeypatch.setattr(PreviousResults, "restore", self._restore)
        return self
