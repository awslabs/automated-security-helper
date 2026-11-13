# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Record every file a test opens, through the interpreter's audit hook.

Patching ``os.open`` sees only that one function, so a test asserting that a
path was never opened would pass while code opened it with ``open()``,
``io.open`` or ``Path.read_text``. The ``open`` audit event is raised for all of
them, in every thread.

Audit hooks cannot be removed, so one hook is installed for the process, the
first time a test asks for it, and does nothing unless a test is recording. A
recording ends with the test: ``record_opens`` registers it through
``monkeypatch``, which restores the module's set of recordings at teardown.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, List, Optional, Tuple

_recordings: Tuple[Tuple[list, bool], ...] = ()
_installed = False


def _hook(event: str, args: Tuple[Any, ...]) -> None:
    if event != "open":
        return
    recordings = _recordings
    if not recordings:
        return
    target = args[0] if args else None
    if target is None or isinstance(target, int):
        # An already-open descriptor: nothing was looked up by name.
        return
    try:
        path = Path(os.fsdecode(target))
    except TypeError:
        return
    flags: Optional[int] = args[2] if len(args) > 2 else None
    for opened, with_flags in recordings:
        opened.append((path, flags) if with_flags else path)


def record_opens(monkeypatch, with_flags: bool = True) -> List[Any]:
    """Every path opened while the calling test runs.

    Each entry is ``(path, flags)``, or just the path with ``with_flags=False``.
    """
    global _installed
    if not _installed:
        sys.addaudithook(_hook)
        _installed = True
    opened: List[Any] = []
    monkeypatch.setattr(
        sys.modules[__name__], "_recordings", _recordings + ((opened, with_flags),)
    )
    return opened
