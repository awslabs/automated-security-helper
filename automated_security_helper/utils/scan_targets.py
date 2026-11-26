# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trees a scan hands each scanner, for answers a scanner gives before it runs.

``ScanPhase`` queues every scanner with the source directory and, when the work
directory holds a file with an extension, the converted files there as well
(``ScanPhase._include_work_dir``). A scanner's ``nothing_to_scan_reason`` answers
for both trees before either is scanned, so it asks this for the same two.
``tests/unit/plugin_modules/ash_builtin/test_nothing_to_scan_reason.py`` holds this
to the task list ScanPhase builds.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, List, Tuple

from automated_security_helper.models.vocab import TargetType

if TYPE_CHECKING:
    from automated_security_helper.base.plugin_context import PluginContext


def scan_targets(
    context: "PluginContext",
) -> List[Tuple[TargetType, Path]]:
    """``(target_type, directory)`` for each tree ScanPhase hands a scanner."""
    targets: List[Tuple[TargetType, Path]] = [
        (TargetType.SOURCE, Path(context.source_dir))
    ]
    work_dir = Path(context.work_dir)
    if work_dir.is_dir() and any(work_dir.rglob("*.*")):
        targets.append((TargetType.CONVERTED, work_dir))
    return targets
