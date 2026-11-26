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


def context_work_dir(context: "PluginContext") -> Path:
    """The context's work directory, the converted tree's root, or a
    ``ValueError`` when the context has none.

    A validated context always has one (``PluginContext._derive_work_dir``
    derives it from the output directory); a context built with
    ``model_construct`` and no work directory does not. A ``ValueError``, not
    ``ScannerError``: that lives in ``core``, and an import of ``core`` here
    would be one more edge against the layer order
    (``tests/unit/test_layer_dag_boundaries.py``).
    """
    work_dir = context.work_dir
    if work_dir is None:
        raise ValueError("The scan's context has no work directory")
    return Path(work_dir)


def scan_targets(
    context: "PluginContext",
) -> List[Tuple[TargetType, Path]]:
    """``(target_type, directory)`` for each tree ScanPhase hands a scanner."""
    targets: List[Tuple[TargetType, Path]] = [
        (TargetType.SOURCE, Path(context.source_dir))
    ]
    work_dir = context_work_dir(context)
    if work_dir.is_dir() and any(work_dir.rglob("*.*")):
        targets.append((TargetType.CONVERTED, work_dir))
    return targets
