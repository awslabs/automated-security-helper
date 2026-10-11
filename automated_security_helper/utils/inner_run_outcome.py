# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Whether the inner run of a container or nix scan completed, as its results file says.

Container and nix mode run a second ASH, the inner run, and then read its
``ash_aggregated_results.json`` back to compute the verdict. The inner run's exit
status does not say whether that file can be used: 0, 1 and 2 are verdicts the
outer process re-derives from the file, and 1 is also what an inner run exits with
when its reports were refused or it failed after the scan phase had written the
file. A refused report file name leaves nothing in ``reports/`` for the outer
process to find, and the file such a run leaves reads as a clean scan.

So the outer process gives the inner run an ID (``OUTER_RUN_ID_ENV``: an
environment variable for nix mode, ``-e`` for the container), and the inner run
writes that ID into its results file as a validation checkpoint:

* ``run_completed`` when ``_run_local_mode`` or ``_run_workspace_mode`` completes
  (``mark_run_completed``, ``mark_results_file_completed``);
* ``report_path_refused``, with the refusal's message, when its reports are
  refused (``record_report_refusal``).

The outer process (``read_back_outcome``) reads the file back only when it holds
the completion marker with the outer process's own ID. With a refusal carrying that
ID it exits 1 with the refusal's message; otherwise it exits 1 saying the inner run
did not complete. That fails closed whatever stopped the inner run, including a
refusal whose record could not be written and an inner ASH older than this one,
which writes no marker. A record with another ID was left by an earlier run, in a
results file read back with ``--use-existing``, and is ignored; the orchestrator
drops such records when it loads existing results (``without_run_records``), so
reports do not repeat them.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from automated_security_helper.utils.atomic_write import write_text_atomically

PathLike = Union[str, "os.PathLike[str]"]

#: The environment variable that carries the outer process's run ID to the inner run.
OUTER_RUN_ID_ENV = "ASH_OUTER_RUN_ID"

#: ``type`` of the checkpoint that records that the inner run completed.
RUN_COMPLETED_CHECKPOINT = "run_completed"

#: ``type`` of the checkpoint that records that the inner run's reports were refused.
REPORT_PATH_REFUSED_CHECKPOINT = "report_path_refused"

_RUN_RECORD_TYPES = (RUN_COMPLETED_CHECKPOINT, REPORT_PATH_REFUSED_CHECKPOINT)
_RUN_ID = re.compile(r"[0-9a-f]{32}")


def new_outer_run_id() -> str:
    """An ID for one container or nix run, to hand to its inner run."""
    return uuid.uuid4().hex


def outer_run_id_from_environment() -> Optional[str]:
    """The run ID an outer process gave this run, or None when it is not an inner run."""
    value = os.environ.get(OUTER_RUN_ID_ENV, "")
    return value if _RUN_ID.fullmatch(value) else None


def _is_run_record(checkpoint: object) -> bool:
    return isinstance(checkpoint, dict) and checkpoint.get("type") in _RUN_RECORD_TYPES


def _run_id_of(checkpoint: Dict[str, Any]) -> Optional[str]:
    metadata = checkpoint.get("metadata")
    return metadata.get("run_id") if isinstance(metadata, dict) else None


def without_run_records(checkpoints: Iterable[Any]) -> List[Any]:
    """``checkpoints`` without any run's completion marker or refusal record."""
    return [checkpoint for checkpoint in checkpoints if not _is_run_record(checkpoint)]


def _completion_marker(run_id: str) -> Dict[str, Any]:
    return {
        "type": RUN_COMPLETED_CHECKPOINT,
        "severity": "info",
        "message": "The run completed.",
        "metadata": {"run_id": run_id},
    }


def mark_run_completed(results: object, run_id: Optional[str]) -> None:
    """Replace the run records in ``results`` with this run's completion marker.

    With no ``run_id`` (not an inner run), only removes the records an earlier run
    left. Leaves ``results`` untouched when there is nothing to change.
    """
    checkpoints = list(getattr(results, "validation_checkpoints", None) or [])
    kept = without_run_records(checkpoints)
    if run_id is None and len(kept) == len(checkpoints):
        return
    if run_id is not None:
        kept.append(_completion_marker(run_id))
    setattr(results, "validation_checkpoints", kept)


def _rewrite_records(results_file: PathLike, record: Dict[str, Any]) -> bool:
    path = Path(results_file)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            return False
        checkpoints = document.get("validation_checkpoints")
        document["validation_checkpoints"] = [
            *without_run_records(checkpoints if isinstance(checkpoints, list) else []),
            record,
        ]
        write_text_atomically(path, json.dumps(document, indent=2))
    except (OSError, ValueError):
        return False
    return True


def mark_results_file_completed(results_file: PathLike, run_id: str) -> bool:
    """Add this run's completion marker to a results file another step wrote.

    Returns False when the file could not be read or rewritten; the outer process
    then reads no marker and fails closed.
    """
    return _rewrite_records(results_file, _completion_marker(run_id))


def record_report_refusal(
    results_file: PathLike, message: str, run_id: str, output_dir: PathLike
) -> bool:
    """Record in the results file that this run's reports were refused, and why.

    ``output_dir`` is the output directory as this run sees it, so the outer
    process can give the paths in ``message`` as it sees them. Returns False when
    the file could not be read or rewritten; the outer process then reads no
    completion marker and fails closed, without the message.
    """
    return _rewrite_records(
        results_file,
        {
            "type": REPORT_PATH_REFUSED_CHECKPOINT,
            "severity": "error",
            "message": message,
            "metadata": {
                "run_id": run_id,
                "output_dir": Path(output_dir).as_posix(),
                "impact": "The run's reports were refused; the message says why.",
            },
        },
    )


@dataclass(frozen=True)
class InnerRunOutcome:
    """What an inner run's results file says about the run with a given ID."""

    completed: bool
    refusal: Optional[str] = None
    inner_output_dir: Optional[str] = None
    marked_by_another_run: bool = False


def read_back_outcome(results: object, run_id: str) -> InnerRunOutcome:
    """Read the records for ``run_id`` from the inner run's results."""
    completed = False
    refusal: Optional[str] = None
    inner_output_dir: Optional[str] = None
    another_run = False
    for checkpoint in getattr(results, "validation_checkpoints", None) or []:
        if not _is_run_record(checkpoint):
            continue
        if _run_id_of(checkpoint) != run_id:
            another_run = True
            continue
        if checkpoint.get("type") == RUN_COMPLETED_CHECKPOINT:
            completed = True
        else:
            refusal = str(checkpoint.get("message") or "The reports were refused.")
            metadata = checkpoint.get("metadata") or {}
            recorded_dir = metadata.get("output_dir")
            inner_output_dir = recorded_dir if isinstance(recorded_dir, str) else None
    return InnerRunOutcome(
        completed=completed and refusal is None,
        refusal=refusal,
        inner_output_dir=inner_output_dir,
        marked_by_another_run=another_run,
    )


def as_seen_from_the_host(message: str, inner_dir: Optional[str], host_dir: str) -> str:
    """``message`` with the inner run's view of the output directory replaced by the host's.

    The container sees the output directory at ``/out``; nix mode sees the same path
    as the host, which leaves the message unchanged.
    """
    if not inner_dir or inner_dir == host_dir:
        return message
    return re.sub(re.escape(inner_dir) + r"(?=/|\b|$)", host_dir, message)
