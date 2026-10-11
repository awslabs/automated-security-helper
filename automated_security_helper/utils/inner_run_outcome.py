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
  (``mark_run_completed``; a workspace run stamps it into the file it streamed,
  with ``workspace.aggregation.stamp_run_record``);
* ``report_path_refused``, with the refusal's message, when its reports are
  refused (``record_report_refusal``, or ``write_refusal_results`` when the run was
  refused before it wrote a results file).

The outer process (``read_back_outcome``) reads the file back only when it holds
the completion marker with the outer process's own ID. With a refusal carrying that
ID it exits 1 with the refusal's message; otherwise it exits 1 saying the inner run
did not complete. That fails closed whatever stopped the inner run, including a
refusal whose record could not be written and an inner ASH older than this one,
which writes no marker. A record with another ID was left by an earlier run, in a
results file read back with ``--use-existing``, and is ignored; the orchestrator
drops such records when it loads existing results (``without_run_records``), so
reports do not repeat them.

What this guards against, and what it does not
----------------------------------------------
It tells the outer process whether the file it reads back is a complete account
of the run it started: not a file an earlier run left, not one a run that stopped
part way wrote, and not one from an ASH that does not record completion. It is not
an authentication mechanism. Code running as the inner run's user can write any
file the inner run can, the marker included. So the ID is kept from the processes
the inner run starts only so that a scanner cannot copy it into a results file by
accident: the inner run takes it out of its environment when it starts
(``take_outer_run_id``), and the scanner sandbox drops it from a scanner's
environment (utils/sandbox/policy.py).
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from automated_security_helper.utils.atomic_write import write_text_atomically

PathLike = Union[str, "os.PathLike[str]"]

#: The environment variable that carries the outer process's run ID to the inner run.
OUTER_RUN_ID_ENV = "ASH_OUTER_RUN_ID"

#: ``type`` of the checkpoint that records that the inner run completed.
RUN_COMPLETED_CHECKPOINT = "run_completed"

#: ``type`` of the checkpoint that records that the inner run's reports were refused.
REPORT_PATH_REFUSED_CHECKPOINT = "report_path_refused"

#: ``type`` of the checkpoint in which the report phase lists the report files it
#: wrote, each with its reporter's format, so the exit code is counted only from
#: the file this run's SARIF reporter wrote (``report_file_written_as``).
REPORTS_WRITTEN_CHECKPOINT = "reports_written"

#: The records that say how one run ended: replaced when the run ends.
_OUTCOME_TYPES = (RUN_COMPLETED_CHECKPOINT, REPORT_PATH_REFUSED_CHECKPOINT)
#: Every record about one run: dropped when another run reads the results back.
_RUN_RECORD_TYPES = (*_OUTCOME_TYPES, REPORTS_WRITTEN_CHECKPOINT)
_RUN_ID = re.compile(r"[0-9a-f]{32}")

#: The last ASH release whose inner run does not record its completion. v3.7.1 and
#: every release before it write no marker, so an image built from one of them is
#: never read back.
LAST_RELEASE_WITHOUT_THE_MARKER = "3.7.1"


def release_records_completion(version: str) -> bool:
    """Whether ``version`` is an ASH release whose inner run records its completion.

    A release after ``LAST_RELEASE_WITHOUT_THE_MARKER``: the code reading this is
    in that release, so its tag builds an image that writes the marker. A
    development, pre-release or local version is not a release, and names no tag.
    """
    from packaging.version import InvalidVersion, Version

    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    return (
        not parsed.is_prerelease
        and parsed.local is None
        and parsed > Version(LAST_RELEASE_WITHOUT_THE_MARKER)
    )


def new_outer_run_id() -> str:
    """An ID for one container or nix run, to hand to its inner run."""
    return uuid.uuid4().hex


def take_outer_run_id() -> Optional[str]:
    """Remove the run ID an outer process gave this run from the environment, and return it.

    Called when the inner run starts, before it starts any process, so none of
    them inherits the ID. None when this is not an inner run. A value that is not
    an ID this ASH gives is reported and not used: the run then writes no marker,
    and the outer process says the run did not complete.
    """
    from automated_security_helper.utils.log import ASH_LOGGER
    from automated_security_helper.utils.process_env import apply_environ_overrides

    value = apply_environ_overrides({OUTER_RUN_ID_ENV: None})[OUTER_RUN_ID_ENV]
    if not value:
        return None
    if _RUN_ID.fullmatch(value):
        return value
    ASH_LOGGER.warning(
        f"Ignoring {OUTER_RUN_ID_ENV}: {value!r} is not a run ID ASH gives the inner "
        "run of a container or nix scan. This run's results file will not record "
        "that it completed."
    )
    return None


def _is_run_record(checkpoint: object) -> bool:
    return isinstance(checkpoint, dict) and checkpoint.get("type") in _RUN_RECORD_TYPES


def _run_id_of(checkpoint: Dict[str, Any]) -> Optional[str]:
    metadata = checkpoint.get("metadata")
    return metadata.get("run_id") if isinstance(metadata, dict) else None


def without_run_records(checkpoints: Iterable[Any]) -> List[Any]:
    """``checkpoints`` without any record about the run that wrote them.

    For results another run reads back (``--use-existing``, ``ash merge``): the
    completion marker, the refusal record and the list of reports written.
    """
    return [checkpoint for checkpoint in checkpoints if not _is_run_record(checkpoint)]


def _without_outcome_records(checkpoints: Iterable[Any]) -> List[Any]:
    return [
        checkpoint
        for checkpoint in checkpoints
        if not (
            isinstance(checkpoint, dict) and checkpoint.get("type") in _OUTCOME_TYPES
        )
    ]


def record_reports_written(
    results: object, written: Iterable[Tuple[str, Optional[str]]]
) -> None:
    """List in ``results`` the report files this run wrote, each with its reporter's format.

    ``written`` holds ``(file name, format)`` pairs, the format being the name
    ``--output-formats`` selects the reporter by (``reporter_format_name``). An
    empty ``written`` records that the run wrote no report file.
    """
    if results is None:
        return
    formats = {name: format_name or None for name, format_name in written}
    checkpoints = [
        checkpoint
        for checkpoint in getattr(results, "validation_checkpoints", None) or []
        if not (
            isinstance(checkpoint, dict)
            and checkpoint.get("type") == REPORTS_WRITTEN_CHECKPOINT
        )
    ]
    checkpoints.append(
        {
            "type": REPORTS_WRITTEN_CHECKPOINT,
            "severity": "info",
            "message": "The report files this run wrote.",
            "metadata": {
                "files": sorted(formats),
                "formats": {name: formats[name] for name in sorted(formats)},
            },
        }
    )
    setattr(results, "validation_checkpoints", checkpoints)


def _reports_written(results: object) -> Optional[Dict[str, Any]]:
    """The metadata of the ``reports_written`` record in ``results``, or None."""
    for checkpoint in getattr(results, "validation_checkpoints", None) or []:
        if (
            isinstance(checkpoint, dict)
            and checkpoint.get("type") == REPORTS_WRITTEN_CHECKPOINT
        ):
            metadata = checkpoint.get("metadata")
            return metadata if isinstance(metadata, dict) else {}
    return None


def records_reports_written(results: object) -> bool:
    """Whether ``results`` record which report files their run wrote."""
    return _reports_written(results) is not None


def report_file_written_as(results: object, format_name: str) -> Optional[str]:
    """The report file this run's ``format_name`` reporter wrote, as ``results`` record it.

    None when no reporter of that format wrote one, when more than one did, and when
    the results record nothing, as for a run whose report phase did not run. A file
    in ``reports/`` that is not recorded is not this run's report: ``--use-existing``
    keeps the reports an earlier run wrote, and another reporter's ``extension`` can
    name the file a reporter of this format would write.
    """
    metadata = _reports_written(results)
    formats = metadata.get("formats") if metadata is not None else None
    if not isinstance(formats, dict):
        return None
    names = [
        name
        for name, written_as in formats.items()
        if isinstance(name, str) and written_as == format_name
    ]
    return names[0] if len(names) == 1 else None


def completion_marker(run_id: str) -> Dict[str, Any]:
    """The checkpoint that records that the run with ``run_id`` completed."""
    return {
        "type": RUN_COMPLETED_CHECKPOINT,
        "severity": "info",
        "message": "The run completed.",
        "metadata": {"run_id": run_id},
    }


def mark_run_completed(results: object, run_id: Optional[str]) -> None:
    """Replace the run records in ``results`` with this run's completion marker.

    With no ``run_id`` (not an inner run), only removes the records an earlier run
    left. Leaves ``results`` untouched when there is nothing to change, or none.
    """
    if results is None:
        return
    checkpoints = list(getattr(results, "validation_checkpoints", None) or [])
    kept = _without_outcome_records(checkpoints)
    if run_id is None and len(kept) == len(checkpoints):
        return
    if run_id is not None:
        kept.append(completion_marker(run_id))
    setattr(results, "validation_checkpoints", kept)


def refusal_record(message: str, run_id: str, output_dir: PathLike) -> Dict[str, Any]:
    """The checkpoint that records that the run with ``run_id`` was refused, and why.

    ``output_dir`` is the output directory as the run sees it, so the outer process
    can give the paths in ``message`` as it sees them.
    """
    return {
        "type": REPORT_PATH_REFUSED_CHECKPOINT,
        "severity": "error",
        "message": message,
        "metadata": {
            "run_id": run_id,
            "output_dir": Path(output_dir).as_posix(),
            "impact": "The run's reports were refused; the message says why.",
        },
    }


def record_report_refusal(
    results_file: PathLike, message: str, run_id: str, output_dir: PathLike
) -> bool:
    """Record in the results file that this run's reports were refused, and why.

    Replaces any run record in the file. Returns False when the file could not be
    read or rewritten; the outer process then reads no record of this run's
    completion and fails closed, without the message.
    """
    try:
        path = Path(results_file)
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            return False
        checkpoints = document.get("validation_checkpoints")
        document["validation_checkpoints"] = [
            *_without_outcome_records(
                checkpoints if isinstance(checkpoints, list) else []
            ),
            refusal_record(message, run_id, output_dir),
        ]
        write_text_atomically(path, json.dumps(document, indent=2))
    except (OSError, TypeError, ValueError):
        return False
    return True


def write_refusal_results(
    results_file: PathLike, message: str, run_id: str, output_dir: PathLike
) -> bool:
    """Write a results file that holds only the refusal, for a run refused before it wrote one.

    A workspace run refuses a report file name before any project is scanned, so
    there is no results file to record the refusal in, and the outer process would
    have only "results file not found" to report. Returns False when it cannot be
    written.
    """
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    try:
        document = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
        document["validation_checkpoints"] = [
            refusal_record(message, run_id, output_dir)
        ]
        path = Path(results_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomically(path, json.dumps(document, indent=2))
    except (OSError, TypeError, ValueError):
        return False
    return True


@dataclass(frozen=True)
class InnerRunOutcome:
    """What an inner run's results file says about the run with a given ID."""

    completed: bool
    refusal: Optional[str] = None
    inner_output_dir: Optional[str] = None
    #: A record carries another run's ID: an earlier run's, in a file read back with
    #: ``--use-existing`` that this run did not finish rewriting.
    marked_by_another_run: bool = False
    #: A record carries no run ID, which only an ASH older than this one writes.
    written_by_an_older_ash: bool = False


def read_back_outcome(results: object, run_id: str) -> InnerRunOutcome:
    """Read the records for ``run_id`` from the inner run's results."""
    completed = False
    refusal: Optional[str] = None
    inner_output_dir: Optional[str] = None
    another_run = False
    older_ash = False
    for checkpoint in getattr(results, "validation_checkpoints", None) or []:
        if not (
            isinstance(checkpoint, dict) and checkpoint.get("type") in _OUTCOME_TYPES
        ):
            continue
        recorded_id = _run_id_of(checkpoint)
        if recorded_id is None:
            older_ash = True
            continue
        if recorded_id != run_id:
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
        written_by_an_older_ash=older_ash,
    )


def as_seen_from_the_host(message: str, inner_dir: Optional[str], host_dir: str) -> str:
    """``message`` with the inner run's view of the output directory replaced by the host's.

    The container sees the output directory at ``/out``; nix mode sees the same path
    as the host, which leaves the message unchanged.
    """
    if not inner_dir or inner_dir == host_dir:
        return message
    # Only where the inner directory starts a path: not inside another one, such as
    # /src/out for an inner /out, and not as the start of a longer name. The host
    # directory is inserted as written, not read as a replacement template.
    pattern = r"(?<![^\s'\"(])" + re.escape(inner_dir) + r"(?=/|\b|$)"
    return re.sub(pattern, lambda _match: host_dir, message)
