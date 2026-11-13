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
records how it ended with that ID:

* ``run_completed``, a validation checkpoint in its results file, when
  ``_run_local_mode`` or ``_run_workspace_mode`` completes (``mark_run_completed``;
  a workspace run stamps it into the file it streamed, with
  ``workspace.aggregation.stamp_run_record``);
* ``report_path_refused``, with the refusal's message, in
  ``ash_inner_run_outcome.json`` beside the results file, when its reports are
  refused (``record_refusal_outcome``).

The refusal is not written into the results file. A run refused before it wrote
one would otherwise leave a results file holding only the refusal, which a later
``--use-existing`` read as a clean scan; and the orchestrator refuses
``--use-existing`` on results that hold no scan or record a refused run
(``existing_results_problem``) whatever wrote them.

The outer process reads the refusal record first (``read_refusal_outcome``): with
its own ID there, it exits 1 with the refusal's message. Otherwise it reads the
results file back only when it holds the completion marker with its own ID
(``read_back_outcome``), and exits 1 saying the inner run did not complete. That
fails closed whatever stopped the inner run, including a refusal whose record
could not be written and an inner ASH older than this one, which writes no marker.
A record with another ID was left by an earlier run and is ignored; the outer
process removes an earlier refusal record before the inner run starts, and the
orchestrator drops the run records in results it loads with ``--use-existing``
(``without_run_records``), so reports do not repeat them.

What this guards against, and what it does not
----------------------------------------------
It tells the outer process whether the file it reads back is a complete account
of the run it started: not a file an earlier run left, not one a run that stopped
part way wrote, and not one from an ASH that does not record completion. It is not
an authentication mechanism. Code running as the inner run's user can write any
file the inner run can, the marker included. So the processes the inner run starts
do not inherit the ID only so that a scanner cannot copy it into a results file by
accident: the inner run takes it out of its environment when it starts
(``take_outer_run_id``), and the scanner sandbox drops it from a scanner's
environment (utils/sandbox/policy.py). It is not hidden from them: a process
running as the same user can read the inner run's starting environment (from
``/proc`` on Linux). Container mode names it with ``-e`` and no value, so it is
not on a command line other processes on the host can list, except through an
``OCI_RUNNER_WRAPPER``, which need not pass the environment on.
"""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from automated_security_helper.core.exceptions import ASHValidationError
from automated_security_helper.utils.atomic_write import write_text_atomically

PathLike = Union[str, "os.PathLike[str]"]


class ExistingResultsRefused(ASHValidationError):
    """``--use-existing`` named a results file that holds no scan to report on."""


#: The environment variable that carries the outer process's run ID to the inner run.
OUTER_RUN_ID_ENV = "ASH_OUTER_RUN_ID"

#: ``type`` of the checkpoint that records that the inner run completed.
RUN_COMPLETED_CHECKPOINT = "run_completed"

#: ``type`` of the record that says the inner run's reports were refused.
REPORT_PATH_REFUSED_CHECKPOINT = "report_path_refused"

#: Where the inner run records a refusal, in its output directory beside the
#: results file: never in the results file, which would then read as a scan.
INNER_RUN_OUTCOME_FILE = "ash_inner_run_outcome.json"

#: ``type`` of the checkpoint in which the report phase lists the report files it
#: wrote, each with its reporter's format, so the exit code is counted only from
#: the file this run's SARIF reporter wrote (``report_file_written_as``).
REPORTS_WRITTEN_CHECKPOINT = "reports_written"

#: The records that say how one run ended: replaced when the run ends.
_OUTCOME_TYPES = (RUN_COMPLETED_CHECKPOINT, REPORT_PATH_REFUSED_CHECKPOINT)
#: Every record about one run: dropped when another run reads the results back.
_RUN_RECORD_TYPES = (*_OUTCOME_TYPES, REPORTS_WRITTEN_CHECKPOINT)
_RUN_ID = re.compile(r"[0-9a-f]{32}")

#: Names this process. The ``reports_written`` record it writes carries it, and
#: ``record_reports_written`` extends only a record that does: one an earlier run
#: wrote into results this process loaded is replaced, whether or not the loader
#: stripped the run records first.
_PROCESS_TOKEN = uuid.uuid4().hex

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
    ``--output-formats`` selects the reporter by (``reporter_format_name``).

    A record an earlier report phase of the same run left in ``results`` is kept
    and extended, not replaced: ``ash merge`` runs a second phase over the same
    results for an off-host reporter, and the first phase's entries (the
    ``ash.sarif`` the exit code is read from among them) are still this run's.
    So an empty ``written`` adds nothing to an earlier record, and records that
    the run wrote no report file only when there is none yet (run_ash_scan calls
    it that way for a run whose report phase did not run).

    Only this process's own record is ever extended. The record carries a
    token for the process that wrote it, and a record with another token, or
    none, is replaced: results read back from a file carry an earlier run's
    record unless the loader stripped the run records first
    (:func:`without_run_records`, which the orchestrator does for
    ``--use-existing`` and ``ash merge`` for each shard and the merged model),
    and a loader that did not would otherwise hand this function that run's
    files as this run's.
    """
    if results is None:
        return
    earlier = _reports_written(results)
    if earlier is not None and earlier.get("run_token") != _PROCESS_TOKEN:
        earlier = None
    formats: Dict[str, Optional[str]] = {}
    if earlier is not None and isinstance(earlier.get("formats"), dict):
        formats.update(
            {
                name: (format_name if isinstance(format_name, str) else None)
                for name, format_name in earlier["formats"].items()
                if isinstance(name, str)
            }
        )
    formats.update({name: format_name or None for name, format_name in written})
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
                "run_token": _PROCESS_TOKEN,
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


def record_refusal_outcome(output_dir: PathLike, message: str, run_id: str) -> bool:
    """Record beside the results file that this run's reports were refused, and why.

    In ``INNER_RUN_OUTCOME_FILE``, replacing it. Returns False when it could not be
    written; the outer process then finds no record of this run's completion and
    fails closed, without the message.
    """
    try:
        path = Path(output_dir) / INNER_RUN_OUTCOME_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomically(
            path, json.dumps(refusal_record(message, run_id, output_dir), indent=2)
        )
    except (OSError, TypeError, ValueError):
        return False
    return True


def not_a_regular_file(path: PathLike) -> Optional[str]:
    """How ``path`` is not a regular file, or None when it is one or is absent.

    Checked without following a link: a file the inner run left is read by this
    process, so a link there would have it read whatever the link names.
    """
    try:
        found = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        return f"cannot be examined ({type(error).__name__})"
    if stat.S_ISLNK(found.st_mode):
        return "is a symlink"
    if not stat.S_ISREG(found.st_mode):
        return "is not a regular file"
    return None


@dataclass(frozen=True)
class InnerRunRefusal:
    """A refusal an inner run recorded, with the output directory as it saw it."""

    message: str
    inner_output_dir: Optional[str] = None


#: Far above any refusal record; a larger file is not one this ASH wrote.
_MAX_OUTCOME_BYTES = 1 << 20


def read_refusal_outcome(
    output_dir: PathLike, run_id: str
) -> Optional[InnerRunRefusal]:
    """The refusal the inner run with ``run_id`` recorded, or None.

    None when there is no record, when it is another run's or carries no run ID,
    and when it cannot be read as one. The caller checks ``not_a_regular_file``
    first; the open here repeats that check on the file it actually opened, so a
    link or a FIFO put at the name in between is neither followed nor waited on.
    """
    path = Path(output_dir) / INNER_RUN_OUTCOME_FILE
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with open(fd, "rb") as handle:
            fd = -1
            # Read as bytes, so the cap is the bytes it names: a text-mode read
            # of the same count took characters, up to four bytes each.
            data = handle.read(_MAX_OUTCOME_BYTES + 1)
    except (OSError, ValueError):
        return None
    finally:
        if fd != -1:
            os.close(fd)
    if len(data) > _MAX_OUTCOME_BYTES:
        return None
    try:
        record = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        # ValueError: not UTF-8, or not JSON. RecursionError: a record nested
        # deeper than the parser can follow, which is no record this ASH wrote.
        return None
    if not (
        isinstance(record, dict)
        and record.get("type") == REPORT_PATH_REFUSED_CHECKPOINT
        and _run_id_of(record) == run_id
    ):
        return None
    metadata = record.get("metadata") or {}
    recorded_dir = metadata.get("output_dir")
    return InnerRunRefusal(
        message=str(record.get("message") or "The reports were refused."),
        inner_output_dir=recorded_dir if isinstance(recorded_dir, str) else None,
    )


def existing_results_problem(results: object) -> Optional[str]:
    """Why ``--use-existing`` must not report on ``results``, or None.

    Results that record a refused run, or that hold neither scanner results nor
    findings, hold no scan: reported on, they read as a clean one. A workspace
    run's unified results hold their projects' scans.
    """
    for checkpoint in getattr(results, "validation_checkpoints", None) or []:
        if (
            isinstance(checkpoint, dict)
            and checkpoint.get("type") == REPORT_PATH_REFUSED_CHECKPOINT
        ):
            return (
                "records that the run that wrote it was refused "
                f"({checkpoint.get('message') or 'its reports were refused'}), so it "
                "holds no complete scan"
            )
    if (
        getattr(results, "scanner_results", None)
        or getattr(results, "workspace", None) is not None
        or _holds_findings(results)
    ):
        return None
    return (
        "holds no scanner results and no findings, as a run that stopped before "
        "its scan recorded anything leaves"
    )


def _holds_findings(results: object) -> bool:
    sarif = getattr(results, "sarif", None)
    return any(
        getattr(run, "results", None) for run in getattr(sarif, "runs", None) or []
    )


@dataclass(frozen=True)
class InnerRunOutcome:
    """What an inner run's results file says about the run with a given ID."""

    completed: bool
    #: A record carries another run's ID: an earlier run's, in a file read back with
    #: ``--use-existing`` that this run did not finish rewriting.
    marked_by_another_run: bool = False
    #: A record carries no run ID, which only an ASH older than this one writes.
    written_by_an_older_ash: bool = False


def read_back_outcome(results: object, run_id: str) -> InnerRunOutcome:
    """Read the completion marker for ``run_id`` from the inner run's results."""
    completed = False
    another_run = False
    older_ash = False
    for checkpoint in getattr(results, "validation_checkpoints", None) or []:
        if not (
            isinstance(checkpoint, dict)
            and checkpoint.get("type") == RUN_COMPLETED_CHECKPOINT
        ):
            continue
        recorded_id = _run_id_of(checkpoint)
        if recorded_id is None:
            older_ash = True
        elif recorded_id != run_id:
            another_run = True
        else:
            completed = True
    return InnerRunOutcome(
        completed=completed,
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
    # /src/out for an inner /out, and not as the start of a longer name such as
    # /out-dir, /out.bak or /out:/y, so only a separator, whitespace, a quote or
    # closing punctuation may follow it, or a period or a colon that ends a
    # sentence or a clause (followed by whitespace or the end), as a message
    # writes "cannot write /out." or "/out: denied". The host directory is
    # inserted as written, not read as a replacement template.
    pattern = (
        r"(?<![^\s'\"(])" + re.escape(inner_dir) + r"(?=[/\s'\"),;]|[.:](?:\s|$)|$)"
    )
    return re.sub(pattern, lambda _match: host_dir, message)
