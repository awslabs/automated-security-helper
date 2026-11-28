# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A compact record of each completed scan, kept beside its output for ``ash trend``.

Why this exists
---------------
A scan's output directory holds one run: the next scan clears it
(``core/previous_results.RESULT_ENTRIES``). Answering "which findings are new,
fixed and carried over the last N runs" needs the findings of N runs, and a CI
that does not archive each ``ash_aggregated_results.json`` has only the last.

With ``global_settings.history.enabled`` a completed scan appends one run record
to ``<output dir>/history/<report_id>.json``. ``history/`` is deliberately not
among ``RESULT_ENTRIES`` or ``WORKING_DIR_NAMES``, so a new scan appends to it and
never clears it, as the logs are never cleared by the scan-start sweep.

What a record is
----------------
Not a copy of the results file. That file carries masked-but-present snippets, raw
scanner payloads and the whole resolved configuration, and fifty of them are a
disk and privacy cost a trend never reads. A record holds one row per finding
with what ``utils.finding_diff.match_findings`` needs to pair it with the same
finding in the next run (its id, scanner, rule, severity, suppression state, place,
and the identity ingredients ``fallback_key`` reads), plus the run's metadata and
the coverage markers ``coverage_warnings`` compares. ``record_version`` is 1.

Which scans are recorded
------------------------
Only scans a comparison would accept (``finding_diff.check_comparable``): a
workspace aggregate, an un-merged shard, a ``--changed-files-only`` run and a
baseline-filtered run are left out, so a series never contains a point a trend
would have to refuse. A scan with no usable ``report_id`` is left out too: the
record is named by it, and the name is what orders the series and what pruning
reads. ``ash merge`` records the merged run the same way
(``cli/merge._record_merge_history``): its history configuration is the merge's
config of record (the shards' recorded configuration with ``--config-overrides``
applied), its owning output directory is the merge's own ``--output-dir``, and
the merged results are one run under their own ``report_id``, so a re-merge of
the same shards replaces its record. A sharded CI's history therefore comes
from the merge; a lone shard is still never recorded, which :func:`record_run`
says at warning.

Retention never deletes what is not ASH's to delete: a record git tracks, and
the record a write just made, are kept (:func:`prune_history`), and every
removal is logged.

Retention and tolerance
-----------------------
Pruning is by run count (``keep_runs``, default 50) at append time: the oldest
records, by the timestamp in their name, go. A count rather than an age because
age needs a clock and deletes without warning. Only files whose name is a run
record's are ever counted or removed; anything else in ``history/`` (a note, a
record a newer ASH wrote under another name) is left alone. A record that is
corrupt, from a newer ``record_version``, or not a run record at all is skipped
when the history is read, never an error.

Nothing here raises into a scan: recording is a convenience, and a failure to
record is a warning.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

from automated_security_helper.utils.finding_diff import (
    ComparabilityRefusal,
    _evaluated_scanners,
    check_comparable,
)
from automated_security_helper.utils.finding_identity import canonical
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability

#: The directory under the output directory that holds the run records.
HISTORY_DIR_NAME = "history"

#: Written into every record; a reader skips a record it does not know.
RECORD_VERSION = 1

#: How many run records are kept when the config does not say.
DEFAULT_KEEP_RUNS = 50

#: The name of a run record: the report id (``new_report_id``'s shape, a prefix, the
#: UTC start second, twelve hex digits) and ``.json``. Strict on purpose: the name
#: is used as a path component and is what pruning is allowed to delete.
_RECORD_NAME = re.compile(
    r"^(?P<id>(?P<prefix>[A-Za-z][A-Za-z0-9-]*)-(?P<stamp>\d{14})-(?P<token>[0-9a-f]{12}))\.json$"
)


#: A record larger than this is not read: a history of fifty is meant to be small.
_MAX_RECORD_BYTES = 64 * 1024 * 1024


class HistoryRefused(RuntimeError):
    """The history cannot be written or read here; the text says why."""


def record_file_name(report_id: str | None) -> str | None:
    """The file name a run with *report_id* is recorded under, or None.

    None for an id that is not ``new_report_id``'s shape, so that an id with a
    separator or a dot never becomes a path.
    """
    if not isinstance(report_id, str):
        return None
    name = f"{report_id}.json"
    return name if _RECORD_NAME.match(name) else None


def _is_link(path: str | os.PathLike[str]) -> bool:
    """Whether *path* is a link, a Windows junction included.

    ``Path.is_symlink()`` does not name a junction
    (``utils.scanned_tree._is_link_stat`` does), so a junction was taken for
    the directory it points at and written or pruned through. A path that
    cannot be looked up is not a link; what it is instead is the caller's next
    check to answer.
    """
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    try:
        return _is_link_stat(os.lstat(path))
    except OSError:
        return False


def _order_key(name: str) -> tuple[str, str, str]:
    """How record names sort: by start second, then token, then name."""
    match = _RECORD_NAME.match(name)
    if match is None:  # callers pass names _RECORD_NAME already accepted
        return ("", "", name)
    return (match["stamp"], match["token"], name)


def run_order_key(report_id: Any) -> tuple[str, str, str] | None:
    """How runs sort by *report_id*: (start second, token, name), or None.

    None for an id that is not ``new_report_id``'s shape: ordering such ids as
    raw strings sorts by prefix first and puts a hand-written id anywhere, so a
    caller with one keeps its given order instead. The key is the one the
    history is ordered by (:func:`record_names`), so ``ash trend`` over
    explicit files and over ``--history`` order the same runs the same way.
    """
    name = record_file_name(report_id)
    if name is None:
        return None
    return _order_key(name)


def _finding_row(finding: "FlatVulnerability") -> dict[str, Any]:
    base = finding.identity_base
    return {
        "id": finding.id,
        "scanner": finding.scanner,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "is_suppressed": finding.is_suppressed,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "has_identity": finding.identity is not None,
        "has_fingerprint_identity": finding.has_fingerprint_identity,
        "identity_base": canonical(base) if base is not None else None,
        "identity_message": finding.identity_message,
        "source_report": finding.source_report,
    }


def _coverage(results: "AshAggregatedResults") -> dict[str, Any]:
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )

    metadata = results.metadata
    exclusions = metadata.ignore_file_exclusions
    return {
        "expected_scanners": sorted(metadata.expected_scanners),
        "evaluated_scanners": sorted(_evaluated_scanners(results)),
        "ignore_file_exclusions": (
            exclusions.model_dump(mode="json") if exclusions is not None else None
        ),
        "incomplete": bool(scan_incompleteness(results, gate=True)),
        "scanner_results_recorded": bool(results.scanner_results),
        "inputs_not_scanned": bool(metadata.inputs_not_scanned),
    }


def run_record_body(results: "AshAggregatedResults") -> dict[str, Any]:
    """The run record's content for *results*, with no check that it is recordable.

    :func:`build_run_record` adds the checks the history needs (a usable ``report_id``,
    a comparable scan); ``ash trend`` over explicit files reads the same content from
    a results file without them.
    """
    metadata = results.metadata
    return {
        "record_version": RECORD_VERSION,
        "report_id": metadata.report_id,
        "generated_at": metadata.generated_at,
        "project_name": metadata.project_name,
        "workspace_project": getattr(metadata, "workspace_project", None),
        "tool_version": metadata.tool_version,
        "coverage": _coverage(results),
        "findings": [_finding_row(f) for f in results.to_flat_vulnerabilities()],
    }


def build_run_record(results: "AshAggregatedResults") -> dict[str, Any] | None:
    """The run record for *results*, or None when this scan is not recorded.

    See the module docstring for which scans are left out.
    """
    if record_file_name(results.metadata.report_id) is None:
        return None
    try:
        check_comparable(results)
    except ComparabilityRefusal:
        return None
    return run_record_body(results)


def history_dir(output_dir: str | os.PathLike[str]) -> Path:
    return Path(output_dir) / HISTORY_DIR_NAME


def _ensure_history_dir(output_dir: Path) -> Path:
    """``<output dir>/history``, made if missing, never through a link."""
    directory = history_dir(output_dir)
    if _is_link(directory):
        raise HistoryRefused(f"{directory} is a link")
    try:
        directory.mkdir(exist_ok=True)
    except FileExistsError:
        pass
    if _is_link(directory) or not directory.is_dir():
        raise HistoryRefused(f"{directory} is not a directory")
    return directory


def _record_names(directory: Path) -> list[str]:
    """Names in *directory* that are run records' (regular files, never links)."""
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if not _RECORD_NAME.match(entry.name):
                continue
            # lstat, not DirEntry.is_symlink(): a Windows junction is a link
            # here too (see _is_link). An entry that cannot be read is not a
            # record.
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if _is_link_stat(info) or not stat.S_ISREG(info.st_mode):
                continue
            names.append(entry.name)
    return sorted(names, key=_order_key)


def _tracked_record_names(directory: Path) -> set[str] | None:
    """The run-record names git tracks in *directory*; None when git gave no list.

    An empty set when *directory* is in no repository: nothing a prune could
    delete there is a committed file. None when it is in a repository whose
    index git could not list, and when git tracks the directory itself as a
    link or a submodule: nothing then tells a committed record from a
    disposable one, so the caller removes nothing, as the committed-output
    refusal fails closed (core/committed_output).
    """
    from automated_security_helper.utils.scan_output_dirs import git_index_below

    answer = git_index_below(directory)
    if answer.names is None:
        return None if answer.repository is not None else set()
    tracked: set[str] = set()
    for name in answer.names:
        if name == "":
            return None
        head = name.split("/", 1)[0]
        if _RECORD_NAME.match(head):
            tracked.add(head)
    return tracked


def prune_history(
    output_dir: str | os.PathLike[str],
    keep_runs: int = DEFAULT_KEEP_RUNS,
    *,
    keep_name: str | None = None,
) -> list[str]:
    """Remove all but the newest *keep_runs* run records; the names removed.

    Only files named as run records are counted or removed. A record that is
    corrupt still holds its place in the count: pruning reads names, not
    content. Three guards keep a prune from deleting what is not a disposable
    old record, because this is the one place ASH deletes files it did not
    write in this run:

    * *keep_name*, when given, is never removed however it sorts: the record
      the caller just wrote stays even when records under future-dated names
      would otherwise push it off the end at once.
    * A record git tracks is never removed. A user who commits ``history/`` to
      keep it across CI checkouts chose to keep those records, and everywhere
      else a run that would delete a tracked file refuses to start
      (core/committed_output); such records still hold their place in the
      count, and skipping them is said once at warning.
    * In a repository whose index git could not list, nothing tells a tracked
      record from a disposable one, so nothing is removed this time, at
      warning.

    Every removal is logged, so a shrinking history is in the scan's log.
    """
    if keep_runs < 1:
        raise ValueError("keep_runs must be at least 1")
    directory = history_dir(output_dir)
    if _is_link(directory) or not directory.is_dir():
        return []
    names = _record_names(directory)
    candidates = [
        name for name in names[: max(0, len(names) - keep_runs)] if name != keep_name
    ]
    if not candidates:
        return []
    tracked = _tracked_record_names(directory)
    if tracked is None:
        ASH_LOGGER.warning(
            f"Not pruning run records in {directory}: git could not list what it "
            f"tracks there, so a committed record cannot be told from a "
            f"disposable one."
        )
        return []
    committed = [name for name in candidates if name in tracked]
    if committed:
        ASH_LOGGER.warning(
            f"Keeping {len(committed)} run record(s) past keep_runs={keep_runs} "
            f"in {directory}: git tracks them, and a committed file is never "
            f"pruned."
        )
    removed = []
    for name in candidates:
        if name in tracked:
            continue
        try:
            (directory / name).unlink()
        except FileNotFoundError:
            continue
        removed.append(name)
    if removed:
        ASH_LOGGER.info(
            f"Pruned {len(removed)} run record(s) past keep_runs={keep_runs} "
            f"from {directory}: {', '.join(removed)}"
        )
    return removed


def write_run_record(
    results: "AshAggregatedResults",
    output_dir: str | os.PathLike[str],
    keep_runs: int = DEFAULT_KEEP_RUNS,
) -> Path | None:
    """Append *results*' run record to the history and prune; its path, or None.

    None when this scan is not recorded (:func:`build_run_record`). A second call
    for the same ``report_id`` replaces the record. Raises on a write failure; see
    :func:`record_run` for the form a scan calls.
    """
    from automated_security_helper.utils.atomic_write import write_text_atomically

    if keep_runs < 1:
        raise ValueError("keep_runs must be at least 1")
    record = build_run_record(results)
    if record is None:
        return None
    root = Path(output_dir)
    directory = _ensure_history_dir(root)
    path = directory / f"{record['report_id']}.json"
    # ensure_ascii keeps a lone surrogate in a path as an escape, which json.loads
    # turns back into the same text.
    text = json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    write_text_atomically(path, text + "\n", root=root)
    # Never the record this call just wrote: records under future-dated names
    # sort newer, so without this the newest real run was the first pruned.
    prune_history(root, keep_runs, keep_name=path.name)
    return path


def record_run(
    results: "AshAggregatedResults",
    output_dir: str | os.PathLike[str],
    keep_runs: int = DEFAULT_KEEP_RUNS,
) -> Path | None:
    """:func:`write_run_record` for a scan: a failure is logged, never raised."""
    from automated_security_helper.utils.error_text import own_error_text

    try:
        path = write_run_record(results, output_dir, keep_runs)
    except Exception as exc:  # noqa: BLE001 - recording must not fail a scan
        ASH_LOGGER.warning(
            f"Could not record this scan in the history: {own_error_text(exc)}"
        )
        return None
    if path is None:
        # Warning, not info: the operator turned the history on, and a CI whose
        # every run is a shard or filtered builds no history at all in silence.
        ASH_LOGGER.warning(
            "This run is not recorded in the history: it is a shard, a workspace "
            "aggregate, or filtered by --changed-files-only or --baseline. "
            "``ash merge`` records the merged run under the same rules, so a "
            "sharded CI's history comes from the merge; a filtered run is not "
            "recorded, merged or not."
        )
    return path


#: Every coverage key the trend indexes without a default
#: (``finding_trend.coverage_warnings_from_records`` and ``_boundary``). The
#: writer (:func:`_coverage`) emits them all, so a record this module wrote
#: always passes; one that lost a key is corrupt and is skipped.
_COVERAGE_KEYS = (
    "expected_scanners",
    "evaluated_scanners",
    "ignore_file_exclusions",
    "incomplete",
    "scanner_results_recorded",
    "inputs_not_scanned",
)


def _valid_coverage(coverage: Any) -> bool:
    if not isinstance(coverage, dict):
        return False
    if any(key not in coverage for key in _COVERAGE_KEYS):
        return False
    # The scanner lists are read into sets, so they must be lists of strings.
    return all(
        isinstance(coverage[key], list)
        and all(isinstance(name, str) for name in coverage[key])
        for key in ("expected_scanners", "evaluated_scanners")
    )


def _valid_row(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    row_id = row.get("id")
    # finding ids are collected into sets and sorted by the trend
    if row_id is not None and not isinstance(row_id, str):
        return False
    # The trend upper-cases the severity, groups by the scanner name and sorts
    # on the rule, file, id and line (finding_trend._severity, wire, the sorts;
    # cli/trend's text formatter), so a value of another type where one of these
    # belongs crashed ``ash trend`` instead of the record being skipped.
    if not all(
        value is None or isinstance(value, str)
        for value in (
            row.get("severity"),
            row.get("scanner"),
            row.get("rule_id"),
            row.get("file_path"),
            row.get("identity_message"),
            row.get("source_report"),
        )
    ):
        return False
    if not all(
        value is None or (isinstance(value, int) and not isinstance(value, bool))
        for value in (row.get("line_start"), row.get("line_end"))
    ):
        return False
    base = row.get("identity_base")
    if base is None:
        return True
    if not isinstance(base, str):
        return False
    try:
        json.loads(base)  # the trend parses it with no fallback
    except ValueError:
        return False
    return True


def _valid_record(data: Any) -> bool:
    """Whether *data* has the exact shape the trend consumes without guards.

    ``build_trend`` indexes the coverage keys and parses each row's
    ``identity_base`` with no fallback, so any shape this admits beyond what
    the consumer handles crashes ``ash trend`` instead of being skipped;
    keep it as strict as the consumer.
    """
    return (
        isinstance(data, dict)
        and data.get("record_version") == RECORD_VERSION
        and isinstance(data.get("report_id"), str)
        and isinstance(data.get("findings"), list)
        and all(_valid_row(row) for row in data["findings"])
        and _valid_coverage(data.get("coverage"))
    )


def read_run_record(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """The run record at *path*, or None for anything that is not one.

    None for a missing, unreadable, corrupt or oversized file, a link, a record
    from another ``record_version``, and a record whose ``report_id`` is not the
    name of the file it is in.
    """
    record_path = Path(path)
    match = _RECORD_NAME.match(record_path.name)
    if match is None or _is_link(record_path):
        return None
    try:
        if record_path.stat().st_size > _MAX_RECORD_BYTES:
            return None
        data = json.loads(record_path.read_text(encoding="utf-8"))
    # RecursionError too: json.loads raises it for nesting past the interpreter's
    # limit, and the module's promise is that a bad record is skipped, never an
    # error into ``ash trend``.
    except (OSError, ValueError, RecursionError):
        return None
    if not _valid_record(data) or data["report_id"] != match["id"]:
        return None
    return data


def read_history(output_dir: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Every readable run record in the history, oldest first.

    Skips what :func:`read_run_record` skips, and says how many it skipped at debug.
    """
    return read_history_counted(output_dir)[0]


def read_history_counted(
    output_dir: str | os.PathLike[str],
) -> tuple[list[dict[str, Any]], int]:
    """The readable run records, oldest first, and how many record names were seen.

    One pass over the directory, so the count of names and the records read
    from them cannot disagree (two passes raced a record written or removed
    between them, and the difference printed as a negative count).
    """
    directory = history_dir(output_dir)
    if _is_link(directory) or not directory.is_dir():
        return [], 0
    records: list[dict[str, Any]] = []
    names = _record_names(directory)
    for name in names:
        record = read_run_record(directory / name)
        if record is not None:
            records.append(record)
    skipped = len(names) - len(records)
    if skipped:
        ASH_LOGGER.debug(f"Skipped {skipped} unreadable run record(s) in {directory}")
    return records, len(names)


def history_enabled(history_config: Any) -> bool:
    """Whether a ``global_settings.history`` section asks for recording."""
    return getattr(history_config, "enabled", False) is True


def record_run_if_enabled(
    history_config: Any,
    results: "AshAggregatedResults",
    output_dir: str | os.PathLike[str],
) -> Path | None:
    """Record the run when the config section enables it; otherwise do nothing."""
    if not history_enabled(history_config):
        return None
    keep = getattr(history_config, "keep_runs", DEFAULT_KEEP_RUNS)
    if not isinstance(keep, int) or isinstance(keep, bool) or keep < 1:
        keep = DEFAULT_KEEP_RUNS
    return record_run(results, output_dir, keep)


def discard_run_record(output_dir: str | os.PathLike[str], report_id: Any) -> bool:
    """Remove the run record of *report_id*, if one is there; whether one went.

    For the paths that take a finished run's output back: a cancel that lands
    after the orchestrator recorded the run, and a workspace project abandoned
    after its scan returned. The record says the run completed, and leaving it
    made the taken-back run a point in ``ash trend``. Never raises (these paths
    run while a cancel or a failure is propagating), never follows a link (the
    history directory included), never removes a record git tracks, and an id
    that is not a record's name (:func:`record_file_name`) names nothing.
    """
    name = record_file_name(report_id)
    if name is None:
        return False
    directory = history_dir(output_dir)
    # The directory too, as prune_history reads it: _is_link below looks only at
    # the final component, so a linked history directory resolved and the
    # target's file was deleted.
    if _is_link(directory):
        return False
    path = directory / name
    if _is_link(path):
        return False
    # A committed record is never removed, as prune_history never removes one;
    # a repository whose index could not be listed tells nothing, so nothing goes.
    tracked = _tracked_record_names(directory)
    if tracked is None or name in tracked:
        return False
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        ASH_LOGGER.warning(
            f"Could not remove the taken-back run's record {path}: {exc}"
        )
        return False
    ASH_LOGGER.info(f"Removed the taken-back run's record {path}")
    return True


def record_names(output_dir: str | os.PathLike[str]) -> Iterable[str]:
    """The names of the run records in the history, oldest first."""
    directory = history_dir(output_dir)
    if _is_link(directory) or not directory.is_dir():
        return []
    return _record_names(directory)
