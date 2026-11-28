# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan that kept its results is settled even when describing its coverage raises.

What the code does, by path
---------------------------
When ``run_ash_scan`` ends with results in hand (a return, an exit 0, or
``ScanIncompleteExit``), the scan's thread works out how the entry will be closed
(``_close_for``: status, coverage payload, severity threshold) before it takes
the settle decision, and then drops the previous scan's results. ``_close_for`` is
documented never to raise, but it reads the exit's ``to_payload()`` and the
judged threshold without a guard of their own.

Before the guard, an error from either left the thread's settle step half done:
the mark was never set, the previous results were neither dropped nor put back,
and the error replaced the scan's own ending. The runner then took it for a
failure and closed a scan that had results on disk as failed.

Now ``_close_for`` catches the error and falls back to the status and no threshold,
once, for every caller. A
completed scan carries no coverage, and ``check_scan_progress`` assesses the
results file for the coverage the entry lacks. An incomplete one carries the gap
named by the exit's own fields, because the registry refuses to close a scan
as incomplete with no gap attached. The scan is settled as one with results and
the previous results are dropped.

That gap was once built from the exit's scanner rows alone. An exit raised only for
a stale content database, an unevaluated rule, a converter or a tool that could not
be stopped has no scanner row, so the gap was empty, the registry refused it, and the
error escaped the runner's task with the entry still running. The fallback now reads
every field of the exit, each field and each row on its own, carries every key of the
payload, stores a row it cannot read as ``unknown``, and falls back to one ``unknown``
incomplete scanner when nothing it read names a gap.

The judged severity threshold is read on its own, so a threshold that cannot be read
costs the close only the threshold: the entry keeps the coverage the close worked out,
a stale content database's full row included. And the history record of a scan taken
back is discarded under its own guard, so a discard that raises no longer keeps the
previous results set aside.

The same function is called a second time, from the runner's arms, for a scan whose
thread did not settle it as one with results: its cancel event was set before the
thread decided, so the thread put the previous results back and recorded no close.
Those calls were not guarded. A raise from the ``ScanIncompleteExit`` arm escaped the
task, which is a fire-and-forget task, and left the entry running; a raise from the
return arm was caught as a runner failure and closed a scan that had ended normally
as failed. ``_close_for`` is documented never to raise, so it now carries the guard
itself, and every caller is covered.

How the tests work
------------------
Each runs the real runner (``_run_scan_async``) over a stand-in scan. The drop and
the restore of the previous results are the real ones over an empty
previous-results area, recorded. Everything is DISARMED: the output directory is
the test's own tmp_path, and no scanner, network or real scan runs.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, List, Tuple
from unittest.mock import patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.previous_results import PreviousResults
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    assess_coverage,
    coverage_has_gap,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.content_databases import StalenessPolicy
from automated_security_helper.utils.content_db_staleness import ContentDbAgeRecord
from automated_security_helper.utils.scan_completeness import incomplete_scanner_reason

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
HOLD_SECONDS = 30.0
# The threshold the entry is registered with. ``finish_scan`` replaces it only with a
# judged threshold, so a close that carries none leaves this one in place; it is not
# the registry's default, so a close that wrote a threshold of its own shows.
REGISTERED_THRESHOLD = "LOW"
#: The threshold a planted judge returns: not the registered one, so a close that
#: kept the judged threshold shows.
JUDGED_THRESHOLD = "HIGH"

EXIT_REASONS = ras.ScanIncompleteness(
    scanners=(("bandit", "ERROR"),), observed=(("bandit", "ERROR"),)
)


async def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scan: Any,
    *,
    cancel_during_the_scan: bool = False,
) -> Tuple[Any, List[PreviousResults], List[PreviousResults]]:
    """Run ``scan`` as the scan through the real runner.

    With ``cancel_during_the_scan`` the entry's cancel event is set as the scan
    starts, so the thread does not settle the scan as one with results: it puts the
    previous results back and records no close, and the runner works the close out
    itself.

    Returns the registry entry, the ``PreviousResults`` whose drop ran and the ones
    whose restore ran.
    """
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    project = tmp_path / "project"
    output_dir = project / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(project),
        output_directory=str(output_dir),
        severity_threshold=REGISTERED_THRESHOLD,
    )
    entry = registry.get_scan(scan_id)
    assert entry is not None

    drops: List[PreviousResults] = []
    restores: List[PreviousResults] = []
    real_discard = PreviousResults.discard
    real_restore = PreviousResults.restore

    def a_drop_that_is_recorded(this: PreviousResults) -> None:
        drops.append(this)
        return real_discard(this)

    def a_restore_that_is_recorded(this: PreviousResults) -> None:
        restores.append(this)
        return real_restore(this)

    def the_scan_after_a_cancel(*args: Any, **kwargs: Any) -> Any:
        entry.cancel_event.set()
        return scan(*args, **kwargs)

    with (
        patch.object(
            ras,
            "run_ash_scan",
            the_scan_after_a_cancel if cancel_during_the_scan else scan,
        ),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch.object(PreviousResults, "discard", a_drop_that_is_recorded),
        patch.object(PreviousResults, "restore", a_restore_that_is_recorded),
    ):
        runner = asyncio.create_task(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(project),
                output_dir=str(output_dir),
                severity_threshold=None,
            )
        )
        await asyncio.wait([runner], timeout=HOLD_SECONDS)
        assert runner.done(), "control: the runner never ended"
        runner.result()
        assert await asyncio.to_thread(entry.runner_done.wait, HOLD_SECONDS), (
            "control: the scan's thread never settled"
        )
    return entry, drops, restores


def _a_planted_failure(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("a planted failure while describing the coverage")


def _assert_the_gap_is_the_exits_rows(coverage: Any) -> None:
    """The coverage names EXIT_REASONS' scanner, in the shape a client reads a gap in."""
    assert coverage is not None, "the entry carries no coverage"
    assert coverage_has_gap(coverage), coverage
    assert [row["scanner"] for row in coverage["incomplete_scanners"]] == ["bandit"], (
        coverage
    )


#: The keys every coverage payload carries.
PAYLOAD_KEYS = set(ras.ScanIncompleteness().to_payload())


def _a_stale_database() -> ContentDbAgeRecord:
    """A content database past its bound under ``content_db_staleness: fail``."""
    return ContentDbAgeRecord(
        name="grype-db",
        scanner="grype",
        built=datetime(2026, 1, 1, tzinfo=timezone.utc),
        measured_by="grype db status",
        max_age=timedelta(days=5),
        measured_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        policy=StalenessPolicy.FAIL,
        bound_source="the tool's default",
        bound_is_tool_default=True,
        refresh="grype db update",
    )


#: Exit reasons with one field set and no scanner row, each with the payload key that
#: field is reported under and what the fallback must name there
#: (``_what_the_rows_name``).
_ONE_REASON_AND_NO_SCANNER_ROW = {
    "only-unevaluated-rules": (
        ras.ScanIncompleteness(unevaluated_rules=("CKV_AWS_20",)),
        "unevaluated_rules",
        ["CKV_AWS_20"],
    ),
    "only-could-not-stop": (
        ras.ScanIncompleteness(
            could_not_stop=(("grype", "grype could not be stopped"),)
        ),
        "could_not_stop",
        ["grype"],
    ),
    "only-stale-content-databases": (
        ras.ScanIncompleteness(stale_content_databases=(_a_stale_database(),)),
        "stale_content_databases",
        [("grype-db", "grype")],
    ),
    "only-converters": (
        ras.ScanIncompleteness(
            converters=(ras.IncompleteConverter("archive", "crashed", ("zip",)),)
        ),
        "incomplete_converters",
        [("archive", "crashed", ["zip"])],
    ),
}


def _what_the_rows_name(key: str, rows: List[Any]) -> List[Any]:
    """The part of each row under ``key`` that says what is incomplete."""
    if key == "unevaluated_rules":
        return list(rows)
    if key == "could_not_stop":
        return [row["scanner"] for row in rows]
    if key == "stale_content_databases":
        return [(row["name"], row["scanner"]) for row in rows]
    if key == "incomplete_converters":
        return [
            (row["converter"], row["reason"], row["failed_input_kinds"]) for row in rows
        ]
    raise AssertionError(f"no projection for {key}")


#: Exit reasons with a scanner row and a stale content database. The payload's row for
#: the database is its record's ``to_dict()``; a gap built from the exit's fields alone
#: once cut it down to the record's name and scanner.
REASONS_WITH_A_STALE_DATABASE = ras.ScanIncompleteness(
    scanners=(("bandit", "ERROR"),),
    observed=(("bandit", "ERROR"),),
    stale_content_databases=(_a_stale_database(),),
)


def _an_assessed_gap() -> dict:
    """Assessed coverage that names a gap (checkov) the exit's own reasons do not."""
    return {
        **ras.ScanIncompleteness().to_payload(),
        "incomplete_scanners": [
            {
                "scanner": "checkov",
                "status": "MISSING",
                "reason": incomplete_scanner_reason("MISSING"),
                "detail": "MISSING",
            }
        ],
    }


class _ReasonsThatCannotBeRead:
    """An exit's reasons whose every field raises when it is read."""

    def __getattr__(self, name: str) -> Any:
        raise RuntimeError(f"a planted failure reading {name}")


class _AnExitWhoseReasonsCannotBeRead(Exception):
    """An exit whose ``incompleteness`` raises when it is read.

    The error is not an ``AttributeError``: ``getattr`` with a default answers that
    with the default, and the guard these cells pin is never reached.
    """

    @property
    def incompleteness(self) -> Any:
        raise RuntimeError("a planted failure reading the exit's reasons")


class _TextThatCannotBeShown:
    """An unevaluated rule whose text cannot be made: ``str()`` of it raises."""

    def __str__(self) -> str:
        raise RuntimeError("a planted failure making the text")


class _ARecordWhoseNameCannotBeRead:
    """A stale content database record whose ``name`` raises when it is read."""

    scanner = "trivy"

    @property
    def name(self) -> str:
        raise RuntimeError("a planted failure reading the name")


class _ARecordWhoseRowCannotBeMade:
    """A stale content database record whose ``to_dict()`` raises; its name and scanner
    can be read."""

    name = "trivy-db"
    scanner = "trivy"

    def to_dict(self) -> Any:
        raise RuntimeError("a planted failure making the row")


class _AnErrorWhoseMessageCannotBeShown(Exception):
    """An error whose own ``__str__`` raises, so a raw f-string of it raises too."""

    def __str__(self) -> str:
        raise RuntimeError("a planted failure making the message")


class _AnExitWhoseResultsCannotBeRead(ras.ScanIncompleteExit):
    """An exit for incomplete coverage whose ``results`` raises when it is read; each
    read is recorded in ``reads``."""

    def __init__(self, incompleteness: Any, reads: List[str]) -> None:
        self._reads = reads
        super().__init__(incompleteness, AshAggregatedResults())

    @property
    def results(self) -> Any:
        self._reads.append("results")
        raise RuntimeError("a planted failure reading the exit's results")

    @results.setter
    def results(self, value: Any) -> None:
        return None


#: Exit reasons with one row that cannot be read between rows that can, each with the
#: payload key the rows are reported under and what the fallback must name there. The
#: row costs only itself: it is stored as ``unknown`` (an observed status that is not a
#: pair is skipped, since it names no scanner), and every row around it reads as it
#: does alone. A stale content database is stored as its record's ``to_dict()``, as in
#: the payload, and as its name and scanner when that row cannot be made (a name that
#: cannot be read being ``unknown``).
_AN_UNREADABLE_ROW_AMONG_READABLE_ONES = {
    "unreadable-converter": (
        ras.ScanIncompleteness(
            converters=(
                ras.IncompleteConverter("archive", "crashed", ("zip",)),
                ("not a converter",),
                ras.IncompleteConverter("installer", "timed out", ()),
            )
        ),
        "incomplete_converters",
        [
            {
                "converter": "archive",
                "reason": "crashed",
                "failed_input_kinds": ["zip"],
            },
            {"converter": "unknown", "reason": "", "failed_input_kinds": []},
            {"converter": "installer", "reason": "timed out", "failed_input_kinds": []},
        ],
    ),
    "unreadable-could-not-stop-row": (
        ras.ScanIncompleteness(
            could_not_stop=(
                ("grype", "grype could not be stopped"),
                ("a", "three", "tuple"),
                ("trivy", "trivy could not be stopped"),
            )
        ),
        "could_not_stop",
        [
            {"scanner": "grype", "reason": "grype could not be stopped"},
            {"scanner": "unknown", "reason": ""},
            {"scanner": "trivy", "reason": "trivy could not be stopped"},
        ],
    ),
    "unreadable-unevaluated-rule": (
        ras.ScanIncompleteness(
            unevaluated_rules=("CKV_AWS_20", _TextThatCannotBeShown(), "CKV_AWS_21")
        ),
        "unevaluated_rules",
        ["CKV_AWS_20", "unknown", "CKV_AWS_21"],
    ),
    "unreadable-stale-database": (
        ras.ScanIncompleteness(
            stale_content_databases=(
                _a_stale_database(),
                _ARecordWhoseRowCannotBeMade(),
                _ARecordWhoseNameCannotBeRead(),
            )
        ),
        "stale_content_databases",
        [
            _a_stale_database().to_dict(),
            {"name": "trivy-db", "scanner": "trivy"},
            {"name": "unknown", "scanner": "trivy"},
        ],
    ),
    "unreadable-observed-status": (
        ras.ScanIncompleteness(
            scanners=(("bandit", "ERROR"),),
            observed=(("not a pair",), ("bandit", "ERROR")),
        ),
        "incomplete_scanners",
        [
            {
                "scanner": "bandit",
                "status": "ERROR",
                "reason": incomplete_scanner_reason("ERROR"),
                "detail": "ERROR",
            }
        ],
    ),
}

#: What the planted close of an incomplete scan fails with.
PLANTED_INCOMPLETE_CLOSE = "a planted failure of the incomplete close"


def _refuse_every_incomplete_close(
    monkeypatch: pytest.MonkeyPatch, closes: List[MCScanStatus]
) -> None:
    """Make every close of an entry as incomplete raise.

    A stand-in for a close that fails because of what it carries. A close with any
    other status reaches the real registry. Every close is recorded in ``closes`` by
    its status.
    """
    real_finish = ScanRegistry.finish_scan

    def a_close_that_fails_when_it_is_incomplete(
        self: ScanRegistry, scan_id: str, status: MCScanStatus, *args: Any, **kw: Any
    ) -> bool:
        closes.append(status)
        if status == MCScanStatus.INCOMPLETE:
            raise RuntimeError(PLANTED_INCOMPLETE_CLOSE)
        return real_finish(self, scan_id, status, *args, **kw)

    monkeypatch.setattr(
        ScanRegistry, "finish_scan", a_close_that_fails_when_it_is_incomplete
    )


@pytest.mark.asyncio
async def test_an_exit_for_incomplete_coverage_whose_payload_cannot_be_built(
    tmp_path, monkeypatch
):
    """``to_payload`` raises on the exit. The scan has results, so it is closed as
    incomplete (not as failed), with the gap named by the exit's own scanner rows:
    the registry refuses an incomplete scan that carries no gap. The previous
    results are dropped, not restored."""
    monkeypatch.setattr(ras.ScanIncompleteness, "to_payload", _a_planted_failure)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    _assert_the_gap_is_the_exits_rows(entry.coverage)
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_for_incomplete_coverage_whose_severity_threshold_cannot_be_judged(
    tmp_path, monkeypatch
):
    """The judged threshold raises for a scan that exited for incomplete coverage. The
    threshold is read on its own, so the scan is closed as incomplete with the exit's
    own payload and no judged threshold (the entry keeps the one it was registered
    with), and the previous results are dropped."""
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage == EXIT_REASONS.to_payload(), entry.coverage
    assert entry.severity_threshold == REGISTERED_THRESHOLD, entry.severity_threshold
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_whose_threshold_alone_cannot_be_judged_keeps_every_row_of_its_payload(
    tmp_path, monkeypatch
):
    """Only the judged threshold raises, for a scan that exited for incomplete coverage
    with a scanner row and a stale content database. The entry keeps the payload the
    close worked out, every row in full (the database's row is its record's
    ``to_dict()``), and the threshold it was registered with. Fails before the fix: the
    whole close fell back to a gap built from the exit's fields, and the database's row
    was cut down to its name and scanner."""
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(
            REASONS_WITH_A_STALE_DATABASE, AshAggregatedResults()
        )

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage == REASONS_WITH_A_STALE_DATABASE.to_payload(), entry.coverage
    assert entry.severity_threshold == REGISTERED_THRESHOLD, entry.severity_threshold
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_whose_threshold_alone_cannot_be_judged_keeps_its_assessed_coverage(
    tmp_path, monkeypatch
):
    """The coverage assessed from the results names a gap (checkov) the exit's own
    reasons do not, and only the judged threshold raises. The entry keeps the assessed
    coverage, which is what the close worked out. Fails before the fix: the fallback
    built the gap from the exit's fields, so it named bandit and dropped the assessed
    one."""
    assessed = _an_assessed_gap()
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)
    monkeypatch.setattr(
        "automated_security_helper.core.resource_management.scan_tracking.assess_coverage",
        lambda results: (True, assessed),
    )

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage == assessed, entry.coverage
    assert entry.severity_threshold == REGISTERED_THRESHOLD, entry.severity_threshold
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_whose_payload_alone_cannot_be_built_keeps_its_assessed_coverage(
    tmp_path, monkeypatch
):
    """The exit's ``to_payload`` raises; the coverage assessed from the results names a
    gap (checkov) and the judged threshold can be read. The payload is read on its own,
    so the entry keeps the assessed coverage and the judged threshold. Fails before the
    fix: the whole close fell back to the gap built from the exit's fields (bandit) with
    no threshold, so the entry kept the one it was registered with."""
    assessed = _an_assessed_gap()
    exit_results = AshAggregatedResults()
    payload_reads: List[Any] = []
    assessments: List[Any] = []
    judged: List[Any] = []

    def a_payload_that_cannot_be_built(this: Any) -> Any:
        payload_reads.append(this)
        raise RuntimeError("a planted failure while describing the coverage")

    def an_assessment_that_names_a_gap(results: Any) -> Any:
        assessments.append(results)
        return True, assessed

    def a_judge(results: Any) -> str:
        judged.append(results)
        return JUDGED_THRESHOLD

    monkeypatch.setattr(
        ras.ScanIncompleteness, "to_payload", a_payload_that_cannot_be_built
    )
    monkeypatch.setattr(
        "automated_security_helper.core.resource_management.scan_tracking.assess_coverage",
        an_assessment_that_names_a_gap,
    )
    monkeypatch.setattr(mcp_tools, "_judged_threshold", a_judge)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, exit_results)

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage == assessed, entry.coverage
    assert entry.severity_threshold == JUDGED_THRESHOLD, entry.severity_threshold
    assert payload_reads == [EXIT_REASONS], payload_reads
    assert len(assessments) == 1 and assessments[0] is exit_results, assessments
    assert len(judged) == 1 and judged[0] is exit_results, judged
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_whose_payload_cannot_be_built_keeps_its_judged_threshold(
    tmp_path, monkeypatch
):
    """The exit's ``to_payload`` raises and the coverage assessed from the results names
    no gap, so the gap is the one the exit's own fields name (bandit), and the judged
    threshold, which can be read, is kept. Fails before the fix on the threshold: the
    whole close fell back to that gap with no threshold, so the entry kept the one it
    was registered with."""
    no_gap = ras.ScanIncompleteness().to_payload()
    assert not coverage_has_gap(no_gap), "control: the assessed coverage names a gap"
    exit_results = AshAggregatedResults()
    named_by_the_exit = mcp_tools._gap_named_by_the_exit(
        ras.ScanIncompleteExit(EXIT_REASONS, exit_results)
    )
    payload_reads: List[Any] = []
    assessments: List[Any] = []
    judged: List[Any] = []

    def a_payload_that_cannot_be_built(this: Any) -> Any:
        payload_reads.append(this)
        raise RuntimeError("a planted failure while describing the coverage")

    def an_assessment_that_names_no_gap(results: Any) -> Any:
        assessments.append(results)
        return False, no_gap

    def a_judge(results: Any) -> str:
        judged.append(results)
        return JUDGED_THRESHOLD

    monkeypatch.setattr(
        ras.ScanIncompleteness, "to_payload", a_payload_that_cannot_be_built
    )
    monkeypatch.setattr(
        "automated_security_helper.core.resource_management.scan_tracking.assess_coverage",
        an_assessment_that_names_no_gap,
    )
    monkeypatch.setattr(mcp_tools, "_judged_threshold", a_judge)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, exit_results)

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage == named_by_the_exit, entry.coverage
    assert entry.severity_threshold == JUDGED_THRESHOLD, entry.severity_threshold
    assert payload_reads == [EXIT_REASONS], payload_reads
    assert len(assessments) == 1 and assessments[0] is exit_results, assessments
    assert len(judged) == 1 and judged[0] is exit_results, judged
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_whose_results_cannot_be_read_is_closed_through_the_fallback(
    tmp_path, monkeypatch
):
    """The exit's ``results`` raises when it is read. The assessment reads it under its
    own guard, and the read made to judge the threshold reaches the guard of
    ``_close_for``, which closes the scan as incomplete with the gap the exit's own
    fields name and no threshold, so the entry keeps the one it was registered with,
    and the previous results are dropped."""
    reads: List[str] = []

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise _AnExitWhoseResultsCannotBeRead(EXIT_REASONS, reads)

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    _assert_the_gap_is_the_exits_rows(entry.coverage)
    assert entry.severity_threshold == REGISTERED_THRESHOLD, entry.severity_threshold
    # Read twice: by the assessment, whose guard catches it, and for the threshold.
    assert reads == ["results", "results"], reads
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_a_return_whose_severity_threshold_cannot_be_judged(
    tmp_path, monkeypatch
):
    """The judged threshold raises for a scan that returned its results: the scan is
    closed as completed with the coverage assessed from its results and no judged
    threshold, so the entry keeps the one it was registered with, and the previous
    results are dropped. Fails before the fix on the coverage: the whole close fell
    back to the status alone."""
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)

    def a_scan_that_returns_its_results(*args: Any, **kwargs: Any) -> Any:
        return AshAggregatedResults()

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_returns_its_results
    )

    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert entry.coverage == assess_coverage(AshAggregatedResults())[1], entry.coverage
    assert entry.severity_threshold == REGISTERED_THRESHOLD, entry.severity_threshold
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_zero_whose_severity_threshold_cannot_be_judged(
    tmp_path, monkeypatch
):
    """The same for a scan that exits 0: it has results of its own, so it is
    completed and the previous results are dropped."""
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)

    def a_scan_that_exits_zero(*args: Any, **kwargs: Any) -> Any:
        raise SystemExit(0)

    entry, drops, restores = await _run(tmp_path, monkeypatch, a_scan_that_exits_zero)

    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_a_scan_with_nothing_to_describe_is_settled_as_before(
    tmp_path, monkeypatch
):
    """Control, no planted failure: the exit's own payload is recorded as the
    coverage and the previous results are dropped."""

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage == EXIT_REASONS.to_payload(), entry.coverage
    assert len(drops) == 1 and restores == [], (drops, restores)


@pytest.mark.asyncio
async def test_an_exit_for_incomplete_coverage_that_was_not_settled_still_closes_the_entry(
    tmp_path, monkeypatch
):
    """Fails on a ``_close_for`` that raises in the ``ScanIncompleteExit`` arm of
    the runner: that call is made for a scan whose thread recorded no close (its
    cancel event was set), nothing guarded it, and the error left the task with the
    entry still running. The entry is closed as incomplete with the gap named by the
    exit's own scanner rows (the registry refuses an incomplete scan that carries no
    gap, and a close with none made the runner's own ``finish_scan`` raise), the
    previous results are put back (not dropped), and the task ends normally."""
    monkeypatch.setattr(ras.ScanIncompleteness, "to_payload", _a_planted_failure)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_incomplete,
        cancel_during_the_scan=True,
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    _assert_the_gap_is_the_exits_rows(entry.coverage)
    assert drops == [] and len(restores) == 1, (drops, restores)


@pytest.mark.asyncio
async def test_a_return_that_was_not_settled_whose_threshold_cannot_be_judged(
    tmp_path, monkeypatch
):
    """The same call in the return arm: a scan that returned its results but whose
    thread recorded no close is closed as completed with no judged threshold, so the
    entry keeps the one it was registered with (as the settled return above). Fails
    on a ``_close_for`` that raises there: the error was taken for a runner failure
    and closed the scan as failed."""
    monkeypatch.setattr(mcp_tools, "_judged_threshold", _a_planted_failure)

    def a_scan_that_returns_its_results(*args: Any, **kwargs: Any) -> Any:
        return AshAggregatedResults()

    entry, drops, restores = await _run(
        tmp_path,
        monkeypatch,
        a_scan_that_returns_its_results,
        cancel_during_the_scan=True,
    )

    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert entry.severity_threshold == REGISTERED_THRESHOLD, entry.severity_threshold
    assert drops == [] and len(restores) == 1, (drops, restores)


@pytest.mark.asyncio
async def test_a_scan_that_was_not_settled_and_has_nothing_to_describe_is_closed_as_before(
    tmp_path, monkeypatch
):
    """Control, no planted failure: the exit's own payload is recorded as the
    coverage of a scan the thread did not settle, and the previous results are put
    back."""

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_incomplete,
        cancel_during_the_scan=True,
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert entry.coverage == EXIT_REASONS.to_payload(), entry.coverage
    assert drops == [] and len(restores) == 1, (drops, restores)


@pytest.mark.asyncio
async def test_a_history_discard_that_raises_still_puts_the_previous_results_back(
    tmp_path, monkeypatch
):
    """A scan whose thread did not keep its results (its cancel event was set) has its
    history record discarded and its previous results put back. The record's removal
    fails with an error whose message cannot be made. The history helper renders that
    message with ``error_text``, so it returns instead of raising, and the previous
    results are put back. Fails before the fix: the helper's own handler formatted the
    message with a plain f-string, which raised out of the helper; the guard at the call
    put the previous results back all the same."""
    from automated_security_helper.utils import scan_history

    removals: List[Tuple[Any, Any]] = []
    discards: List[str] = []
    real_discard_history_record = ras.discard_history_record

    def a_removal_that_fails(*args: Any, **kwargs: Any) -> bool:
        removals.append((args, kwargs))
        raise _AnErrorWhoseMessageCannotBeShown

    def a_discard_that_is_recorded(results: Any, output_dir: Path) -> None:
        discards.append("called")
        real_discard_history_record(results, output_dir)
        discards.append("returned")

    monkeypatch.setattr(scan_history, "discard_run_record", a_removal_that_fails)
    monkeypatch.setattr(ras, "discard_history_record", a_discard_that_is_recorded)

    def a_scan_that_returns_its_results(*args: Any, **kwargs: Any) -> Any:
        return AshAggregatedResults()

    entry, drops, restores = await _run(
        tmp_path,
        monkeypatch,
        a_scan_that_returns_its_results,
        cancel_during_the_scan=True,
    )

    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert len(removals) == 1, removals
    assert discards == ["called", "returned"], discards
    assert drops == [] and len(restores) == 1, (drops, restores)


@pytest.mark.asyncio
async def test_a_history_helper_that_raises_still_puts_the_previous_results_back(
    tmp_path, monkeypatch
):
    """The call that discards a taken-back scan's history record is guarded on its own,
    as a backstop for a helper that raises after all: the helper raises here, and the
    previous results are put back all the same. Fails without that guard: the raise
    skipped the restore, which shared the discard's ``try``, and the previous results
    stayed set aside."""
    discards: List[Tuple[Any, Any]] = []

    def a_discard_that_raises(results: Any, output_dir: Path) -> None:
        discards.append((results, output_dir))
        raise RuntimeError("a planted failure of the history discard")

    monkeypatch.setattr(ras, "discard_history_record", a_discard_that_raises)

    def a_scan_that_returns_its_results(*args: Any, **kwargs: Any) -> Any:
        return AshAggregatedResults()

    entry, drops, restores = await _run(
        tmp_path,
        monkeypatch,
        a_scan_that_returns_its_results,
        cancel_during_the_scan=True,
    )

    assert entry.status == MCScanStatus.COMPLETED, (entry.status, entry.error_message)
    assert len(discards) == 1, discards
    results, output_dir = discards[0]
    assert isinstance(results, AshAggregatedResults), discards
    assert output_dir == tmp_path / "project" / ".ash" / "ash_output", discards
    assert drops == [] and len(restores) == 1, (drops, restores)


@pytest.mark.asyncio
async def test_an_incomplete_close_that_raises_for_a_scan_that_kept_no_results_fails_the_entry(
    tmp_path, monkeypatch
):
    """The scan exits for incomplete coverage after its cancel event was set, so its
    thread kept no results and recorded no close, and the runner's close of the entry
    as incomplete raises. The failure arm finds no mark, so it closes the entry as
    failed with the error, the previous results are put back, and the task ends
    normally. Before, the error left the ``ScanIncompleteExit`` arm, which no sibling
    arm catches, so it escaped the task with the entry still running."""
    closes: List[MCScanStatus] = []
    _refuse_every_incomplete_close(monkeypatch, closes)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path,
        monkeypatch,
        a_scan_that_exits_incomplete,
        cancel_during_the_scan=True,
    )

    # The close as incomplete, which raised, then the close as failed.
    assert closes == [MCScanStatus.INCOMPLETE, MCScanStatus.FAILED], closes
    assert entry.status == MCScanStatus.FAILED, (entry.status, entry.error_message)
    assert PLANTED_INCOMPLETE_CLOSE in (entry.error_message or ""), entry.error_message
    assert drops == [] and len(restores) == 1, (drops, restores)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(_ONE_REASON_AND_NO_SCANNER_ROW))
async def test_an_exit_with_no_scanner_row_whose_payload_cannot_be_built_is_closed_incomplete(
    tmp_path, monkeypatch, case
):
    """The exit's one reason is not a scanner row, and ``to_payload`` raises, so
    working out the close fails and the fallback builds the gap. Built from the
    scanner rows alone, that gap was empty: the registry refused to close the scan as
    incomplete, the error escaped the runner's task, and the entry stayed RUNNING. The
    gap now names the exit's reason under the key the payload names it under, it
    carries every key of the payload, and the previous results are dropped."""
    reasons, key, named = _ONE_REASON_AND_NO_SCANNER_ROW[case]
    assert reasons and not reasons.scanners, "control: the exit has a scanner row"
    monkeypatch.setattr(ras.ScanIncompleteness, "to_payload", _a_planted_failure)

    def a_scan_that_exits_incomplete(*args: Any, **kwargs: Any) -> Any:
        raise ras.ScanIncompleteExit(reasons, AshAggregatedResults())

    entry, drops, restores = await _run(
        tmp_path, monkeypatch, a_scan_that_exits_incomplete
    )

    assert entry.status == MCScanStatus.INCOMPLETE, (entry.status, entry.error_message)
    assert coverage_has_gap(entry.coverage), entry.coverage
    assert set(entry.coverage) == PAYLOAD_KEYS, entry.coverage
    assert _what_the_rows_name(key, entry.coverage[key]) == named, entry.coverage
    assert len(drops) == 1 and restores == [], (drops, restores)


def test_an_unreadable_scanner_row_is_stored_as_unknown_and_keeps_the_rows_around_it():
    """One scanner row cannot be read (it is not a (name, detail) pair). It is stored
    as ``unknown`` and every other row is kept, with its status and its reason token,
    the partial-coverage one included. Before, one try held the whole loop, so that
    row and every row after it were dropped."""
    reasons = ras.ScanIncompleteness(
        scanners=(("bandit", "ERROR"), ("not a pair",), ("grype", "MISSING")),
        observed=(("bandit", "ERROR"), ("grype", "MISSING")),
        partial_coverage=("grype",),
    )

    gap = mcp_tools._gap_named_by_the_exit(
        ras.ScanIncompleteExit(reasons, AshAggregatedResults())
    )

    rows = gap["incomplete_scanners"]
    assert [row["scanner"] for row in rows] == ["bandit", "unknown", "grype"], gap
    bandit, unreadable, grype = rows
    assert bandit == {
        "scanner": "bandit",
        "status": "ERROR",
        "reason": incomplete_scanner_reason("ERROR"),
        "detail": "ERROR",
    }, bandit
    assert unreadable == {
        "scanner": "unknown",
        "status": "",
        "reason": incomplete_scanner_reason(""),
        "detail": "",
    }, unreadable
    assert (grype["status"], grype["reason"]) == (
        "MISSING",
        incomplete_scanner_reason("MISSING", partial=True),
    ), grype


@pytest.mark.parametrize("case", sorted(_AN_UNREADABLE_ROW_AMONG_READABLE_ONES))
def test_an_unreadable_row_in_each_other_list_keeps_the_rows_around_it(case):
    """Each other list the fallback reads holds one row it cannot read between rows it
    can: an incomplete converter that is not a row, a tool that could not be stopped
    given as three words, an unevaluated rule whose text cannot be made, a stale
    content database record whose row cannot be made or whose name cannot be read, and
    an observed status that is not a (scanner, status) pair. A stale database is stored
    as its record's ``to_dict()``, as in the payload, and as its name and scanner when
    that row cannot be made (a name that cannot be read being ``unknown``). The row
    costs only itself: it is stored as
    ``unknown`` (the status that is not a pair is skipped, and the scanner after it
    still gets its status), and every row around it is kept, in order. Before, the
    fallback read the scanner rows only, all inside one ``try``, so one row it could
    not read dropped itself and every row after it."""
    reasons, key, named = _AN_UNREADABLE_ROW_AMONG_READABLE_ONES[case]

    gap = mcp_tools._gap_named_by_the_exit(
        ras.ScanIncompleteExit(reasons, AshAggregatedResults())
    )

    assert gap[key] == named, gap
    assert set(gap) == PAYLOAD_KEYS, gap
    assert coverage_has_gap(gap), gap


def test_a_reason_lookup_that_raises_costs_the_row_only_its_token(monkeypatch):
    """The lookup of a scanner's reason token raises. The row is kept, as it was read,
    with the token the lookup gives a status it does not know
    (``unrecognized_status``), written out in the fallback: a lookup that fails must
    not cost the row or make the fallback raise, which the close of a scan that kept
    its results relies on never happening. The fallback imports the lookup where it
    calls it, so the attribute patched here is the module's; this file's own name for
    it is untouched."""
    monkeypatch.setattr(
        "automated_security_helper.utils.scan_completeness.incomplete_scanner_reason",
        _a_planted_failure,
    )

    gap = mcp_tools._gap_named_by_the_exit(
        ras.ScanIncompleteExit(EXIT_REASONS, AshAggregatedResults())
    )

    assert gap["incomplete_scanners"] == [
        {
            "scanner": "bandit",
            "status": "ERROR",
            "reason": "unrecognized_status",
            "detail": "ERROR",
        }
    ], gap


@pytest.mark.parametrize(
    "case",
    ["scanner-rows", "no-reasons-attribute", *sorted(_ONE_REASON_AND_NO_SCANNER_ROW)],
)
def test_the_fallback_gap_carries_every_key_of_the_payload(case):
    """A progress response spreads the stored coverage into the reply, so a key the
    fallback leaves out is a KeyError for a client reading it from this one scan. The
    fallback carries every key ``to_payload()`` emits, and a gap, whatever it read."""
    if case == "scanner-rows":
        ended: BaseException = ras.ScanIncompleteExit(
            EXIT_REASONS, AshAggregatedResults()
        )
    elif case == "no-reasons-attribute":
        ended = SystemExit(1)
    else:
        ended = ras.ScanIncompleteExit(
            _ONE_REASON_AND_NO_SCANNER_ROW[case][0], AshAggregatedResults()
        )

    gap = mcp_tools._gap_named_by_the_exit(ended)

    assert set(gap) == PAYLOAD_KEYS, gap
    assert coverage_has_gap(gap), gap


@pytest.mark.parametrize(
    "case",
    [
        "no-reasons-attribute",
        "reasons-attribute-raises",
        "every-field-raises",
        "every-field-empty",
    ],
)
def test_an_exit_that_names_nothing_readable_names_one_unknown_scanner(case):
    """Nothing the exit carries can be read, or none of it names a gap. The exit is
    raised only when a field of it is set, so the scan has a gap all the same: the
    fallback names one incomplete scanner ``unknown``, which the registry accepts, and
    every other list is empty. The row's reason is the token the lookup gives a status
    it does not know. It never raises, where before a reason object whose fields raise
    made the read of ``no_scanner_ran`` raise out of it, and so did an exit whose
    ``incompleteness`` raises when it is read."""
    if case == "no-reasons-attribute":
        ended: BaseException = SystemExit(1)
    elif case == "reasons-attribute-raises":
        ended = _AnExitWhoseReasonsCannotBeRead()
    elif case == "every-field-raises":
        ended = ras.ScanIncompleteExit(
            _ReasonsThatCannotBeRead(), AshAggregatedResults()
        )
    else:
        ended = ras.ScanIncompleteExit(ras.ScanIncompleteness(), AshAggregatedResults())

    gap = mcp_tools._gap_named_by_the_exit(ended)

    assert coverage_has_gap(gap), gap
    assert set(gap) == PAYLOAD_KEYS, gap
    assert gap["incomplete_scanners"] == [
        {
            "scanner": "unknown",
            "status": "",
            "reason": incomplete_scanner_reason(""),
            "detail": "",
        }
    ], gap
    assert gap["no_scanner_ran"] is False, gap
    for key in PAYLOAD_KEYS - {"incomplete_scanners", "no_scanner_ran"}:
        assert gap[key] == [], (key, gap)
