# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One real ASH scan, driven end to end over the MCP protocol.

WHY THIS EXISTS
---------------
The scan flow is the thing ASH's MCP server is for, and it is the part of the
server that no unit test can reach. Every unit module in tests/unit/cli/ that
touches results does it by patching ``mcp_get_scan_results`` and handing the tool a
dict the test wrote. That is the right shape for a unit test, and it is why a real
one was needed: the dicts those tests hand in do not match what a real scan
produces, and a documented behavior depends on the difference -- see the xfail at
the bottom of this module.

The deleted test_mcp_integration.py had a ``TestMcpScanWorkflow`` class for this
area. It mocked the scan. This module does not.

WHAT "END TO END" MEANS HERE
----------------------------
A real secret is planted in a real directory. ``run_ash_scan`` is called over the
protocol, which starts a real ASH local-mode scan in a worker thread of this
process. ``get_scan_progress`` is polled the way the tool's own docstring tells
clients to poll it. When it reports completion the findings are read back with
``get_scan_results``, the report inventory with ``get_scan_result_paths``, and the
files named in that inventory are opened off disk. Nothing in that chain is
doubled.

Measured cost on a 192-core host: 13 seconds. The whole module runs on one scan,
because every test asserts a different property of the same completed run. Splitting
them into independent tests would mean a scan each for no extra coverage.

WHY THE SCAN FIXTURE IS SYNCHRONOUS
-----------------------------------
``completed_scan`` drives the protocol inside a single ``asyncio.run`` and returns plain
data, so the tests that read it are ordinary synchronous functions. Two problems
disappear as a result. An ``async def`` module-scoped fixture would have to agree with
pytest-asyncio's loop scoping to be visible to function-scoped tests, and an
``async with`` split across a fixture's ``yield`` puts the client's enter and exit in
different asyncio tasks, which anyio's cancel scope refuses outright -- measured as
every test passing and every one of them erroring in teardown. Recording observations
and asserting them afterwards also means a test reads what the server said at the time
rather than re-querying a server that has since moved on.

The one async test in this module,
``test_completion_is_reported_from_the_aggregated_file_alone``, does not use that
fixture: it needs no scan, so it opens its own client the ordinary way.

WHY THE MODULE ASSERTS THAT SCANNERS RAN
----------------------------------------
A scanner that is not installed reports ``MISSING`` and contributes zero findings,
and a scan in which every scanner is MISSING or SKIPPED completes successfully and
reports a clean tree. That is the worst possible false negative for a security
scanner and it is indistinguishable from a genuinely clean repository unless
something checks.
``test_the_scan_examined_something_rather_than_skipping_every_scanner`` is that
check, and it is what makes the findings assertions mean anything.

WHY THE SEVERITY THRESHOLD IS NOT ASSERTED
------------------------------------------
``run_ash_scan`` takes ``severity_threshold`` and its schema documents it as
"Minimum severity threshold". Traced through the implementation, the value is
validated, stored on the registry entry and echoed back in progress responses, and
never reaches the scan: ``_run_scan_async`` in cli/mcp_tools.py calls the underlying
``run_ash_scan`` without it, and no results path filters on it. A test asserting
that a threshold changes the findings would fail; a test asserting that it does not
would pin a documented argument's ineffectiveness as intended behavior. Neither is
right, so the parameter is left at its default and only the echo is checked.
Reported separately.

ISOLATION
---------
The scan target is a per-module temporary directory and ASH writes its output tree
inside that target, so two xdist workers never share a path. ``ASH_MCP_ALLOWED_ROOTS``
is set for the duration of the scan and restored afterwards; that bounds this scan
and doubles as the accept-path control for the root policy whose refusal path is
tested in test_mcp_protocol_integration.py. Registry assertions are membership tests
on this scan's own id, never totals, because the registry is a process-global
singleton shared with every other test in the same xdist worker.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

# The AWS documentation's example secret key. detect-secrets flags it, which is what
# makes the findings assertions below real, and it is published as an example so
# committing it leaks nothing.
AWS_EXAMPLE_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # nosec B105 — test fixture with dummy AWS key

# How long to wait for a real local-mode scan of a one-file tree. The scan itself
# measured 13 seconds; the ceiling is deliberately far above that because the suite
# runs 192-wide and a scan competing for CPU with 191 siblings is slow, not broken.
# A timeout tight enough to catch a hang is a timeout that fires under load.
SCAN_TIMEOUT_SECONDS = 600

# run_ash_scan's docstring tells clients to poll every five seconds. This is shorter
# so the test does not spend most of its runtime asleep; the interval is a client
# choice, not a server contract.
POLL_INTERVAL_SECONDS = 0.5


# The reports the module goes on to open. Named here rather than inline so the wait and
# the assertions cannot drift apart.
REQUIRED_REPORTS = ("ash.sarif", "ash.flat.json")


async def _await_report_files(output_dir: Path) -> None:
    """Wait until the reports this module reads have been written, or fail.

    See the call site for why this is needed. Bounded by the same ceiling as the scan
    itself: reports take milliseconds, so anything approaching the ceiling means the
    REPORT phase did not run rather than that it was slow.
    """
    reports = output_dir / "reports"
    loop = asyncio.get_running_loop()
    deadline = loop.time() + SCAN_TIMEOUT_SECONDS
    while True:
        missing = [name for name in REQUIRED_REPORTS if not (reports / name).is_file()]
        if not missing:
            return
        if loop.time() > deadline:
            pytest.fail(
                f"The scan reported completion but never wrote {missing} into "
                f"{reports}. Completion is decided by ash_aggregated_results.json, so "
                "a REPORT phase that failed outright looks like a completed scan."
            )
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


async def _drive_one_scan(source: Path) -> Dict[str, Any]:
    """Run one scan over a real client and return everything it produced."""
    from mcp import Client

    from automated_security_helper.cli.mcp_server import mcp

    progress_events: List[Tuple[float, Optional[float], Optional[str]]] = []

    async def record_progress(progress, total, message):
        progress_events.append((progress, total, message))

    async with Client(mcp, raise_exceptions=True) as client:
        started = await client.call_tool(
            "run_ash_scan",
            {"source_dir": str(source)},
            progress_callback=record_progress,
        )
        start_payload = started.structured_content["result"]
        if not start_payload.get("success"):
            pytest.fail(
                "The scan never started, so no assertion in this module would be "
                f"measuring a scan: {start_payload}"
            )
        scan_id = start_payload["scan_id"]

        loop = asyncio.get_running_loop()
        deadline = loop.time() + SCAN_TIMEOUT_SECONDS
        polls = 0
        while True:
            response = await client.call_tool("get_scan_progress", {"scan_id": scan_id})
            progress = response.structured_content["result"]
            polls += 1
            if progress.get("is_complete") or progress.get("status") in (
                "completed",
                "failed",
                "cancelled",
            ):
                break
            if loop.time() > deadline:
                pytest.fail(
                    f"Scan {scan_id} did not reach a terminal state within "
                    f"{SCAN_TIMEOUT_SECONDS}s after {polls} polls. Last progress: "
                    f"{progress}"
                )
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

        output_dir = progress["output_directory"]

        # is_complete does NOT mean the report files are on disk, and this wait is here
        # because that bit me. check_scan_progress decides completion by testing for
        # ash_aggregated_results.json, which the REPORT phase writes before it writes
        # any report, so the documented poll-then-read loop can reach the read while
        # the reporters are still running. Measured: get_scan_result_paths reported
        # ash.sarif as `exists: False` on a scan whose own log shows it written 40ms
        # later. The scan passed in isolation and failed when a sibling module shifted
        # the timing by a few hundred milliseconds, which is the shape of a test that
        # would have been rerun until green.
        #
        # test_completion_is_reported_from_the_aggregated_file_alone pins the mechanism
        # without depending on timing. This loop is the harness working around it, not
        # the test asserting it -- if the files never arrive it fails rather than
        # waiting forever.
        await _await_report_files(Path(output_dir))

        # Re-read progress once the tree has settled, and use *that* as the progress the
        # tests assert against. The first response that said is_complete was produced
        # while the REPORT phase was still running, and create_scan_progress_from_files
        # builds its per-scanner section by reading the aggregated results file -- which
        # at that moment may be half-written. Under 192 xdist workers the poll landed
        # there and the per-scanner section came back empty, failing a test that had
        # passed every single-worker run. Re-reading after the reports exist is also what
        # a client would do, so this is the observation worth pinning.
        settled = await client.call_tool("get_scan_progress", {"scan_id": scan_id})
        progress = settled.structured_content["result"]

        results = await client.call_tool(
            "get_scan_results", {"output_dir": output_dir, "filter_level": "full"}
        )
        summary_filtered = await client.call_tool(
            "get_scan_results", {"output_dir": output_dir, "filter_level": "summary"}
        )
        paths = await client.call_tool(
            "get_scan_result_paths", {"output_dir": output_dir}
        )
        active = await client.call_tool("list_active_scans", {})
        cancel = await client.call_tool("cancel_scan", {"scan_id": scan_id})

    return {
        "scan_id": scan_id,
        "source": source,
        "output_dir": Path(output_dir),
        "start": start_payload,
        "progress": progress,
        "progress_events": progress_events,
        "polls": polls,
        "results": results.structured_content["result"],
        "summary_filtered": summary_filtered.structured_content["result"],
        "paths": paths.structured_content["result"],
        "active": active.structured_content["result"],
        "cancel": cancel.structured_content["result"],
    }


@pytest.fixture(scope="module")
def completed_scan(tmp_path_factory: pytest.TempPathFactory) -> Dict[str, Any]:
    """Plant a secret, run one real scan through the protocol, return the record."""
    root = tmp_path_factory.mktemp("mcp_scan")
    source = root / "source"
    source.mkdir()
    (source / "credentials.py").write_text(
        "# Deliberate finding: the AWS documentation's example secret key.\n"
        f'AWS_SECRET_ACCESS_KEY = "{AWS_EXAMPLE_SECRET_KEY}"\n'
    )

    # Bounds this module's scan to its own temporary tree, and makes the scan the
    # accept-path control for the root policy: if the policy started refusing
    # everything, run_ash_scan would return a refusal and _drive_one_scan would fail
    # loudly rather than every test here silently measuring nothing.
    previous = os.environ.get("ASH_MCP_ALLOWED_ROOTS")
    os.environ["ASH_MCP_ALLOWED_ROOTS"] = str(root)
    try:
        return asyncio.run(_drive_one_scan(source))
    finally:
        if previous is None:
            os.environ.pop("ASH_MCP_ALLOWED_ROOTS", None)
        else:
            os.environ["ASH_MCP_ALLOWED_ROOTS"] = previous


def test_the_scan_reaches_completion_and_reports_where_it_wrote(
    completed_scan: Dict[str, Any],
) -> None:
    """The poll loop the tool documents converges, and names the output tree.

    ``run_ash_scan`` returns before the scan finishes and tells clients to poll
    ``get_scan_progress`` until ``is_complete``; a client has no other way to learn
    the scan is done. So the contract under test is that polling terminates with
    ``completed`` and hands back an ``output_directory`` that exists -- everything
    else in this module reads that directory.

    ``status`` is asserted to be ``completed`` rather than merely terminal. A scan
    that reached ``failed`` would also end the loop, and treating that as done is how
    a broken scan gets read as a clean one.
    """
    progress = completed_scan["progress"]

    assert progress["status"] == "completed", (
        f"Scan finished in state {progress['status']!r}: "
        f"{progress.get('error_message')}"
    )
    assert progress["is_complete"] is True
    assert progress["scan_id"] == completed_scan["scan_id"]
    assert completed_scan["output_dir"].is_dir(), (
        "get_scan_progress named an output directory that does not exist: "
        f"{completed_scan['output_dir']}"
    )
    assert completed_scan["polls"] >= 1


def test_the_scan_examined_something_rather_than_skipping_every_scanner(
    completed_scan: Dict[str, Any],
) -> None:
    """Not every scanner was SKIPPED or MISSING, and detect-secrets was one that ran.

    This is the control the rest of the module depends on. A scan where every scanner
    is MISSING because nothing is installed completes, reports zero findings, and is
    indistinguishable from a scan of a clean repository. Without this assertion a
    suite could go green against an image with no scanners in it while reporting that
    the scan flow works.

    detect-secrets is named specifically because it is the scanner that finds the
    planted key. If it were absent the findings assertions below would be measuring
    some other scanner's opinion of a two-line Python file.

    WHERE THE OUTCOME LIVES, AND WHERE IT DOES NOT
    ----------------------------------------------
    Read from ``raw_results.scanner_results``, which is where the scan phase records
    what each scanner actually did. That is still the authoritative source, but the
    reason has changed, and so has the second half of this test.

    It used to be that ``get_scan_progress`` could not answer the question at all.
    ``mcp_server.get_scan_progress`` opened with ``if not
    progress_info.get("success")``, which no producer ever satisfied, so it returned
    before reaching either the per-scanner file walk or
    ``summarize_scanner_statuses``. What a client got was the registry's own map, and
    that map hardcoded ``MCScannerStatus.COMPLETED`` for every entry in
    ``scanner_results`` -- so a scan where nothing was installed reported every
    scanner ``"completed"`` and read exactly like a clean repository. A control
    written against progress would have passed on it, which is the failure this test
    exists to catch, and the assertion here pinned the two vocabularies as disjoint
    to keep a client from reading one as the other.

    Both halves of that are now fixed: the guard discriminates on an explicit
    ``success: False`` rather than on the key's absence, and the registry maps the
    recorded status instead of asserting COMPLETED. So progress does carry real
    outcomes, and the assertions below pin that rather than its absence -- per the
    instruction the old assertion's own message gave.

    One caveat kept from the old note, because it is why this test still reads the
    results. The ``scanners`` section is built by globbing
    ``scanners/*/*/ASH.ScanResults.json``, and each leaf is that file verbatim. Those
    files are a scanner's own report of its run, and they can disagree with the
    aggregated view that applied the severity threshold: on the scan this module
    drives, detect-secrets finds the planted key and the aggregated results call it
    FAILED while its own result file still says PASSED. ``scanner_statuses`` is read
    from ``scanner_results`` and does not have that problem, which is why it, and not
    the globbed map, is what the tool documents for telling "never ran" from "ran
    clean".
    """
    scanner_results = completed_scan["results"]["raw_results"]["scanner_results"]
    assert scanner_results, "The scan reported no scanner results at all"

    statuses = {
        name: str(info.get("status", "")).upper()
        for name, info in scanner_results.items()
    }
    ran = {
        name
        for name, status in statuses.items()
        if status not in ("SKIPPED", "MISSING", "")
    }
    assert ran, (
        "Every scanner reported SKIPPED or MISSING, so this scan examined nothing and "
        f"its clean result means nothing: {statuses}"
    )
    assert "detect-secrets" in ran, (
        "detect-secrets did not run, so the planted secret proves nothing about this "
        f"scan: {statuses}"
    )

    progress = completed_scan["progress"]
    progress_statuses = {
        str(leaf.get("status", "")).upper()
        for targets in progress["scanners"].values()
        for leaf in targets.values()
    }
    assert progress_statuses, "get_scan_progress reported no per-scanner entries"
    assert progress_statuses & {"PASSED", "FAILED", "SKIPPED", "MISSING"}, (
        "get_scan_progress reported no scanner outcome in the results vocabulary "
        f"({sorted(progress_statuses)}). The whole map coming back as 'completed' is "
        "the signature of the guard short-circuiting before the file walk, which is "
        "what made a scan with nothing installed read as a clean one."
    )

    # The counts have to disagree whenever a scanner did not pass, or the progress
    # view is back to grading every scanner COMPLETED. Asserted as a relationship and
    # not as numbers: which scanners are installed varies by environment, and this
    # test must not start depending on that.
    did_not_pass = {name for name, status in statuses.items() if status != "PASSED"}
    if did_not_pass:
        assert progress["completed_scanners"] < progress["total_scanners"], (
            f"{sorted(did_not_pass)} did not pass, yet progress reports "
            f"{progress['completed_scanners']} of {progress['total_scanners']} "
            "scanners completed"
        )

    # The list a client needs to tell "never ran" from "ran and found nothing". It
    # reached no client at all while the guard short-circuited, and it is derived
    # from scanner_results, so the set equality is exact rather than approximate.
    expected_skipped = {
        name for name, status in statuses.items() if status in ("SKIPPED", "MISSING")
    }
    reported_skipped = {entry["scanner"] for entry in progress["skipped_scanners"]}
    assert reported_skipped == expected_skipped, (
        f"skipped_scanners reported {sorted(reported_skipped)} but the results call "
        f"{sorted(expected_skipped)} SKIPPED or MISSING"
    )


def test_the_planted_secret_comes_back_as_an_actionable_finding(
    completed_scan: Dict[str, Any],
) -> None:
    """A real secret in a real file produces real findings through the protocol.

    Counts are lower bounds, not equalities. The scan runs ASH's default local-mode
    scanner set, so adding a scanner to ASH can legitimately raise the total and
    pinning an exact number would make this fail on an unrelated change. What cannot
    legitimately change is that a hardcoded AWS secret key yields at least one
    critical, actionable finding.
    """
    stats = completed_scan["results"]["summary_stats"]

    assert stats["total"] >= 1, (
        f"A file containing a hardcoded AWS secret key produced no findings: {stats}"
    )
    assert stats["actionable"] >= 1, (
        f"Every finding was suppressed, so nothing is actionable: {stats}"
    )
    assert stats["severity_counts"]["critical"] >= 1, (
        f"A hardcoded secret was not reported as critical: {stats['severity_counts']}"
    )


def test_the_report_inventory_names_files_that_exist_and_parse(
    completed_scan: Dict[str, Any],
) -> None:
    """``get_scan_result_paths`` is an inventory a client reads files from.

    The tool's whole purpose is to let a client decide which report to open, so a path
    it reports as existing has to be openable and a report it reports a size for has to
    have content. Three of the ten report types are checked by opening them: SARIF and
    the flat JSON because they are the machine-readable ones agents consume, and the
    aggregated results file because every other MCP results tool reads it.

    The SARIF is parsed and its results counted rather than merely deserialized. A
    syntactically valid SARIF document with an empty ``runs`` list is what a broken
    reporter emits, and it reads as a clean scan.
    """
    files = completed_scan["paths"]["files"]
    assert completed_scan["paths"]["success"] is True

    for name in ("sarif", "flat_json", "aggregated_results"):
        entry = files[name]
        assert entry["exists"] is True, f"{name} report was not written: {entry}"
        assert entry["size_bytes"] > 0, f"{name} report is empty: {entry}"
        assert Path(entry["path"]).is_file(), (
            f"{name} is reported as existing at a path that is not a file: {entry}"
        )

    sarif = json.loads(Path(files["sarif"]["path"]).read_text(encoding="utf-8"))
    total_results = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
    assert total_results >= 1, (
        "The SARIF report parsed but carries no results. An empty runs list is what a "
        "broken reporter produces, and a client reading it sees a clean scan."
    )

    aggregated = json.loads(
        Path(files["aggregated_results"]["path"]).read_text(encoding="utf-8")
    )
    assert aggregated.get("scanner_results"), (
        "The aggregated results file carries no scanner_results section, which is what "
        "every other MCP results tool reads."
    )


def test_the_scan_is_listed_and_a_finished_scan_cannot_be_cancelled(
    completed_scan: Dict[str, Any],
) -> None:
    """``list_active_scans`` knows about this scan, and ``cancel_scan`` refuses it.

    Membership, never totals. ``get_scan_registry()`` is a process-global singleton
    shared by every test in one xdist worker, so an assertion that one scan exists
    would pass when this module runs alone and fail when it runs beside a sibling that
    started one. That is the kind of failure that gets rerun until it passes.

    The cancel half is the interesting one: cancelling a completed scan is refused with
    ``success: False`` and the state named, not accepted as a no-op. A client that
    cancelled and got success would believe it had stopped something.
    """
    scan_id = completed_scan["scan_id"]
    active = completed_scan["active"]

    assert active["success"] is True
    listed = {entry["scan_id"] for entry in active["all_scans"]}
    assert scan_id in listed, (
        f"The scan is absent from list_active_scans: {sorted(listed)}"
    )
    assert scan_id not in {entry["scan_id"] for entry in active["active_scans"]}, (
        "A completed scan is still reported as active"
    )

    cancel = completed_scan["cancel"]
    assert cancel["success"] is False, (
        "Cancelling a completed scan reported success. A client would believe it had "
        "stopped work that had already finished."
    )
    assert cancel["status"] == "completed"


def test_the_server_sends_a_progress_notification_while_starting_the_scan(
    completed_scan: Dict[str, Any],
) -> None:
    """``run_ash_scan`` reports progress over the protocol, not only in its return value.

    The tool calls ``ctx.report_progress`` before returning, which becomes a real
    ``notifications/progress`` message carrying the request's progress token. A direct
    function call with a MagicMock context records that the method was called; only a
    client can show that the notification was serialized, routed and delivered.

    One event is asserted rather than a stream. ``monitor_scan_progress`` keeps sending
    updates after ``run_ash_scan`` has answered, and those arrive against a request the
    client has already completed, so they do not reach this callback -- measured as
    exactly one event delivered, both immediately and after the scan finished.
    "At least one, carrying a total" is the part that is stable.
    """
    events = completed_scan["progress_events"]
    assert events, (
        "No progress notification was delivered during the run_ash_scan call. The tool "
        "calls ctx.report_progress before returning, and a client that tracks progress "
        "notifications would see nothing."
    )
    progress, total, message = events[0]
    assert total == 1.0, f"Progress was reported against no total: {events[0]!r}"
    assert progress == 0.0
    assert message, "The progress notification carried no message"


def test_the_resolved_session_id_is_echoed_back(completed_scan: Dict[str, Any]) -> None:
    """The scan response names the session it resolved to.

    The in-memory transport carries no headers, which is the same situation as stdio:
    one local client and no way to tell two callers apart, so ``resolve_session_id``
    returns ``DEFAULT_SESSION_ID``.

    The echo is not decoration. Session ids decide which directory a delivered source
    tree lands in, and on Bedrock AgentCore whether the id holds still across calls
    within one session is an open question recorded in cli/mcp/session_identity.py.
    That docstring names this echo as the way to settle it against a live runtime
    without rebuilding the image, so a tool that stopped echoing would remove the only
    available diagnostic.
    """
    from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID

    assert completed_scan["start"]["session_id"] == DEFAULT_SESSION_ID, (
        f"Resolved session id is {completed_scan['start']['session_id']!r}; a "
        "headerless transport should resolve to the default session."
    )


@pytest.mark.asyncio
async def test_completion_is_reported_from_the_aggregated_file_alone(
    ash_mcp_client, tmp_path: Path
) -> None:
    """``is_complete`` means one file exists. It does not mean the reports do.

    WHY THIS IS WORTH A TEST OF ITS OWN
    -----------------------------------
    ``run_ash_scan``'s docstring tells a client to poll ``get_scan_progress`` until
    ``is_complete`` and then read results. ``check_scan_progress`` decides completion by
    calling ``check_scan_completion``, which tests for ``ash_aggregated_results.json``
    and nothing else -- and the REPORT phase writes that file before it writes any of
    the ten reports. So a client that follows the documented loop can call
    ``get_scan_result_paths`` and be told ``ash.sarif`` does not exist, on a scan that
    writes it moments later.

    That is not theoretical. This module hit it: the report assertions passed when the
    module ran alone and failed when a sibling shifted the timing, with the scan's own
    log showing the SARIF written 40 milliseconds after the read. An agent consuming ASH
    over MCP sees the same thing as an empty report set on a scan that found findings.

    Asserted without timing. The registry is handed an output directory that contains
    exactly the aggregated results file and no ``reports`` directory at all -- which is
    what the real directory looks like for those few milliseconds -- and
    ``get_scan_progress`` is asked over the protocol. It answers ``completed``. No sleep,
    no race, and it fails if completion ever starts depending on the reports.

    The scan is registered directly rather than started, because starting one would
    reintroduce the timing this test exists to remove. ``register_scan`` is the same
    call ``mcp_scan_directory`` makes.
    """
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    output_dir = tmp_path / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    (output_dir / "ash_aggregated_results.json").write_text(
        json.dumps({"metadata": {"summary_stats": {}}, "scanner_results": {}}),
        encoding="utf-8",
    )
    assert not (output_dir / "reports").exists(), "Fixture wrote reports it should not"

    scan_id = get_scan_registry().register_scan(
        directory_path=str(tmp_path),
        output_directory=str(output_dir),
        severity_threshold="MEDIUM",
        config_path=None,
    )

    async with ash_mcp_client() as client:
        response = await client.call_tool("get_scan_progress", {"scan_id": scan_id})

    progress = response.structured_content["result"]
    assert progress["is_complete"] is True, (
        "Completion no longer follows from the aggregated results file alone. If a "
        "reports check was added, the poll-then-read race is fixed and the wait in "
        "_await_report_files can go -- update both together."
    )
    assert progress["status"] == "completed"
    assert not (output_dir / "reports").exists(), (
        "get_scan_progress created a reports directory as a side effect"
    )


def test_filter_level_summary_returns_a_summary(completed_scan: Dict[str, Any]) -> None:
    """``get_scan_results(filter_level="summary")`` returns the summary shape.

    WHY THIS WAS AN XFAIL, AND WHY THE MARKER IS GONE
    ------------------------------------------------
    The behavior is documented in the tool's own schema -- "summary: Return only
    summary data (metadata, findings counts, scanner summaries)" -- and
    ``filter_summary`` exists, is imported, and produces exactly that shape when handed
    a real payload. What was missing was the key that gates it. On the success path
    ``mcp_get_scan_results`` returns whatever
    ``get_scan_results_with_error_handling`` produced, and that dict had no ``success``
    member, so::

        if "error" in results or not results.get("success"):
            return results

    fired on every successful scan and the unfiltered payload came back whatever
    ``filter_level`` said. ``scanners``, ``severities`` and ``actionable_only`` sat
    downstream of the same early return and were equally inert, and
    ``get_scan_summary``'s ``_source_function`` tag never got attached either.

    Measured rather than inferred: on a completed scan the payload's keys were
    ``actionable_findings, completion_time, is_complete, operation, raw_results,
    scan_id, scanner_reports, status, summary_stats, timestamp, total_scanners`` -- no
    ``success``, no ``_filter``, and ``raw_results`` present at a filter level whose
    documented job is to omit it. Handing that same payload to ``filter_summary``
    directly produced the documented shape, which located the defect at the gate
    rather than in the filter.

    The producer now sets ``success`` and the gate discriminates on a ``False`` value
    rather than on the key's absence, so this is an ordinary assertion. The
    ``xfail(strict=True)`` marker was chosen precisely so that it would fail the
    moment the defect was fixed, forcing this conversion instead of allowing a
    silently-passing xpass.
    """
    filtered = completed_scan["summary_filtered"]

    assert filtered.get("_filter") == "summary", (
        f"filter_level=summary did not apply a filter; keys were {sorted(filtered)}"
    )
    assert "raw_results" not in filtered, (
        "filter_level=summary returned raw_results, which is the payload it exists to "
        "omit"
    )
    assert "findings_summary" in filtered
    assert "scanner_summary" in filtered
