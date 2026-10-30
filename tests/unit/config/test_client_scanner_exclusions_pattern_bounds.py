# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivered checkov skip path runs under the scanner's time bound, in a child process.

``checkov_skips`` compiles a ``skip_path`` entry a delivered config supplied as a
regular expression and searches it in every finding's path, once per finding per
entry. It ran with no bound: one entry that backtracks heavily held the result
processing for as long as it liked, where checkov's own run would have been
killed at ``scan_timeout``. The search now runs in a child process bounded by
that same ``scan_timeout``, carried on the exclusion when it is moved out of the
options (``ClientScannerExclusion.scan_timeout``); a search still running at the
deadline is killed and fails the pass with a ScannerError that names the option.
A literal entry cannot backtrack and is searched inline, in this process.

Why a process and not a thread: Python's matcher holds the interpreter lock for
the whole of a search, so a thread joined with a timeout learned of the overrun
only when the search finished on its own. The overrunning search here is a real
one, ``(a+)+$`` over a run of 64 ``a`` characters ending in ``b``, which
backtracks through 2**64 states and finishes on no machine. Under the thread the
call never returned, so each test that runs it runs it inside a child of its own
(``_outcome_of``) and reads back what the call did, within a limit of its own:
at the deadline a killed search reads ``ScannerError``, a search the bound could
not end reads as no answer within the limit.

A suppression pass asks every entry about every finding, so the bound is spent
once over the pass, not once per call: ``EvaluationBudget`` opens one deadline
per ``scan_timeout`` the first time it is used, hands each later search what is
left, and remembers an entry that ran out so it is not searched again. The SARIF
pass creates one budget and hands it down through ``matching_exclusion`` and
``hides``; the tests here pin each hop with a budget that records what it saw.

The budget's searches run in ONE worker child it starts at its first bounded
evaluation and reuses (a process per search cost a fork per finding on Linux and
a fresh interpreter per finding where the start method is ``spawn``); a worker
killed at the deadline is replaced by the next evaluation, ``close()`` ends it,
and the pass closes its budget when it is done. The tests pin that lifecycle by
pid: one pid across evaluations, none after ``close()``, a new one after a kill.
"""

from __future__ import annotations

import multiprocessing
import operator
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

import pytest

import automated_security_helper.config.client_scanner_exclusions as exclusions_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_scanner_exclusions import (
    ClientScannerExclusion,
    EvaluationBudget,
    EvaluationTimedOut,
    checkov_skips,
    evaluated_within,
    matching_exclusion,
    strip_client_scanner_exclusions,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason

pytestmark = pytest.mark.unit

#: A backtracking pattern that matches nothing in a run of ``a``; searched inline
#: over 120 characters in a few milliseconds on any interpreter.
STAR_PATTERN = "a*a*a*b"
QUICK_RELATIVE = "a" * 120
QUICK_ABSOLUTE = "/scan/" + QUICK_RELATIVE
#: A search that finishes on no machine: the nested quantifier backtracks through
#: 2**64 states before it fails against the trailing ``b``.
NEVER_ENDING_PATTERN = r"(a+)+$"
NEVER_ENDING_TEXT = "a" * 64 + "b"
NEVER_ENDING_ABSOLUTE = "/scan/" + NEVER_ENDING_TEXT
#: The bound an overrunning search is stopped at.
TINY_TIMEOUT = 0.5
#: The bound a fast bounded call must finish under, a worker start included.
#: Where the start method is ``spawn`` (Windows, macOS) that start is a fresh
#: interpreter importing this package, seconds on a loaded venue (5.0 lost three
#: ids on a Windows run of eight workers), so the bound is generous: a green call
#: returns in milliseconds, and no test asserts elapsed time against it.
FAST_TIMEOUT = 60.0
#: How long a test waits for the bounded call before reading it as unbounded.
GUARD_LIMIT = 20.0


def _never_ending_search() -> None:
    re.search(NEVER_ENDING_PATTERN, NEVER_ENDING_TEXT)


def _five() -> int:
    return 5


def _missing_key() -> Any:
    return {}["missing"]


def _hides(entry: ClientScannerExclusion, relative: str, absolute: str) -> bool:
    return entry.hides(relative=relative, absolute=absolute, rule_id=None)


def _reported(connection: Any, function: Callable[..., Any], args: tuple) -> None:
    """In the guard's child: run the call and send back one line saying what it did."""
    try:
        function(*args)
        connection.send("returned")
    except ScannerError as error:
        connection.send(f"ScannerError: {error}")
    except Exception as error:  # the test reads the type
        connection.send(type(error).__name__)
    finally:
        connection.close()


def _outcome_of(
    function: Callable[..., Any], *args: Any, limit: float = GUARD_LIMIT
) -> str:
    """What ``function(*args)`` did, read from a child of the test's own.

    The bounded call is made in a forked child so a bound that does not hold
    (the thread of the first cut, which the search never returned to) leaves a
    hanging child the test kills after ``limit`` seconds, not a hanging test.
    Where there is no ``fork`` the call is made inline: the bound under test
    holds there too, and the guard is only against the unbounded shape.
    """
    if "fork" not in multiprocessing.get_all_start_methods():
        try:
            function(*args)
            return "returned"
        except ScannerError as error:
            return f"ScannerError: {error}"
    context = multiprocessing.get_context("fork")
    receiving, sending = context.Pipe(duplex=False)
    child = context.Process(target=_reported, args=(sending, function, args))
    child.start()
    sending.close()
    try:
        if receiving.poll(limit):
            return receiving.recv()
        return f"no answer within {limit} s"
    finally:
        receiving.close()
        if child.is_alive():
            child.kill()
        child.join()


# ---------------------------------------------------------------------------
# The bound itself
# ---------------------------------------------------------------------------


def test_evaluated_within_returns_the_result_or_re_raises():
    assert evaluated_within(FAST_TIMEOUT, "x", _five) == 5
    assert evaluated_within(None, "x", _five) == 5
    assert evaluated_within(FAST_TIMEOUT, "x", operator.add, 2, 3) == 5
    with pytest.raises(KeyError):
        evaluated_within(FAST_TIMEOUT, "x", _missing_key)


def test_evaluated_within_runs_the_bounded_call_in_another_process():
    assert evaluated_within(FAST_TIMEOUT, "x", os.getpid) != os.getpid()
    assert evaluated_within(None, "x", os.getpid) == os.getpid()


def test_evaluated_within_fails_at_the_deadline_naming_the_source():
    started = time.monotonic()

    with pytest.raises(ScannerError) as raised:
        evaluated_within(TINY_TIMEOUT, "the slow thing", time.sleep, 10)

    assert time.monotonic() - started < 5
    assert "the slow thing" in str(raised.value)
    assert "scan_timeout" in str(raised.value)


def test_a_search_that_holds_the_interpreter_lock_is_stopped_at_the_bound():
    started = time.monotonic()

    outcome = _outcome_of(
        evaluated_within, TINY_TIMEOUT, "the search", _never_ending_search
    )

    assert outcome.startswith("ScannerError: ")
    assert "the search" in outcome
    assert time.monotonic() - started < GUARD_LIMIT / 2


# ---------------------------------------------------------------------------
# checkov's skip path
# ---------------------------------------------------------------------------


def test_a_slow_skip_path_is_stopped_at_the_bound():
    outcome = _outcome_of(
        checkov_skips,
        NEVER_ENDING_PATTERN,
        NEVER_ENDING_ABSOLUTE,
        NEVER_ENDING_TEXT,
        TINY_TIMEOUT,
    )

    assert outcome.startswith("ScannerError: ")
    assert "scanners.checkov.options.skip_path" in outcome
    assert NEVER_ENDING_PATTERN not in outcome


def test_a_fast_skip_path_answers_under_the_bound():
    """The answer comes back through the bounded path. The bound is generous:
    the test shows the result crosses the bound, not that the search is fast,
    and a 20 ms bound failed at random on a loaded worker whose thread was not
    scheduled in time."""
    assert (
        checkov_skips(
            "vend.r", "/scan/vendor/x.tf", "vendor/x.tf", timeout=FAST_TIMEOUT
        )
        is True
    )
    assert (
        checkov_skips("vend.r", "/scan/src/x.tf", "src/x.tf", timeout=FAST_TIMEOUT)
        is False
    )


def test_without_a_bound_the_search_runs_as_before():
    """``timeout=None`` is the scanner left unbounded (``scan_timeout: null``)."""
    assert (
        checkov_skips(STAR_PATTERN, QUICK_ABSOLUTE, QUICK_RELATIVE, timeout=None)
        is False
    )
    assert checkov_skips(STAR_PATTERN, QUICK_ABSOLUTE, QUICK_RELATIVE) is False


@pytest.mark.parametrize(
    "pattern",
    [
        "a{4294967296}",
        "(" * 1500 + "a" + ")" * 1500,
    ],
)
def test_a_pattern_the_compiler_refuses_is_read_as_a_substring(pattern):
    """``re.compile`` raises OverflowError for a repetition count past its
    limit and RecursionError for a nesting deeper than its parser follows;
    only re.error was caught, and the other two failed the suppression pass.
    Such a pattern is a substring now, as checkov reads it."""
    assert checkov_skips(pattern, "/scan/src/x.tf", "src/x.tf", timeout=5) is False
    assert (
        checkov_skips(pattern, f"/scan/{pattern}/x.tf", f"{pattern}/x.tf", timeout=5)
        is True
    )


def test_a_literal_skip_path_is_searched_inline(monkeypatch):
    """A literal cannot backtrack, so no process is spent on it; a pattern with
    regular-expression syntax goes through the bound."""
    bounded: list = []

    def recording(timeout, source, function, *args):
        bounded.append(source)
        return function(*args)

    monkeypatch.setattr(exclusions_module, "evaluated_within", recording)

    assert (
        checkov_skips("vendor", "/scan/vendor/x.tf", "vendor/x.tf", timeout=5) is True
    )
    assert bounded == []
    assert (
        checkov_skips("vend.r", "/scan/vendor/x.tf", "vendor/x.tf", timeout=5) is True
    )
    assert len(bounded) == 1


def test_an_exclusion_carries_the_bound_into_hides():
    entry = ClientScannerExclusion(
        scanner="checkov",
        option="skip_path",
        kind="checkov",
        pattern=NEVER_ENDING_PATTERN,
        reason="r",
        scan_timeout=TINY_TIMEOUT,
    )

    outcome = _outcome_of(_hides, entry, NEVER_ENDING_TEXT, NEVER_ENDING_ABSOLUTE)

    assert outcome.startswith("ScannerError: ")


def test_an_exclusion_without_a_bound_searches_as_before():
    entry = ClientScannerExclusion(
        scanner="checkov",
        option="skip_path",
        kind="checkov",
        pattern=STAR_PATTERN,
        reason="r",
    )

    assert entry.scan_timeout is None
    assert (
        entry.hides(relative=QUICK_RELATIVE, absolute=QUICK_ABSOLUTE, rule_id=None)
        is False
    )


def test_the_evaluation_child_is_a_fork_on_linux():
    if not sys.platform.startswith("linux"):
        pytest.skip("the fork is chosen on Linux only")
    assert exclusions_module._process_context().get_start_method() == "fork"


# ---------------------------------------------------------------------------
# One deadline per suppression pass
# ---------------------------------------------------------------------------


class _RecordingBudget(EvaluationBudget):
    """A budget that notes each key it is asked about and answers inline."""

    def __init__(self) -> None:
        super().__init__()
        self.keys: list = []

    def evaluate(self, timeout, source, key, function, *args):
        self.keys.append(key)
        return function(*args)


def test_a_budget_spends_one_deadline_over_a_pass():
    budget = EvaluationBudget()
    # Start the worker under a deadline of its own, so the one-second deadline
    # below is spent on the sleeps and not on a spawn platform's interpreter start.
    assert budget.evaluate(FAST_TIMEOUT, "warm", "warm", _five) == 5
    started = time.monotonic()

    budget.evaluate(1.0, "first", "k1", time.sleep, 0.6)
    with pytest.raises(ScannerError) as second:
        budget.evaluate(1.0, "second", "k2", time.sleep, 0.6)
    spent_at = time.monotonic() - started
    with pytest.raises(ScannerError) as repeated:
        budget.evaluate(1.0, "second again", "k2", _five)
    # Past the deadline for certain, whichever side of it the kill landed on.
    time.sleep(0.05)
    with pytest.raises(ScannerError) as late:
        budget.evaluate(1.0, "third", "k3", _five)

    assert spent_at < 1.5
    assert time.monotonic() - started - spent_at < 0.3
    assert "second" in str(second.value)
    assert "scan_timeout" in str(second.value)
    assert "not searched again" in str(repeated.value)
    assert "spent" in str(late.value)
    assert budget.timed_out == ("k2", "k3")


def test_a_budget_remembers_an_entry_that_ran_out(monkeypatch):
    calls: list = []

    def running_out(self, wait, timeout, source, function, args):
        calls.append(source)
        raise EvaluationTimedOut("ran out")

    monkeypatch.setattr(exclusions_module._EvaluationWorker, "evaluate", running_out)
    budget = EvaluationBudget()

    with pytest.raises(EvaluationTimedOut):
        budget.evaluate(5.0, "s", "k", _five)
    with pytest.raises(ScannerError) as repeated:
        budget.evaluate(5.0, "s", "k", _five)

    assert calls == ["s"]
    assert "not searched again" in str(repeated.value)
    assert budget.timed_out == ("k",)


def test_a_budget_opens_one_deadline_per_scan_timeout():
    budget = EvaluationBudget()

    first = budget.remaining(10.0)
    time.sleep(0.05)
    again = budget.remaining(10.0)
    other = budget.remaining(3.0)

    assert again < first
    assert 2.9 < other <= 3.0


def test_a_budget_with_no_bound_runs_inline():
    budget = EvaluationBudget()

    assert budget.evaluate(None, "s", "k", os.getpid) == os.getpid()
    assert budget.timed_out == ()
    assert budget.worker_pid is None


# ---------------------------------------------------------------------------
# One worker process per pass
# ---------------------------------------------------------------------------


def _evaluation_workers() -> list:
    return [
        child
        for child in multiprocessing.active_children()
        if child.name == "ash-pattern-evaluation"
    ]


def test_a_budget_reuses_one_worker_across_its_evaluations():
    budget = EvaluationBudget()
    assert budget.worker_pid is None

    first = budget.evaluate(FAST_TIMEOUT, "s", "k1", os.getpid)
    second = budget.evaluate(FAST_TIMEOUT, "s", "k2", os.getpid)
    third = budget.evaluate(FAST_TIMEOUT, "s", "k3", operator.add, 2, 3)

    assert first == second != os.getpid()
    assert budget.worker_pid == first
    assert third == 5
    budget.close()
    assert budget.worker_pid is None
    assert _evaluation_workers() == []


def test_a_closed_budget_starts_a_new_worker_when_asked_again():
    budget = EvaluationBudget()
    first = budget.evaluate(FAST_TIMEOUT, "s", "k1", os.getpid)
    budget.close()

    again = budget.evaluate(FAST_TIMEOUT, "s", "k2", os.getpid)

    assert again != first
    assert again != os.getpid()
    budget.close()


def test_a_worker_killed_at_the_deadline_is_replaced():
    budget = EvaluationBudget()
    first = budget.evaluate(FAST_TIMEOUT, "s", "k1", os.getpid)

    with pytest.raises(EvaluationTimedOut):
        budget.evaluate(TINY_TIMEOUT, "s", "slow", time.sleep, 10)
    assert budget.worker_pid is None
    replaced = budget.evaluate(FAST_TIMEOUT, "s", "k3", os.getpid)

    assert replaced != first
    assert replaced != os.getpid()
    assert budget.timed_out == ("slow",)
    budget.close()


def test_a_worker_hands_an_error_back_and_stays_alive():
    budget = EvaluationBudget()

    with pytest.raises(KeyError):
        budget.evaluate(FAST_TIMEOUT, "s", "k1", _missing_key)
    pid = budget.worker_pid

    assert pid is not None
    assert budget.evaluate(FAST_TIMEOUT, "s", "k2", os.getpid) == pid
    budget.close()


def test_evaluated_within_leaves_no_worker_behind():
    assert evaluated_within(FAST_TIMEOUT, "x", os.getpid) != os.getpid()

    assert _evaluation_workers() == []


def test_a_budget_used_as_a_context_manager_closes_on_exit():
    with EvaluationBudget() as budget:
        pid = budget.evaluate(FAST_TIMEOUT, "s", "k1", os.getpid)
        assert budget.worker_pid == pid

    assert budget.worker_pid is None


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="the fork start method is Linux's"
)
def test_a_forked_worker_exits_when_the_parent_end_closes_without_a_farewell():
    """A forked child inherits the parent's end of its own pipe. Unless the child
    closes that copy, a parent that dies without ``close()`` leaves the worker
    reading a pipe it holds open itself, forever. With the copy closed, the parent
    end's closing alone is end-of-file to the worker, and it exits."""
    budget = EvaluationBudget()
    assert budget.evaluate(FAST_TIMEOUT, "s", "k1", os.getpid) != os.getpid()
    worker = budget._worker
    process = worker._process

    # The parent's end goes away with no None sent, as a dead parent's would.
    worker._connection.close()
    process.join(5.0)

    assert not process.is_alive()
    budget.close()


def test_a_pass_starts_one_process_on_the_spawn_path(monkeypatch):
    """Where the start method is ``spawn`` (Windows, macOS) every process start is a
    fresh interpreter importing this module, so a pass must start ONE worker and
    reuse it; a start per evaluation is what spent a pass's scan_timeout on
    interpreter starts alone. Counted with the real spawn context."""
    spawn = multiprocessing.get_context("spawn")
    started: list = []

    class _CountingContext:
        Pipe = staticmethod(spawn.Pipe)
        get_start_method = staticmethod(spawn.get_start_method)

        @staticmethod
        def Process(*args, **kwargs):
            process = spawn.Process(*args, **kwargs)
            started.append(process)
            return process

    monkeypatch.setattr(exclusions_module, "_process_context", lambda: _CountingContext)
    budget = EvaluationBudget()

    pids = {budget.evaluate(FAST_TIMEOUT, "s", f"k{n}", os.getpid) for n in range(3)}
    budget.close()

    assert len(started) == 1
    assert pids == {started[0].pid}
    assert os.getpid() not in pids


def test_the_skip_path_search_is_charged_to_the_budget_by_its_pattern():
    budget = _RecordingBudget()

    assert (
        checkov_skips(
            "vend.r", "/scan/vendor/x.tf", "vendor/x.tf", timeout=5, budget=budget
        )
        is True
    )
    assert (
        checkov_skips(
            "vendor", "/scan/vendor/x.tf", "vendor/x.tf", timeout=5, budget=budget
        )
        is True
    )

    assert budget.keys == ["skip_path:vend.r"]


def test_hides_and_matching_exclusion_hand_the_budget_down():
    budget = _RecordingBudget()
    entry = ClientScannerExclusion(
        scanner="checkov",
        option="skip_path",
        kind="checkov",
        pattern="vend.r",
        reason="r",
        scan_timeout=5,
    )

    assert (
        entry.hides(
            relative="vendor/x.tf",
            absolute="/scan/vendor/x.tf",
            rule_id=None,
            budget=budget,
        )
        is True
    )
    assert (
        matching_exclusion(
            [entry],
            scanner_name="checkov",
            relative="vendor/x.tf",
            absolute="/scan/vendor/x.tf",
            rule_id=None,
            budget=budget,
        )
        is entry
    )

    assert budget.keys == ["skip_path:vend.r", "skip_path:vend.r"]


def _report_of(uris: list) -> Any:
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "AWS Labs - Automated Security Helper"}
                    },
                    "results": [
                        {
                            "ruleId": "CKV_1",
                            "message": {"text": "finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                            "properties": {"scanner_name": "checkov"},
                        }
                        for uri in uris
                    ],
                }
            ],
        }
    )


def test_the_suppression_pass_shares_one_budget_across_its_findings(
    tmp_path, monkeypatch
):
    """``apply_suppressions_to_sarif`` creates one budget, hands it to every
    client-exclusion question of the pass, and closes it when the pass is done."""
    import automated_security_helper.utils.sarif_utils as sarif_utils
    from automated_security_helper.base.plugin_context import PluginContext

    seen: list = []
    closed: list = []

    class _ClosingBudget(EvaluationBudget):
        def close(self, graceful: bool = True) -> None:
            closed.append(self)
            super().close(graceful)

    def recording(result, run, exclusions, normalize, source_dir, budget=None):
        seen.append(budget)
        return None

    monkeypatch.setattr(sarif_utils, "_client_exclusion_for", recording)
    monkeypatch.setattr(exclusions_module, "EvaluationBudget", _ClosingBudget)
    config = AshConfig()
    config._client_scanner_exclusions = [
        ClientScannerExclusion(
            scanner="checkov",
            option="skip_path",
            kind="checkov",
            pattern="vend.r",
            reason="r",
            scan_timeout=5,
        )
    ]
    source = tmp_path / "src"
    source.mkdir()
    context = PluginContext(
        source_dir=source, output_dir=tmp_path / "out", config=config
    )

    sarif_utils.apply_suppressions_to_sarif(
        _report_of(["vendor/x.tf", "src/y.tf"]), context
    )

    assert len(seen) == 2
    assert isinstance(seen[0], EvaluationBudget)
    assert seen[0] is seen[1]
    assert closed == [seen[0]]


# ---------------------------------------------------------------------------
# The moved entry records the scanner's own time limit
# ---------------------------------------------------------------------------


def _strip(config, tmp_path: Path):
    # The operator document sits under the test's own path: a fixed
    # ``/operator`` resolved to ``C:/operator`` on Windows and matched nothing.
    documents = {
        tmp_path / "operator" / "ash.yaml": {},
        tmp_path / "c.yaml": {},
    }
    return strip_client_scanner_exclusions(
        config,
        documents,
        AshConfig(),
        source_dir=tmp_path,
        scanned_root=tmp_path,
        is_delivered=lambda path: Path(path) == tmp_path / "c.yaml",
    )


@pytest.mark.parametrize("configured", [45, None])
def test_the_moved_checkov_entry_carries_the_scanners_scan_timeout(
    tmp_path, configured
):
    config = AshConfig()
    config.scanners.checkov.options.skip_path = [
        IgnorePathWithReason(path="vendor", reason="r")
    ]
    config.scanners.checkov.options.scan_timeout = configured

    _strip(config, tmp_path)

    moved = [
        item for item in config._client_scanner_exclusions if item.scanner == "checkov"
    ]
    assert [item.pattern for item in moved] == ["vendor"]
    assert moved[0].scan_timeout == configured


def test_the_default_scan_timeout_is_carried_when_the_option_is_unset(tmp_path):
    config = AshConfig()
    config.scanners.checkov.options.skip_path = [
        IgnorePathWithReason(path="vendor", reason="r")
    ]

    _strip(config, tmp_path)

    moved = [
        item for item in config._client_scanner_exclusions if item.scanner == "checkov"
    ]
    assert moved[0].scan_timeout == config.scanners.checkov.options.scan_timeout
    assert moved[0].scan_timeout is not None
