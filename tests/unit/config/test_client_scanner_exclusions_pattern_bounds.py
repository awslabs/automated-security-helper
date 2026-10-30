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
    checkov_skips,
    evaluated_within,
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
#: The bound an overrunning search is stopped at, and the time a bounded fast
#: search may take (a child process has to start inside it).
TINY_TIMEOUT = 0.5
FAST_TIMEOUT = 5.0
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
# The moved entry records the scanner's own time limit
# ---------------------------------------------------------------------------


def _strip(config, tmp_path: Path):
    documents = {
        Path("/operator/ash.yaml"): {},
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
