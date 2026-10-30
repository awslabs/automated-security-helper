# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivered checkov skip path runs in ASH's process under the scanner's time bound.

``checkov_skips`` compiles a ``skip_path`` entry a delivered config supplied as a
regular expression and searches it in every finding's path, in the host process,
once per finding per entry. It ran with no bound: one entry that backtracks
heavily held the result processing for as long as it liked, where checkov's own
run would have been killed at ``scan_timeout``. The search now runs in a thread
bounded by that same ``scan_timeout``, carried on the exclusion when it is moved
out of the options (``ClientScannerExclusion.scan_timeout``), and a search still
running at the deadline fails the pass with a ScannerError that names the option;
the thread itself cannot be stopped and is left running until the process exits.
A literal entry cannot backtrack and is searched inline, with no thread.

The overrunning search is a stand-in whose ``search`` sleeps for a known time
(``_SlowSearch``), put in place of the compiled pattern through
``_checkov_pattern``: a real backtracking pattern takes an interpreter-dependent
time (``a*a*a*b`` over 300 ``a`` characters read 0.41 s on Python 3.9 and under the
20 ms bound on Python 3.12), so it cannot pin the bound. The stand-in's thread
ends on its own half a second later.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

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
#: A skip path with regular-expression syntax, so the bounded path is taken.
REGEX_PATTERN = "vend.r"
TINY_TIMEOUT = 0.02
SLOW_SECONDS = 0.5


class _SlowSearch:
    """Stands in for a compiled pattern whose search overruns the bound."""

    def search(self, text: str) -> Optional[Any]:
        time.sleep(SLOW_SECONDS)
        return None


def _searches_slowly(monkeypatch) -> None:
    """Every compiled skip path becomes the overrunning stand-in."""
    monkeypatch.setattr(
        exclusions_module, "_checkov_pattern", lambda pattern: _SlowSearch()
    )


# ---------------------------------------------------------------------------
# The bound itself
# ---------------------------------------------------------------------------


def test_evaluated_within_returns_the_result_or_re_raises():
    assert evaluated_within(1, "x", lambda: 5) == 5
    assert evaluated_within(None, "x", lambda: 7) == 7
    with pytest.raises(KeyError):
        evaluated_within(1, "x", lambda: {}["missing"])


def test_evaluated_within_fails_at_the_deadline_naming_the_source():
    started = time.monotonic()

    with pytest.raises(ScannerError) as raised:
        evaluated_within(TINY_TIMEOUT, "the slow thing", lambda: time.sleep(0.5))

    assert time.monotonic() - started < 0.45
    assert "the slow thing" in str(raised.value)
    assert "scan_timeout" in str(raised.value)


# ---------------------------------------------------------------------------
# checkov's skip path
# ---------------------------------------------------------------------------


def test_a_slow_skip_path_is_stopped_at_the_bound(monkeypatch):
    _searches_slowly(monkeypatch)
    started = time.monotonic()

    with pytest.raises(ScannerError) as raised:
        checkov_skips(
            REGEX_PATTERN, "/scan/vendor/x.tf", "vendor/x.tf", timeout=TINY_TIMEOUT
        )

    assert time.monotonic() - started < SLOW_SECONDS
    assert "scanners.checkov.options.skip_path" in str(raised.value)
    assert REGEX_PATTERN not in str(raised.value)


def test_a_fast_skip_path_answers_under_the_bound():
    assert (
        checkov_skips(
            "vend.r", "/scan/vendor/x.tf", "vendor/x.tf", timeout=TINY_TIMEOUT
        )
        is True
    )
    assert (
        checkov_skips("vend.r", "/scan/src/x.tf", "src/x.tf", timeout=TINY_TIMEOUT)
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
    """A literal cannot backtrack, so no thread is spent on it; a pattern with
    regular-expression syntax goes through the bound."""
    bounded: list = []

    def recording(timeout, source, run):
        bounded.append(source)
        return run()

    monkeypatch.setattr(exclusions_module, "evaluated_within", recording)

    assert (
        checkov_skips("vendor", "/scan/vendor/x.tf", "vendor/x.tf", timeout=5) is True
    )
    assert bounded == []
    assert (
        checkov_skips("vend.r", "/scan/vendor/x.tf", "vendor/x.tf", timeout=5) is True
    )
    assert len(bounded) == 1


def test_an_exclusion_carries_the_bound_into_hides(monkeypatch):
    _searches_slowly(monkeypatch)
    entry = ClientScannerExclusion(
        scanner="checkov",
        option="skip_path",
        kind="checkov",
        pattern=REGEX_PATTERN,
        reason="r",
        scan_timeout=TINY_TIMEOUT,
    )

    with pytest.raises(ScannerError):
        entry.hides(relative="vendor/x.tf", absolute="/scan/vendor/x.tf", rule_id=None)


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
