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

The slow pattern is polynomial, not exponential: ``a*a*a*b`` searched in a run of
300 ``a`` characters backtracks for a few tenths of a second (measured 0.4 s) and
then finishes, so the thread a test leaves behind ends on its own.
"""

from __future__ import annotations

import time
from pathlib import Path

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

SLOW_PATTERN = "a*a*a*b"
#: A path whose last component is a run of 300 ``a``: the pattern's three
#: stars backtrack over it for a few tenths of a second before the search fails.
SLOW_RELATIVE = "a" * 300
SLOW_ABSOLUTE = "/scan/" + SLOW_RELATIVE
#: The same shape, short enough to search inline in a few milliseconds.
QUICK_RELATIVE = "a" * 120
QUICK_ABSOLUTE = "/scan/" + QUICK_RELATIVE
TINY_TIMEOUT = 0.02


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


def test_a_slow_skip_path_is_stopped_at_the_bound():
    started = time.monotonic()

    with pytest.raises(ScannerError) as raised:
        checkov_skips(SLOW_PATTERN, SLOW_ABSOLUTE, SLOW_RELATIVE, timeout=TINY_TIMEOUT)

    assert time.monotonic() - started < 2.0
    assert "scanners.checkov.options.skip_path" in str(raised.value)
    assert SLOW_PATTERN not in str(raised.value)


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
        checkov_skips(SLOW_PATTERN, QUICK_ABSOLUTE, QUICK_RELATIVE, timeout=None)
        is False
    )
    assert checkov_skips(SLOW_PATTERN, QUICK_ABSOLUTE, QUICK_RELATIVE) is False


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


def test_an_exclusion_carries_the_bound_into_hides():
    entry = ClientScannerExclusion(
        scanner="checkov",
        option="skip_path",
        kind="checkov",
        pattern=SLOW_PATTERN,
        reason="r",
        scan_timeout=TINY_TIMEOUT,
    )

    with pytest.raises(ScannerError):
        entry.hides(relative=SLOW_RELATIVE, absolute=SLOW_ABSOLUTE, rule_id=None)


def test_an_exclusion_without_a_bound_searches_as_before():
    entry = ClientScannerExclusion(
        scanner="checkov",
        option="skip_path",
        kind="checkov",
        pattern=SLOW_PATTERN,
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
