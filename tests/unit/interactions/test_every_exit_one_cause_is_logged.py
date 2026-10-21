# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every exit-1 cause that holds is logged, in arm order, before the exit.

_compute_exit_code's arms each log their cause and the function returns 1 once,
after the last of them. An arm that returned as soon as it logged hid every
cause after it: an operator working from ash.log fixed one cause, re-ran, and
met the next. The completeness object is stood in for here, so the cell sets
exactly the arms it names and asserts the exact error lines in order.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

from automated_security_helper.interactions import run_ash_scan
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER

_STOP = [("watched", "ASH could not stop watched-tool (pid 4242)")]
_INCOMPLETE = [("bandit", "MISSING")]
_OBSERVED = [("bandit", "MISSING"), ("semgrep", "SKIPPED")]
_CONVERTERS = [("jupyter", "the converter crashed")]
_RULES = ["CDK-1", "CDK-2"]
_STALE = [SimpleNamespace(name="grype-db", message=lambda: "grype-db is 40 days old")]

#: Each arm's error lines, as _compute_exit_code logs them.
_LINES = {
    "stop": [
        (
            "Scan failed: 1 scanner tool(s) could not be stopped and may still be "
            "running: watched"
        ),
        "ASH could not stop watched-tool (pid 4242)",
    ],
    "incomplete": ["Scan incomplete: bandit (MISSING)"],
    "converters": [
        (
            "Conversion incomplete, so the scanners were given fewer targets than "
            "this repository has: jupyter (the converter crashed)"
        )
    ],
    "rules": [
        (
            "Scan incomplete: 2 rule(s) could not be evaluated, so this scan "
            "reports nothing about compliance with them: CDK-1, CDK-2"
        )
    ],
    "stale": [
        (
            "Scan failed: 1 content database(s) are past their declared age "
            "bound: grype-db"
        ),
        "grype-db is 40 days old",
    ],
}


def _incompleteness(**arms):
    """A stand-in for scan_incompleteness's answer with only ``arms`` set."""
    return SimpleNamespace(
        could_not_stop=arms.get("could_not_stop", []),
        observed=arms.get("observed", list(_OBSERVED)),
        scanners=arms.get("scanners", []),
        no_scanner_ran=arms.get("no_scanner_ran", False),
        converters=arms.get("converters", []),
        unevaluated_rules=arms.get("unevaluated_rules", []),
        stale_content_databases=arms.get("stale_content_databases", []),
    )


class _ErrorLines(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.lines: list = []

    def emit(self, record) -> None:
        self.lines.append(record.getMessage())


def _exit_code_and_error_lines(monkeypatch, incompleteness):
    """The exit code for results whose completeness is ``incompleteness``, with
    the gate on, and the error lines it logged."""
    monkeypatch.setattr(
        run_ash_scan, "scan_incompleteness", lambda *a, **k: incompleteness
    )
    monkeypatch.setattr(
        run_ash_scan, "_resolve_fail_on_incomplete_scanners", lambda *a, **k: True
    )
    sink = _ErrorLines()
    ASH_LOGGER.addHandler(sink)
    try:
        code = run_ash_scan._compute_exit_code(
            AshAggregatedResults(),
            SimpleNamespace(fail_on_findings=None, shard_index=None, shard_count=None),
        )
    finally:
        ASH_LOGGER.removeHandler(sink)
    return code, sink.lines


def test_every_arm_that_fires_is_logged_in_arm_order(monkeypatch):
    """All five causes at once: a tool ASH could not stop, an incomplete
    scanner, an incomplete conversion, rules that could not be evaluated and a
    stale content database. Each is logged, in the order of the arms, and the
    run exits 1 once."""
    code, lines = _exit_code_and_error_lines(
        monkeypatch,
        _incompleteness(
            could_not_stop=_STOP,
            scanners=_INCOMPLETE,
            converters=_CONVERTERS,
            unevaluated_rules=_RULES,
            stale_content_databases=_STALE,
        ),
    )

    assert code == 1, code
    expected = (
        _LINES["stop"]
        + _LINES["incomplete"]
        + _LINES["converters"]
        + _LINES["rules"]
        + _LINES["stale"]
    )
    assert lines == expected, lines
