# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HTML cards keep the order ``sorted()`` gave them.

``REFERENCE_KEY`` is the sort key ``HtmlReporter._format_finding_cards`` used
before the cards were ordered through the emitter's severity ordering, kept
verbatim as an oracle: suppressed rows after live ones, then the severity's
place on the ladder (an off-ladder word after every named one), the file, the
line (none reading as 0) and the rule, with rows equal on every key staying in
the order they came. Real findings go through the real card renderer, and the
order of the rendered titles must equal the oracle's.
"""

import random
import re
from types import SimpleNamespace
from typing import List

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.vocab import Severity
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    _SEVERITY_ORDER,
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters._report_frames import (
    severity_order,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    _SEVERITY_ORDER as _EMITTER_ORDER,
    ReportContentEmitter,
)
from tests.unit.models._flat_vulnerability_helpers import flat_with_severity

pytestmark = pytest.mark.unit


def REFERENCE_KEY(finding):
    return (
        finding.is_suppressed,
        _SEVERITY_ORDER.get(finding.severity.upper(), len(_SEVERITY_ORDER)),
        finding.file_path or "",
        finding.line_start or 0,
        finding.rule_id or "",
    )


NFC = "café.py"
NFD = "café.py"

FILES = [None, "", "a.py", "b.py", "B.py", "src/z.py", NFC, NFD, "ÿ.py"]
LINES = [None, 0, 1, 2, 17, -1, 2**31, 2**63, 10**30]
RULES = [None, "", "A", "a", "B1", "R-10", "R-9"]
SEVERITIES = [severity.value for severity in Severity]


def _row(index: int, severity, **fields) -> FlatVulnerability:
    return flat_with_severity(
        severity, id=f"f-{index}", title=f"T{index:04d}", **fields
    )


def _random_rows(seed: int, count: int) -> List[FlatVulnerability]:
    rng = random.Random(seed)
    return [
        _row(
            index,
            rng.choice(SEVERITIES + ["weird"]),
            is_suppressed=rng.random() < 0.4,
            file_path=rng.choice(FILES),
            line_start=rng.choice(LINES),
            rule_id=rng.choice(RULES),
        )
        for index in range(count)
    ]


def _rendered_titles(rows: List[FlatVulnerability]) -> List[str]:
    emitter = ReportContentEmitter(AshAggregatedResults())
    emitter.flat_vulns = list(rows)
    document = HtmlReporter._format_finding_cards(emitter)
    return re.findall(r'<h3 id="finding-\d+">(.*?)</h3>', document)


def _expected_titles(rows: List[FlatVulnerability]) -> List[str]:
    return [row.title for row in sorted(rows, key=REFERENCE_KEY)]


class TestTheCardsKeepTheOrderTheOracleGives:
    @pytest.mark.parametrize("seed", range(30))
    def test_random_mixes(self, seed):
        rows = _random_rows(seed, 8 + seed * 3)
        assert _rendered_titles(rows) == _expected_titles(rows)

    def test_suppressed_cards_follow_every_live_card(self):
        rows = [
            _row(0, "CRITICAL", is_suppressed=True, file_path="a.py"),
            _row(1, "LOW", file_path="z.py"),
            _row(2, "HIGH", is_suppressed=True, file_path="a.py"),
            _row(3, "INFO", file_path="z.py"),
        ]
        assert _rendered_titles(rows) == ["T0001", "T0003", "T0000", "T0002"]
        assert _rendered_titles(rows) == _expected_titles(rows)

    def test_rows_equal_on_every_key_keep_the_order_they_came_in(self):
        rows = [
            _row(index, "HIGH", file_path="a.py", line_start=3, rule_id="R")
            for index in (5, 2, 9, 0, 7)
        ]
        assert _rendered_titles(rows) == ["T0005", "T0002", "T0009", "T0000", "T0007"]

    def test_a_row_with_no_line_sorts_with_line_zero(self):
        rows = [
            _row(0, "HIGH", file_path="a.py", line_start=1, rule_id="R"),
            _row(1, "HIGH", file_path="a.py", line_start=None, rule_id="R"),
            _row(2, "HIGH", file_path="a.py", line_start=0, rule_id="R"),
            _row(3, "HIGH", file_path="a.py", line_start=-1, rule_id="R"),
        ]
        assert _rendered_titles(rows) == ["T0003", "T0001", "T0002", "T0000"]
        assert _rendered_titles(rows) == _expected_titles(rows)

    def test_lines_beyond_sixty_four_bits_still_order(self):
        rows = [
            _row(0, "HIGH", file_path="a.py", line_start=10**30),
            _row(1, "HIGH", file_path="a.py", line_start=2**63),
            _row(2, "HIGH", file_path="a.py", line_start=2**63 - 1),
        ]
        assert _rendered_titles(rows) == ["T0002", "T0001", "T0000"]

    def test_an_off_ladder_severity_sorts_after_every_named_one(self):
        rows = [
            _row(0, "weird", file_path="a.py"),
            _row(1, "INFO", file_path="z.py"),
        ]
        assert _rendered_titles(rows) == ["T0001", "T0000"]

    def test_no_findings_reaches_the_empty_notice(self):
        assert "No findings in this report" in HtmlReporter._format_finding_cards(
            ReportContentEmitter(AshAggregatedResults())
        )


LONE_SURROGATE = chr(0xDC80)
EDGE_FILES = ["", "a", LONE_SURROGATE, chr(0xD7FF), chr(0xE000), NFC, NFD]
EDGE_LINES = [0, 1, -1, 2**63, 2**63 - 1, 10**30, -(10**30)]


def _standin(index, severity, suppressed, file_path, line_start, rule_id):
    return SimpleNamespace(
        index=index,
        severity=severity,
        is_suppressed=suppressed,
        file_path=file_path,
        line_start=line_start,
        rule_id=rule_id,
    )


def _standins(seed: int, count: int):
    rng = random.Random(seed)
    return [
        _standin(
            index,
            rng.choice(SEVERITIES + ["weird"]),
            rng.choice([True, False, None, 0, 1]),
            rng.choice(EDGE_FILES + [None]),
            rng.choice(EDGE_LINES + [None]),
            rng.choice(RULES + [LONE_SURROGATE]),
        )
        for index in range(count)
    ]


class TestTheEmittersOrderWithSuppressionFlags:
    @pytest.mark.parametrize("seed", range(40))
    def test_it_equals_the_sorted_key_over_edge_text_and_lines(self, seed):
        rows = _standins(seed, 5 + seed)
        flags = [bool(row.is_suppressed) for row in rows]
        got = ReportContentEmitter.by_severity(rows, suppressed=flags)
        want = sorted(
            rows, key=lambda row: (bool(row.is_suppressed),) + REFERENCE_PLACE_KEY(row)
        )
        assert [row.index for row in got] == [row.index for row in want]

    @pytest.mark.parametrize("seed", range(10))
    def test_without_flags_it_orders_as_it_always_did(self, seed):
        rows = _standins(seed, 20)
        got = ReportContentEmitter.by_severity(rows)
        want = sorted(rows, key=REFERENCE_PLACE_KEY)
        assert [row.index for row in got] == [row.index for row in want]

    def test_a_line_of_none_and_a_line_of_zero_tie(self):
        rows = [
            _standin(0, "HIGH", False, "a", 0, "R"),
            _standin(1, "HIGH", False, "a", None, "R"),
            _standin(2, "HIGH", False, "a", -1, "R"),
            _standin(3, "HIGH", False, "a", None, "R"),
        ]
        got = ReportContentEmitter.by_severity(rows, suppressed=[False] * 4)
        assert [row.index for row in got] == [2, 0, 1, 3]

    def test_a_row_whose_flag_is_none_sorts_as_live(self):
        flags = [True, None, False]
        positions = severity_order([(0, "a", 0, "r")] * 3, [bool(f) for f in flags])
        assert positions == [1, 2, 0]
        assert severity_order([(0, "a", 0, "r")] * 3, flags) == [1, 2, 0]

    def test_a_flag_count_that_differs_from_the_key_count_is_refused(self):
        with pytest.raises(ValueError):
            severity_order([(0, "a", 0, "r")] * 2, [False])

    def test_no_keys_with_flags_is_empty(self):
        assert severity_order([], []) == []


def REFERENCE_PLACE_KEY(row):
    """The emitter's own sort key, as written before the flags were added."""
    return (
        _EMITTER_ORDER.get(str(row.severity).upper(), len(_EMITTER_ORDER)),
        row.file_path or "",
        row.line_start or 0,
        row.rule_id or "",
    )
