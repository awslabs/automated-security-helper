# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization goldens for ``report_content_emitter``.

These tests pin what the module does today, not what it should do. They exist so
that the counts, group-bys and top-N aggregations the reporters share can be
re-implemented (on a dataframe, say) and proven byte-identical: a failing test
here after such a change means observable output moved. Ordering and tie-break
rules are part of that output, so they are pinned with literal expected values,
including the cases where the rule is only an accident of insertion order
(``Counter.most_common`` and the stable sort in the detailed findings).

Nothing here asserts a behavior is *right*. Where the current answer looks odd
(a negative hotspot limit returning nothing, an unknown severity counted as its
own lower-cased bucket) the test says so in a comment and pins it anyway.
"""

import json
from datetime import timedelta, timezone

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
    _SEVERITY_ORDER,
    _UNLISTED_SEVERITY_PLACE,
    _location_snippet,
    _snippet_text,
    coverage_shortfall_text,
    parse_scan_time,
    refuse_negative_limit,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.unit.models._flat_vulnerability_helpers import flat_with_severity

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _vuln(**overrides) -> FlatVulnerability:
    fields = {
        "id": "f-1",
        "title": "a finding",
        "description": "",
        "severity": "MEDIUM",
        "scanner": "bandit",
        "scanner_type": "SAST",
    }
    fields.update(overrides)
    severity = fields.pop("severity")
    return flat_with_severity(severity, **fields)


def _emitter(vulns) -> ReportContentEmitter:
    """An emitter over the default (empty) model whose findings are *vulns*.

    The default model records no config, so every finding is graded at ASH's
    default gate (MEDIUM): MEDIUM and above are actionable, LOW and INFO are not,
    and a severity the ladder does not know fails closed (actionable).
    """
    emitter = ReportContentEmitter(AshAggregatedResults())
    emitter.flat_vulns = list(vulns)
    return emitter


def _sarif_model(results, *, scanners=("bandit",)) -> AshAggregatedResults:
    """A model whose SARIF holds *results* (``(rule, level, path, props)``)."""
    model = AshAggregatedResults()
    model.ash_config = None
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": [
                        {
                            "ruleId": rule,
                            "level": level,
                            "message": {"text": f"{rule} message"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": path},
                                        "region": {"startLine": 3},
                                    }
                                }
                            ],
                            "properties": {"scanner_name": scanner, **props},
                        }
                        for rule, level, path, scanner, props in results
                    ],
                    "invocations": [],
                }
            ],
        }
    )
    for name in scanners:
        model.scanner_results[name] = ScannerTargetStatusInfo(duration=1.5)
    return model


# --------------------------------------------------------------------------
# Module-level helpers
# --------------------------------------------------------------------------


class TestParseScanTime:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("2026-01-15T12:30:45", "2026-01-15T12:30:45+00:00"),
            ("2026-01-15T12:30:45Z", "2026-01-15T12:30:45+00:00"),
            ("2026-01-15T12:30:45.987654", "2026-01-15T12:30:45+00:00"),
            ("2026-01-15T12:30:45.5Z", "2026-01-15T12:30:45+00:00"),
            ("2026-01-15T12:30:45+05:30", "2026-01-15T12:30:45+05:30"),
            ("2026-01-15T12:30:45-08:00", "2026-01-15T12:30:45-08:00"),
            ("2026-01-15 - 12:00 (UTC)", "2026-01-15T12:00:00+00:00"),
            ("2026-01-15 12:30:45", "2026-01-15T12:30:45+00:00"),
            ("  2026-01-15T12:30:45  ", "2026-01-15T12:30:45+00:00"),
        ],
    )
    def test_each_recorded_layout_names_one_instant(self, text, expected):
        parsed = parse_scan_time(text)
        assert parsed is not None
        assert parsed.isoformat() == expected

    @pytest.mark.parametrize(
        "text",
        ["", "Unknown", "yesterday", "2026-13-45T00:00:00", "15/01/2026", "2026-01-15"],
    )
    def test_an_unreadable_time_is_none(self, text):
        assert parse_scan_time(text) is None

    def test_an_offset_is_the_zone_the_time_was_written_in(self):
        east = parse_scan_time("2026-01-15T12:00:00+02:00")
        utc = parse_scan_time("2026-01-15T10:00:00Z")
        assert east == utc
        assert east.utcoffset() == timedelta(hours=2)
        assert utc.utcoffset() == timedelta(0)
        assert utc.tzinfo is timezone.utc

    def test_an_out_of_range_offset_is_none(self):
        assert parse_scan_time("2026-01-15T12:00:00+99:99") is None


class TestCoverageShortfallText:
    def test_an_unknown_size_row(self):
        text = coverage_shortfall_text(None, None)
        assert text == (
            "coverage unknown; how many targets it evaluated could not be "
            "determined, so that count is not known"
        )
        assert coverage_shortfall_text(5, None) == text
        assert coverage_shortfall_text(None, 2) == text

    def test_a_partial_loss(self):
        assert coverage_shortfall_text(10, 3) == (
            "evaluated 7 of 10 target(s); 3 could not be evaluated"
        )

    def test_a_total_loss(self):
        assert coverage_shortfall_text(4, 4) == (
            "evaluated 0 of 4 target(s); 4 could not be evaluated"
        )

    def test_failed_above_attempted_never_prints_a_negative_evaluated_count(self):
        assert coverage_shortfall_text(2, 5) == (
            "evaluated 0 of 2 target(s); 5 could not be evaluated"
        )

    def test_zero_attempted_zero_failed(self):
        assert coverage_shortfall_text(0, 0) == (
            "evaluated 0 of 0 target(s); 0 could not be evaluated"
        )


class TestRefuseNegativeLimit:
    @pytest.mark.parametrize("value", [0, 1, 20, 10_000])
    def test_zero_and_up_pass_through(self, value):
        assert refuse_negative_limit(value) == value

    @pytest.mark.parametrize("value", [-1, -20])
    def test_a_negative_number_is_refused_with_this_text(self, value):
        with pytest.raises(ValueError) as raised:
            refuse_negative_limit(value)
        assert str(raised.value) == (
            "must be 0 or more: 0 lists none, and a negative number would drop "
            "the last items instead"
        )


class TestSnippetHelpers:
    def test_snippet_text_reads_a_string_or_an_objects_text_only(self):
        assert _snippet_text("x = 1") == "x = 1"
        assert _snippet_text("") == ""
        assert _snippet_text({"text": "y = 2"}) == "y = 2"
        assert _snippet_text({"text": ""}) == ""
        assert _snippet_text({"text": 5}) is None
        assert _snippet_text({"binary": "AA=="}) is None
        assert _snippet_text(5) is None
        assert _snippet_text(["x"]) is None
        assert _snippet_text(None) is None

    def test_a_location_reads_context_region_before_region(self):
        location = {
            "physicalLocation": {
                "region": {"snippet": {"text": "from region"}},
                "contextRegion": {"snippet": {"text": "from context"}},
            }
        }
        assert _location_snippet(location) == "from context"

    def test_a_location_falls_back_to_region_when_context_has_no_text(self):
        location = {
            "physicalLocation": {
                "contextRegion": {"snippet": {"text": ""}},
                "region": {"snippet": {"text": "from region"}},
            }
        }
        assert _location_snippet(location) == "from region"

    @pytest.mark.parametrize(
        "location",
        [
            None,
            "text",
            [],
            {},
            {"physicalLocation": None},
            {"physicalLocation": {}},
            {"physicalLocation": {"region": "nope"}},
            {"physicalLocation": {"region": {"snippet": 7}}},
        ],
        ids=repr,
    )
    def test_anything_else_is_none(self, location):
        assert _location_snippet(location) is None


# --------------------------------------------------------------------------
# Top hotspots: Counter + most_common
# --------------------------------------------------------------------------


class TestTopHotspots:
    def test_no_findings_is_an_empty_list(self):
        assert _emitter([]).get_top_hotspots() == []

    def test_only_actionable_findings_with_a_file_path_are_counted(self):
        emitter = _emitter(
            [
                _vuln(severity="HIGH", file_path="a.py"),
                _vuln(severity="HIGH", file_path="a.py", is_suppressed=True),
                _vuln(severity="LOW", file_path="a.py"),
                _vuln(severity="INFO", file_path="b.py"),
                _vuln(severity="HIGH", file_path=None),
                _vuln(severity="HIGH", file_path=""),
                _vuln(severity="CRITICAL", file_path="c.py"),
            ]
        )
        assert emitter.get_top_hotspots() == [
            {"location": "a.py", "count": 1},
            {"location": "c.py", "count": 1},
        ]

    def test_every_finding_below_the_gate_gives_no_hotspots(self):
        emitter = _emitter(
            [
                _vuln(severity="LOW", file_path="a.py"),
                _vuln(severity="INFO", file_path="b.py"),
            ]
        )
        assert emitter.get_top_hotspots() == []

    def test_most_findings_first_and_ties_keep_first_seen_order(self):
        # a:1 b:3 c:2 d:3 e:2, seen in that first-appearance order.
        order = ["a", "b", "c", "d", "e", "b", "c", "d", "b", "d", "e"]
        emitter = _emitter([_vuln(severity="HIGH", file_path=f"{n}.py") for n in order])
        assert emitter.get_top_hotspots() == [
            {"location": "b.py", "count": 3},
            {"location": "d.py", "count": 3},
            {"location": "c.py", "count": 2},
            {"location": "e.py", "count": 2},
            {"location": "a.py", "count": 1},
        ]

    def test_a_tie_follows_input_order_not_name_order(self):
        reversed_names = ["z.py", "m.py", "a.py"]
        emitter = _emitter(
            [_vuln(severity="HIGH", file_path=n) for n in reversed_names]
        )
        assert [row["location"] for row in emitter.get_top_hotspots()] == reversed_names

    def test_the_default_limit_is_ten(self):
        emitter = _emitter(
            [_vuln(severity="HIGH", file_path=f"f{i:02d}.py") for i in range(15)]
        )
        names = [row["location"] for row in emitter.get_top_hotspots()]
        assert names == [f"f{i:02d}.py" for i in range(10)]

    @pytest.mark.parametrize(
        ("limit", "expected_count"),
        [(0, 0), (1, 1), (3, 3), (5, 5), (6, 5), (1000, 5)],
    )
    def test_limit_bounds_the_rows(self, limit, expected_count):
        emitter = _emitter(
            [_vuln(severity="HIGH", file_path=f"f{i}.py") for i in range(5)]
        )
        assert len(emitter.get_top_hotspots(limit)) == expected_count

    def test_a_negative_limit_returns_nothing(self):
        # Counter.most_common(-1) is an empty list, not "all but the last".
        emitter = _emitter([_vuln(severity="HIGH", file_path="a.py")])
        assert emitter.get_top_hotspots(-1) == []
        assert emitter.get_top_hotspots(-50) == []

    def test_paths_are_distinct_keys_exactly_as_written(self):
        emitter = _emitter(
            [
                _vuln(severity="HIGH", file_path="src/a.py"),
                _vuln(severity="HIGH", file_path="./src/a.py"),
                _vuln(severity="HIGH", file_path="src/A.py"),
                _vuln(severity="HIGH", file_path="src/a.py"),
                _vuln(severity="HIGH", file_path="src/a.py "),
            ]
        )
        assert emitter.get_top_hotspots() == [
            {"location": "src/a.py", "count": 2},
            {"location": "./src/a.py", "count": 1},
            {"location": "src/A.py", "count": 1},
            {"location": "src/a.py ", "count": 1},
        ]

    def test_unicode_paths_are_kept_whole(self):
        emitter = _emitter(
            [
                _vuln(severity="HIGH", file_path="src/café/テスト.py"),
                _vuln(severity="HIGH", file_path="src/café/テスト.py"),
                _vuln(severity="HIGH", file_path="src/café/a.py"),
                _vuln(severity="HIGH", file_path="файл.py"),
            ]
        )
        # NFC "café" and NFD "café" are different keys.
        assert emitter.get_top_hotspots() == [
            {"location": "src/café/テスト.py", "count": 2},
            {"location": "src/café/a.py", "count": 1},
            {"location": "файл.py", "count": 1},
        ]

    def test_an_unknown_severity_is_actionable_so_it_counts(self):
        emitter = _emitter(
            [
                _vuln(severity="BOGUS", file_path="a.py"),
                _vuln(severity="", file_path="a.py"),
            ]
        )
        assert emitter.get_top_hotspots() == [{"location": "a.py", "count": 2}]

    def test_large_n_counts_are_non_increasing_and_ties_keep_first_seen_order(self):
        # 120 files; file i gets (i * 7) % 5 + 1 findings, interleaved round-robin
        # so each file's first appearance is by i.
        wanted = {i: (i * 7) % 5 + 1 for i in range(120)}
        vulns = []
        for round_ in range(5):
            for i in range(120):
                if wanted[i] > round_:
                    vulns.append(_vuln(severity="HIGH", file_path=f"p/{i:03d}.py"))
        rows = _emitter(vulns).get_top_hotspots(120)
        assert len(rows) == 120
        counts = [row["count"] for row in rows]
        assert counts == sorted(counts, reverse=True)
        assert sum(counts) == len(vulns) == 360
        by_count: dict[int, list[str]] = {}
        for row in rows:
            by_count.setdefault(row["count"], []).append(row["location"])
        assert {c: len(names) for c, names in by_count.items()} == {
            5: 24,
            4: 24,
            3: 24,
            2: 24,
            1: 24,
        }
        for names in by_count.values():
            assert names == sorted(names)

    def test_large_n_golden_head(self):
        wanted = {i: (i * 7) % 5 + 1 for i in range(120)}
        vulns = []
        for round_ in range(5):
            for i in range(120):
                if wanted[i] > round_:
                    vulns.append(_vuln(severity="HIGH", file_path=f"p/{i:03d}.py"))
        rows = _emitter(vulns).get_top_hotspots(8)
        # Files i with (i * 7) % 5 == 4, i.e. i % 5 == 2, hold 5 findings each.
        assert rows == [
            {"location": "p/002.py", "count": 5},
            {"location": "p/007.py", "count": 5},
            {"location": "p/012.py", "count": 5},
            {"location": "p/017.py", "count": 5},
            {"location": "p/022.py", "count": 5},
            {"location": "p/027.py", "count": 5},
            {"location": "p/032.py", "count": 5},
            {"location": "p/037.py", "count": 5},
        ]

    def test_the_same_file_under_two_scanners_is_one_hotspot(self):
        emitter = _emitter(
            [
                _vuln(severity="HIGH", file_path="a.py", scanner="bandit"),
                _vuln(severity="HIGH", file_path="a.py", scanner="semgrep"),
            ]
        )
        assert emitter.get_top_hotspots() == [{"location": "a.py", "count": 2}]


# --------------------------------------------------------------------------
# Findings overview and detailed findings: filter, sort, slice
# --------------------------------------------------------------------------


class TestFindingsOverview:
    def test_every_finding_is_a_row_in_input_order(self):
        emitter = _emitter(
            [
                _vuln(
                    severity="LOW",
                    scanner="b",
                    rule_id="R2",
                    title="t2",
                    file_path="x.py",
                ),
                _vuln(
                    severity="HIGH",
                    scanner="a",
                    rule_id="R1",
                    title="t1",
                    file_path="y.py",
                ),
            ]
        )
        assert emitter.get_findings_overview() == [
            {
                "severity": "LOW",
                "scanner": "b",
                "rule_id": "R2",
                "title": "t2",
                "file_path": "x.py",
            },
            {
                "severity": "HIGH",
                "scanner": "a",
                "rule_id": "R1",
                "title": "t1",
                "file_path": "y.py",
            },
        ]

    def test_missing_fields_read_as_their_stand_ins(self):
        emitter = _emitter(
            [_vuln(severity="", scanner="", rule_id=None, title="", file_path=None)]
        )
        assert emitter.get_findings_overview() == [
            {
                "severity": "UNKNOWN",
                "scanner": "Unknown",
                "rule_id": "N/A",
                "title": "Unknown Issue",
                "file_path": "N/A",
            }
        ]

    def test_suppressed_findings_are_listed_too(self):
        emitter = _emitter([_vuln(is_suppressed=True)])
        assert len(emitter.get_findings_overview()) == 1

    def test_no_findings(self):
        assert _emitter([]).get_findings_overview() == []


class TestSeveritySortKey:
    def test_the_severity_table_and_the_unlisted_place(self):
        assert _SEVERITY_ORDER == {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        assert _UNLISTED_SEVERITY_PLACE == 5

    def test_the_key_is_severity_place_file_line_rule(self):
        key = ReportContentEmitter._severity_sort_key(
            _vuln(severity="High", file_path="a.py", line_start=7, rule_id="R")
        )
        assert key == (1, "a.py", 7, "R")

    def test_missing_parts_sort_as_empty_and_zero(self):
        key = ReportContentEmitter._severity_sort_key(
            _vuln(severity="LOW", file_path=None, line_start=None, rule_id=None)
        )
        assert key == (3, "", 0, "")

    @pytest.mark.parametrize("severity", ["", "UNKNOWN", "BOGUS", "moderate"])
    def test_an_unlisted_severity_sorts_after_info(self, severity):
        key = ReportContentEmitter._severity_sort_key(_vuln(severity=severity))
        assert key[0] == 5


class TestDetailedFindings:
    def test_no_findings(self):
        assert _emitter([]).get_detailed_findings() == []

    def test_only_actionable_findings_are_detailed(self):
        emitter = _emitter(
            [
                _vuln(severity="LOW", rule_id="LOW-1"),
                _vuln(severity="INFO", rule_id="INFO-1"),
                _vuln(severity="HIGH", rule_id="HIGH-1", is_suppressed=True),
                _vuln(severity="HIGH", rule_id="HIGH-2"),
            ]
        )
        assert [row["rule_id"] for row in emitter.get_detailed_findings()] == ["HIGH-2"]

    def test_order_is_severity_then_file_then_line_then_rule(self):
        emitter = _emitter(
            [
                _vuln(severity="MEDIUM", file_path="a.py", line_start=1, rule_id="M"),
                _vuln(severity="HIGH", file_path="b.py", line_start=9, rule_id="Z"),
                _vuln(severity="HIGH", file_path="b.py", line_start=9, rule_id="A"),
                _vuln(severity="HIGH", file_path="b.py", line_start=2, rule_id="Q"),
                _vuln(severity="HIGH", file_path="a.py", line_start=50, rule_id="Q"),
                _vuln(severity="CRITICAL", file_path="z.py", line_start=1, rule_id="C"),
                _vuln(severity="HIGH", file_path=None, line_start=None, rule_id=None),
                _vuln(severity="BOGUS", file_path="a.py", line_start=1, rule_id="B"),
            ]
        )
        got = [
            (row["severity"], row["location"], row["rule_id"])
            for row in emitter.get_detailed_findings()
        ]
        assert got == [
            ("CRITICAL", "z.py:1", "C"),
            ("HIGH", "N/A", "N/A"),
            ("HIGH", "a.py:50", "Q"),
            ("HIGH", "b.py:2", "Q"),
            ("HIGH", "b.py:9", "A"),
            ("HIGH", "b.py:9", "Z"),
            ("MEDIUM", "a.py:1", "M"),
            ("BOGUS", "a.py:1", "B"),
        ]

    def test_findings_equal_on_every_key_keep_input_order(self):
        emitter = _emitter(
            [
                _vuln(
                    severity="HIGH",
                    file_path="a.py",
                    line_start=1,
                    rule_id="R",
                    title=t,
                )
                for t in ("third", "first", "second")
            ]
        )
        assert [row["title"] for row in emitter.get_detailed_findings()] == [
            "third",
            "first",
            "second",
        ]

    def test_the_default_cap_is_twenty(self):
        emitter = _emitter(
            [
                _vuln(severity="HIGH", file_path=f"f{i:02d}.py", rule_id=f"R{i}")
                for i in range(30)
            ]
        )
        rows = emitter.get_detailed_findings()
        assert len(rows) == 20
        assert rows[0]["location"] == "f00.py"
        assert rows[-1]["location"] == "f19.py"

    @pytest.mark.parametrize(
        ("limit", "expected"),
        [(0, 0), (1, 1), (4, 4), (7, 7), (99, 7), (-1, 0), (-99, 0)],
    )
    def test_the_cap_and_a_negative_cap(self, limit, expected):
        emitter = _emitter(
            [_vuln(severity="HIGH", file_path=f"f{i}.py") for i in range(7)]
        )
        assert len(emitter.get_detailed_findings(limit)) == expected

    def test_the_detailed_row_has_exactly_these_keys_in_this_order(self):
        (row,) = _emitter(
            [
                _vuln(
                    severity="HIGH",
                    title="t",
                    scanner="s",
                    rule_id="r",
                    file_path="f.py",
                    line_start=3,
                    description="d",
                    cve_id="CVE-1",
                    cwe_id="CWE-2",
                    code_snippet="x = 1",
                )
            ]
        ).get_detailed_findings()
        assert list(row) == [
            "title",
            "severity",
            "scanner",
            "rule_id",
            "location",
            "description",
            "cve_id",
            "cwe_id",
            "code_snippet",
        ]
        assert row == {
            "title": "t",
            "severity": "HIGH",
            "scanner": "s",
            "rule_id": "r",
            "location": "f.py:3",
            "description": "d",
            "cve_id": "CVE-1",
            "cwe_id": "CWE-2",
            "code_snippet": "x = 1",
        }

    def test_missing_fields_read_as_their_stand_ins(self):
        (row,) = _emitter(
            [
                _vuln(
                    severity="BOGUS",
                    title="",
                    scanner="",
                    rule_id=None,
                    file_path=None,
                    description="",
                )
            ]
        ).get_detailed_findings()
        assert row == {
            "title": "Unknown Issue",
            "severity": "BOGUS",
            "scanner": "Unknown",
            "rule_id": "N/A",
            "location": "N/A",
            "description": "",
            "cve_id": None,
            "cwe_id": None,
            "code_snippet": None,
        }

    def test_unicode_is_carried_through_unchanged(self):
        (row,) = _emitter(
            [
                _vuln(
                    severity="HIGH",
                    title="タイトル ☃",
                    file_path="файл.py",
                    line_start=2,
                    description="éè",
                )
            ]
        ).get_detailed_findings()
        assert row["title"] == "タイトル ☃"
        assert row["location"] == "файл.py:2"
        assert row["description"] == "éè"


class TestDetailedFindingLocation:
    @pytest.mark.parametrize(
        ("path", "start", "end", "expected"),
        [
            (None, None, None, "N/A"),
            (None, 5, 9, "N/A"),
            ("a.py", None, None, "a.py"),
            ("a.py", None, 9, "a.py"),
            ("a.py", 0, 9, "a.py"),
            ("a.py", 5, None, "a.py:5"),
            ("a.py", 5, 0, "a.py:5"),
            ("a.py", 5, 5, "a.py:5"),
            ("a.py", 5, 9, "a.py:5-9"),
            ("a.py", 9, 5, "a.py:9-5"),
        ],
    )
    def test_location_text(self, path, start, end, expected):
        row = _emitter([])._create_detailed_finding(
            _vuln(file_path=path, line_start=start, line_end=end)
        )
        assert row["location"] == expected


# --------------------------------------------------------------------------
# Policy-not-gating
# --------------------------------------------------------------------------


class TestPolicyNotGatingFindings:
    def test_with_no_policy_gate_off_nothing_is_left_out(self):
        emitter = _emitter([_vuln(severity="HIGH")])
        assert emitter.get_policy_not_gating_findings() == []
        assert not emitter.is_policy_not_gating(emitter.flat_vulns[0])

    def test_left_out_findings_are_sorted_and_capped(self):
        emitter = _emitter(
            [
                _vuln(
                    severity="LOW", rule_id="L", file_path="a.py", workspace_project="p"
                ),
                _vuln(
                    severity="CRITICAL",
                    rule_id="C",
                    file_path="b.py",
                    workspace_project="p",
                ),
                _vuln(
                    severity="HIGH",
                    rule_id="H",
                    file_path="c.py",
                    workspace_project="p",
                ),
                _vuln(
                    severity="HIGH",
                    rule_id="X",
                    file_path="d.py",
                    workspace_project="q",
                ),
            ]
        )
        emitter._policy_not_gating = {"p"}
        emitter._is_policy_origin_finding = lambda vuln: True  # type: ignore[method-assign]

        rows = emitter.get_policy_not_gating_findings()
        assert [row["rule_id"] for row in rows] == ["C", "H", "L"]
        assert [
            row["rule_id"] for row in emitter.get_policy_not_gating_findings(2)
        ] == [
            "C",
            "H",
        ]
        assert emitter.get_policy_not_gating_findings(0) == []
        assert emitter.get_policy_not_gating_findings(-3) == []
        assert rows[0] == {
            "severity": "CRITICAL",
            "scanner": "bandit",
            "rule_id": "C",
            "title": "a finding",
            "file_path": "b.py",
        }

    def test_a_left_out_finding_is_not_actionable_and_not_a_hotspot(self):
        emitter = _emitter(
            [_vuln(severity="HIGH", file_path="a.py", workspace_project="p")]
        )
        emitter._policy_not_gating = {"p"}
        emitter._is_policy_origin_finding = lambda vuln: True  # type: ignore[method-assign]
        assert emitter.get_top_hotspots() == []
        assert emitter.get_detailed_findings() == []

    def test_a_suppressed_finding_is_never_left_out(self):
        emitter = _emitter(
            [_vuln(severity="HIGH", workspace_project="p", is_suppressed=True)]
        )
        emitter._policy_not_gating = {"p"}
        emitter._is_policy_origin_finding = lambda vuln: True  # type: ignore[method-assign]
        assert emitter.get_policy_not_gating_findings() == []

    @pytest.mark.parametrize(
        ("properties", "expected"),
        [
            (None, False),
            ("", False),
            ("not json", False),
            ("[]", False),
            ('{"origin": "workspace-policy"}', True),
            ('{"origin": "scanner"}', False),
            ('{"tags": ["workspace-policy"]}', False),
        ],
    )
    def test_policy_origin_is_read_from_the_origin_property_alone(
        self, properties, expected
    ):
        assert (
            ReportContentEmitter._is_policy_origin_finding(_vuln(properties=properties))
            is expected
        )


# --------------------------------------------------------------------------
# Code snippet extraction
# --------------------------------------------------------------------------


class TestExtractCodeSnippet:
    @staticmethod
    def _extract(**fields):
        return _emitter([])._extract_code_snippet(_vuln(**fields))

    @staticmethod
    def _raw(value):
        return json.dumps(value)

    def test_the_flat_code_snippet_wins_over_the_raw_data(self):
        assert (
            self._extract(code_snippet="flat", raw_data=self._raw({"snippet": "raw"}))
            == "flat"
        )

    def test_no_raw_data_is_none(self):
        assert self._extract() is None
        assert self._extract(raw_data="") is None

    @pytest.mark.parametrize("raw", ["not json", "[1, 2]", '"text"', "7", "null"])
    def test_raw_data_that_is_not_a_json_object_is_none(self, raw):
        assert self._extract(raw_data=raw) is None

    def test_the_snippet_key_comes_first(self):
        raw = {
            "snippet": "top",
            "locations": [
                {"physicalLocation": {"region": {"snippet": {"text": "loc"}}}}
            ],
        }
        assert self._extract(raw_data=self._raw(raw)) == "top"

    def test_an_empty_snippet_key_falls_through_to_the_locations(self):
        raw = {
            "snippet": {"text": ""},
            "locations": [
                {"physicalLocation": {"region": {"snippet": {"text": "loc"}}}}
            ],
        }
        assert self._extract(raw_data=self._raw(raw)) == "loc"

    def test_the_first_location_with_text_wins(self):
        raw = {
            "locations": [
                {"physicalLocation": {"region": {"snippet": {"text": ""}}}},
                {
                    "physicalLocation": {
                        "contextRegion": {"snippet": {"text": "second"}}
                    }
                },
                {"physicalLocation": {"region": {"snippet": {"text": "third"}}}},
            ]
        }
        assert self._extract(raw_data=self._raw(raw)) == "second"

    def test_a_code_flow_location_is_read_after_the_locations(self):
        raw = {
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {"snippet": {"text": ""}},
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "region": {"snippet": {"text": "flow"}}
                                        }
                                    }
                                },
                            ]
                        }
                    ]
                }
            ]
        }
        assert self._extract(raw_data=self._raw(raw)) == "flow"

    def test_a_code_flow_locations_own_snippet_is_read_first(self):
        raw = {
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "snippet": "direct",
                                    "location": {
                                        "physicalLocation": {
                                            "region": {"snippet": {"text": "wrapped"}}
                                        }
                                    },
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        assert self._extract(raw_data=self._raw(raw)) == "direct"

    def test_a_message_fence_is_read_with_the_flatteners_reader(self):
        raw = {"message": {"text": "found it\n```python\nx = 1\ny = 2\n```\nmore"}}
        assert self._extract(raw_data=self._raw(raw)) == "x = 1\ny = 2"

    def test_a_message_with_no_fence_gives_nothing(self):
        raw = {"message": {"text": "just words"}}
        assert self._extract(raw_data=self._raw(raw)) is None

    @pytest.mark.parametrize(
        "message",
        [{"text": 5}, {"text": None}, {"other": "x"}, "text", 5, None],
        ids=repr,
    )
    def test_a_message_that_is_not_text_is_none(self, message):
        assert self._extract(raw_data=self._raw({"message": message})) is None

    def test_an_object_with_no_snippet_anywhere_is_none(self):
        assert self._extract(raw_data=self._raw({"ruleId": "R"})) is None

    def test_malformed_locations_do_not_raise(self):
        raw = {"locations": "nope", "codeFlows": [{"threadFlows": [{"locations": []}]}]}
        assert self._extract(raw_data=self._raw(raw)) is None

    def test_a_code_flow_location_that_is_not_an_object_is_swallowed(self):
        # loc.get() raises AttributeError on a string; the broad except returns None.
        raw = {"codeFlows": [{"threadFlows": [{"locations": ["bare string"]}]}]}
        assert self._extract(raw_data=self._raw(raw)) is None

    def test_unicode_snippet_text_is_returned_whole(self):
        raw = {"snippet": "s = 'テスト ☃'"}
        assert self._extract(raw_data=self._raw(raw)) == "s = 'テスト ☃'"


# --------------------------------------------------------------------------
# Scanner rows, scan summary
# --------------------------------------------------------------------------


class TestScannerResults:
    def test_no_scanners_no_rows(self):
        assert ReportContentEmitter(AshAggregatedResults()).get_scanner_results() == []

    def test_a_row_has_these_keys_in_this_order(self):
        model = _sarif_model(
            [("R1", "warning", "a.py", "bandit", {})], scanners=("bandit",)
        )
        (row,) = ReportContentEmitter(model).get_scanner_results()
        assert list(row) == [
            "scanner_name",
            "suppressed",
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "total",
            "passed",
            "threshold",
            "threshold_source",
            "actionable",
            "status",
            "excluded",
            "dependencies_missing",
            "missing_reason",
            "skipped_reason",
            "duration",
            "targets_attempted",
            "targets_failed",
            "counters_unusable",
        ]
        assert row["scanner_name"] == "bandit"
        assert row["medium"] == 1
        assert row["total"] == 1
        assert row["actionable"] == 1
        assert row["status"] == "FAILED"
        assert row["duration"] == 1.5

    def test_rows_follow_the_scanner_metrics_order(self):
        model = _sarif_model(
            [
                ("R1", "warning", "a.py", "semgrep", {}),
                ("R2", "note", "b.py", "bandit", {}),
            ],
            scanners=("semgrep", "bandit"),
        )
        names = [
            row["scanner_name"]
            for row in ReportContentEmitter(model).get_scanner_results()
        ]
        assert names == [
            m.scanner_name for m in ReportContentEmitter(model).scanner_metrics
        ]
        assert sorted(names) == ["bandit", "semgrep"]


class TestScanSummary:
    def test_an_empty_model(self):
        summary = ReportContentEmitter(AshAggregatedResults()).get_scan_summary()
        assert list(summary) == [
            "title",
            "tone",
            "description",
            "next_step",
            "actionable",
            "active",
            "below_threshold",
            "policy_not_gating",
            "suppressed",
            "counts",
            "completed",
            "scanners",
            "skipped",
            "unavailable",
            "unavailable_count",
            "shortfalls",
            "stale",
            "converter_gaps",
            "unevaluated_rules",
            "could_not_stop",
        ]
        assert summary["title"] == "No scanners completed"
        assert summary["tone"] == "warning"
        assert summary["counts"] == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        assert summary["completed"] == 0
        assert summary["scanners"] == 0
        assert summary["actionable"] == 0
        assert summary["active"] == 0

    def test_findings_with_no_scanner_rows_are_counted_from_the_flat_findings(self):
        emitter = _emitter(
            [
                _vuln(severity="CRITICAL"),
                _vuln(severity="HIGH"),
                _vuln(severity="HIGH"),
                _vuln(severity="LOW"),
                _vuln(severity="INFO"),
                _vuln(severity="HIGH", is_suppressed=True),
                _vuln(severity="Moderate"),
                _vuln(severity=""),
            ]
        )
        summary = emitter.get_scan_summary()
        # The first five plus the stand-in names: the suppressed one is not counted
        # under a bucket, and a name outside the five gets a bucket of its own.
        assert summary["counts"] == {
            "critical": 1,
            "high": 2,
            "medium": 0,
            "low": 1,
            "info": 1,
            "moderate": 1,
            "unknown": 1,
        }
        assert summary["suppressed"] == 1
        # CRITICAL + 2 HIGH + the two unrecognised severities (fail closed).
        assert summary["actionable"] == 5
        assert summary["active"] == 7
        assert summary["below_threshold"] == 2
        assert summary["title"] == "No scanners completed"

    def test_scanner_rows_sum_into_the_counts(self):
        model = _sarif_model(
            [
                ("R1", "error", "a.py", "bandit", {}),
                ("R2", "warning", "a.py", "bandit", {}),
                ("R3", "warning", "b.py", "semgrep", {}),
                ("R4", "note", "c.py", "semgrep", {}),
                ("R5", "none", "d.py", "semgrep", {}),
            ],
            scanners=("bandit", "semgrep"),
        )
        summary = ReportContentEmitter(model).get_scan_summary()
        assert summary["counts"] == {
            # SARIF level "error" is graded CRITICAL, not HIGH.
            "critical": 1,
            "high": 0,
            "medium": 2,
            "low": 1,
            "info": 1,
        }
        assert summary["actionable"] == 3
        assert summary["active"] == 5
        assert summary["below_threshold"] == 2
        assert summary["scanners"] == 2
        assert summary["completed"] == 2
        assert summary["skipped"] == 0
        assert summary["unavailable"] == []
        assert summary["unavailable_count"] == 0
        assert summary["title"] == "Review required"
        assert summary["tone"] == "danger"
        assert summary["description"] == (
            "3 findings at or above the configured scanner thresholds."
        )
        assert summary["next_step"] == (
            "Review findings by severity, then inspect the source."
        )

    def test_one_actionable_finding_reads_in_the_singular(self):
        model = _sarif_model(
            [("R1", "warning", "a.py", "bandit", {})], scanners=("bandit",)
        )
        summary = ReportContentEmitter(model).get_scan_summary()
        assert summary["actionable"] == 1
        assert summary["description"] == (
            "1 finding at or above the configured scanner thresholds."
        )

    def test_a_clean_run_reads_as_no_actionable_findings(self):
        model = _sarif_model(
            [("R1", "note", "a.py", "bandit", {})], scanners=("bandit",)
        )
        summary = ReportContentEmitter(model).get_scan_summary()
        assert summary["title"] == "No actionable findings"
        assert summary["tone"] == "success"
        assert summary["actionable"] == 0
        assert summary["below_threshold"] == 1
        assert summary["description"] == (
            "Completed scanners reported no findings at or above their configured "
            "thresholds."
        )
        assert summary["next_step"] == (
            "Review scanner coverage and findings below the threshold."
        )

    def test_a_listed_scanner_with_no_results_is_completed(self):
        model = _sarif_model([], scanners=("bandit", "semgrep"))
        summary = ReportContentEmitter(model).get_scan_summary()
        assert summary["scanners"] == 2
        assert summary["completed"] == 2
        assert summary["counts"] == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        assert summary["title"] == "No actionable findings"

    def test_findings_an_additional_report_lists_join_the_counts(self):
        model = _sarif_model(
            [("R1", "warning", "a.py", "bandit", {})], scanners=("bandit",)
        )
        extra = _vuln(severity="HIGH", scanner="plugin")
        extra._source_report = "plugin-report"
        suppressed_extra = _vuln(severity="HIGH", scanner="plugin", is_suppressed=True)
        suppressed_extra._source_report = "plugin-report"
        # An empty list marks the report list-form without the model flattening
        # any finding out of it.
        model.additional_reports["plugin-report"] = []
        emitter = ReportContentEmitter(model)
        emitter.flat_vulns = list(emitter.flat_vulns) + [extra, suppressed_extra]
        summary = emitter.get_scan_summary()
        assert summary["counts"]["high"] == 1
        assert summary["counts"]["medium"] == 1
        assert summary["suppressed"] == 1
        assert summary["actionable"] == 2


class TestAdditionalReportFindings:
    def test_only_list_form_reports_name_findings(self):
        model = AshAggregatedResults()
        model.additional_reports["listed"] = [{"a": 1}]
        model.additional_reports["mapped"] = {"source": {}}
        emitter = ReportContentEmitter(model)
        listed = _vuln()
        listed._source_report = "listed"
        mapped = _vuln()
        mapped._source_report = "mapped"
        plain = _vuln()
        emitter.flat_vulns = [listed, mapped, plain]
        assert emitter._additional_report_findings() == [listed]

    def test_no_list_reports_is_an_empty_list(self):
        model = AshAggregatedResults()
        emitter = ReportContentEmitter(model)
        emitter.flat_vulns = [_vuln()]
        assert emitter._additional_report_findings() == []


class TestMetadata:
    def test_an_unrecorded_scan_has_unknown_fields_and_no_delta(self):
        model = AshAggregatedResults()
        # A fresh model stamps its own generation time; clear it.
        model.metadata.generated_at = None
        metadata = ReportContentEmitter(model).get_metadata()
        assert list(metadata) == [
            "project",
            "scan_time",
            "report_time",
            "tool_version",
            "time_delta",
        ]
        assert metadata["scan_time"] == "Unknown"
        assert metadata["time_delta"] is None
        assert metadata["report_time"].endswith("+00:00")

    def test_a_readable_scan_time_gives_a_positive_delta(self):
        model = AshAggregatedResults()
        model.metadata.generated_at = "2020-01-01T00:00:00Z"
        model.metadata.project_name = "demo"
        metadata = ReportContentEmitter(model).get_metadata()
        assert metadata["project"] == "demo"
        assert metadata["scan_time"] == "2020-01-01T00:00:00Z"
        assert metadata["time_delta"] > timedelta(days=365)

    def test_an_unreadable_scan_time_is_shown_as_written_with_no_delta(self):
        model = AshAggregatedResults()
        model.metadata.generated_at = "last tuesday"
        metadata = ReportContentEmitter(model).get_metadata()
        assert metadata["scan_time"] == "last tuesday"
        assert metadata["time_delta"] is None
