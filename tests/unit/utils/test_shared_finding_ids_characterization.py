# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization of the positional join of flattened rows onto SARIF results.

``shared_ids_by_position`` pairs each result with the flattened row that describes
it. These tests hold the contract of the join as the object-walking implementation
had it. The oracle below is that implementation, copied here unchanged, and every
case is checked against it as well as against its expected value, so a change to
the join that moves any answer, on a table of cases or on a seeded random sweep,
fails here.
"""

from __future__ import annotations

import random
from types import SimpleNamespace
from typing import Any, List, Optional

import pytest

from automated_security_helper.utils.shared_finding_ids import (
    flat_describes_result,
    shared_ids_by_position,
)

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------
# The oracle: the object-walking join, as it was before the frame migration.
# --------------------------------------------------------------------------


def _ref_ids_by_position(flat: List[Any], results: List[Any]) -> List[Optional[str]]:
    rows = [item for item in flat if getattr(item, "source_report", None) is None]
    ids: List[Optional[str]] = []
    if len(rows) == len(results):
        for item, result in zip(rows, results):
            ids.append(_ref_usable_id(item) if _ref_describes(item, result) else None)
        return ids
    cursor = 0
    for result in results:
        paired = None
        for offset in range(cursor, len(rows)):
            if _ref_describes(rows[offset], result):
                paired = rows[offset]
                cursor = offset + 1
                break
        ids.append(_ref_usable_id(paired) if paired is not None else None)
    return ids


def _ref_usable_id(item: Any) -> Optional[str]:
    identifier = getattr(item, "id", None)
    if isinstance(identifier, str) and identifier:
        return identifier
    return None


def _ref_describes(item: Any, result: Any) -> bool:
    try:
        flat_rule = _ref_stripped(getattr(item, "rule_id", None))
        result_rule = _ref_stripped(getattr(result, "ruleId", None))
        if flat_rule != result_rule:
            return False
        flat_file = _ref_stripped(getattr(item, "file_path", None))
        if flat_file != _ref_stripped(_ref_first_file_path(result)):
            return False
        return getattr(item, "line_start", None) == _ref_first_start_line(result)
    except Exception:  # noqa: BLE001
        return False


def _ref_stripped(value: Any) -> Any:
    if isinstance(value, str):
        value = value.strip()
    return value or None


def _ref_first_start_line(result: Any) -> Optional[int]:
    locations = getattr(result, "locations", None) or []
    if not locations:
        return None
    physical = getattr(locations[0], "physicalLocation", None)
    root = getattr(physical, "root", None)
    if root is None:
        return None
    for name in ("region", "contextRegion"):
        region = getattr(root, name, None)
        line = getattr(region, "startLine", None) if region is not None else None
        if line is not None:
            return int(line)
    return None


def _ref_first_file_path(result: Any) -> Optional[str]:
    locations = getattr(result, "locations", None) or []
    if not locations:
        return None
    physical = getattr(locations[0], "physicalLocation", None)
    root = getattr(physical, "root", None)
    if root is None:
        return None
    artifact = getattr(root, "artifactLocation", None)
    uri = getattr(artifact, "uri", None) if artifact is not None else None
    if not uri:
        return None
    text = str(uri)
    if text.startswith("file://"):
        from automated_security_helper.utils.sarif_utils import (
            _file_uri_to_path_text,
        )

        text = _file_uri_to_path_text(text)
    return text or None


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def _row(identifier, rule, path, line=7, source_report=None):
    return SimpleNamespace(
        id=identifier,
        rule_id=rule,
        file_path=path,
        line_start=line,
        source_report=source_report,
    )


def _res(rule, uri="app/main.py", line=7, context_line=None, locations=True):
    if not locations:
        return SimpleNamespace(ruleId=rule, locations=[])
    region = SimpleNamespace(startLine=line) if line is not None else None
    context = (
        SimpleNamespace(startLine=context_line) if context_line is not None else None
    )
    root = SimpleNamespace(
        artifactLocation=SimpleNamespace(uri=uri) if uri is not None else None,
        region=region,
        contextRegion=context,
    )
    return SimpleNamespace(
        ruleId=rule,
        locations=[SimpleNamespace(physicalLocation=SimpleNamespace(root=root))],
    )


class _RaisingId:
    """A row whose id read raises, as a lazy property or proxy could."""

    rule_id = "R1"
    file_path = "app/main.py"
    line_start = 7
    source_report = None

    @property
    def id(self):
        raise RuntimeError("unreadable id")


class _RaisingRule:
    """A row whose rule read raises: it describes nothing, and the walk goes on."""

    id = "never"
    file_path = "app/main.py"
    line_start = 7
    source_report = None

    @property
    def rule_id(self):
        raise RuntimeError("unreadable rule")


def _both(flat, results):
    expected = _ref_ids_by_position(flat, results)
    assert shared_ids_by_position(flat, results) == expected
    return expected


# --------------------------------------------------------------------------
# Table of cases
# --------------------------------------------------------------------------


class TestEqualLengthPairsByPosition:
    def test_every_position_agrees(self):
        flat = [_row("a", "R1", "x.py"), _row("b", "R2", "y.py", 3)]
        results = [_res("R1", "x.py"), _res("R2", "y.py", 3)]
        assert _both(flat, results) == ["a", "b"]

    def test_a_disagreeing_position_is_none_and_costs_that_position_only(self):
        flat = [_row("a", "R1", "x.py"), _row("b", "R2", "y.py", 3)]
        results = [_res("R1", "x.py"), _res("R9", "y.py", 3)]
        assert _both(flat, results) == ["a", None]

    def test_equal_lengths_never_walk_to_a_later_row(self):
        flat = [_row("b", "R2", "y.py"), _row("a", "R1", "x.py")]
        results = [_res("R1", "x.py"), _res("R2", "y.py")]
        assert _both(flat, results) == [None, None]

    def test_an_empty_or_non_text_id_is_none(self):
        flat = [_row("", "R1", "x.py"), _row(None, "R2", "x.py"), _row(5, "R3", "x.py")]
        results = [_res("R1", "x.py"), _res("R2", "x.py"), _res("R3", "x.py")]
        assert _both(flat, results) == [None, None, None]

    def test_nothing_at_all(self):
        assert _both([], []) == []


class TestWalkWhenCountsDiffer:
    def test_an_extra_row_is_skipped(self):
        flat = [
            _row("a", "R1", "x.py"),
            _row("z", "R9", "q.py"),
            _row("b", "R2", "x.py"),
        ]
        results = [_res("R1", "x.py"), _res("R2", "x.py")]
        assert _both(flat, results) == ["a", "b"]

    def test_a_missing_row_costs_one_position(self):
        flat = [_row("a", "R1", "x.py"), _row("c", "R3", "x.py")]
        results = [_res("R1", "x.py"), _res("R2", "x.py"), _res("R3", "x.py")]
        assert _both(flat, results) == ["a", None, "c"]

    def test_the_walk_never_goes_back(self):
        flat = [
            _row("b", "R2", "x.py"),
            _row("a", "R1", "x.py"),
            _row("z", "Z", "z.py"),
        ]
        results = [_res("R1", "x.py"), _res("R2", "x.py")]
        assert _both(flat, results) == ["a", None]

    def test_a_row_is_taken_once(self):
        flat = [_row("a", "R1", "x.py"), _row("q", "Q", "q.py")]
        results = [_res("R1", "x.py"), _res("R1", "x.py"), _res("R1", "x.py")]
        assert _both(flat, results) == ["a", None, None]
        assert _both(flat + flat, results) == ["a", "a", None]

    def test_two_hits_of_one_rule_in_one_file_take_their_own_lines(self):
        flat = [
            _row("late", "R1", "x.py", 40),
            _row("early", "R1", "x.py", 4),
            _row("stray", "R9", "q.py"),
        ]
        results = [_res("R1", "x.py", 4), _res("R1", "x.py", 40)]
        assert _both(flat, results) == ["early", None]
        # Rows in the results' own order pair both hits.
        assert _both([flat[1], flat[0], flat[2]], results) == ["early", "late"]

    def test_results_with_no_rows_at_all(self):
        assert _both([], [_res("R1")]) == [None]

    def test_rows_with_no_results(self):
        assert _both([_row("a", "R1", "x.py")], []) == []


class TestSourceReportRowsTakePartInNothing:
    def test_additional_report_rows_are_left_out(self):
        flat = [
            _row("a", "R1", "x.py"),
            _row("n1", "R1", "x.py", source_report="npm"),
            _row("b", "R2", "x.py"),
        ]
        results = [_res("R1", "x.py"), _res("R2", "x.py")]
        assert _both(flat, results) == ["a", "b"]

    def test_an_additional_row_never_fills_a_missing_sarif_row(self):
        flat = [_row("a", "R1", "x.py"), _row("n2", "R2", "x.py", source_report="npm")]
        results = [_res("R1", "x.py"), _res("R2", "x.py")]
        assert _both(flat, results) == ["a", None]

    def test_an_item_with_no_source_report_attribute_is_a_sarif_row(self):
        bare = SimpleNamespace(id="a", rule_id="R1", file_path="x.py", line_start=7)
        assert _both([bare], [_res("R1", "x.py")]) == ["a"]


class TestWhatDescribesAResult:
    @pytest.mark.parametrize(
        "row, result",
        [
            (_row("a", " R1 ", " x.py "), _res("R1", "x.py")),
            (_row("a", "R1", "x.py"), _res(" R1", "x.py ")),
            (_row("a", "", "", None), _res(None, None, None)),
            (_row("a", None, None, None), _res("", "", None)),
            (_row("a", "R1", "x.py", 3), _res("R1", "x.py", None, context_line=3)),
            (_row("a", "R1", "x.py", 4), _res("R1", "x.py", 4, context_line=9)),
            (_row("a", "R1", None, None), _res("R1", locations=False)),
            (_row("a", "R1", "/a/b c.py"), _res("R1", "file:///a/b%20c.py")),
            (_row("a", "R1", "x.py", 2**70), _res("R1", "x.py", 2**70)),
            (_row("a", "R1", "x.py", True), _res("R1", "x.py", 1)),
            (_row("a", "R1", "x.py", 3.0), _res("R1", "x.py", 3)),
        ],
    )
    def test_pairs(self, row, result):
        assert _both([row], [result]) == ["a"]
        assert flat_describes_result(row, result) is True

    @pytest.mark.parametrize(
        "row, result",
        [
            (_row("a", "R1", "x.py", 3), _res("R1", "x.py", 4)),
            (_row("a", "R1", "x.py", None), _res("R1", "x.py", 4)),
            (_row("a", "R1", "x.py", 4), _res("R1", "x.py", None)),
            (_row("a", "R1", "x.py", 3.5), _res("R1", "x.py", 3)),
            (_row("a", "R1", "x.py", "3"), _res("R1", "x.py", 3)),
            (_row("a", "R1", "x.py"), _res("R2", "x.py")),
            (_row("a", "R1", "x.py"), _res("R1", "y.py")),
            (_row("a", "R1", "x.py"), _res("r1", "x.py")),
            (_row("a", "R1", "x.py", 7), _res("R1", "x.py", 7 + 2**70)),
            (_row("a", "R1", "x.py"), _res("R1", "x.py", "not a number")),
        ],
    )
    def test_does_not_pair(self, row, result):
        assert _both([row], [result]) == [None]
        assert flat_describes_result(row, result) is False


class TestReadsThatRaise:
    def test_an_unreadable_id_raises_out_of_the_join_only_when_it_is_paired(self):
        flat = [_RaisingId()]
        with pytest.raises(RuntimeError):
            shared_ids_by_position(flat, [_res("R1", "app/main.py")])
        with pytest.raises(RuntimeError):
            _ref_ids_by_position(flat, [_res("R1", "app/main.py")])
        # Not paired (another rule): the id is never read.
        assert _both(flat, [_res("R9", "app/main.py")]) == [None]
        # Walk, with the unreadable row after the paired one: never read.
        mixed = [_row("a", "R1", "app/main.py"), _RaisingId(), _row("c", "R2", "q.py")]
        assert _both(mixed, [_res("R1", "app/main.py"), _res("R3", "z.py")]) == [
            "a",
            None,
        ]

    def test_an_unreadable_rule_is_no_pair_and_never_an_exception(self):
        flat = [_RaisingRule(), _row("b", "R1", "app/main.py")]
        assert _both(flat, [_res("R1", "app/main.py")]) == ["b"]
        assert _both([_RaisingRule()], [_res("R1", "app/main.py")]) == [None]

    def test_a_result_whose_read_raises_pairs_with_nothing(self):
        class Bad:
            @property
            def ruleId(self):
                raise RuntimeError("no")

            locations: list = []

        assert _both([_row("a", "R1", "x.py")], [Bad()]) == [None]
        assert _both([_row("a", "R1", "x.py"), _row("b", "R1", "x.py")], [Bad()]) == [
            None
        ]

    def test_a_result_with_a_bad_line_pairs_with_nothing(self):
        bad = _res("R1", "x.py", line=object())
        assert _both([_row("a", "R1", "x.py")], [bad]) == [None]


class TestTextThatPolarsCannotHold:
    def test_a_lone_surrogate_in_a_path_is_carried_and_compared(self):
        weird = "dir/\udcff-name.py"
        flat = [_row("w", "R1", weird), _row("n", "R1", "dir/other.py")]
        results = [_res("R1", weird), _res("R1", "dir/other.py")]
        assert _both(flat, results) == ["w", "n"]

    def test_surrogates_that_differ_do_not_pair(self):
        flat = [_row("w", "R1", "a\udcff.py")]
        assert _both(flat, [_res("R1", "a\udcfe.py")]) == [None]

    def test_a_surrogate_in_a_rule_id(self):
        flat = [_row("w", "R\ud800", "x.py"), _row("z", "Q", "x.py")]
        assert _both(flat, [_res("R\ud800", "x.py"), _res("Q", "x.py")]) == ["w", "z"]

    def test_a_surrogate_and_its_look_alike_stay_different(self):
        # wire() must not conflate a lone surrogate with any real character.
        flat = [_row("w", "R1", "a\udc80")]
        assert _both(flat, [_res("R1", "a\u0080")]) == [None]
        assert _both(flat, [_res("R1", "a\udc80")]) == ["w"]


# --------------------------------------------------------------------------
# Seeded random sweep: new join == oracle on every generated input
# --------------------------------------------------------------------------

_RULES = ["R1", "R2", " R2 ", "", None, "R\ud801"]
_PATHS = ["x.py", "y.py", " x.py", "", None, "d/\udcff.py", "file:///x.py"]
_LINES = [None, 1, 2, 7, 2**65]


def _random_case(rng: random.Random):
    n_rows = rng.randint(0, 7)
    n_results = rng.randint(0, 7)
    rows = []
    for k in range(n_rows):
        path = rng.choice(_PATHS)
        if path == "file:///x.py":
            path = "/x.py"
        rows.append(
            _row(
                rng.choice(["", None, f"id-{k}", f"id-{k}", f"id-{k}"]),
                rng.choice(_RULES),
                path,
                rng.choice(_LINES),
                rng.choice([None, None, None, "npm"]),
            )
        )
    results = [
        _res(
            rng.choice(_RULES),
            rng.choice(_PATHS),
            rng.choice(_LINES),
            context_line=rng.choice([None, None, 1, 7]),
            locations=rng.random() > 0.1,
        )
        for _ in range(n_results)
    ]
    return rows, results


@pytest.mark.parametrize("seed", range(40))
def test_the_join_agrees_with_the_oracle_on_random_inputs(seed):
    rng = random.Random(seed)
    for _ in range(60):
        rows, results = _random_case(rng)
        assert shared_ids_by_position(rows, results) == _ref_ids_by_position(
            rows, results
        )


@pytest.mark.parametrize("seed", range(10))
def test_a_flattening_that_mirrors_its_results_agrees_with_the_oracle(seed):
    """Rows built from the results themselves, then shuffled, dropped and padded:
    the shapes the real flattening produces and the shapes it fails in."""
    rng = random.Random(1000 + seed)
    for _ in range(40):
        results = [
            _res(
                rng.choice(["R1", "R2", "R3"]),
                rng.choice(["x.py", "y.py"]),
                rng.choice([1, 2, 3]),
            )
            for _ in range(rng.randint(0, 9))
        ]
        rows = [
            _row(
                f"id-{i}",
                r.ruleId,
                r.locations[0].physicalLocation.root.artifactLocation.uri,
                r.locations[0].physicalLocation.root.region.startLine,
            )
            for i, r in enumerate(results)
        ]
        if rng.random() < 0.3:
            rng.shuffle(rows)
        if rows and rng.random() < 0.5:
            rows.pop(rng.randrange(len(rows)))
        if rng.random() < 0.5:
            rows.insert(
                rng.randint(0, len(rows)),
                _row("stray", "ZZ", "z.py", 1, rng.choice([None, "npm"])),
            )
        assert shared_ids_by_position(rows, results) == _ref_ids_by_position(
            rows, results
        )
