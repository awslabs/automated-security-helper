# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``top_locations`` and ``active_level_counts`` answer what their predecessors did.

``REFERENCE_TOP_LOCATIONS`` and ``REFERENCE_ACTIVE_LEVEL_COUNTS`` are the two
bodies as they were written before ``_report_frames`` took the ordered count and
the stable top-N from ``utils.frame_ops``, kept verbatim as oracles (the pattern
``test_suppression_frame_equivalence`` follows). The reports print these rows, so
the order among equal counts, the limit rules and the text that reaches a frame
(lone surrogates, canonically equal but different spellings) are output, and the
two implementations must agree on every one of them.
"""

import random
from typing import Iterable, List

import polars as pl
import pytest

from automated_security_helper.plugin_modules.ash_builtin.reporters._report_frames import (
    active_level_counts,
    graded_frame,
    top_locations,
)
from automated_security_helper.utils.frame_text import unwire, wire

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# the oracles: the two bodies as they were
# ---------------------------------------------------------------------------


def REFERENCE_ACTIVE_LEVEL_COUNTS(frame: pl.DataFrame) -> List[tuple[str, int]]:
    counted = (
        frame.filter(~pl.col("is_suppressed"))
        .group_by("level", maintain_order=True)
        .len()
    )
    return [(level, int(count)) for level, count in counted.iter_rows()]


def REFERENCE_TOP_LOCATIONS(
    locations: Iterable[str], limit: int | None
) -> List[tuple[str, int]]:
    if limit is not None and limit <= 0:
        return []
    ranked = (
        pl.DataFrame(
            {"location": pl.Series([wire(item) for item in locations], dtype=pl.String)}
        )
        .group_by("location", maintain_order=True)
        .len()
        .sort("len", descending=True, maintain_order=True)
    )
    if limit is not None:
        ranked = ranked.head(limit)
    return [(unwire(location), int(count)) for location, count in ranked.iter_rows()]


# ---------------------------------------------------------------------------
# the inputs
# ---------------------------------------------------------------------------

LONE_SURROGATE = chr(0xDC80)
BMP_BELOW = chr(0xD7FF)
BMP_ABOVE = chr(0xE000)
# The next two are the same text in two spellings: NFC is "e" with acute as one
# code point, NFD is "e" followed by a combining acute.
NFC = "café.py"
NFD = "café.py"

LOCATION_CASES = {
    "empty": [],
    "one": ["a.py"],
    "all equal": ["a.py"] * 5,
    "all distinct": [f"f{i}.py" for i in range(7)],
    "ties in first-seen order": ["c", "a", "b", "a", "b", "c", "d"],
    "a later heavier location overtakes": ["x", "y", "y", "z", "z", "z"],
    "nfc and nfd are two locations": [NFC, NFD, NFD, NFC, NFD],
    "a lone surrogate beside the bmp edges": [
        LONE_SURROGATE,
        BMP_BELOW,
        BMP_ABOVE,
        LONE_SURROGATE,
        BMP_ABOVE,
    ],
    "surrogate inside a path": [f"src/{LONE_SURROGATE}.py", "src/ok.py"] * 2,
}

LIMITS = [None, 0, -1, 1, 2, 3, 6, 7, 8, 10**6]


def _random_locations(seed: int) -> List[str]:
    rng = random.Random(seed)
    pool = [
        "a",
        "b",
        "c",
        "src/x.py",
        NFC,
        NFD,
        LONE_SURROGATE,
        BMP_BELOW,
        BMP_ABOVE,
        "",
    ]
    return [rng.choice(pool) for _ in range(rng.randint(0, 40))]


# ---------------------------------------------------------------------------
# top_locations
# ---------------------------------------------------------------------------


class TestTopLocations:
    @pytest.mark.parametrize("name", list(LOCATION_CASES))
    @pytest.mark.parametrize("limit", LIMITS)
    def test_every_case_and_limit_matches_the_oracle(self, name, limit):
        locations = LOCATION_CASES[name]
        assert top_locations(list(locations), limit) == REFERENCE_TOP_LOCATIONS(
            list(locations), limit
        )

    @pytest.mark.parametrize("seed", range(40))
    @pytest.mark.parametrize("limit", [None, 0, 1, 3, 100])
    def test_random_mixes_match_the_oracle(self, seed, limit):
        locations = _random_locations(seed)
        assert top_locations(list(locations), limit) == REFERENCE_TOP_LOCATIONS(
            list(locations), limit
        )

    def test_equal_counts_keep_the_order_first_seen(self):
        assert top_locations(["c", "a", "b", "a", "b", "c", "d"], None) == [
            ("c", 2),
            ("a", 2),
            ("b", 2),
            ("d", 1),
        ]

    @pytest.mark.parametrize("limit", [0, -1, -5])
    def test_a_limit_of_zero_or_less_selects_nothing(self, limit):
        assert top_locations(["a", "a", "b"], limit) == []

    @pytest.mark.parametrize("limit", [0, -1])
    def test_a_limit_of_zero_or_less_does_not_read_the_locations(self, limit):
        consumed: list[str] = []

        def locations():
            for item in ("a", "b"):
                consumed.append(item)
                yield item

        assert top_locations(locations(), limit) == []
        assert consumed == []

    def test_a_lone_surrogate_comes_back_as_it_went_in(self):
        rows = top_locations([LONE_SURROGATE, BMP_BELOW, LONE_SURROGATE], None)
        assert rows == [(LONE_SURROGATE, 2), (BMP_BELOW, 1)]

    def test_canonically_equal_spellings_are_counted_apart(self):
        assert top_locations([NFC, NFD, NFC], None) == [(NFC, 2), (NFD, 1)]

    def test_the_counts_are_python_ints(self):
        rows = top_locations(["a", "a"], 1)
        assert all(type(count) is int for _, count in rows)


# ---------------------------------------------------------------------------
# active_level_counts
# ---------------------------------------------------------------------------

LEVEL_CASES = {
    "empty": ([], []),
    "all active": (["high", "low", "high"], [False, False, False]),
    "all suppressed": (["high", "low"], [True, True]),
    "a suppressed first sighting does not place the level": (
        ["low", "high", "low", "high"],
        [True, False, False, False],
    ),
    "levels in first-seen order": (
        ["medium", "critical", "medium", "info", "critical", "low"],
        [False, False, False, False, False, False],
    ),
    "an off-ladder bucket gets a row of its own": (
        ["high", "moderate", "moderate", "unknown"],
        [False, False, False, False],
    ),
    "a suppressed mix": (
        ["high", "high", "medium", "low", "medium"],
        [False, True, False, True, False],
    ),
}


class TestActiveLevelCounts:
    @pytest.mark.parametrize("name", list(LEVEL_CASES))
    def test_every_case_matches_the_oracle(self, name):
        levels, suppressed = LEVEL_CASES[name]
        frame = graded_frame(levels, suppressed, [False] * len(levels))
        assert active_level_counts(frame) == REFERENCE_ACTIVE_LEVEL_COUNTS(frame)

    @pytest.mark.parametrize("seed", range(40))
    def test_random_mixes_match_the_oracle(self, seed):
        rng = random.Random(seed)
        rows = rng.randint(0, 30)
        levels = [
            rng.choice(["critical", "high", "medium", "low", "info", "unknown", "x"])
            for _ in range(rows)
        ]
        suppressed = [rng.random() < 0.4 for _ in range(rows)]
        frame = graded_frame(levels, suppressed, [False] * rows)
        assert active_level_counts(frame) == REFERENCE_ACTIVE_LEVEL_COUNTS(frame)

    def test_the_levels_come_back_in_first_seen_order(self):
        frame = graded_frame(
            ["low", "high", "low", "critical"], [False] * 4, [False] * 4
        )
        assert active_level_counts(frame) == [("low", 2), ("high", 1), ("critical", 1)]

    def test_a_level_with_only_suppressed_rows_has_no_row(self):
        frame = graded_frame(["low", "high"], [True, False], [False, False])
        assert active_level_counts(frame) == [("high", 1)]

    def test_the_counts_are_python_ints(self):
        frame = graded_frame(["low", "low"], [False, False], [False, False])
        assert all(type(count) is int for _, count in active_level_counts(frame))
