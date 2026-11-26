# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ceiling_unreachable_counts`` counts on one frame and keeps the dict's answer.

``_oracle`` is the function as it was written before the per-scanner count moved
onto a frame, kept unchanged. The two are compared on ``list(result.items())`` so
the order of the keys is pinned along with the counts: the dict reaches the results
file and the MCP payload in that order.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import pytest

from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    sarif_level_fails_threshold,
)
from automated_security_helper.workspace.policy import (
    ceiling_unreachable_counts,
    normalise_scanner_name,
)

pytestmark = pytest.mark.unit


def _oracle(
    results: Iterable[Mapping[str, Any]],
    declared_threshold: str | None,
    effective_threshold: str | None,
    *,
    non_gating_scanners: Iterable[str] = (),
) -> dict[str, int]:
    if declared_threshold == effective_threshold:
        return {}

    not_gating = {normalise_scanner_name(str(name)) for name in non_gating_scanners}
    counts: dict[str, int] = {}
    for result in results:
        if not isinstance(result, Mapping):
            continue
        if result.get("suppressions"):
            continue

        properties = result.get("properties")
        issue_severity = ""
        if isinstance(properties, Mapping):
            issue_severity = str(properties.get("issue_severity") or "").strip().upper()
        if issue_severity in SEVERITIES:
            continue
        if not_gating and isinstance(properties, Mapping):
            scanner_name = properties.get("scanner_name")
            if scanner_name and normalise_scanner_name(str(scanner_name)) in not_gating:
                continue

        level = result.get("level")
        if sarif_level_fails_threshold(
            level, declared_threshold
        ) != sarif_level_fails_threshold(level, effective_threshold):
            continue
        if not sarif_level_fails_threshold(level, effective_threshold):
            continue

        scanner = None
        if isinstance(properties, Mapping):
            scanner = properties.get("scanner_name")
        name = str(scanner) if scanner else "unattributed"
        counts[name] = counts.get(name, 0) + 1

    return counts


def _finding(scanner: Any = "checkov", level: Any = "error", **extra: Any) -> dict:
    result: dict[str, Any] = {"level": level, "properties": {"scanner_name": scanner}}
    result.update(extra)
    return result


def _same(results, declared, effective, **kwargs) -> dict[str, int]:
    results = list(results)
    expected = _oracle(results, declared, effective, **kwargs)
    actual = ceiling_unreachable_counts(results, declared, effective, **kwargs)
    assert list(actual.items()) == list(expected.items())
    assert all(type(n) is int for n in actual.values())
    return actual


def test_a_run_whose_z_findings_come_before_its_a_findings_keeps_that_order():
    results = [
        _finding("z"),
        _finding("a"),
        _finding("z"),
        _finding("m"),
        _finding("a"),
    ]
    out = _same(results, "HIGH", "LOW")
    assert list(out) == ["z", "a", "m"]
    assert list(out.values()) == [2, 2, 1]


@pytest.mark.parametrize(
    "scanner",
    [
        "Checkov",
        "  padded  ",
        "",
        None,
        0,
        7,
        True,
        False,
        ["a", 1],
        {"k": "v"},
        chr(0xDC80),
        chr(0xD7FF),
        chr(0xE000),
        "café",
        "\U0001f600",
    ],
)
def test_scanner_names_of_every_shape_group_as_the_dict_did(scanner):
    results = [
        _finding(scanner),
        _finding("other"),
        _finding(scanner),
        _finding(chr(0xDC80)),
        _finding(chr(0xD7FF)),
        _finding(chr(0xE000)),
    ]
    _same(results, "HIGH", "LOW")


def test_surrogate_and_neighbours_stay_three_keys():
    results = [_finding(chr(0xE000)), _finding(chr(0xDC80)), _finding(chr(0xD7FF))]
    out = _same(results, "HIGH", "LOW")
    assert len(out) == 3


@pytest.mark.parametrize(
    "severity",
    [" high ", "high", "HIGH", "LOW", "bogus", "", None, 3, 0, " medium", "CRITICAL"],
)
def test_issue_severity_shapes(severity):
    result = _finding("s")
    result["properties"]["issue_severity"] = severity
    _same([result, _finding("t")], "HIGH", "LOW")


@pytest.mark.parametrize(
    "level", ["error", "warning", "note", "none", None, 3, "ERROR", "bogus"]
)
@pytest.mark.parametrize(
    "thresholds", [("HIGH", "LOW"), ("LOW", "HIGH"), ("MEDIUM", "CRITICAL")]
)
def test_levels_and_threshold_pairs(level, thresholds):
    missing = {"properties": {"scanner_name": "s"}}
    _same([_finding("s", level), missing], *thresholds)


@pytest.mark.parametrize(
    "thresholds", [("HIGH", "HIGH"), (None, None), ("", ""), (None, "")]
)
def test_equal_thresholds_return_nothing(thresholds):
    assert _same([_finding("s")], *thresholds) == {}


def test_missing_level_key_is_read_like_the_dict_did():
    _same([{"properties": {"scanner_name": "s"}}], "HIGH", "LOW")


@pytest.mark.parametrize("suppressions", [[{"kind": "x"}], [], None, "", 0])
def test_suppressions_present_empty_and_none(suppressions):
    _same([_finding("s", suppressions=suppressions), _finding("t")], "HIGH", "LOW")


@pytest.mark.parametrize(
    "properties", [None, "text", 5, [], ["a"], {}, {"scanner_name": None}]
)
def test_properties_missing_or_not_a_mapping(properties):
    results = [{"level": "error", "properties": properties}, _finding("t")]
    _same(results, "HIGH", "LOW")
    _same([{"level": "error"}], "HIGH", "LOW")


@pytest.mark.parametrize("entry", [None, "x", 3, [], ["a"], ("a",)])
def test_non_mapping_entries_are_skipped(entry):
    _same([entry, _finding("s"), entry], "HIGH", "LOW")


@pytest.mark.parametrize(
    "non_gating",
    [
        ["Checkov"],
        [" checkov "],
        ["check-ov"],
        ["CHECKOV", "bandit"],
        [],
        [""],
        [None, 3],
        ["other"],
    ],
)
def test_non_gating_scanners_with_case_and_punctuation_variants(non_gating):
    results = [
        _finding("checkov"),
        _finding("Checkov"),
        _finding("bandit"),
        _finding(None),
        _finding(" checkov "),
    ]
    _same(results, "HIGH", "LOW", non_gating_scanners=non_gating)


def test_nothing_counted_returns_an_empty_dict():
    out = _same([_finding("s", "none"), _finding("t", "none")], "HIGH", "LOW")
    assert out == {}
    assert _same([], "HIGH", "LOW") == {}


def test_a_generator_of_results_is_read_once():
    results = [_finding("a"), _finding("b"), _finding("a")]
    expected = _oracle(iter(results), "HIGH", "LOW")
    actual = ceiling_unreachable_counts(iter(results), "HIGH", "LOW")
    assert list(actual.items()) == list(expected.items())
