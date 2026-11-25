# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization goldens for ``utils/severity_ladder.py``.

These pin what the module does TODAY, so a later change of its engine (the result
to rule join, the level coalesce chain and the threshold case-when) can be shown
to be behavior-identical. Every expectation is a literal written down from a read
of the code, never derived from it. Where today's behavior looks odd it is pinned
as it is and the oddity is named in the test: a golden that has to move is a
finding to report, not a line to update.

Precedence order is the behavior, so the order of the branches is pinned
explicitly: rule reference, then ``ruleIndex``, then ``ruleId``; scoped lookup
before global; ``issue_severity`` before the level; scanner threshold before the
global one before the environment default.
"""

from __future__ import annotations

import logging
from enum import Enum
from types import SimpleNamespace
from typing import Any, List

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    ReportingConfiguration,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import severity_ladder as ladder
from automated_security_helper.utils.severity_ladder import (
    MISSING_SARIF_LEVEL,
    SEVERITIES,
    SEVERITY_THRESHOLDS,
    component_labels,
    effective_sarif_level,
    normalize_threshold,
    resolve_missing_levels,
    resolve_scanner_threshold,
    result_fails_scanner_threshold,
    result_scanner_labels,
    result_scanner_name,
    result_severity,
    sarif_level_fails_threshold,
    severity_fails_threshold,
    stricter_of,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_warning_state(monkeypatch):
    """Each test starts with no warning already spent in this process."""
    monkeypatch.setattr(ladder, "_WARNED_OFF_TABLE", set())
    monkeypatch.setattr(ladder, "_WARNED_DROPPED_SCANNER", set())


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@pytest.fixture
def ash_log():
    """The messages the module logs on the "ash" logger, captured directly so the
    test does not depend on how that logger propagates."""
    logger = logging.getLogger("ash")
    handler = _Capture()
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield handler.messages
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


class _Level(str, Enum):
    error = "error"
    warning = "warning"
    note = "note"
    none = "none"


def _rule(rule_id, level=None, **extra) -> SimpleNamespace:
    """A stand-in rule. ``level=None`` is a rule with no defaultConfiguration."""
    return SimpleNamespace(id=rule_id, defaultConfiguration=level, **extra)


def _sarif_rule(rule_id: str, level: str | None = None) -> ReportingDescriptor:
    if level is None:
        return ReportingDescriptor(id=rule_id)
    return ReportingDescriptor(
        id=rule_id, defaultConfiguration=ReportingConfiguration(level=level)
    )


def _run_report(results, driver_rules=None, extensions=None, driver_name="ash"):
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(name=driver_name, rules=driver_rules),
                    extensions=extensions,
                ),
                results=results,
            )
        ],
    )


def _levels(report: SarifReport) -> List[str]:
    out = []
    for result in report.runs[0].results:
        level = result.level
        out.append(str(getattr(level, "value", level)))
    return out


# ---------------------------------------------------------------------------
# The ladder as data
# ---------------------------------------------------------------------------


def test_ladder_constants_golden():
    assert SEVERITY_THRESHOLDS == ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert SEVERITIES == ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert MISSING_SARIF_LEVEL == "warning"
    assert ladder._SEVERITY_RANK == {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }
    assert ladder._THRESHOLD_MIN_RANK == {
        "ALL": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    assert ladder._SARIF_LEVEL_TO_SEVERITY == {
        "error": "CRITICAL",
        "warning": "MEDIUM",
        "note": "LOW",
        "none": "INFO",
    }
    assert ladder._UNKNOWN_THRESHOLD_MIN_RANK == 4
    assert ladder._UNKNOWN_SEVERITY_RANK == 4


# ---------------------------------------------------------------------------
# effective_sarif_level: first link of the coalesce chain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "result,expected",
    [
        ({"level": "error"}, "error"),
        ({"level": "warning"}, "warning"),
        ({"level": "note"}, "note"),
        ({"level": "none"}, "none"),
        ({"level": "ERROR"}, "error"),
        ({"level": "  Note  "}, "note"),
        ({"level": "NoNe"}, "none"),
        ({}, "warning"),
        ({"level": None}, "warning"),
        ({"level": ""}, "warning"),
        ({"level": "critical"}, "warning"),
        ({"level": "fatal"}, "warning"),
        ({"level": 0}, "warning"),
        ({"level": False}, "warning"),
        ({"level": []}, "warning"),
        ({"level": 5}, "warning"),
        ({"level": _Level.error}, "error"),
        ({"level": _Level.none}, "none"),
        ({"level": SimpleNamespace(value="Note")}, "note"),
        ({"level": SimpleNamespace(value=None)}, "warning"),
    ],
)
def test_effective_sarif_level_from_dict(result, expected):
    assert effective_sarif_level(result) == expected


@pytest.mark.parametrize(
    "level,expected",
    [
        ("error", "error"),
        (" WARNING ", "warning"),
        (_Level.note, "note"),
        (None, "warning"),
        ("bogus", "warning"),
    ],
)
def test_effective_sarif_level_from_object(level, expected):
    assert effective_sarif_level(SimpleNamespace(level=level)) == expected


def test_effective_sarif_level_object_without_level_attribute():
    assert effective_sarif_level(SimpleNamespace()) == "warning"
    assert effective_sarif_level(object()) == "warning"
    assert effective_sarif_level(None) == "warning"


def test_effective_sarif_level_dict_does_not_read_attributes():
    class WithBoth(dict):
        level = "error"

    # A dict is read with .get, never through its attributes.
    assert effective_sarif_level(WithBoth()) == "warning"
    assert effective_sarif_level(WithBoth(level="note")) == "note"


def test_effective_sarif_level_on_a_real_result_model():
    assert effective_sarif_level(Result(message=Message(text="x"))) == "warning"
    assert (
        effective_sarif_level(Result(message=Message(text="x"), level="error"))
        == "error"
    )
    assert (
        effective_sarif_level(Result(message=Message(text="x"), level="note")) == "note"
    )


# ---------------------------------------------------------------------------
# component_labels and result_scanner_labels
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "component,expected",
    [
        (
            SimpleNamespace(name="Grype", fullName="Anchore Grype"),
            {"grype", "anchore grype"},
        ),
        (SimpleNamespace(name="  Trivy  "), {"trivy"}),
        (SimpleNamespace(name="x", fullName="X"), {"x"}),
        (SimpleNamespace(name="", fullName="   "), set()),
        (SimpleNamespace(name=None, fullName=None), set()),
        (SimpleNamespace(name=5, fullName=["a"]), set()),
        (SimpleNamespace(), set()),
        (None, set()),
        (SimpleNamespace(name="ÄÖ-Ünï"), {"äö-ünï"}),
    ],
)
def test_component_labels_golden(component, expected):
    labels = component_labels(component)
    assert isinstance(labels, frozenset)
    assert labels == frozenset(expected)


def _props(**kwargs):
    return SimpleNamespace(**kwargs)


def test_result_scanner_labels_attribute_and_tool_name():
    result = SimpleNamespace(
        properties=_props(
            scanner_name=" Grype ",
            scanner_details=SimpleNamespace(tool_name="Anchore-Grype"),
        )
    )
    assert result_scanner_labels(result) == frozenset({"grype", "anchore-grype"})


def test_result_scanner_labels_details_as_mapping():
    result = SimpleNamespace(
        properties=_props(scanner_name=None, scanner_details={"tool_name": "Semgrep"})
    )
    assert result_scanner_labels(result) == frozenset({"semgrep"})


def test_result_scanner_labels_reads_model_extra():
    result = SimpleNamespace(
        properties=_props(
            model_extra={
                "scanner_name": "Bandit",
                "scanner_details": {"tool_name": "bandit-cli"},
            }
        )
    )
    assert result_scanner_labels(result) == frozenset({"bandit", "bandit-cli"})


def test_result_scanner_labels_attribute_beats_nothing_extra_is_additive():
    # Both the attribute and the extra key are read; neither shadows the other.
    result = SimpleNamespace(
        properties=_props(scanner_name="A", model_extra={"scanner_name": "B"})
    )
    assert result_scanner_labels(result) == frozenset({"a", "b"})


def test_result_scanner_labels_attribute_details_shadow_extra_details():
    result = SimpleNamespace(
        properties=_props(
            scanner_details={"tool_name": "attr"},
            model_extra={"scanner_details": {"tool_name": "extra"}},
        )
    )
    assert result_scanner_labels(result) == frozenset({"attr"})


def test_result_scanner_labels_empty_cases():
    assert result_scanner_labels(SimpleNamespace()) == frozenset()
    assert result_scanner_labels(SimpleNamespace(properties=None)) == frozenset()
    assert result_scanner_labels(SimpleNamespace(properties=_props())) == frozenset()
    assert (
        result_scanner_labels(SimpleNamespace(properties=_props(scanner_name="  ")))
        == frozenset()
    )
    assert (
        result_scanner_labels(SimpleNamespace(properties=_props(scanner_name=7)))
        == frozenset()
    )
    # A dict-shaped result has no ``properties`` attribute: empty, not an error.
    assert result_scanner_labels({"properties": {"scanner_name": "x"}}) == frozenset()


def test_result_scanner_labels_swallows_a_raising_read():
    class Boom:
        @property
        def properties(self):
            raise RuntimeError("boom")

    assert result_scanner_labels(Boom()) == frozenset()


def test_result_scanner_labels_ignores_non_dict_model_extra():
    result = SimpleNamespace(
        properties=_props(scanner_name="Kept", model_extra=["scanner_name"])
    )
    assert result_scanner_labels(result) == frozenset({"kept"})


def test_result_scanner_labels_on_a_real_result():
    result = Result(
        message=Message(text="x"),
        properties={"scanner_name": "Grype", "scanner_details": {"tool_name": "g"}},
    )
    assert result_scanner_labels(result) == frozenset({"grype", "g"})


# ---------------------------------------------------------------------------
# _rule_of: the result to rule join, precedence order
# ---------------------------------------------------------------------------


def _join(result, components, component_names=None):
    by_id: dict = {}
    for rules in components:
        for rule in rules:
            by_id.setdefault(getattr(rule, "id", None), rule)
    return ladder._rule_of(result, components, by_id, component_names)


def _result(**kwargs):
    kwargs.setdefault("rule", None)
    kwargs.setdefault("ruleId", None)
    kwargs.setdefault("ruleIndex", None)
    return SimpleNamespace(**kwargs)


def test_join_by_rule_id_driver_first_copy_wins():
    first, second = _rule("R", "error"), _rule("R", "note")
    other = _rule("S", "none")
    assert _join(_result(ruleId="R"), [[first, other], [second]]) is first


def test_join_by_rule_id_falls_through_to_an_extension():
    ext_rule = _rule("E", "error")
    assert _join(_result(ruleId="E"), [[_rule("D")], [ext_rule]]) is ext_rule


def test_join_no_match_is_none():
    assert _join(_result(ruleId="missing"), [[_rule("D")]]) is None
    assert _join(_result(), [[_rule("D")]]) is None
    assert _join(_result(ruleId=""), [[_rule("D")]]) is None


def test_join_rule_index_into_driver_rules():
    a, b = _rule("A"), _rule("B")
    assert _join(_result(ruleIndex=1), [[a, b]]) is b
    assert _join(_result(ruleIndex=0), [[a, b]]) is a


def test_join_rule_index_with_agreeing_id():
    a, b = _rule("A"), _rule("B")
    assert _join(_result(ruleIndex=1, ruleId="B"), [[a, b]]) is b


def test_join_rule_index_with_disagreeing_id_yields_to_the_id():
    a, b = _rule("A"), _rule("B")
    assert _join(_result(ruleIndex=0, ruleId="B"), [[a, b]]) is b


def test_join_rule_index_with_disagreeing_unknown_id_is_none():
    a, b = _rule("A"), _rule("B")
    assert _join(_result(ruleIndex=0, ruleId="nope"), [[a, b]]) is None


@pytest.mark.parametrize("index", [-1, 2, 99])
def test_join_rule_index_out_of_range_falls_back_to_the_id(index):
    a, b = _rule("A"), _rule("B")
    assert _join(_result(ruleIndex=index), [[a, b]]) is None
    assert _join(_result(ruleIndex=index, ruleId="A"), [[a, b]]) is a


def test_join_rule_index_zero_is_a_real_index_not_falsy():
    a = _rule("A")
    assert _join(_result(ruleIndex=0), [[a]]) is a


def test_join_rule_index_does_not_reach_into_extensions():
    ext = _rule("E")
    assert _join(_result(ruleIndex=0), [[], [ext]]) is None


def test_join_rule_reference_index_into_driver():
    a, b = _rule("A"), _rule("B")
    reference = SimpleNamespace(index=1, id=None, toolComponent=None)
    assert _join(_result(rule=reference), [[a, b]]) is b


def test_join_rule_reference_beats_rule_index_and_rule_id_fields():
    a, b, c = _rule("A"), _rule("B"), _rule("C")
    reference = SimpleNamespace(index=2, id=None, toolComponent=None)
    result = _result(rule=reference, ruleIndex=0, ruleId=None)
    assert _join(result, [[a, b, c]]) is c


def test_join_rule_reference_component_index_picks_an_extension():
    d, e0, e1 = _rule("D"), _rule("E0"), _rule("E1")
    reference = SimpleNamespace(
        index=0, id=None, toolComponent=SimpleNamespace(index=1)
    )
    assert _join(_result(rule=reference), [[d], [e0], [e1]]) is e1


def test_join_rule_reference_component_index_zero_is_the_first_extension():
    d, e0 = _rule("D"), _rule("E0")
    reference = SimpleNamespace(
        index=0, id=None, toolComponent=SimpleNamespace(index=0)
    )
    assert _join(_result(rule=reference), [[d], [e0]]) is e0


def test_join_rule_reference_component_index_past_the_end_names_no_rules():
    d = _rule("D")
    reference = SimpleNamespace(index=0, id="D", toolComponent=SimpleNamespace(index=5))
    # The named component is empty, so the index misses; the id is then looked up
    # globally and finds the driver's rule.
    assert _join(_result(rule=reference), [[d]]) is d


def test_join_rule_reference_negative_component_index_means_the_driver():
    d = _rule("D")
    reference = SimpleNamespace(
        index=0, id=None, toolComponent=SimpleNamespace(index=-1)
    )
    assert _join(_result(rule=reference), [[d]]) is d


def test_join_rule_reference_by_id_only():
    a, b = _rule("A"), _rule("B")
    reference = SimpleNamespace(id="B", index=-1, toolComponent=None)
    assert _join(_result(rule=reference), [[a, b]]) is b


def test_join_rule_reference_index_none_is_treated_as_unindexed():
    a = _rule("A")
    reference = SimpleNamespace(id="A", index=None, toolComponent=None)
    assert _join(_result(rule=reference), [[a]]) is a


def test_join_rule_reference_wrapped_in_root():
    a, b = _rule("A"), _rule("B")
    body = SimpleNamespace(index=1, id=None, toolComponent=None)
    assert _join(_result(rule=SimpleNamespace(root=body)), [[a, b]]) is b


def test_join_result_rule_id_beats_reference_id_for_the_stated_id():
    a, b = _rule("A"), _rule("B")
    reference = SimpleNamespace(id="A", index=-1, toolComponent=None)
    assert _join(_result(rule=reference, ruleId="B"), [[a, b]]) is b


def test_join_indexed_rule_with_disagreeing_id_falls_to_the_stated_id():
    a, b = _rule("A"), _rule("B")
    reference = SimpleNamespace(index=0, id=None, toolComponent=None)
    assert _join(_result(rule=reference, ruleId="B"), [[a, b]]) is b


def test_join_hierarchical_id_falls_back_to_each_prefix():
    parent = _rule("CA1001")
    mid = _rule("CA1001/sub")
    assert _join(_result(ruleId="CA1001/sub/leaf"), [[parent]]) is parent
    assert _join(_result(ruleId="CA1001/sub/leaf"), [[parent, mid]]) is mid
    assert _join(_result(ruleId="CA1001/sub"), [[parent]]) is parent
    # A trailing slash strips to the parent, so the parent grades it.
    assert _join(_result(ruleId="CA1001/"), [[parent]]) is parent
    assert _join(_result(ruleId="/x"), [[parent]]) is None


def test_join_exact_id_beats_a_shorter_prefix():
    parent, exact = _rule("CA1001"), _rule("CA1001/sub")
    assert _join(_result(ruleId="CA1001/sub"), [[parent, exact]]) is exact


def test_join_scoped_lookup_by_scanner_label_beats_global_first_wins():
    driver_rule = _rule("CVE-1", "warning")
    ext_rule = _rule("CVE-1", "error")
    components = [[driver_rule], [ext_rule]]
    names = [frozenset({"merged"}), frozenset({"grype"})]
    result = _result(ruleId="CVE-1", properties=_props(scanner_name="Grype"))
    assert _join(result, components, names) is ext_rule
    # The same id for a scanner that matches no component reads globally.
    other = _result(ruleId="CVE-1", properties=_props(scanner_name="trivy"))
    assert _join(other, components, names) is driver_rule


def test_join_scoped_lookup_needs_component_names():
    driver_rule, ext_rule = _rule("CVE-1"), _rule("CVE-1")
    result = _result(ruleId="CVE-1", properties=_props(scanner_name="grype"))
    # No component_names given: the scanner scope is not consulted at all.
    assert _join(result, [[driver_rule], [ext_rule]], None) is driver_rule
    assert _join(result, [[driver_rule], [ext_rule]], []) is driver_rule


def test_join_scoped_lookup_first_matching_component_in_order():
    first, second = _rule("X"), _rule("X")
    components = [[first], [second]]
    names = [frozenset({"scan"}), frozenset({"scan"})]
    result = _result(ruleId="X", properties=_props(scanner_name="scan"))
    assert _join(result, components, names) is first


def test_join_scope_tries_every_prefix_before_any_global_lookup():
    own_parent = _rule("CA1001")
    other_exact = _rule("CA1001/sub")
    components = [[other_exact], [own_parent]]
    names = [frozenset({"other"}), frozenset({"mine"})]
    result = _result(ruleId="CA1001/sub", properties=_props(scanner_name="mine"))
    # The scanner's own component holds the prefix; the other scanner's exact id
    # does not win over it.
    assert _join(result, components, names) is own_parent


def test_join_reference_named_component_scope_beats_scanner_scope():
    named = _rule("X")
    scanner_owned = _rule("X")
    components = [[named], [scanner_owned]]
    names = [frozenset({"merged"}), frozenset({"scan"})]
    reference = SimpleNamespace(index=-1, id="X", toolComponent=None)
    result = _result(rule=reference, properties=_props(scanner_name="scan"))
    # Named component is the driver (no toolComponent index): its copy wins.
    assert _join(result, components, names) is named


def test_join_rules_without_id_attribute_never_match():
    class NoId:
        pass

    assert _join(_result(ruleId="x"), [[NoId()]]) is None


# ---------------------------------------------------------------------------
# resolve_missing_levels: the coalesce chain on real SARIF models
# ---------------------------------------------------------------------------


def _unlevelled(**kwargs) -> Result:
    return Result(message=Message(text="x"), **kwargs)


def test_resolve_missing_levels_no_rule_gets_warning():
    report = _run_report([_unlevelled(ruleId="none-such")], [_sarif_rule("A", "error")])
    resolve_missing_levels(report)
    assert _levels(report) == ["warning"]


def test_resolve_missing_levels_takes_the_rule_default():
    report = _run_report(
        [_unlevelled(ruleId="A"), _unlevelled(ruleId="B"), _unlevelled(ruleId="C")],
        [_sarif_rule("A", "error"), _sarif_rule("B", "note"), _sarif_rule("C", "none")],
    )
    resolve_missing_levels(report)
    assert _levels(report) == ["error", "note", "none"]


def test_resolve_missing_levels_rule_without_a_stated_level_gives_warning():
    report = _run_report([_unlevelled(ruleId="A")], [_sarif_rule("A")])
    resolve_missing_levels(report)
    assert _levels(report) == ["warning"]


def test_resolve_missing_levels_rule_configuration_without_level_set_gives_warning():
    rule = ReportingDescriptor(id="A", defaultConfiguration=ReportingConfiguration())
    report = _run_report([_unlevelled(ruleId="A")], [rule])
    resolve_missing_levels(report)
    assert _levels(report) == ["warning"]


def test_resolve_missing_levels_keeps_a_stated_level():
    report = _run_report(
        [_unlevelled(ruleId="A", level="note")], [_sarif_rule("A", "error")]
    )
    resolve_missing_levels(report)
    assert _levels(report) == ["note"]


def test_resolve_missing_levels_stated_level_none_is_kept():
    report = _run_report(
        [_unlevelled(ruleId="A", level="none")], [_sarif_rule("A", "error")]
    )
    resolve_missing_levels(report)
    assert _levels(report) == ["none"]


@pytest.mark.parametrize(
    "kind", ["pass", "open", "review", "informational", "notApplicable"]
)
def test_resolve_missing_levels_non_fail_kind_is_none(kind):
    report = _run_report(
        [_unlevelled(ruleId="A", kind=kind)], [_sarif_rule("A", "error")]
    )
    resolve_missing_levels(report)
    assert _levels(report) == ["none"]


def test_resolve_missing_levels_explicit_fail_kind_uses_the_rule():
    report = _run_report(
        [_unlevelled(ruleId="A", kind="fail")], [_sarif_rule("A", "error")]
    )
    resolve_missing_levels(report)
    assert _levels(report) == ["error"]


def test_resolve_missing_levels_non_fail_kind_beats_rule_default_even_with_a_rule():
    report = _run_report(
        [_unlevelled(ruleId="A", kind="pass")], [_sarif_rule("A", "note")]
    )
    resolve_missing_levels(report)
    assert _levels(report) == ["none"]


def test_resolve_missing_levels_rule_index_and_extension_reference():
    ext = ToolComponent(name="ext", rules=[_sarif_rule("EXT", "error")])
    results = [
        _unlevelled(ruleIndex=1),
        _unlevelled(rule={"index": 0, "toolComponent": {"index": 0}}),
        _unlevelled(ruleIndex=7),
    ]
    report = _run_report(
        results, [_sarif_rule("A", "note"), _sarif_rule("B", "none")], [ext]
    )
    resolve_missing_levels(report)
    assert _levels(report) == ["none", "error", "warning"]


def test_resolve_missing_levels_hierarchical_id_uses_the_parent_rule():
    report = _run_report(
        [_unlevelled(ruleId="CA1001/sub")], [_sarif_rule("CA1001", "error")]
    )
    resolve_missing_levels(report)
    assert _levels(report) == ["error"]


def test_resolve_missing_levels_driver_copy_wins_without_scanner_scope():
    ext = ToolComponent(name="ext", rules=[_sarif_rule("DUP", "error")])
    report = _run_report(
        [_unlevelled(ruleId="DUP")], [_sarif_rule("DUP", "note")], [ext]
    )
    resolve_missing_levels(report)
    assert _levels(report) == ["note"]


def test_resolve_missing_levels_scanner_scope_picks_its_own_extension():
    ext_grype = ToolComponent(name="grype", rules=[_sarif_rule("CVE-1", "error")])
    ext_trivy = ToolComponent(name="trivy", rules=[_sarif_rule("CVE-1")])
    grype = _unlevelled(ruleId="CVE-1", properties={"scanner_name": "grype"})
    trivy = _unlevelled(ruleId="CVE-1", properties={"scanner_name": "trivy"})
    anon = _unlevelled(ruleId="CVE-1")
    report = _run_report(
        [grype, trivy, anon], [], [ext_trivy, ext_grype], driver_name="merged"
    )
    resolve_missing_levels(report)
    # grype's own copy says error; trivy's own copy states nothing (warning); a
    # result with no scanner reads the first copy across components (trivy's).
    assert _levels(report) == ["error", "warning", "warning"]


def test_resolve_missing_levels_no_runs_is_a_noop():
    report = SarifReport(version="2.1.0", runs=[])
    assert resolve_missing_levels(report) is None
    assert resolve_missing_levels(SimpleNamespace()) is None
    assert resolve_missing_levels(SimpleNamespace(runs=None)) is None


def test_resolve_missing_levels_run_without_results_or_rules():
    report = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name="ash")))],
    )
    resolve_missing_levels(report)
    assert report.runs[0].results is None or list(report.runs[0].results) == []


def test_resolve_missing_levels_returns_none_and_mutates_in_place():
    result = _unlevelled(ruleId="A")
    report = _run_report([result], [_sarif_rule("A", "error")])
    assert resolve_missing_levels(report) is None
    assert report.runs[0].results[0] is result
    assert str(getattr(result.level, "value", result.level)) == "error"


def test_resolve_missing_levels_is_idempotent():
    report = _run_report(
        [_unlevelled(ruleId="A"), _unlevelled(ruleId="B")],
        [_sarif_rule("A", "error")],
    )
    resolve_missing_levels(report)
    first = _levels(report)
    resolve_missing_levels(report)
    assert _levels(report) == first == ["error", "warning"]


def test_resolve_missing_levels_per_run_scope_is_isolated():
    run_a = Run(
        tool=Tool(driver=ToolComponent(name="a", rules=[_sarif_rule("R", "error")])),
        results=[_unlevelled(ruleId="R")],
    )
    run_b = Run(
        tool=Tool(driver=ToolComponent(name="b", rules=[_sarif_rule("R", "note")])),
        results=[_unlevelled(ruleId="R")],
    )
    report = SarifReport(version="2.1.0", runs=[run_a, run_b])
    resolve_missing_levels(report)
    got = [
        str(getattr(r.level, "value", r.level))
        for run in report.runs
        for r in run.results
    ]
    assert got == ["error", "note"]


def test_resolve_missing_levels_stand_in_with_no_fields_set_attribute():
    """A result with no ``model_fields_set`` reads as having its level set, so a
    stand-in is left alone."""
    stand_in = SimpleNamespace(ruleId="A", level="sentinel")
    report = SimpleNamespace(
        runs=[
            SimpleNamespace(
                tool=SimpleNamespace(
                    driver=SimpleNamespace(name="d", rules=[_rule("A", "error")]),
                    extensions=None,
                ),
                results=[stand_in],
            )
        ]
    )
    resolve_missing_levels(report)
    assert stand_in.level == "sentinel"


def test_resolve_missing_levels_large_n_preserves_result_order_and_first_rule_wins():
    rules = [
        _sarif_rule(f"R{i}", ("error", "warning", "note", "none")[i % 4])
        for i in range(200)
    ]
    rules.append(_sarif_rule("R0", "none"))  # a later duplicate id never wins
    results = [_unlevelled(ruleId=f"R{i % 210}") for i in range(1000)]
    report = _run_report(results, rules)
    resolve_missing_levels(report)
    expected = []
    for i in range(1000):
        n = i % 210
        expected.append(
            ("error", "warning", "note", "none")[n % 4] if n < 200 else "warning"
        )
    assert _levels(report) == expected
    assert [r.ruleId for r in report.runs[0].results] == [
        f"R{i % 210}" for i in range(1000)
    ]


# ---------------------------------------------------------------------------
# result_severity: issue_severity beats the level
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "result,expected",
    [
        ({"level": "error"}, "CRITICAL"),
        ({"level": "warning"}, "MEDIUM"),
        ({"level": "note"}, "LOW"),
        ({"level": "none"}, "INFO"),
        ({}, "MEDIUM"),
        ({"level": "bogus"}, "MEDIUM"),
        ({"level": None}, "MEDIUM"),
        ({"level": "error", "properties": {"issue_severity": "low"}}, "LOW"),
        ({"level": "note", "properties": {"issue_severity": "HIGH"}}, "HIGH"),
        ({"level": "none", "properties": {"issue_severity": " critical "}}, "CRITICAL"),
        ({"properties": {"issue_severity": "Info"}}, "INFO"),
        ({"properties": {"issue_severity": "medium"}}, "MEDIUM"),
        ({"level": "error", "properties": {"issue_severity": "UNKNOWN"}}, "CRITICAL"),
        ({"level": "note", "properties": {"issue_severity": ""}}, "LOW"),
        ({"level": "note", "properties": {"issue_severity": 3}}, "LOW"),
        ({"level": "note", "properties": {"issue_severity": None}}, "LOW"),
        ({"level": "error", "properties": {"issue_severity": ["HIGH"]}}, "CRITICAL"),
        ({"level": "error", "properties": {}}, "CRITICAL"),
        ({"level": "error", "properties": None}, "CRITICAL"),
        ({"level": "error", "properties": "HIGH"}, "CRITICAL"),
        ({"level": _Level.note}, "LOW"),
        ({"level": "WARNING"}, "MEDIUM"),
    ],
)
def test_result_severity_dict_golden(result, expected):
    assert result_severity(result) == expected


def test_result_severity_object_forms():
    obj = SimpleNamespace(
        level="error", properties=SimpleNamespace(issue_severity="low")
    )
    assert result_severity(obj) == "LOW"
    obj = SimpleNamespace(level="note", properties=SimpleNamespace())
    assert result_severity(obj) == "LOW"
    obj = SimpleNamespace(level="note", properties=None)
    assert result_severity(obj) == "LOW"
    obj = SimpleNamespace(level="note", properties={"issue_severity": "high"})
    assert result_severity(obj) == "HIGH"
    assert result_severity(SimpleNamespace()) == "MEDIUM"


def test_result_severity_on_real_result_models():
    base = {"message": Message(text="x")}
    assert result_severity(Result(**base)) == "MEDIUM"
    assert result_severity(Result(level="error", **base)) == "CRITICAL"
    assert result_severity(Result(level="none", **base)) == "INFO"
    assert (
        result_severity(
            Result(level="error", properties={"issue_severity": "high"}, **base)
        )
        == "HIGH"
    )


def test_result_severity_dict_reads_properties_key_not_attribute():
    class D(dict):
        properties = SimpleNamespace(issue_severity="LOW")

    assert result_severity(D(level="error")) == "CRITICAL"


# ---------------------------------------------------------------------------
# normalize_threshold
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("ALL", "ALL"),
        ("low", "LOW"),
        ("  Medium ", "MEDIUM"),
        ("high", "HIGH"),
        ("Critical", "CRITICAL"),
        ("INFO", None),
        ("NONE", None),
        ("", None),
        ("   ", None),
        (None, None),
        (0, None),
        (False, None),
        ([], None),
        (True, None),
        (5, None),
        (["high"], None),
        ("hi gh", None),
        ("ALL ", "ALL"),
        ("\tlow\n", "LOW"),
    ],
)
def test_normalize_threshold_golden(value, expected):
    assert normalize_threshold(value) == expected


def test_normalize_threshold_reads_str_of_non_text_truthy():
    class Named:
        def __str__(self):
            return " high "

    assert normalize_threshold(Named()) == "HIGH"


# ---------------------------------------------------------------------------
# severity_fails_threshold: the threshold case-when
# ---------------------------------------------------------------------------

_ALL_FAIL = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

#: threshold -> the severities that fail it, written out by hand.
_FAILS = {
    "ALL": _ALL_FAIL,
    "LOW": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
    "MEDIUM": {"CRITICAL", "HIGH", "MEDIUM"},
    "HIGH": {"CRITICAL", "HIGH"},
    "CRITICAL": {"CRITICAL"},
}


@pytest.mark.parametrize("threshold", list(_FAILS))
@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
def test_severity_fails_threshold_matrix(severity, threshold):
    assert severity_fails_threshold(severity, threshold) is (
        severity in _FAILS[threshold]
    )


@pytest.mark.parametrize("threshold", list(_FAILS))
def test_unknown_severity_fails_every_ladder_threshold(threshold):
    assert severity_fails_threshold("BOGUS", threshold) is True
    assert severity_fails_threshold("", threshold) is True
    assert severity_fails_threshold("urgent", threshold) is True


@pytest.mark.parametrize("severity", ["critical", "High", " medium"[1:], "LoW", "info"])
def test_severity_is_case_insensitive(severity):
    expected = severity.upper() in _FAILS["MEDIUM"]
    assert severity_fails_threshold(severity, "MEDIUM") is expected


def test_severity_with_surrounding_whitespace_is_unknown_and_fails_closed():
    # ``severity.upper()`` is not stripped: " LOW" is not LOW and fails closed.
    assert severity_fails_threshold(" LOW", "CRITICAL") is True


@pytest.mark.parametrize("threshold", [None, ""])
def test_gate_off_fails_nothing(threshold):
    for severity in list(_ALL_FAIL) + ["BOGUS"]:
        assert severity_fails_threshold(severity, threshold) is False


@pytest.mark.parametrize(
    "threshold",
    ["low", "high", "Medium", "INFO", "NONE", "ALL ", " ALL", "bogus", "*", " "],
)
def test_off_table_text_threshold_gates_like_critical(threshold, ash_log):
    for severity in _ALL_FAIL:
        assert severity_fails_threshold(severity, threshold) is (severity == "CRITICAL")
    assert severity_fails_threshold("BOGUS", threshold) is True
    assert len(ash_log) == 1  # once per value, however many findings


@pytest.mark.parametrize("threshold", [0, False, [], 5, 1.5, ["HIGH"], {"a": 1}, ()])
def test_non_text_threshold_gates_like_critical_even_when_falsy(threshold, ash_log):
    for severity in _ALL_FAIL:
        assert severity_fails_threshold(severity, threshold) is (severity == "CRITICAL")
    assert len(ash_log) == 1


def test_off_table_warning_text_for_a_ladder_shaped_word(ash_log):
    severity_fails_threshold("HIGH", "low")
    assert ash_log == [
        (
            "Severity threshold 'low' is not one of ALL, LOW, MEDIUM, HIGH, CRITICAL "
            "(case-sensitive); it gates like CRITICAL, so only critical findings fail "
            "against it"
        )
    ]


def test_off_table_warning_text_for_free_text_and_non_text(ash_log):
    severity_fails_threshold("HIGH", "has spaces here")
    severity_fails_threshold("HIGH", ["x"])
    severity_fails_threshold("HIGH", 0)
    assert ash_log == [
        (
            "Severity threshold a 15-character value (not shown: not a ladder-shaped "
            "word) is not one of ALL, LOW, MEDIUM, HIGH, CRITICAL (case-sensitive); it "
            "gates like CRITICAL, so only critical findings fail against it"
        ),
        (
            "Severity threshold a value of type list (not shown: not text) is not one "
            "of ALL, LOW, MEDIUM, HIGH, CRITICAL (case-sensitive); it gates like "
            "CRITICAL, so only critical findings fail against it"
        ),
        (
            "Severity threshold a value of type int (not shown: not text) is not one "
            "of ALL, LOW, MEDIUM, HIGH, CRITICAL (case-sensitive); it gates like "
            "CRITICAL, so only critical findings fail against it"
        ),
    ]


def test_off_table_warning_is_once_per_value_and_once_per_type(ash_log):
    for _ in range(5):
        severity_fails_threshold("HIGH", "low")
    severity_fails_threshold("HIGH", "Low")
    severity_fails_threshold("HIGH", [1])
    severity_fails_threshold("HIGH", [2, 3])  # same type, same key: silent
    severity_fails_threshold("HIGH", 7)
    assert len(ash_log) == 4
    assert ladder._WARNED_OFF_TABLE == {"low", "Low", "<list>", "<int>"}


def test_on_ladder_and_gate_off_never_warn(ash_log):
    for threshold in (*SEVERITY_THRESHOLDS, None, ""):
        severity_fails_threshold("HIGH", threshold)
    assert ash_log == []
    assert ladder._WARNED_OFF_TABLE == set()


def test_warned_set_state_is_process_wide_across_functions(ash_log):
    severity_fails_threshold("HIGH", "weird")
    sarif_level_fails_threshold("error", "weird")
    stricter_of("weird", "HIGH")  # stricter_of never warns
    assert len(ash_log) == 1


# ---------------------------------------------------------------------------
# _threshold_for_log
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("low", "'low'"),
        ("a-b_c.d9", "'a-b_c.d9'"),
        ("x" * 32, "'" + "x" * 32 + "'"),
        ("x" * 33, "a 33-character value (not shown: not a ladder-shaped word)"),
        ("", "a 0-character value (not shown: not a ladder-shaped word)"),
        ("a b", "a 3-character value (not shown: not a ladder-shaped word)"),
        # ``$`` matches before a trailing newline, so this one is quoted.
        ("a\n", "'a\\n'"),
        ("a\n\n", "a 3-character value (not shown: not a ladder-shaped word)"),
        ("${SECRET}", "a 9-character value (not shown: not a ladder-shaped word)"),
        (5, "a value of type int (not shown: not text)"),
        (None, "a value of type NoneType (not shown: not text)"),
        ([1], "a value of type list (not shown: not text)"),
    ],
)
def test_threshold_for_log_golden(value, expected):
    assert ladder._threshold_for_log(value) == expected


# ---------------------------------------------------------------------------
# sarif_level_fails_threshold
# ---------------------------------------------------------------------------

#: threshold -> the SARIF levels that fail it, by hand (error is CRITICAL,
#: warning MEDIUM, note LOW, none INFO).
_LEVEL_FAILS = {
    "ALL": {"error", "warning", "note", "none"},
    "LOW": {"error", "warning", "note"},
    "MEDIUM": {"error", "warning"},
    "HIGH": {"error"},
    "CRITICAL": {"error"},
}


@pytest.mark.parametrize("threshold", list(_LEVEL_FAILS))
@pytest.mark.parametrize("level", ["error", "warning", "note", "none"])
def test_sarif_level_fails_threshold_matrix(level, threshold):
    assert sarif_level_fails_threshold(level, threshold) is (
        level in _LEVEL_FAILS[threshold]
    )


def test_sarif_error_cannot_be_told_from_high_under_a_critical_threshold():
    assert sarif_level_fails_threshold("error", "CRITICAL") is True
    assert severity_fails_threshold("HIGH", "CRITICAL") is False


@pytest.mark.parametrize("level", [None, "", "bogus", "fatal", 0, 5])
def test_sarif_missing_or_unknown_level_reads_as_warning(level):
    assert sarif_level_fails_threshold(level, "MEDIUM") is True
    assert sarif_level_fails_threshold(level, "HIGH") is False
    assert sarif_level_fails_threshold(level, "ALL") is True


def test_sarif_level_case_and_enum_and_whitespace():
    assert sarif_level_fails_threshold("ERROR", "HIGH") is True
    assert sarif_level_fails_threshold(" Note ", "LOW") is True
    assert sarif_level_fails_threshold(_Level.note, "MEDIUM") is False
    assert sarif_level_fails_threshold(_Level.error, "CRITICAL") is True


@pytest.mark.parametrize("threshold", [None, ""])
def test_sarif_gate_off(threshold):
    for level in ("error", "warning", "note", "none", None):
        assert sarif_level_fails_threshold(level, threshold) is False


def test_sarif_off_table_threshold_gates_like_critical(ash_log):
    assert sarif_level_fails_threshold("error", "high") is True
    assert sarif_level_fails_threshold("warning", "high") is False
    assert len(ash_log) == 1


# ---------------------------------------------------------------------------
# _gate_is_off, _strictness_key, stricter_of
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,off",
    [
        (None, True),
        ("", True),
        (" ", False),
        (0, False),
        (False, False),
        ([], False),
        ("ALL", False),
        ("x", False),
    ],
)
def test_gate_is_off_golden(value, off):
    assert ladder._gate_is_off(value) is off


@pytest.mark.parametrize(
    "value,key",
    [
        ("ALL", (0, "00")),
        ("LOW", (0, "01")),
        ("MEDIUM", (0, "02")),
        ("HIGH", (0, "03")),
        ("CRITICAL", (0, "04")),
        ("low", (1, "low")),
        ("zzz", (1, "zzz")),
        (0, (1, "<int>")),
        (False, (1, "<bool>")),
        ([], (1, "<list>")),
        (None, (2, "")),
        ("", (2, "")),
    ],
)
def test_strictness_key_golden(value, key):
    assert ladder._strictness_key(value) == key


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("ALL", "CRITICAL", "ALL"),
        ("LOW", "HIGH", "LOW"),
        ("HIGH", "LOW", "LOW"),
        ("MEDIUM", "MEDIUM", "MEDIUM"),
        ("CRITICAL", "HIGH", "HIGH"),
        ("CRITICAL", None, "CRITICAL"),
        (None, "CRITICAL", "CRITICAL"),
        ("", "LOW", "LOW"),
        ("LOW", "", "LOW"),
        (None, None, None),
        ("", "", None),
        (None, "", None),
        ("", None, None),
        ("CRITICAL", "zzz", "CRITICAL"),
        ("zzz", "CRITICAL", "CRITICAL"),
        ("HIGH", "low", "HIGH"),
        ("low", "HIGH", "HIGH"),
        ("aaa", "bbb", "aaa"),
        ("bbb", "aaa", "aaa"),
        (0, None, 0),
        (None, 0, 0),
        # Non-text values are keyed by type name: "<bool>" sorts before "<int>".
        (0, False, False),
        (False, 0, False),
        (0, "CRITICAL", "CRITICAL"),
        ([], "LOW", "LOW"),
        (0, "", 0),
    ],
)
def test_stricter_of_golden(a, b, expected):
    result = stricter_of(a, b)
    assert result == expected
    assert type(result) is type(expected)


def test_stricter_of_is_commutative_over_distinct_keys():
    values = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "zzz", None, ""]
    for a in values:
        for b in values:
            ab, ba = stricter_of(a, b), stricter_of(b, a)
            if ladder._strictness_key(a) != ladder._strictness_key(b):
                assert ab == ba, (a, b)


def test_stricter_of_tie_returns_the_first_argument():
    first, second = [], [1]  # one type, so one key: a tie
    assert stricter_of(first, second) is first
    assert stricter_of(second, first) is second
    assert stricter_of(None, "") is None
    # Different types are not a tie: "<list>" sorts before "<tuple>".
    assert stricter_of((), []) == []
    assert stricter_of([], ()) == []


def test_stricter_of_never_warns(ash_log):
    stricter_of("weird", "weirder")
    assert ash_log == []


def test_stricter_of_folds_to_the_strictest_over_a_large_list():
    ladder_values = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"] * 200
    acc = None
    for v in ladder_values:
        acc = stricter_of(acc, v)
    assert acc == "ALL"
    acc = None
    for v in ["CRITICAL", "HIGH"] * 100:
        acc = stricter_of(acc, v)
    assert acc == "HIGH"


# ---------------------------------------------------------------------------
# result_scanner_name and result_fails_scanner_threshold
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "result,expected",
    [
        ({"properties": {"scanner_name": "grype"}}, "grype"),
        ({"properties": {"scanner_name": ""}}, None),
        ({"properties": {"scanner_name": 5}}, None),
        ({"properties": {"scanner_name": None}}, None),
        ({"properties": {}}, None),
        ({"properties": None}, None),
        ({"properties": "x"}, None),
        ({}, None),
        ({"properties": {"scanner_name": " "}}, " "),
        (SimpleNamespace(properties=SimpleNamespace(scanner_name="bandit")), "bandit"),
        (SimpleNamespace(properties={"scanner_name": "semgrep"}), "semgrep"),
        (SimpleNamespace(properties=SimpleNamespace()), None),
        (SimpleNamespace(properties=None), None),
        (SimpleNamespace(), None),
    ],
)
def test_result_scanner_name_golden(result, expected):
    assert result_scanner_name(result) == expected


def test_result_scanner_name_does_not_strip_or_case_fold():
    assert result_scanner_name({"properties": {"scanner_name": " Grype "}}) == " Grype "


def test_result_fails_scanner_threshold_uses_the_scanners_own_threshold():
    thresholds = {"strict": "ALL", "lax": "CRITICAL", None: "MEDIUM"}
    seen: list = []

    def resolver(name):
        seen.append(name)
        return thresholds.get(name, "MEDIUM")

    note = lambda name: {  # noqa: E731
        "level": "note",
        "properties": {"scanner_name": name} if name else {},
    }
    assert result_fails_scanner_threshold(note("strict"), resolver) is True
    assert result_fails_scanner_threshold(note("lax"), resolver) is False
    assert result_fails_scanner_threshold(note(None), resolver) is False
    assert seen == ["strict", "lax", None]


def test_result_fails_scanner_threshold_severity_is_issue_severity_first():
    result = {
        "level": "note",
        "properties": {"scanner_name": "s", "issue_severity": "CRITICAL"},
    }
    assert result_fails_scanner_threshold(result, lambda name: "CRITICAL") is True
    result["properties"]["issue_severity"] = "low"
    assert result_fails_scanner_threshold(result, lambda name: "CRITICAL") is False


def test_result_fails_scanner_threshold_gate_off_for_a_scanner():
    result = {"level": "error", "properties": {"scanner_name": "off"}}
    assert result_fails_scanner_threshold(result, lambda name: None) is False
    assert result_fails_scanner_threshold(result, lambda name: "") is False


def test_result_fails_scanner_threshold_resolver_called_exactly_once():
    calls: list = []

    def resolver(name):
        calls.append(name)
        return "LOW"

    result_fails_scanner_threshold({"level": "error"}, resolver)
    assert calls == [None]


# ---------------------------------------------------------------------------
# resolve_scanner_threshold: scanner, then global, then the environment default
# ---------------------------------------------------------------------------


def _config(value: Any = "<absent>") -> SimpleNamespace:
    if value == "<absent>":
        return SimpleNamespace(global_settings=SimpleNamespace())
    return SimpleNamespace(global_settings=SimpleNamespace(severity_threshold=value))


@pytest.fixture
def default_level(monkeypatch):
    """The environment default pinned to HIGH for the duration of a test."""
    from automated_security_helper.core import constants

    monkeypatch.setattr(constants, "ASH_DEFAULT_SEVERITY_LEVEL", "HIGH")
    return "HIGH"


@pytest.mark.parametrize(
    "scanner,expected",
    [
        ("LOW", ("LOW", "config")),
        ("low", ("LOW", "config")),
        ("  critical ", ("CRITICAL", "config")),
        ("ALL", ("ALL", "config")),
        ("weird", ("weird", "config")),
        (" Weird ", (" Weird ", "config")),
        ("INFO", ("INFO", "config")),
    ],
)
def test_scanner_text_threshold_wins(scanner, expected, default_level):
    assert resolve_scanner_threshold(scanner, _config("CRITICAL")) == expected


@pytest.mark.parametrize("scanner", [None, "", "   ", "\t"])
def test_blank_or_missing_scanner_falls_to_global(scanner, default_level):
    assert resolve_scanner_threshold(scanner, _config("low")) == ("LOW", "global")


@pytest.mark.parametrize("scanner", [0, False, [], 5, ["HIGH"], 1.5, {"a": 1}])
def test_non_text_scanner_threshold_is_unset_and_warns(scanner, default_level, ash_log):
    assert resolve_scanner_threshold(scanner, _config("LOW")) == ("LOW", "global")
    assert len(ash_log) == 1
    assert (
        "is ignored; the global severity threshold applies to that scanner"
        in ash_log[0]
    )


def test_dropped_scanner_warning_text_and_dedupe(default_level, ash_log):
    cfg = _config("LOW")
    resolve_scanner_threshold(5, cfg, scanner_name="bandit")
    resolve_scanner_threshold(6, cfg, scanner_name="bandit")  # same scanner, type
    resolve_scanner_threshold(5, cfg, scanner_name="grype")
    resolve_scanner_threshold([1], cfg, scanner_name="bandit")
    resolve_scanner_threshold(5, cfg)
    resolve_scanner_threshold(5, cfg)
    assert ash_log == [
        (
            "Scanner bandit's severity threshold a value of type int (not shown: not "
            "text) is ignored; the global severity threshold applies to that scanner"
        ),
        (
            "Scanner grype's severity threshold a value of type int (not shown: not "
            "text) is ignored; the global severity threshold applies to that scanner"
        ),
        (
            "Scanner bandit's severity threshold a value of type list (not shown: not "
            "text) is ignored; the global severity threshold applies to that scanner"
        ),
        (
            "Scanner severity threshold a value of type int (not shown: not text) is "
            "ignored; the global severity threshold applies to that scanner"
        ),
    ]
    assert ladder._WARNED_DROPPED_SCANNER == {
        "bandit: <int>",
        "grype: <int>",
        "bandit: <list>",
        "<int>",
    }


def test_none_scanner_threshold_never_warns(default_level, ash_log):
    resolve_scanner_threshold(None, _config("LOW"))
    assert ash_log == []


@pytest.mark.parametrize(
    "configured,expected",
    [
        ("high", ("HIGH", "global")),
        (" medium ", ("MEDIUM", "global")),
        ("ALL", ("ALL", "global")),
        ("weird", ("weird", "global")),
        (" Weird ", (" Weird ", "global")),
    ],
)
def test_global_text_threshold(configured, expected, default_level):
    assert resolve_scanner_threshold(None, _config(configured)) == expected


@pytest.mark.parametrize("configured", [None, "", "   ", 0, False, 5, [], ["HIGH"]])
def test_blank_or_non_text_global_falls_to_the_environment_default(
    configured, default_level
):
    assert resolve_scanner_threshold(None, _config(configured)) == ("HIGH", "global")


def test_global_non_text_never_warns_or_returns_the_value(default_level, ash_log):
    result = resolve_scanner_threshold(None, _config(5))
    assert result == ("HIGH", "global")
    assert ash_log == []


@pytest.mark.parametrize(
    "ash_config",
    [
        None,
        object(),
        SimpleNamespace(),
        SimpleNamespace(global_settings=None),
        SimpleNamespace(global_settings=SimpleNamespace()),
    ],
)
def test_no_usable_config_uses_the_environment_default(ash_config, default_level):
    assert resolve_scanner_threshold(None, ash_config) == ("HIGH", "global")


def test_scanner_threshold_ignores_config_entirely_when_set(default_level):
    # No attribute of the config is even read.
    class Exploding:
        @property
        def global_settings(self):
            raise AssertionError("must not be read")

    assert resolve_scanner_threshold("low", Exploding()) == ("LOW", "config")


def test_default_is_the_constants_value_read_at_call_time(monkeypatch):
    from automated_security_helper.core import constants

    monkeypatch.setattr(constants, "ASH_DEFAULT_SEVERITY_LEVEL", "LOW")
    assert resolve_scanner_threshold(None, None) == ("LOW", "global")
    monkeypatch.setattr(constants, "ASH_DEFAULT_SEVERITY_LEVEL", "CRITICAL")
    assert resolve_scanner_threshold(None, None) == ("CRITICAL", "global")


def test_default_value_is_returned_unvalidated(monkeypatch):
    from automated_security_helper.core import constants

    monkeypatch.setattr(constants, "ASH_DEFAULT_SEVERITY_LEVEL", "whatever")
    assert resolve_scanner_threshold("", _config("")) == ("whatever", "global")


def test_resolve_never_returns_a_gate_off_value(default_level):
    for scanner in (None, "", " ", 0, False, []):
        for configured in (None, "", " ", 0, False, []):
            threshold, source = resolve_scanner_threshold(scanner, _config(configured))
            assert threshold and source == "global"


def test_resolve_then_gate_end_to_end(default_level):
    cfg = _config("MEDIUM")

    def resolver_for(scanner_threshold):
        return resolve_scanner_threshold(scanner_threshold, cfg)[0]

    note = {"level": "note"}
    warning = {"level": "warning"}
    assert result_fails_scanner_threshold(note, lambda n: resolver_for("low")) is True
    assert result_fails_scanner_threshold(note, lambda n: resolver_for(None)) is False
    assert result_fails_scanner_threshold(warning, lambda n: resolver_for(None)) is True
    assert (
        result_fails_scanner_threshold(warning, lambda n: resolver_for("critical"))
        is False
    )


# ---------------------------------------------------------------------------
# Unicode and large-N ordering
# ---------------------------------------------------------------------------


def test_unicode_severities_and_thresholds_are_unrecognised(ash_log):
    assert severity_fails_threshold("ÉLEVÉ", "HIGH") is True  # unknown severity: closed
    assert severity_fails_threshold("HIGH", "ÉLEVÉ") is False
    assert severity_fails_threshold("CRITICAL", "ÉLEVÉ") is True
    assert len(ash_log) == 1  # one text, one warning, however it is compared
    assert ladder._WARNED_OFF_TABLE == {"ÉLEVÉ"}
    # Fullwidth capitals normalize under str.upper() but are not ladder words.
    assert normalize_threshold("ｈｉｇｈ") is None
    assert normalize_threshold("ﬁ") is None


def test_large_n_gate_counts_golden():
    levels = ["error", "warning", "note", "none"] * 2500
    results = [{"level": level} for level in levels]
    counts = {
        t: sum(result_fails_scanner_threshold(r, lambda n, t=t: t) for r in results)
        for t in SEVERITY_THRESHOLDS
    }
    assert counts == {
        "ALL": 10000,
        "LOW": 7500,
        "MEDIUM": 5000,
        "HIGH": 2500,
        "CRITICAL": 2500,
    }


def test_large_n_result_severity_order_is_input_order():
    results = [
        {"level": "note", "properties": {"issue_severity": "high"}}
        if i % 3 == 0
        else {"level": "error"}
        if i % 3 == 1
        else {}
        for i in range(999)
    ]
    got = [result_severity(r) for r in results]
    assert got == [("HIGH", "CRITICAL", "MEDIUM")[i % 3] for i in range(999)]
