# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The count and status arithmetic, pinned against verbatim copies of the loops.

Four places count findings by scanner and severity (the statistics calculator's
per-scanner read, ``get_severity_metrics_from_sarif``, the workspace
aggregation's actionable counts, and the per-scanner summary the calculator
rolls up), and two places grade a scanner's status through the same ordered
case-when (``get_unified_scanner_metrics`` and ``get_summary_statistics``). The
oracles below are those loops as they stood before the counts moved onto one
frame pipeline, copied unchanged; every case runs the shipped code and the
oracle on the same input and requires the same answer, an exception included.

The corpus is a seeded random set of results (case-folded and unattributed
scanner names, a lone surrogate in a name, every level, declared severities
that are and are not known, suppressions in every state) plus the hand-built
cases the arithmetic turns on.
"""

from __future__ import annotations

import itertools
import random
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    _resolve_result_severity,
    get_severity_metrics_from_sarif,
    is_result_suppressed,
)
from automated_security_helper.utils.severity_ladder import (
    result_fails_scanner_threshold,
    result_scanner_name,
)
from automated_security_helper.workspace.aggregation import (
    UNATTRIBUTED_SCANNER,
    actionable_results_by_scanner,
    count_actionable_results,
    effective_threshold_resolver,
    result_is_suppressed,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_SCANNERS = ["Bandit", "bandit", "semgrep", "Semgrep", None, "sc\udcffan", "grype"]
_LEVELS = ["error", "warning", "note", "none", None]
_DECLARED = [None, None, "CRITICAL", "high", " Medium ", "low", "INFO", "weird"]
_STATES = [None, "accepted", "rejected", "underReview"]


def _result_dict(rng: random.Random) -> Dict[str, Any]:
    properties: Dict[str, Any] = {}
    scanner = rng.choice(_SCANNERS)
    if scanner is not None:
        properties["scanner_name"] = scanner
    declared = rng.choice(_DECLARED)
    if declared is not None:
        properties["issue_severity"] = declared
    result: Dict[str, Any] = {
        "ruleId": f"R{rng.randrange(5)}",
        "message": {"text": "m"},
        "properties": properties,
    }
    level = rng.choice(_LEVELS)
    if level is not None:
        result["level"] = level
    if rng.random() < 0.4:
        state = rng.choice(_STATES)
        suppression: Dict[str, Any] = {"kind": "external"}
        if state is not None:
            suppression["state"] = state
        result["suppressions"] = [suppression]
    return result


def _corpus(seed: int, size: int = 60) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    return [_result_dict(rng) for _ in range(size)]


def _sarif(results: List[Dict[str, Any]]) -> SarifReport:
    built = []
    for item in results:
        properties = item["properties"]
        built.append(
            Result(
                ruleId=item["ruleId"],
                level=item.get("level"),
                message=Message(text="m"),
                properties=PropertyBag(**properties),
                suppressions=[Suppression(**s) for s in item.get("suppressions", [])]
                or None,
            )
        )
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH", version="1")),
                results=built,
            )
        ],
    )


def _model(results: List[Dict[str, Any]]) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.sarif = _sarif(results)
    return model


def _outcome(fn: Callable[[], Any]) -> Any:
    try:
        return ("value", fn())
    except Exception as error:  # noqa: BLE001 -- the oracle compare reads the failure
        return ("raised", type(error).__name__, str(error))


# --------------------------------------------------------------------------
# The loops as they stood, copied unchanged.
# --------------------------------------------------------------------------


def oracle_sarif_counts(model, scanner_name):
    counts = ScannerSeverityCount()
    if model.sarif:
        for result in model.sarif.get_all_results():
            result_scanner = ScannerStatisticsCalculator._get_scanner_name_from_result(
                result
            )
            if not (result_scanner and result_scanner.lower() == scanner_name.lower()):
                continue
            if is_result_suppressed(result):
                counts.increment("suppressed")
            else:
                counts.increment(_resolve_result_severity(result))
    dict_counts = ScannerStatisticsCalculator._dict_result_counts(model, scanner_name)
    for field in ("suppressed", "critical", "high", "medium", "low", "info"):
        setattr(counts, field, getattr(counts, field) + getattr(dict_counts, field))
    return (
        counts.suppressed,
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.info,
    )


def oracle_severity_metrics(sarif_report):
    # get_severity_metrics_from_sarif after its two in-place normalizations.
    counts = ScannerSeverityCount()
    for result in sarif_report.get_all_results():
        if is_result_suppressed(result):
            counts.increment("suppressed")
        else:
            counts.increment(_resolve_result_severity(result))
    return counts


def oracle_actionable(results, threshold, threshold_for=None):
    effective = effective_threshold_resolver(threshold, threshold_for)
    counts: Dict[str, int] = {}
    for result in results:
        if not hasattr(result, "get"):
            continue
        scanner = result_scanner_name(result)
        name = scanner or UNATTRIBUTED_SCANNER
        counts.setdefault(name, 0)
        if result_is_suppressed(result):
            continue
        if result_fails_scanner_threshold(result, effective):
            counts[name] += 1
    return counts


def _dump(counts: ScannerSeverityCount):
    return counts.model_dump()


# --------------------------------------------------------------------------
# Per-scanner severity counts from the SARIF (+ dict reports).
# --------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(12))
def test_the_per_scanner_counts_equal_the_loop_for_every_name(seed):
    results = _corpus(seed)
    names = {n for n in _SCANNERS if n} | {"missing", "BANDIT"}
    for name in sorted(names):
        model = _model(results)
        expected = _outcome(lambda: oracle_sarif_counts(model, name))
        actual = _outcome(
            lambda: ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, name
            )
        )
        assert actual == expected, (seed, name)


def test_a_model_with_no_sarif_counts_zero():
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    assert ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
        model, "bandit"
    ) == (0, 0, 0, 0, 0, 0)


def test_a_result_whose_severity_the_counts_do_not_know_raises_as_before():
    results = [
        {
            "ruleId": "R",
            "message": {"text": "m"},
            "properties": {"scanner_name": "bandit", "issue_severity": "weird"},
        }
    ]
    model = _model(results)
    assert _outcome(
        lambda: ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
            model, "bandit"
        )
    ) == _outcome(lambda: oracle_sarif_counts(model, "bandit"))


def test_a_scanner_name_with_a_lone_surrogate_is_counted_under_itself():
    results = [
        {
            "ruleId": "R",
            "level": "error",
            "message": {"text": "m"},
            "properties": {"scanner_name": "sc\udcffan"},
        },
        {
            "ruleId": "R",
            "level": "note",
            "message": {"text": "m"},
            "properties": {"scanner_name": "sc\udcffan"},
            "suppressions": [{"kind": "external"}],
        },
    ]
    model = _model(results)
    # Whatever the name reads as, the counts are the loop's.
    for name in ("SC\udcffAN", "sc\udcffan", "scan"):
        assert _outcome(
            lambda: ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, name
            )
        ) == _outcome(lambda: oracle_sarif_counts(model, name))


# --------------------------------------------------------------------------
# The names the SARIF holds, and the counts read for every name of the union.
# --------------------------------------------------------------------------


def oracle_sarif_names(model):
    # ``_get_scanner_names_from_sarif`` as it stood (its debug logging dropped):
    # a set of the exact spellings, listed in the set's order.
    names = set()
    if model.sarif and model.sarif.runs:
        for run in model.sarif.runs:
            if not run.results:
                continue
            for result in run.results:
                name = ScannerStatisticsCalculator._get_scanner_name_from_result(result)
                if name:
                    names.add(name)
    return list(names)


def oracle_union_counts(model):
    # The union loop of ``extract_scanner_statistics`` over a model whose names come
    # from the SARIF alone, one name per case-folded spelling, each counted by the
    # per-name walk. Keyed by the folded name: which spelling of two the set listed
    # first follows string hashing, so it is not part of what is pinned here.
    counts = {}
    for name in oracle_sarif_names(model):
        folded = name.lower()
        if folded in counts:
            continue
        counts[folded] = oracle_sarif_counts(model, name)
    return counts


def _stats_counts(model):
    stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)
    return {
        name.lower(): tuple(
            row[field]
            for field in ("suppressed", "critical", "high", "medium", "low", "info")
        )
        for name, row in stats.items()
    }


@pytest.mark.parametrize("seed", range(12))
def test_every_union_name_reads_the_counts_the_per_name_walk_gives(seed):
    results = _corpus(seed)
    expected = _outcome(lambda: oracle_union_counts(_model(results)))
    actual = _outcome(lambda: _stats_counts(_model(results)))
    assert actual == expected, seed


def _batch_counts(model, name):
    batch = ScannerStatisticsCalculator.sarif_counts_by_scanner(model)
    return ScannerStatisticsCalculator._with_dict_counts(
        model, name, batch.for_name(name)
    )


@pytest.mark.parametrize("seed", range(12))
def test_the_batch_counts_of_every_name_equal_the_per_name_loop(seed):
    results = _corpus(seed)
    names = {n for n in _SCANNERS if n} | {"missing", "BANDIT", ""}
    for name in sorted(names):
        model = _model(results)
        expected = _outcome(lambda: oracle_sarif_counts(model, name))
        actual = _outcome(lambda: _batch_counts(model, name))
        assert actual == expected, (seed, name)


def test_the_batch_names_the_scanners_of_named_results_only():
    results = [
        {
            "ruleId": "R",
            "level": "error",
            "message": {"text": "m"},
            "properties": {},
        },
        {
            "ruleId": "R",
            "level": "note",
            "message": {"text": "m"},
            "properties": {"scanner_name": "bandit"},
        },
    ]
    model = _model(results)
    batch = ScannerStatisticsCalculator.sarif_counts_by_scanner(model)
    assert batch.names == ["bandit"]
    assert batch.for_name("") == ScannerSeverityCount()
    assert "" not in ScannerStatisticsCalculator.extract_scanner_statistics(model)


@pytest.mark.parametrize("first,second", [("Bandit", "bandit"), ("bandit", "Bandit")])
def test_a_scanner_named_only_in_the_sarif_keeps_the_spelling_it_was_first_named_by(
    first, second
):
    results = [
        {
            "ruleId": "R",
            "level": "error",
            "message": {"text": "m"},
            "properties": {"scanner_name": name},
        }
        for name in (first, second, first)
    ]
    model = _model(results)
    assert ScannerStatisticsCalculator._get_scanner_names_from_sarif(model) == [
        first,
        second,
    ]
    stats = ScannerStatisticsCalculator.extract_scanner_statistics(model)
    assert list(stats) == [first]
    assert stats[first]["critical"] == 3


def test_a_name_that_is_not_text_is_folded_only_when_a_result_names_a_scanner():
    empty = _model([])
    named = _model(_corpus(0))
    for model in (empty, named):
        assert _outcome(lambda: _batch_counts(model, 5)) == _outcome(
            lambda: oracle_sarif_counts(model, 5)
        )


@pytest.mark.parametrize("seed", range(12))
def test_the_names_found_in_the_sarif_equal_the_old_names_as_a_set(seed):
    model = _model(_corpus(seed))
    assert set(ScannerStatisticsCalculator._get_scanner_names_from_sarif(model)) == set(
        oracle_sarif_names(model)
    )
    assert len(ScannerStatisticsCalculator._get_scanner_names_from_sarif(model)) == len(
        oracle_sarif_names(model)
    )


# --------------------------------------------------------------------------
# get_severity_metrics_from_sarif.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(12))
def test_the_sarif_severity_metrics_equal_the_loop(seed):
    results = _corpus(seed)
    a, b = _sarif(results), _sarif(results)
    expected = _outcome(lambda: _dump(_normalized_oracle(a)))
    actual = _outcome(lambda: _dump(get_severity_metrics_from_sarif(b, None)))
    assert actual == expected


def _normalized_oracle(report):
    from automated_security_helper.utils.sarif_utils import (
        normalize_sarif_result_severities,
        resolve_missing_levels,
    )

    if not report or not getattr(report, "runs", None):
        return ScannerSeverityCount()
    normalize_sarif_result_severities(report)
    resolve_missing_levels(report)
    return oracle_severity_metrics(report)


def test_no_report_and_no_runs_count_nothing():
    assert _dump(get_severity_metrics_from_sarif(None, None)) == _dump(
        ScannerSeverityCount()
    )
    assert _dump(
        get_severity_metrics_from_sarif(SarifReport(version="2.1.0", runs=[]), None)
    ) == _dump(ScannerSeverityCount())


# --------------------------------------------------------------------------
# The workspace aggregation's actionable counts.
# --------------------------------------------------------------------------


def _own(mapping: Dict[Optional[str], Optional[str]]):
    return lambda scanner: mapping.get(scanner)


@pytest.mark.parametrize("seed", range(12))
@pytest.mark.parametrize(
    "threshold,own",
    [
        ("HIGH", None),
        ("low", None),
        ("CRITICAL", {"bandit": "LOW", "semgrep": "MEDIUM"}),
        (None, {"bandit": "MEDIUM"}),
        (None, None),
        ("", {"Semgrep": "HIGH"}),
    ],
)
def test_the_actionable_counts_equal_the_loop(seed, threshold, own):
    results = _corpus(seed)
    threshold_for = _own(own) if own is not None else None
    expected = _outcome(lambda: oracle_actionable(results, threshold, threshold_for))
    actual = _outcome(
        lambda: actionable_results_by_scanner(
            results, threshold, threshold_for=threshold_for
        )
    )
    assert actual == expected
    if expected[0] == "value":
        assert list(actual[1]) == list(expected[1])  # first-seen order
        assert count_actionable_results(
            results, threshold, threshold_for=threshold_for
        ) == sum(expected[1].values())


def test_a_non_mapping_result_is_skipped_and_a_resolver_is_not_asked_for_it():
    asked: List[Any] = []

    def own(scanner):
        asked.append(scanner)
        return None

    results = [
        object(),
        {
            "ruleId": "R",
            "level": "error",
            "message": {"text": "m"},
            "properties": {"scanner_name": "bandit"},
        },
    ]
    assert actionable_results_by_scanner(results, "LOW", threshold_for=own) == {
        "bandit": 1
    }
    assert asked == ["bandit"]


def test_a_suppressed_result_never_asks_the_gate():
    asked: List[Any] = []

    def own(scanner):
        asked.append(scanner)
        return "LOW"

    results = [
        {
            "ruleId": "R",
            "level": "error",
            "message": {"text": "m"},
            "properties": {"scanner_name": "bandit"},
            "suppressions": [{"kind": "external"}],
        }
    ]
    assert actionable_results_by_scanner(results, "LOW", threshold_for=own) == {
        "bandit": 0
    }
    assert asked == []


def test_a_scanner_name_with_a_lone_surrogate_keeps_its_text_in_the_actionable_keys():
    results = [
        {
            "ruleId": "R",
            "level": "error",
            "message": {"text": "m"},
            "properties": {"scanner_name": "sc\udcffan"},
        }
    ]
    assert actionable_results_by_scanner(results, "LOW") == {"sc\udcffan": 1}


# --------------------------------------------------------------------------
# The ordered status case-when, through both of its readers.
# --------------------------------------------------------------------------

_FLAGS = (
    "error",
    "unusable",
    "actionable",
    "excluded",
    "dependencies_missing",
    "evaluated_nothing",
)


def _stats(error, actionable, excluded, dependencies_missing, evaluated_nothing):
    return {
        "suppressed": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": 0,
        "actionable": 1 if actionable else 0,
        "duration": None,
        "threshold": "HIGH",
        "threshold_source": "default",
        "error": error,
        "excluded": excluded,
        "dependencies_missing": dependencies_missing,
        "evaluated_nothing": evaluated_nothing,
    }


def _expected_status(error, unusable, actionable, excluded, missing, nothing):
    # The branch order, written once here: error or unusable counters, findings,
    # excluded, dependencies missing, evaluated nothing, otherwise the recorded row.
    if error or unusable:
        return "ERROR"
    if actionable:
        return "FAILED"
    if excluded:
        return "SKIPPED"
    if missing:
        return "MISSING"
    if nothing:
        return "SKIPPED"
    return "PASSED"


@pytest.mark.parametrize("combo", list(itertools.product([False, True], repeat=6)))
def test_the_status_cascade_and_the_summary_buckets_follow_one_order(combo):
    error, unusable, actionable, excluded, missing, nothing = combo
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    stats = {"s": _stats(error, actionable, excluded, missing, nothing)}
    counters = (None, None) if unusable else (1, 0)
    with (
        patch.object(
            ScannerStatisticsCalculator,
            "extract_scanner_statistics",
            return_value=stats,
        ),
        patch(
            "automated_security_helper.core.unified_metrics.target_counts",
            return_value=(1, 0),
        ),
        patch(
            "automated_security_helper.core.unified_metrics.counters_unusable",
            return_value=unusable,
        ),
        patch.object(
            ScannerStatisticsCalculator,
            "dict_counts_unrecorded",
            return_value=False,
        ),
        patch.object(
            ScannerStatisticsCalculator, "graded_level_agrees", return_value=True
        ),
        patch(
            "automated_security_helper.core.unified_metrics.tool_exit_code",
            return_value=None,
        ),
        patch(
            "automated_security_helper.core.unified_metrics.dependencies_recorded_satisfied",
            return_value=False,
        ),
        patch(
            "automated_security_helper.core.unified_metrics.recorded_reason",
            return_value=None,
        ),
    ):
        (metrics,) = get_unified_scanner_metrics(model)
        summary = ScannerStatisticsCalculator.get_summary_statistics(model)

    expected = _expected_status(*combo)
    assert str(getattr(metrics.status, "value", metrics.status)) == expected
    buckets = {
        "ERROR": "error_scanners",
        "FAILED": "failed_scanners",
        "SKIPPED": "skipped_scanners",
        "MISSING": "missing_scanners",
        "PASSED": "passed_scanners",
    }
    for status, key in buckets.items():
        assert summary[key] == (1 if status == expected else 0), (combo, key)
    assert (
        counters is not None
    )  # the unusable pair is patched through counters_unusable
