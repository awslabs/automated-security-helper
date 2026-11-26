# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The flatten's suppressed-count reconciliation, pinned against the block it replaces.

``AshAggregatedResults.to_flat_vulnerabilities`` sets the summary's suppressed count
from the flattened findings and then reconciles each scanner row with the count the
unified metrics give it, in two loops. Both loops asked the per-name SARIF reader
(``extract_sarif_counts_for_scanner``), which walks the whole SARIF once per call.
``oracle_reconcile`` below is that block, copied unchanged with the per-name reader
in both loops; each case builds the same model twice, runs the shipped flatten on one
and the oracle on the other, and requires the same summary count, the same rows
(type, both suppressed counts, the fields each marks as set, and whether the row
object was left alone) and the same raise, if any.

The cases are seeded random models plus the hand-built ones the reconciliation
turns on: row keys in either case, rows of the three shapes the rows can hold,
dict-result reports under two keys that fold to one name, results a scanner owns
only by a tag or by ``scanner_details``, stale rows and an empty SARIF.
"""

from __future__ import annotations

import random
from typing import Any, Callable, Dict

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
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
from tests.unit.models._suppressed_count_helpers import dict_report

pytestmark = pytest.mark.unit

_NAMES = ["Bandit", "bandit", "Shape", "shape", "grype"]
_RUN_TOOLS = ["bandit", "shape-tool", "ASH Aggregated Results"]


# --------------------------------------------------------------------------
# The block as it stood, copied unchanged.
# --------------------------------------------------------------------------


def oracle_reconcile(model: AshAggregatedResults, flat_vulns) -> None:
    suppressed_by_scanner = model._suppressed_by_scanner(flat_vulns)
    model.metadata.summary_stats.suppressed = sum(suppressed_by_scanner.values())
    row_names = {
        name.lower() for name in model.scanner_results if isinstance(name, str)
    }
    for scanner_key, count in suppressed_by_scanner.items():
        if scanner_key in row_names:
            count = max(
                count,
                ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                    model, scanner_key
                )[0],
            )
        model._apply_suppression_side_effects(scanner_key, count)
    for row_name, row in model.scanner_results.items():
        if (
            isinstance(row, ScannerTargetStatusInfo)
            and isinstance(row_name, str)
            and row_name.lower() not in suppressed_by_scanner
            and (row.suppressed_finding_count or row.severity_counts.suppressed)
        ):
            counted = ScannerStatisticsCalculator.extract_sarif_counts_for_scanner(
                model, row_name
            )[0]
            row.suppressed_finding_count = counted
            row.severity_counts.suppressed = counted


# --------------------------------------------------------------------------
# Models.
# --------------------------------------------------------------------------


def _result(
    scanner: str | None = None,
    tags: list[str] | None = None,
    details: str | None = None,
    suppression: str | None = "in effect",
) -> Result:
    properties: Dict[str, Any] = {}
    if scanner is not None:
        properties["scanner_name"] = scanner
    if tags is not None:
        properties["tags"] = tags
    if details is not None:
        properties["scanner_details"] = {"tool_name": details}
    suppressions = None
    if suppression == "in effect":
        suppressions = [Suppression(kind="external", justification="reviewed")]
    elif suppression == "rejected":
        suppressions = [Suppression(kind="external", state="rejected")]
    return Result(
        ruleId="R",
        level="error",
        message=Message(text="m"),
        properties=PropertyBag(**properties),
        suppressions=suppressions,
    )


def _sarif(results: list[Result], tool: str = "shape-tool") -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=tool, version="1")),
                results=results,
                properties=PropertyBag(),
            )
        ],
    )


def _empty() -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    return model


def _random_model(seed: int) -> AshAggregatedResults:
    rng = random.Random(seed)
    results = []
    for _ in range(rng.randrange(0, 9)):
        how = rng.choice(["named", "tag", "details", "none"])
        results.append(
            _result(
                scanner=rng.choice(_NAMES) if how == "named" else None,
                tags=[rng.choice(["bandit", "grype"])] if how == "tag" else None,
                details=rng.choice(_NAMES) if how == "details" else None,
                suppression=rng.choice(["in effect", "in effect", "rejected", None]),
            )
        )
    model = _empty()
    if results:
        model.sarif = _sarif(results, rng.choice(_RUN_TOOLS))
    for name in rng.sample([*_NAMES, "stale"], k=rng.randrange(0, 4)):
        shape = rng.choice(["target", "target", "dict", "info"])
        if shape == "target":
            row: Any = ScannerTargetStatusInfo(
                suppressed_finding_count=rng.randrange(0, 4),
                severity_counts=ScannerSeverityCount(suppressed=rng.randrange(0, 4)),
            )
        elif shape == "dict":
            row = {"status": "PASSED", "suppressed_finding_count": rng.randrange(0, 3)}
        else:
            row = ScannerStatusInfo()
        model.scanner_results[name] = row
    reports = {
        name: {"source": dict_report(rng.randrange(0, 4), name)}
        for name in rng.sample(_NAMES, k=rng.randrange(0, 3))
    }
    if reports:
        model.additional_reports = reports
    return model


def _two_keys_that_fold_to_one_name() -> AshAggregatedResults:
    # The row is "Bandit"; the SARIF holds two suppressed results the metrics give
    # it by their tag alone; the dict reports sit under "Bandit" (none suppressed)
    # and "bandit" (five). The row's own spelling reads the first and not the second.
    model = _empty()
    model.sarif = _sarif(
        [_result(tags=["bandit"]), _result(tags=["bandit"])], "ASH Aggregated Results"
    )
    model.scanner_results["Bandit"] = ScannerTargetStatusInfo(
        suppressed_finding_count=4,
        severity_counts=ScannerSeverityCount(suppressed=4),
    )
    model.additional_reports = {
        "Bandit": {"source": dict_report(0, "Bandit")},
        "bandit": {"source": dict_report(5, "bandit")},
    }
    return model


def _row_key_in_the_other_case() -> AshAggregatedResults:
    model = _empty()
    model.sarif = _sarif(
        [
            _result(scanner="bandit"),
            _result(scanner="BANDIT"),
            _result(scanner="bandit"),
        ]
    )
    model.scanner_results["BANDIT"] = ScannerTargetStatusInfo()
    return model


def _every_row_shape_beside_a_tag_only_result() -> AshAggregatedResults:
    model = _empty()
    model.sarif = _sarif(
        [_result(tags=["grype"]), _result(details="Shape"), _result(scanner="shape")]
    )
    model.scanner_results["grype"] = ScannerTargetStatusInfo(suppressed_finding_count=1)
    model.scanner_results["Shape"] = {"status": "PASSED", "suppressed_finding_count": 2}
    model.scanner_results["stale"] = ScannerTargetStatusInfo(
        suppressed_finding_count=3,
        severity_counts=ScannerSeverityCount(suppressed=3),
    )
    model.scanner_results["info"] = ScannerStatusInfo()
    return model


def _empty_sarif_with_a_stale_row() -> AshAggregatedResults:
    model = _empty()
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(
        suppressed_finding_count=2,
        severity_counts=ScannerSeverityCount(suppressed=2),
    )
    return model


_CASES: Dict[str, Callable[[], AshAggregatedResults]] = {
    **{f"seed-{seed}": (lambda seed=seed: _random_model(seed)) for seed in range(40)},
    "two-keys-fold-to-one-name": _two_keys_that_fold_to_one_name,
    "row-key-in-the-other-case": _row_key_in_the_other_case,
    "every-row-shape": _every_row_shape_beside_a_tag_only_result,
    "empty-sarif-stale-row": _empty_sarif_with_a_stale_row,
}


# --------------------------------------------------------------------------
# What is compared.
# --------------------------------------------------------------------------


def _observe(model: AshAggregatedResults, before: Dict[Any, Any]) -> Dict[str, Any]:
    rows: Dict[Any, Dict[str, Any]] = {}
    for key, row in model.scanner_results.items():
        entry: Dict[str, Any] = {"left_alone": before.get(key) is row}
        if isinstance(row, dict):
            entry["dict"] = dict(row)
        else:
            counts = getattr(row, "severity_counts", None)
            entry.update(
                type=type(row).__name__,
                suppressed_finding_count=getattr(row, "suppressed_finding_count", None),
                severity_suppressed=getattr(counts, "suppressed", None),
                fields_set=sorted(row.model_fields_set),
                counts_fields_set=(
                    sorted(counts.model_fields_set) if counts is not None else None
                ),
            )
        rows[key] = entry
    stats = model.metadata.summary_stats
    return {
        "rows": rows,
        "summary": stats.suppressed,
        "summary_fields_set": sorted(stats.model_fields_set),
    }


def _outcome(run: Callable[[], Any]) -> tuple:
    try:
        run()
    except Exception as error:  # noqa: BLE001 -- the compare reads the failure
        return ("raised", type(error).__name__, str(error))
    return ("value",)


def _shipped(case: str) -> tuple:
    model = _CASES[case]()
    before = dict(model.scanner_results)
    outcome = _outcome(model.to_flat_vulnerabilities)
    return outcome, _observe(model, before)


def _oracle(case: str) -> tuple:
    # The findings the oracle reconciles against are flattened from a model of
    # its own, so the model under test sees only the copied block.
    flat_vulns = _CASES[case]().to_flat_vulnerabilities()
    model = _CASES[case]()
    before = dict(model.scanner_results)
    outcome = _outcome(lambda: oracle_reconcile(model, flat_vulns))
    return outcome, _observe(model, before)


@pytest.mark.parametrize("case", list(_CASES))
def test_the_reconciliation_leaves_the_summary_and_every_row_as_the_block_did(case):
    assert _shipped(case) == _oracle(case)


def test_the_hand_built_cases_reach_each_loop():
    # The corpus must exercise what it pins. The first loop sets a row to the
    # larger of the flattened count and the metrics' count: three suppressed
    # results under two spellings of one scanner reach the row under a third.
    _, first = _oracle("row-key-in-the-other-case")
    assert first["rows"]["BANDIT"]["suppressed_finding_count"] == 3
    # The second loop sets a row the flattened counts do not name: two results the
    # metrics give the row by their tag alone, and none from the row's own spelling
    # of the dict reports.
    _, second = _oracle("two-keys-fold-to-one-name")
    assert second["rows"]["Bandit"]["suppressed_finding_count"] == 2
    assert second["rows"]["Bandit"]["severity_suppressed"] == 2


# --------------------------------------------------------------------------
# One walk, made only when a loop needs a count.
# --------------------------------------------------------------------------


def _spy_on_the_readers(monkeypatch) -> Dict[str, int]:
    calls = {"batch": 0, "per_name": 0}
    batch = ScannerStatisticsCalculator.sarif_counts_by_scanner
    per_name = ScannerStatisticsCalculator.extract_sarif_counts_for_scanner

    def counting_batch(model):
        calls["batch"] += 1
        return batch(model)

    def counting_per_name(model, name):
        calls["per_name"] += 1
        return per_name(model, name)

    monkeypatch.setattr(
        ScannerStatisticsCalculator,
        "sarif_counts_by_scanner",
        staticmethod(counting_batch),
    )
    monkeypatch.setattr(
        ScannerStatisticsCalculator,
        "extract_sarif_counts_for_scanner",
        staticmethod(counting_per_name),
    )
    return calls


def test_a_model_whose_loops_read_no_count_walks_nothing(monkeypatch):
    calls = _spy_on_the_readers(monkeypatch)
    model = _empty()
    model.sarif = _sarif([_result(scanner="bandit"), _result(scanner="grype")])

    model.to_flat_vulnerabilities()

    assert calls == {"batch": 0, "per_name": 0}


def test_every_row_the_loops_reconcile_shares_one_walk(monkeypatch):
    calls = _spy_on_the_readers(monkeypatch)
    model = _empty()
    model.sarif = _sarif(
        [_result(scanner="bandit"), _result(scanner="grype"), _result(tags=["shape"])]
    )
    for name in ("Bandit", "grype", "stale"):
        model.scanner_results[name] = ScannerTargetStatusInfo(
            suppressed_finding_count=1,
            severity_counts=ScannerSeverityCount(suppressed=1),
        )

    model.to_flat_vulnerabilities()

    assert calls == {"batch": 1, "per_name": 0}
