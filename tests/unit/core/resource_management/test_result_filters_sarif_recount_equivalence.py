# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The SARIF recounts in the result filters count what the loops counted.

``ORACLE_filter_actionable_only`` and ``ORACLE_stats_of_sarif`` are the two
functions as they were written before their per-result counting moved onto the
frame helpers, kept unchanged (the first without its docstring) as oracles. They
call the module's own leaf helpers, so only the counting differs. Raw JSON SARIF
whose scanner names are mixed-case, null, non-text, empty or a lone surrogate
written as a JSON escape goes through both, and the comparison is
``json.dumps`` without ``sort_keys``, so the key order of every dict the
response carries counts, as does the missing-thresholds ValueError.
"""

import copy
import json
import random
from typing import Any, Dict, Optional

import pytest

from automated_security_helper.core.resource_management import result_filters as rf
from automated_security_helper.core.resource_management.result_filters import (
    _SEVERITY_KEYS,
    _actionable_in_view,
    _get_finding_severity,
    _outcome_counter,
    _sarif_scanner_name,
    _seed_scanners_the_sarif_never_named,
    _stats_of_scanners,
    _stats_of_sarif,
    _workspace_project_gates,
    filter_actionable_only,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# the oracles: the two functions as they were
# ---------------------------------------------------------------------------


def ORACLE_filter_actionable_only(results: Dict[str, Any]) -> Dict[str, Any]:
    filtered_results = copy.deepcopy(results)
    kept_counts: Optional[Dict[str, int]] = None
    kept_per_scanner: Dict[str, Dict[str, int]] = {}
    saw_a_result = False

    raw = filtered_results.get("raw_results")
    if isinstance(raw, dict) and "sarif" in raw and raw["sarif"] is None:
        stats = filtered_results.get("summary_stats")
        actionable = stats.get("actionable") if isinstance(stats, dict) else None
        if rf._count(actionable) > 0:
            filtered_results["findings_available"] = False
            warnings = filtered_results.get("warnings")
            if not isinstance(warnings, list):
                warnings = filtered_results["warnings"] = []
            warnings.append(
                "The scan's results carry no SARIF, so its "
                f"{actionable} actionable finding(s) cannot be listed"
            )

    if isinstance(raw, dict) and "sarif" in raw and isinstance(raw["sarif"], dict):
        sarif = filtered_results["raw_results"]["sarif"]
        thresholds = filtered_results["raw_results"].get("severity_thresholds")
        if "runs" in sarif:
            if not isinstance(thresholds, dict):
                raise ValueError(
                    "The scan's SARIF came without raw_results.severity_thresholds, "
                    "so which of its findings are actionable cannot be decided"
                )
            kept_counts = dict.fromkeys(_SEVERITY_KEYS, 0)
            projects = _workspace_project_gates(filtered_results["raw_results"])
            for run in sarif["runs"]:
                if "results" in run and run["results"]:
                    saw_a_result = True
                    for r in run["results"]:
                        name = _sarif_scanner_name(r)
                        if name is not None:
                            kept_per_scanner.setdefault(
                                name, dict.fromkeys(_SEVERITY_KEYS, 0)
                            )
                    run["results"] = [
                        r
                        for r in run["results"]
                        if _actionable_in_view(r, thresholds, projects)
                    ]
                    for r in run["results"]:
                        bucket = _get_finding_severity(r).lower()
                        if bucket in kept_counts:
                            kept_counts[bucket] += 1
                        name = _sarif_scanner_name(r)
                        if name is not None and bucket in kept_per_scanner[name]:
                            kept_per_scanner[name][bucket] += 1
            if kept_per_scanner or not saw_a_result:
                _seed_scanners_the_sarif_never_named(
                    filtered_results["raw_results"], kept_per_scanner
                )

    scanner_rows = None
    if (
        "raw_results" in filtered_results
        and "scanner_results" in filtered_results["raw_results"]
    ):
        scanner_rows = filtered_results["raw_results"]["scanner_results"]
        for name, scanner_data in scanner_rows.items():
            if not isinstance(scanner_data, dict):
                continue
            if "suppressed_finding_count" in scanner_data:
                scanner_data["suppressed_finding_count"] = 0
            if (
                "severity_counts" in scanner_data
                and "suppressed" in scanner_data["severity_counts"]
            ):
                scanner_data["severity_counts"]["suppressed"] = 0
            kept = kept_per_scanner.get(name)
            if kept is None:
                continue
            kept_total = sum(kept.values())
            if "finding_count" in scanner_data:
                scanner_data["finding_count"] = kept_total
            scanner_data["actionable_finding_count"] = kept_total
            if isinstance(scanner_data.get("severity_counts"), dict):
                scanner_data["severity_counts"] = {
                    **scanner_data["severity_counts"],
                    **kept,
                }

    if "summary_stats" in filtered_results:
        summary_stats = filtered_results["summary_stats"]
        if not isinstance(summary_stats, dict) or not summary_stats:
            if isinstance(scanner_rows, dict) and scanner_rows:
                summary_stats = _stats_of_scanners(scanner_rows)
                filtered_results["summary_stats"] = summary_stats
            else:
                summary_stats = None
        if summary_stats:
            summary_stats["suppressed"] = 0
            if isinstance(summary_stats.get("severity_counts"), dict):
                summary_stats["severity_counts"]["suppressed"] = 0
            summary_stats["total"] = summary_stats.get("actionable")
            if kept_counts is not None:
                if isinstance(summary_stats.get("severity_counts"), dict):
                    summary_stats["severity_counts"] = {
                        **summary_stats["severity_counts"],
                        **kept_counts,
                    }
                for bucket, value in kept_counts.items():
                    if bucket in summary_stats:
                        summary_stats[bucket] = value

    if "_content_filters" not in filtered_results:
        filtered_results["_content_filters"] = {}
    filtered_results["_content_filters"]["actionable_only"] = True

    return filtered_results


def ORACLE_stats_of_sarif(
    sarif: Dict[str, Any],
    thresholds: Any,
    projects: Optional[Dict[str, Dict[str, Any]]],
) -> Dict[str, Any]:
    from automated_security_helper.utils.sarif_utils import is_result_suppressed

    counts = dict.fromkeys(_SEVERITY_KEYS, 0)
    total = 0
    actionable: Optional[int] = 0 if isinstance(thresholds, dict) else None
    for run in sarif.get("runs") or []:
        for result in (run.get("results") or []) if isinstance(run, dict) else []:
            if is_result_suppressed(result):
                counts["suppressed"] += 1
                continue
            total += 1
            bucket = _get_finding_severity(result).lower()
            if bucket in counts:
                counts[bucket] += 1
            if actionable is not None and _actionable_in_view(
                result, thresholds, projects
            ):
                actionable += 1
    return {
        "severity_counts": counts,
        "total": total,
        "actionable": actionable,
    }


# ---------------------------------------------------------------------------
# inputs: raw JSON, as the loader hands it over
# ---------------------------------------------------------------------------

# Scanner names as JSON text: mixed case, empty, null, non-text, a lone
# surrogate and a non-ASCII name written as escapes.
_NAMES_JSON = [
    '"bandit"',
    '"Bandit"',
    '"BANDIT"',
    '"semgrep"',
    '"opengrep"',
    '"\\ud800x"',
    '"\\udfff"',
    '"caf\\u00e9"',
    '"caf\\u00c3\\u00a9"',
    '""',
    "null",
    "5",
    "true",
    '["bandit"]',
    '{"a": 1}',
]
_SEVERITIES_JSON = [
    "null",
    '"CRITICAL"',
    '"critical"',
    '"HIGH"',
    '"High"',
    '"MEDIUM"',
    '"LOW"',
    '"INFO"',
    '"bogus"',
    "7",
]
_LEVELS_JSON = ['"error"', '"warning"', '"note"', '"none"', "null", '"weird"']
_SUPPRESSIONS_JSON = [
    "null",
    "[]",
    '[{"kind": "inSource", "status": "accepted"}]',
    '[{"kind": "external", "status": "rejected"}]',
    '[{"kind": "external", "status": "underReview"}]',
    '[{"kind": "inSource"}]',
]
_PROJECTS_JSON = ["null", '"p1"', '"p2"', '"ghost"', '""']
_ORIGINS_JSON = ["null", '"workspace-policy"', '"other"']


def _result(rnd: random.Random) -> Dict[str, Any]:
    props = {}
    if rnd.random() < 0.9:
        props["scanner_name"] = json.loads(rnd.choice(_NAMES_JSON))
    if rnd.random() < 0.6:
        props["issue_severity"] = json.loads(rnd.choice(_SEVERITIES_JSON))
    if rnd.random() < 0.4:
        props["workspace_project"] = json.loads(rnd.choice(_PROJECTS_JSON))
    if rnd.random() < 0.3:
        props["origin"] = json.loads(rnd.choice(_ORIGINS_JSON))
    result: Dict[str, Any] = {"ruleId": f"R{rnd.randrange(5)}", "properties": props}
    if rnd.random() < 0.9:
        result["level"] = json.loads(rnd.choice(_LEVELS_JSON))
    suppressions = json.loads(rnd.choice(_SUPPRESSIONS_JSON))
    if suppressions is not None:
        result["suppressions"] = suppressions
    return result


def _run(rnd: random.Random) -> Dict[str, Any]:
    shape = rnd.random()
    run: Dict[str, Any] = {"tool": {"driver": {"name": "t"}}}
    if shape < 0.1:
        return run  # no results key
    if shape < 0.2:
        run["results"] = []
    elif shape < 0.3:
        run["results"] = None
    else:
        run["results"] = [_result(rnd) for _ in range(rnd.randrange(1, 9))]
    return run


def _thresholds(rnd: random.Random) -> Any:
    shape = rnd.random()
    if shape < 0.08:
        return None
    if shape < 0.12:
        return ["not", "a", "dict"]
    names = ["bandit", "Bandit", "semgrep", "opengrep", "\ud800x", "café"]
    levels = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL", None, ""]
    out = {n: rnd.choice(levels) for n in names if rnd.random() < 0.6}
    if rnd.random() < 0.8:  # the "" key is the global threshold
        out[""] = rnd.choice(levels)
    return out


def _projects_block(rnd: random.Random) -> Optional[Dict[str, Any]]:
    if rnd.random() < 0.6:
        return None
    entries = []
    for key in ("p1", "p2"):
        if rnd.random() < 0.8:
            entries.append(
                {
                    "project": key,
                    "severity_threshold": rnd.choice(["ALL", "HIGH", None, ""]),
                    "scanner_thresholds": {"bandit": rnd.choice(["LOW", "", None])},
                    "withheld_scanner_thresholds": rnd.choice([["semgrep"], [], None]),
                    "policy_scanners_gate": rnd.choice([True, False, None]),
                }
            )
    return {"projects": entries}


def _scanner_rows(rnd: random.Random) -> Dict[str, Any]:
    rows: Dict[str, Any] = {}
    for name in ("bandit", "Bandit", "semgrep", "opengrep", "idle", "\ud800x"):
        if rnd.random() < 0.7:
            row: Dict[str, Any] = {
                "status": rnd.choice(["PASSED", "FAILED", "SKIPPED"])
            }
            if rnd.random() < 0.8:
                row["finding_count"] = rnd.randrange(9)
            if rnd.random() < 0.8:
                row["actionable_finding_count"] = rnd.randrange(9)
            if rnd.random() < 0.8:
                row["suppressed_finding_count"] = rnd.randrange(9)
            if rnd.random() < 0.8:
                row["severity_counts"] = {
                    "critical": 1,
                    "high": 2,
                    "suppressed": rnd.randrange(4),
                }
            rows[name] = row
    if rnd.random() < 0.1:
        rows["junk"] = "not a dict"
    return rows


def _document(rnd: random.Random) -> Dict[str, Any]:
    raw: Dict[str, Any] = {}
    sarif_shape = rnd.random()
    if sarif_shape < 0.05:
        raw["sarif"] = None
    elif sarif_shape < 0.1:
        raw["sarif"] = {"version": "2.1.0"}  # no "runs"
    else:
        raw["sarif"] = {
            "version": "2.1.0",
            "runs": [_run(rnd) for _ in range(rnd.randrange(0, 4))],
        }
    thresholds = _thresholds(rnd)
    if rnd.random() < 0.95:
        raw["severity_thresholds"] = thresholds
    workspace = _projects_block(rnd)
    if workspace is not None:
        raw["workspace"] = workspace
    if rnd.random() < 0.9:
        raw["scanner_results"] = _scanner_rows(rnd)
    document: Dict[str, Any] = {"raw_results": raw}
    stats_shape = rnd.random()
    if stats_shape < 0.6:
        document["summary_stats"] = {
            "actionable": rnd.randrange(9),
            "total": 99,
            "suppressed": 4,
            "critical": 3,
            "high": 3,
            "severity_counts": {"critical": 3, "suppressed": 5, "low": 1},
        }
    elif stats_shape < 0.8:
        document["summary_stats"] = {}
    return document


def _outcome(fn, *args):
    try:
        return json.dumps(fn(*args), ensure_ascii=True)
    except ValueError as exc:
        return f"ValueError: {exc}"


SEEDS = range(600)


@pytest.mark.parametrize("seed", SEEDS)
def test_filter_actionable_only_matches_the_loops(seed):
    rnd = random.Random(seed)
    document = _document(rnd)
    before = json.dumps(document, ensure_ascii=True)
    assert _outcome(filter_actionable_only, document) == _outcome(
        ORACLE_filter_actionable_only, document
    )
    assert json.dumps(document, ensure_ascii=True) == before  # input untouched


@pytest.mark.parametrize("seed", SEEDS)
def test_stats_of_sarif_matches_the_loops(seed):
    rnd = random.Random(10_000 + seed)
    document = _document(rnd)
    raw = document["raw_results"]
    sarif = raw["sarif"] if isinstance(raw["sarif"], dict) else {"runs": []}
    thresholds = raw.get("severity_thresholds")
    projects = _workspace_project_gates(raw)
    assert _outcome(_stats_of_sarif, sarif, thresholds, projects) == _outcome(
        ORACLE_stats_of_sarif, sarif, thresholds, projects
    )


def test_the_seeded_inputs_reach_every_shape_the_comparison_is_for():
    """A coverage check on the generator, so a green run means something."""
    seen = {
        "named_rows": 0,
        "unnamed_rows": 0,
        "surrogate": 0,
        "raised": 0,
        "no_results_key": 0,
        "empty_results": 0,
        "null_results": 0,
        "gate_false": 0,
        "no_global_threshold": 0,
        "nonzero_kept": 0,
    }
    for seed in SEEDS:
        document = _document(random.Random(seed))
        raw = document["raw_results"]
        out = _outcome(ORACLE_filter_actionable_only, document)
        seen["raised"] += out.startswith("ValueError")
        if isinstance(raw.get("severity_thresholds"), dict):
            seen["no_global_threshold"] += "" not in raw["severity_thresholds"]
        for entry in (raw.get("workspace") or {}).get("projects", []):
            seen["gate_false"] += entry["policy_scanners_gate"] is False
        sarif = raw["sarif"] if isinstance(raw["sarif"], dict) else {}
        for run in sarif.get("runs", []):
            if "results" not in run:
                seen["no_results_key"] += 1
            elif run["results"] == []:
                seen["empty_results"] += 1
            elif run["results"] is None:
                seen["null_results"] += 1
            for r in run.get("results") or []:
                name = _sarif_scanner_name(r)
                seen["named_rows"] += name is not None
                seen["unnamed_rows"] += name is None
                seen["surrogate"] += bool(name) and name.startswith("\ud800")
        if not out.startswith("ValueError"):
            kept = json.loads(out)["raw_results"].get("sarif")
            if isinstance(kept, dict):
                for run in kept.get("runs", []):
                    seen["nonzero_kept"] += bool(run.get("results"))
    assert all(value > 0 for value in seen.values()), seen


def test_outcome_counter_is_still_the_modules():
    # the oracle and the code share this helper; a rename here must be loud
    assert _outcome_counter({"status": "PASSED"}) == "passed"
