# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``WorkspaceAggregator.add`` counts a project's results the way the loop did.

``OracleAggregator.add`` below is ``WorkspaceAggregator.add`` as it was written
before its per-result partition and finding count moved onto one frame, kept
verbatim as an oracle (it calls the same leaf helpers). Each case builds one set
of outcomes and runs, deep-copies it into two aggregators with separate output
directories, and requires the aggregator under test and the oracle to agree on:

* ``list(d.items())`` of every per-scanner dict, so first-seen order is pinned
  (``==`` on a dict ignores it);
* the unconvertible total;
* the name and bytes of every spool file;
* the ``scanner_results`` payload the rollup publishes.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import pytest

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.workspace.aggregation import (
    SCANNER_EXIT_CODE_UNRECORDED,
    UNATTRIBUTED_SCANNER,
    WorkspaceAggregator,
    _larger_code,
    _worse_status,
    count_actionable_results,
    is_policy_origin,
    rebase_run_for_project,
    result_is_suppressed,
    result_scanner_name,
)
from automated_security_helper.workspace.plan import ProjectPlan
from tests.unit.workspace.test_workspace_reporting import _plan

pytestmark = pytest.mark.unit

PER_SCANNER_DICTS = (
    "_scanner_display",
    "_scanner_status",
    "_scanner_findings",
    "_scanner_actionable",
    "_scanner_exit_code",
    "_scanner_excluded",
    "_scanner_dependencies",
)


# ---------------------------------------------------------------------------
# the oracle: add() as it was, one result at a time
# ---------------------------------------------------------------------------


class OracleAggregator(WorkspaceAggregator):
    def add(
        self,
        outcome: WorkspaceProjectResult,
        run: Optional[Mapping[str, Any]],
        project: ProjectPlan,
    ) -> None:
        self._outcomes[outcome.project] = outcome

        flags = outcome.carried_scanner_flags
        for raw_name, status in (outcome.scanners or {}).items():
            scanner = self._rollup_key(raw_name)
            code = outcome.carried_scanner_exit_codes.get(
                raw_name, SCANNER_EXIT_CODE_UNRECORDED
            )
            held = self._scanner_status.get(scanner)
            worse = _worse_status(held, status)
            if scanner not in self._scanner_exit_code or worse != held:
                self._scanner_exit_code[scanner] = code
            elif status == held:
                self._scanner_exit_code[scanner] = _larger_code(
                    self._scanner_exit_code[scanner], code
                )
            self._scanner_status[scanner] = worse
            self._scanner_findings.setdefault(scanner, 0)
            self._scanner_actionable.setdefault(scanner, 0)
            if raw_name in flags:
                excluded, satisfied = flags[raw_name]
                self._scanner_excluded[scanner] = (
                    self._scanner_excluded.get(scanner, True) and excluded
                )
                self._scanner_dependencies[scanner] = (
                    self._scanner_dependencies.get(scanner, True) and satisfied
                )

        if run is None:
            return

        rebased, unconvertible = rebase_run_for_project(run, project)
        self._unconvertible += unconvertible

        by_scanner: Dict[str, List[Mapping[str, Any]]] = {}
        for result in rebased.get("results") or []:
            if not isinstance(result, Mapping):
                continue
            scanner = result_scanner_name(result)
            name = self._rollup_key(scanner or UNATTRIBUTED_SCANNER)
            by_scanner.setdefault(name, []).append(result)
            self._scanner_status.setdefault(name, None)
            if result_is_suppressed(result):
                continue
            self._scanner_findings[name] = self._scanner_findings.get(name, 0) + 1

        for name in by_scanner:
            self._scanner_actionable.setdefault(name, 0)
        carried = outcome.carried_scanner_actionable_counts
        if carried is not None:
            if outcome.actionable_finding_count:
                for raw_name, actionable in carried.items():
                    name = self._rollup_key(raw_name)
                    self._scanner_actionable[name] = (
                        self._scanner_actionable.get(name, 0) + actionable
                    )
        elif outcome.actionable_finding_count:
            gate_off = outcome.policy_scanners_gate is False
            for name, results in by_scanner.items():
                counted = [
                    result
                    for result in results
                    if not (gate_off and is_policy_origin(result))
                ]
                actionable = count_actionable_results(
                    counted,
                    project.gate_threshold,
                    threshold_for=outcome.threshold_for_scanner,
                )
                self._scanner_actionable[name] = (
                    self._scanner_actionable.get(name, 0) + actionable
                )

        self._make_spool_dir()
        spool_path = (
            self.spool_dir / f"{len(self._spooled):04d}-{outcome.project}.run.json"
        )
        from automated_security_helper.utils.sandbox.fs_guard import (
            open_for_atomic_write,
        )

        with open_for_atomic_write(spool_path, root=self.output_dir) as handle:
            json.dump(rebased, handle)
        self._spooled[outcome.project] = spool_path


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------

MISSING = object()

LONE_SURROGATE = chr(0xDC80)
BELOW_SURROGATES = chr(0xD7FF)
ABOVE_SURROGATES = chr(0xE000)


def result(
    scanner: Any = "bandit",
    *,
    severity: str = "HIGH",
    suppressions: Any = MISSING,
    origin: Optional[str] = None,
    properties: Any = MISSING,
    uri: str = "src/a.py",
) -> Dict[str, Any]:
    """One SARIF result, shaped the way a project scan emits it."""
    if properties is MISSING:
        properties = {"issue_severity": severity}
        if scanner is not MISSING:
            properties["scanner_name"] = scanner
        if origin is not None:
            properties["origin"] = origin
    built: Dict[str, Any] = {
        "ruleId": "RULE",
        "level": "error",
        "message": {"text": "m"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}}},
        ],
    }
    if properties is not None:
        built["properties"] = properties
    if suppressions is not MISSING:
        built["suppressions"] = suppressions
    return built


def run_of(results: Any = MISSING) -> Dict[str, Any]:
    built: Dict[str, Any] = {"tool": {"driver": {"name": "ash"}}}
    if results is not MISSING:
        built["results"] = results
    return built


def outcome_of(
    key: str,
    *,
    scanners: Optional[Dict[str, str]] = None,
    carried: Optional[Dict[str, int]] = None,
    actionable: int = 0,
    gate: Optional[bool] = True,
) -> WorkspaceProjectResult:
    built = WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        output_path=f"projects/{key}",
        scanners=scanners or {},
        actionable_finding_count=actionable,
        policy_scanners_gate=gate,
    )
    if carried is not None:
        built.carry_scanner_actionable_counts(carried)
    return built


Project = Tuple[WorkspaceProjectResult, Optional[Dict[str, Any]]]


def one(results: Any = MISSING, **outcome_kwargs: Any) -> List[Project]:
    return [(outcome_of("web", **outcome_kwargs), run_of(results))]


def accepted() -> List[Dict[str, str]]:
    return [{"kind": "inSource", "state": "accepted"}]


def stateless() -> List[Dict[str, str]]:
    return [{"kind": "inSource"}]


def rejected() -> List[Dict[str, str]]:
    return [{"kind": "inSource", "state": "rejected"}]


def under_review() -> List[Dict[str, str]]:
    return [{"kind": "inSource", "state": "underReview"}]


CASES: Dict[str, List[Project]] = {
    "two-spellings-of-one-scanner": one(
        [result("Bandit"), result(" bandit "), result("BANDIT")]
    ),
    "lone-surrogate-beside-its-neighbours": one(
        [
            result(LONE_SURROGATE),
            result(BELOW_SURROGATES),
            result(ABOVE_SURROGATES),
            result(LONE_SURROGATE),
            result(BELOW_SURROGATES + "X"),
        ]
    ),
    "names-that-are-not-text": one(
        [
            result(""),
            result(None),
            result(1),
            result(["a"]),
            result(MISSING),
            result("real"),
        ]
    ),
    "properties-missing-or-not-a-dict": one(
        [
            result(properties=None),
            result(properties="text"),
            result(properties=["scanner_name", "x"]),
            result(properties={}),
            result("real"),
        ]
    ),
    "suppression-states": one(
        [
            result("a"),
            result("a", suppressions=[]),
            result("a", suppressions=accepted()),
            result("a", suppressions=stateless()),
            result("a", suppressions=rejected()),
            result("a", suppressions=under_review()),
            result("b", suppressions=accepted()),
            result("b", suppressions=rejected()),
        ]
    ),
    "first-result-suppressed-later-one-not": one(
        [
            result("zeta", suppressions=accepted()),
            result("alpha"),
            result("beta", suppressions=accepted()),
            result("zeta"),
            result("alpha", suppressions=accepted()),
            result("beta"),
            result("zeta"),
        ]
    ),
    "every-result-of-a-scanner-suppressed": one(
        [
            result("quiet", suppressions=accepted()),
            result("loud"),
            result("quiet", suppressions=stateless()),
            result("loud"),
        ]
    ),
    "non-mapping-entries": one(
        [None, [1, 2], "text", 7, result("a"), None, result("b")]
    ),
    "results-missing": one(),
    "results-empty": one([]),
    "results-none": one(None),
    "run-none": [(outcome_of("web", scanners={"Bandit": "PASSED"}), None)],
    "carried-split-with-actionable": one(
        [result("a"), result("b", severity="LOW"), result("a", severity="LOW")],
        scanners={"A": "FAILED", "b": "PASSED"},
        carried={"a": 2, "B": 1, "ghost": 4},
        actionable=3,
    ),
    "carried-split-zero-actionable": one(
        [result("a"), result("b")],
        scanners={"a": "PASSED"},
        carried={"a": 2, "b": 1},
        actionable=0,
    ),
    "no-split-gate-on": one(
        [
            result("a", severity="CRITICAL"),
            result("b", severity="LOW"),
            result("a", severity="LOW"),
            result("pol", severity="HIGH", origin="policy"),
        ],
        actionable=2,
        gate=True,
    ),
    "no-split-gate-off-with-policy-origin": one(
        [
            result("a", severity="CRITICAL"),
            result("pol", severity="HIGH", origin="policy"),
            result("pol", severity="HIGH", origin="policy", suppressions=accepted()),
            result("b", severity="MEDIUM"),
        ],
        actionable=2,
        gate=False,
    ),
    "no-split-gate-unset": one(
        [result("a"), result("b", severity="LOW")],
        actionable=1,
        gate=None,
    ),
    "no-split-zero-actionable": one(
        [result("a"), result("b")],
        actionable=0,
    ),
    "scanner-rows-and-findings-meet": one(
        [result("Bandit"), result("semgrep", suppressions=accepted())],
        scanners={"bandit": "PASSED", "Semgrep": "FAILED", "only-a-row": "SKIPPED"},
        actionable=1,
    ),
    "two-projects": [
        (
            outcome_of("web", scanners={"bandit": "PASSED"}),
            run_of([result("Bandit"), result("zeta", suppressions=accepted())]),
        ),
        (
            outcome_of("api", scanners={"Bandit": "FAILED"}, actionable=1),
            run_of([result(" bandit "), result("alpha"), result("zeta")]),
        ),
    ],
}


def _add_all(aggregator: WorkspaceAggregator, projects: Sequence[Project]) -> None:
    plan_by_key = {project.key: project for project in aggregator.plan.projects}
    for outcome, run in projects:
        aggregator.add(outcome, run, plan_by_key[outcome.project])


def _snapshot(aggregator: WorkspaceAggregator) -> Dict[str, Any]:
    spool: Dict[str, bytes] = {}
    if aggregator.spool_dir.exists():
        spool = {
            path.name: path.read_bytes()
            for path in sorted(aggregator.spool_dir.iterdir())
        }
    return {
        "dicts": {
            name: list(getattr(aggregator, name).items()) for name in PER_SCANNER_DICTS
        },
        "unconvertible": aggregator._unconvertible,
        "spool": spool,
        "spooled": [(key, path.name) for key, path in aggregator._spooled.items()],
        "payload": list(aggregator._scanner_results_payload().items()),
    }


def _build(tmp_path, cls, projects: Sequence[Project]) -> WorkspaceAggregator:
    keys = [outcome.project for outcome, _ in projects]
    plan = _plan(tmp_path / "ws", *dict.fromkeys(keys))
    aggregator = cls(plan=plan, output_dir=tmp_path / f"out-{cls.__name__}")
    _add_all(aggregator, copy.deepcopy(list(projects)))
    return aggregator


@pytest.mark.parametrize("name", list(CASES))
def test_add_counts_as_the_loop_did(tmp_path, name):
    projects = CASES[name]
    got = _snapshot(_build(tmp_path, WorkspaceAggregator, projects))
    want = _snapshot(_build(tmp_path, OracleAggregator, projects))
    assert got == want


@pytest.mark.parametrize("name", [n for n, p in CASES.items() if len(p) > 1])
def test_add_counts_as_the_loop_did_in_the_other_order(tmp_path, name):
    projects = list(reversed(CASES[name]))
    got = _snapshot(_build(tmp_path, WorkspaceAggregator, projects))
    want = _snapshot(_build(tmp_path, OracleAggregator, projects))
    assert got == want


def test_the_cases_exercise_what_they_claim(tmp_path):
    """Controls: the oracle sees suppressed and unsuppressed rows, so a vacuous
    comparison (both sides empty) cannot pass."""
    state = _snapshot(
        _build(
            tmp_path, OracleAggregator, CASES["first-result-suppressed-later-one-not"]
        )
    )
    assert state["dicts"]["_scanner_findings"] == [
        ("alpha", 1),
        ("zeta", 2),
        ("beta", 1),
    ]
    assert [name for name, _ in state["dicts"]["_scanner_status"]] == [
        "zeta",
        "alpha",
        "beta",
    ]
    quiet = _snapshot(
        _build(
            tmp_path, OracleAggregator, CASES["every-result-of-a-scanner-suppressed"]
        )
    )
    assert dict(quiet["dicts"]["_scanner_findings"]) == {"loud": 2}
    assert dict(quiet["dicts"]["_scanner_status"]) == {"quiet": None, "loud": None}
    assert dict(quiet["dicts"]["_scanner_actionable"]) == {"quiet": 0, "loud": 0}
