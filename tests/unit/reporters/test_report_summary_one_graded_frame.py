# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``get_scan_summary`` answers what it did before it graded each finding once.

``_OldSummary`` below carries ``get_scan_summary`` and ``_graded_frame`` as they
were written when the summary built a graded frame per count (the workspace
recount, the no-scanner-rows branch, the additional-report rows and the policy
total each graded their own rows): the code is kept as it was, comments and
docstrings aside, as an oracle. The new emitter and the oracle are built over
the same model for every combination of

* a workspace scan or a single-directory scan,
* scanner rows or none,
* list-form additional reports or none,
* a workspace policy that gates or does not,
* suppressed rows among the findings or none,
* the duplicate fold on or off,

and the whole summary dict must be equal. A probe on the two grading hooks
counts their calls, and the new emitter's counts may only drop.
"""

import itertools
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
    is_workspace_scan,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    SUMMARY_ACTIONABLE,
    SUMMARY_BELOW_THRESHOLD,
    SUMMARY_POLICY_NOT_GATING,
    SUMMARY_SUPPRESSED,
    OutcomeTone,
    ReportContentEmitter,
    _add_level_counts,
    flag_total,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.finding_clusters import clusters_by_project
from automated_security_helper.utils.severity_ladder import SEVERITY_COUNT_KEYS

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# the oracle: the summary as it was written, one frame per count
# ---------------------------------------------------------------------------


class _OldSummary:
    def get_scan_summary(self):
        from automated_security_helper.core.unified_metrics import coverage_shortfalls
        from automated_security_helper.utils.content_db_staleness import (
            scanners_in_error_for_a_stale_database,
            stale_content_databases,
        )
        from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_skipped_rows import (
            skipped_projects,
        )
        from automated_security_helper.interactions.run_ash_scan import (
            scan_incompleteness,
        )

        results = self.get_scanner_results()
        ran_against_stale = scanners_in_error_for_a_stale_database(self.model)
        shortfalls = coverage_shortfalls(self.model)
        partial_scanners = {
            name
            for name, attempted, failed in shortfalls
            if attempted is not None and failed is not None and failed < attempted
        }

        def ran(result):
            return result["status"] in (
                ScannerStatus.PASSED,
                ScannerStatus.FAILED,
            ) or (
                result["status"] == ScannerStatus.ERROR
                and (
                    result["scanner_name"] in ran_against_stale
                    or result["scanner_name"] in partial_scanners
                )
            )

        counts = {
            level: sum(result[level] for result in results)
            for level in SEVERITY_COUNT_KEYS
        }
        actionable = sum(result["actionable"] for result in results)
        suppressed = sum(result["suppressed"] for result in results)
        rows_failed = any(
            result["status"] == ScannerStatus.FAILED for result in results
        )
        if is_workspace_scan(self.model):
            actionable = sum(
                self.is_finding_actionable(vuln) for vuln in self.flat_vulns
            )
            rows_failed = False
        if not results:
            counts = dict.fromkeys(counts, 0)
            every = self._graded_frame(self.flat_vulns, actionable=True)
            _add_level_counts(counts, every)
            actionable = flag_total(every, "actionable")
            suppressed = flag_total(every, "is_suppressed")
        else:
            extras = self._graded_frame(
                self._additional_report_findings(),
                actionable=not is_workspace_scan(self.model),
            )
            _add_level_counts(counts, extras)
            suppressed += flag_total(extras, "is_suppressed")
            if not is_workspace_scan(self.model):
                actionable += flag_total(extras, "actionable")
        completed = sum(ran(result) for result in results)
        skipped = sum(result["status"] == ScannerStatus.SKIPPED for result in results)
        unavailable = [
            result["scanner_name"]
            for result in results
            if result["status"] != ScannerStatus.SKIPPED and not ran(result)
        ]
        stale = stale_content_databases(self.model)
        skipped_workspace = [
            entry for entry in skipped_projects(self.model) if entry.reason.is_error
        ]
        coverage = scan_incompleteness(self.model, gate=True)
        shortfall_scanners = {name for name, _, _ in shortfalls}
        unavailable.extend(
            name
            for name, _ in coverage.scanners
            if name not in unavailable and name not in shortfall_scanners
        )
        completed_names = {result["scanner_name"] for result in results if ran(result)}
        unavailable_count = sum(name not in completed_names for name in unavailable)
        active = sum(counts.values())
        policy_not_gating = flag_total(self._graded_frame(self.flat_vulns), "left_out")
        could_not_stop = list(coverage.could_not_stop)
        incomplete = bool(
            unavailable
            or shortfalls
            or skipped_workspace
            or coverage.converters
            or coverage.unevaluated_rules
            or coverage.no_scanner_ran
            or could_not_stop
        )
        finding_label = "finding" if actionable == 1 else "findings"
        gap_tone = (
            OutcomeTone.DANGER if actionable or rows_failed else OutcomeTone.WARNING
        )

        if not completed:
            title, tone = "No scanners completed", OutcomeTone.WARNING
            description = "Scanner coverage is unavailable."
            next_step = (
                "Check scanner results and dependencies, then run the scan again."
            )
        elif could_not_stop:
            title, tone = "Scan incomplete", gap_tone
            description = (
                f"{actionable} actionable {finding_label}. A scanner tool could not be "
                "stopped and may still be writing, so this report may not be final."
            )
            next_step = "Stop the named tool, then run the scan again."
        elif incomplete:
            title, tone = "Scan incomplete", gap_tone
            description = f"{actionable} actionable {finding_label}. Some inputs or scanners were not evaluated."
            next_step = "Review findings, resolve coverage gaps, and scan again."
        elif stale:
            title, tone = "Scan needs attention", gap_tone
            description = f"{actionable} actionable {finding_label}. Content database freshness needs review."
            next_step = "Review the database notices, refresh the affected scanners, and scan again."
        elif actionable or rows_failed:
            title, tone = "Review required", OutcomeTone.DANGER
            description = f"{actionable} {finding_label} at or above the configured scanner thresholds."
            next_step = "Review findings by severity, then inspect the source."
        else:
            title, tone = "No actionable findings", OutcomeTone.SUCCESS
            if policy_not_gating:
                policy_noun = "finding is" if policy_not_gating == 1 else "findings are"
                description = (
                    "Completed scanners reported no findings that count toward the "
                    f"outcome. {policy_not_gating} workspace-policy {policy_noun} "
                    "reported and left out of it because policy_scanners_gate is off."
                )
                next_step = (
                    "Review the workspace-policy findings left out of the outcome, "
                    "then scanner coverage and findings below the threshold."
                )
            else:
                description = "Completed scanners reported no findings at or above their configured thresholds."
                next_step = "Review scanner coverage and findings below the threshold."

        summary = {
            "title": title,
            "tone": tone.value,
            "description": description,
            "next_step": next_step,
            SUMMARY_ACTIONABLE: actionable,
            "active": active,
            SUMMARY_BELOW_THRESHOLD: max(0, active - actionable - policy_not_gating),
            SUMMARY_POLICY_NOT_GATING: policy_not_gating,
            SUMMARY_SUPPRESSED: suppressed,
            "counts": counts,
            "completed": completed,
            "scanners": len(results),
            "skipped": skipped,
            "unavailable": unavailable,
            "unavailable_count": unavailable_count,
            "shortfalls": shortfalls,
            "stale": stale,
            "converter_gaps": coverage.converters,
            "unevaluated_rules": coverage.unevaluated_rules,
            "could_not_stop": could_not_stop,
        }
        if self.fold:
            summary["deduplicated"] = self._deduplicated_counts()
        return summary

    def _graded_frame(self, vulns, *, actionable=False):
        from automated_security_helper.plugin_modules.ash_builtin.reporters._report_frames import (
            graded_frame,
        )
        from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
            _severity_level,
        )

        return graded_frame(
            levels=[_severity_level(vuln.severity) for vuln in vulns],
            is_suppressed=[bool(vuln.is_suppressed) for vuln in vulns],
            left_out=[self.is_policy_not_gating(vuln) for vuln in vulns],
            actionable=(
                [self.is_finding_actionable(vuln) for vuln in vulns]
                if actionable
                else None
            ),
        )


class _Counting:
    """Counts calls to the two grading hooks, nested calls included."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = {"actionable": 0, "policy": 0}

    def is_finding_actionable(self, vuln):
        self.calls["actionable"] += 1
        return super().is_finding_actionable(vuln)

    def is_policy_not_gating(self, vuln):
        self.calls["policy"] += 1
        return super().is_policy_not_gating(vuln)


class OldEmitter(_Counting, _OldSummary, ReportContentEmitter):
    pass


class NewEmitter(_Counting, ReportContentEmitter):
    pass


# ---------------------------------------------------------------------------
# the scenarios
# ---------------------------------------------------------------------------


def _result(rule: str, level: str, *, named: bool, **properties) -> dict:
    # A result that names no scanner is imported SARIF: it gives the scan no
    # scanner row, which is the "no scanner rows" scenario.
    scanner = {"scanner_name": "bandit"} if named else {}
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": f"finding {rule}"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/{rule}.py"}}}
        ],
        "properties": {
            **scanner,
            "workspace_project": "svc",
            **properties,
        },
    }


def _sarif_results(named: bool) -> list[dict]:
    return [
        _result("CRIT-1", "error", named=named),
        _result("POLICY-CRIT", "error", named=named, origin="workspace-policy"),
        _result("WARN-1", "warning", named=named),
        _result("POLICY-WARN", "warning", named=named, origin="workspace-policy"),
        _result("LOW-1", "note", named=named),
        _result("LOW-2", "note", named=named),
    ]


LISTED_FINDINGS = [
    {"title": "listed critical", "severity": "CRITICAL", "file_path": "a.py"},
    {"title": "listed high", "severity": "HIGH", "file_path": "b.py"},
    {"title": "listed medium", "severity": "MEDIUM", "file_path": "b.py"},
    {"title": "listed low", "severity": "LOW", "file_path": "c.py"},
    {"title": "listed info", "severity": "INFO", "file_path": "c.py"},
]

#: Positions, in the flat list, of rows marked suppressed in a scenario that
#: has suppressed rows: one SARIF row and (when listed findings exist) two of
#: the listed ones, so a suppressed extra sits among active ones.
SUPPRESSED_AT = (2, 7, 9)


def _model(
    tmp_path: Path,
    *,
    workspace: bool,
    scanner_rows: bool,
    listed: bool,
    policy_gates: bool,
) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = None
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": _sarif_results(named=scanner_rows),
                    "invocations": [],
                }
            ],
        }
    )
    if scanner_rows:
        model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
    if listed:
        model.additional_reports = {"custom-plugin": [dict(f) for f in LISTED_FINDINGS]}
    if workspace:
        model.workspace = WorkspaceResults(
            workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            exit_code=0,
            projects=[
                WorkspaceProjectResult(
                    project="svc",
                    relative_path="svc",
                    display_label="svc",
                    status=ProjectRunStatus.COMPLETED,
                    severity_threshold="HIGH",
                    output_path="projects/svc",
                    policy_scanners_gate=policy_gates,
                    policy_origin_finding_count=2,
                )
            ],
        )
    return model


def _emitter(cls, model, *, fold: bool, suppressed: bool):
    emitter = cls(model, human_presentation=True)
    if suppressed:
        for position in SUPPRESSED_AT:
            if position < len(emitter.flat_vulns):
                emitter.flat_vulns[position].is_suppressed = True
    if fold:
        emitter.fold = True
        emitter._clusters = clusters_by_project(emitter.flat_vulns)
        emitter._positions = {
            id(vuln): position for position, vuln in enumerate(emitter.flat_vulns)
        }
    return emitter


# Each scenario is (workspace, scanner rows, listed findings, policy gates,
# suppressed rows, fold); the call-count line prints it as W R L G S F flags.
SCENARIOS = list(itertools.product([False, True], repeat=6))


def _name(scenario) -> str:
    workspace, scanner_rows, listed, policy_gates, suppressed, fold = scenario
    return "-".join(
        [
            "workspace" if workspace else "single",
            "rows" if scanner_rows else "norows",
            "listed" if listed else "nolisted",
            "gates" if policy_gates else "leftout",
            "suppressed" if suppressed else "live",
            "fold" if fold else "nofold",
        ]
    )


@pytest.fixture(params=SCENARIOS, ids=_name)
def pair(request, tmp_path):
    workspace, scanner_rows, listed, policy_gates, suppressed, fold = request.param
    model = _model(
        tmp_path,
        workspace=workspace,
        scanner_rows=scanner_rows,
        listed=listed,
        policy_gates=policy_gates,
    )
    old = _emitter(OldEmitter, model, fold=fold, suppressed=suppressed)
    new = _emitter(NewEmitter, model, fold=fold, suppressed=suppressed)
    # The scenario is the one it says it is.
    assert bool(new.get_scanner_results()) == scanner_rows
    assert bool(new._additional_report_findings()) == listed
    assert is_workspace_scan(model) == workspace
    return old, new, request.param


class TestTheSummaryIsUnchanged:
    def test_the_whole_summary_equals_the_oracle(self, pair):
        old, new, _ = pair
        assert new.get_scan_summary() == old.get_scan_summary()

    def test_the_grading_hooks_are_called_no_more_often(self, pair, capsys):
        old, new, scenario = pair
        old.get_scan_summary()
        new.get_scan_summary()
        code = "".join(
            f"{letter}{int(flag)}" for letter, flag in zip("WRLGSF", scenario)
        )
        print(
            f"CALLS {code} "
            f"old actionable={old.calls['actionable']} policy={old.calls['policy']} "
            f"new actionable={new.calls['actionable']} policy={new.calls['policy']}"
        )
        assert new.calls["actionable"] <= old.calls["actionable"]
        assert new.calls["policy"] <= old.calls["policy"]


class _IntHooks:
    """Grading hooks that answer 1 and 0 where the real ones answer True and False."""

    def is_finding_actionable(self, vuln):
        return int(super().is_finding_actionable(vuln))

    def is_policy_not_gating(self, vuln):
        return int(super().is_policy_not_gating(vuln))


class IntEmitter(_IntHooks, ReportContentEmitter):
    pass


class _TruthyHooks:
    """Grading hooks that answer a truthy or falsy non-bool of another type."""

    def is_finding_actionable(self, vuln):
        return "yes" if super().is_finding_actionable(vuln) else ""

    def is_policy_not_gating(self, vuln):
        return [vuln] if super().is_policy_not_gating(vuln) else []


class TruthyEmitter(_TruthyHooks, ReportContentEmitter):
    pass


@pytest.fixture(params=SCENARIOS, ids=_name)
def plain_and_odd(request, tmp_path):
    workspace, scanner_rows, listed, policy_gates, suppressed, fold = request.param
    model = _model(
        tmp_path,
        workspace=workspace,
        scanner_rows=scanner_rows,
        listed=listed,
        policy_gates=policy_gates,
    )
    return (
        _emitter(ReportContentEmitter, model, fold=fold, suppressed=suppressed),
        _emitter(IntEmitter, model, fold=fold, suppressed=suppressed),
        _emitter(TruthyEmitter, model, fold=fold, suppressed=suppressed),
    )


class TestAGradingHookThatAnswersANonBool:
    """A hook that returns 1 for True used to raise TypeError from the frame's
    strict Boolean column, and the summary was lost. Every grading enters the
    frame through ``bool``, as the suppression flag does."""

    def test_a_hook_that_answers_one_and_zero_gives_the_same_summary(
        self, plain_and_odd
    ):
        plain, odd, _ = plain_and_odd
        assert odd.get_scan_summary() == plain.get_scan_summary()

    def test_a_hook_that_answers_a_truthy_or_falsy_object_gives_the_same_summary(
        self, plain_and_odd
    ):
        plain, _, truthy = plain_and_odd
        assert truthy.get_scan_summary() == plain.get_scan_summary()


class TestTheScenariosAreNotEmpty:
    """Guards that the oracle comparison has something to compare."""

    def test_a_single_scan_with_rows_and_listed_findings_counts_the_listed_ones(
        self, tmp_path
    ):
        model = _model(
            tmp_path,
            workspace=False,
            scanner_rows=True,
            listed=True,
            policy_gates=True,
        )
        with_listed = _emitter(
            NewEmitter, model, fold=False, suppressed=False
        ).get_scan_summary()
        model = _model(
            tmp_path,
            workspace=False,
            scanner_rows=True,
            listed=False,
            policy_gates=True,
        )
        without = _emitter(
            NewEmitter, model, fold=False, suppressed=False
        ).get_scan_summary()
        assert with_listed[SUMMARY_ACTIONABLE] > without[SUMMARY_ACTIONABLE]

    def test_a_workspace_policy_that_does_not_gate_leaves_findings_out(self, tmp_path):
        model = _model(
            tmp_path,
            workspace=True,
            scanner_rows=True,
            listed=False,
            policy_gates=False,
        )
        summary = _emitter(
            NewEmitter, model, fold=False, suppressed=False
        ).get_scan_summary()
        assert summary[SUMMARY_POLICY_NOT_GATING] == 2

    def test_suppressed_rows_are_counted_as_suppressed(self, tmp_path):
        model = _model(
            tmp_path,
            workspace=False,
            scanner_rows=False,
            listed=True,
            policy_gates=True,
        )
        summary = _emitter(
            NewEmitter, model, fold=False, suppressed=True
        ).get_scan_summary()
        assert summary[SUMMARY_SUPPRESSED] == 3
