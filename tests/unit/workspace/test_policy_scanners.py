# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``workspace.additional_scanners`` has to actually DO.

Why this file exists
--------------------
Criterion 21 already had tests. Every one of them asserted the return value of
``policy_for_project`` -- ``resolved.policy_scanners == ("semgrep",)`` and
nothing further. That is a fixture pinning the CLASSIFIER, and the classifier
was never the part that was broken: the field was computed, validated, pushed
down per project, stored on the plan and printed in ``--dry-run``, and no
scanner was ever enabled by it. Five green tests, a feature that did nothing.

So every test here asserts an OUTCOME instead of a classification:

* the scanner is enabled in the config the scan actually reads, on a project
  whose own config switched it OFF (`1.`),
* a real scan really runs it and really reports its findings (`4.`),
* those findings carry ``origin: workspace-policy`` (`2.`, `4.`),
* and the gate flag decides whether they can fail the project, in BOTH
  directions (`3.`, `4.`).

The discriminating fixture, and why the obvious one proves nothing
-----------------------------------------------------------------
Every scanner ASH ships is a declared field on ``ScannerConfigSegment`` and
every ``ScannerPluginConfigBase`` inherits ``enabled: bool = True``. So a
project that simply never mentions detect-secrets *already runs it*, and
``resolver._scanner_state`` lists it among that project's enabled scanners --
which makes ``policy_scanners`` empty for it, by design.

The case where the field can be observed at all is therefore the project that
explicitly DISABLES a scanner the policy requires. That is also the case the
feature exists for: a security floor a project cannot opt out of. Tests here
use ``scanners: {detect-secrets: {enabled: false}}`` for that reason, and the
control at the bottom of section 1 fails if the fixture stops discriminating.

Known limitation pinned here on purpose
---------------------------------------
``--scanners`` still wins over policy (``test_an_explicit_scanner_selection_
still_bounds_the_run``). ``enabled_scanners`` is a whole-run allowlist from the
operator's own command line; policy raising a scanner back into a run the
operator narrowed by hand would be the one direction they cannot see coming.
It is asserted rather than merely documented so that changing the decision
requires changing a test.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any, ClassVar

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.resolver import resolve_workspace

AshConfig.model_rebuild()

# The scanner used throughout. Pure Python, ships with ASH, needs no external
# binary, and section 4 runs it for real -- so it has to be one that is present
# in a bare test environment rather than one that reads MISSING there.
SCANNER = "detect-secrets"


# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------


class RecordingOrchestrator:
    """Captures the kwargs the executor passed. Runs nothing.

    Same shape as ``test_policy_wiring.RecordingOrchestrator``; duplicated
    rather than imported because this file also needs the finding-returning
    double below and the two want one place that resets them.
    """

    built: ClassVar[list[RecordingOrchestrator]] = []
    # Set per test. A SARIF run to hand back, and the scanner statuses to claim.
    sarif_results: ClassVar[list[dict[str, Any]]] = []
    scanner_statuses: ClassVar[dict[str, str]] = {}

    def __init__(self, **kwargs: Any) -> None:
        from pathlib import PurePath

        self.kwargs: dict[str, Any] = kwargs
        src = kwargs["source_dir"]
        self.key = (src if isinstance(src, PurePath) else PurePath(src)).name
        RecordingOrchestrator.built.append(self)

    @classmethod
    def create(cls, **kwargs: Any) -> RecordingOrchestrator:
        return cls(**kwargs)

    def execute_scan(self, phases=None):
        from automated_security_helper.schemas.sarif_schema_model import (
            Run,
            SarifReport,
            Tool,
            ToolComponent,
        )

        results = AshAggregatedResults()
        if RecordingOrchestrator.sarif_results:
            run = Run(
                tool=Tool(driver=ToolComponent(name="ash")),
                results=[],
            )
            # Built through the model so the dict shape the executor reads is
            # the shape a real scan produces, not one invented here.
            run = Run.model_validate(
                {
                    "tool": {"driver": {"name": "ash"}},
                    "results": RecordingOrchestrator.sarif_results,
                }
            )
            results.sarif = SarifReport(version="2.1.0", runs=[run])
        return results


@pytest.fixture(autouse=True)
def _reset():
    RecordingOrchestrator.built = []
    RecordingOrchestrator.sarif_results = []
    RecordingOrchestrator.scanner_statuses = {}
    yield
    RecordingOrchestrator.built = []
    RecordingOrchestrator.sarif_results = []
    RecordingOrchestrator.scanner_statuses = {}


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _project(root, name, body=None, secret=False):
    project = root / name
    (project / "src").mkdir(parents=True, exist_ok=True)
    (project / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
    if secret:
        # A detect-secrets keyword hit. Deliberately a made-up literal, and
        # deliberately not a token shaped like any real credential format.
        (project / "src" / "settings.py").write_text(
            'aws_secret_access_key = "notarealsecretjustatestfixture0000000000"\n',  # pragma: allowlist secret
            encoding="utf-8",
        )
    if body is not None:
        ash_dir = project / ".ash"
        ash_dir.mkdir(exist_ok=True)
        (ash_dir / "ash.yaml").write_text(body, encoding="utf-8")
    return project


def _workspace(root, names):
    path = root / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": n} for n in names]}), encoding="utf-8"
    )
    return path


def _policy(root, body):
    (root / ".ash").mkdir(exist_ok=True)
    (root / ".ash" / "ash-workspace.yaml").write_text(body, encoding="utf-8")


def _run(tmp_path, plan, factory=RecordingOrchestrator.create, **overrides):
    settings_kwargs: dict[str, Any] = {
        "output_dir": tmp_path / "out",
        "phases": ("scan",),
        "max_parallel_projects": 1,
    }
    settings_kwargs.update(overrides)
    return execute_workspace(
        plan,
        ProjectScanSettings(**settings_kwargs),
        orchestrator_factory=factory,
    )


def _kwargs_for(key):
    matches = [o.kwargs for o in RecordingOrchestrator.built if o.key == key]
    assert matches, (
        f"no orchestrator was built for {key!r}; built="
        f"{[o.key for o in RecordingOrchestrator.built]}"
    )
    return matches[0]


def _scanner_entry(config, name="detect_secrets"):
    return getattr(config.scanners, name)


@contextmanager
def _capture_ash_warnings():
    """Collect records emitted on ASH's own logger.

    A handler attached directly to ``ASH_LOGGER`` rather than pytest's ``caplog``
    fixture. ``caplog`` installs itself on the root logger and so depends on
    propagation, and ASH configures its logger with extra levels and its own
    handlers -- so a caplog-based assertion here would be testing the logging
    configuration as much as the message, and would read as "no warning" if
    propagation were ever turned off.
    """
    import logging

    from automated_security_helper.utils.log import ASH_LOGGER

    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)


def _finding(scanner, *, severity="HIGH", level="error", path="src/settings.py"):
    """One SARIF result in the shape a scanned project really produces.

    ``properties.scanner_name`` is what ``attach_scanner_details`` writes per
    result, and it is the only per-result scanner attribution available: the
    merge collapses every scanner into ``runs[0]``, so ``tool.driver.name``
    names the aggregate rather than the scanner that found this.
    """
    return {
        "ruleId": f"{scanner}-rule",
        "level": level,
        "message": {"text": f"a finding from {scanner}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "scanner_name": scanner,
            "issue_severity": severity,
            "tags": [scanner],
        },
    }


def _results_of(outcome, key="api"):
    matches = [p for p in outcome.payload.projects if p.project == key]
    assert matches, (
        f"no project {key!r} in {[p.project for p in outcome.payload.projects]}"
    )
    return matches[0]


def _unified_results(tmp_path):
    """The SARIF results in the unified workspace file."""
    path = tmp_path / "out" / "ash_aggregated_results.json"
    assert path.is_file(), f"no unified results at {path}"
    payload = json.loads(path.read_text(encoding="utf-8"))
    runs = (payload.get("sarif") or {}).get("runs") or []
    return [result for run in runs for result in (run.get("results") or [])]


# ---------------------------------------------------------------------------
# 1. The scanner is enabled in the config the scan reads
# ---------------------------------------------------------------------------


def test_a_policy_scanner_is_enabled_in_the_config_the_project_scans_with(tmp_path):
    """The whole feature, at the call boundary.

    ``scan_phase`` decides enablement as ``is_in_enabled_scanners and
    is_enabled``, where ``is_enabled`` is ``plugin_instance.config.enabled`` --
    read from this config through ``AshConfig.get_plugin_config``. So this
    assertion is the necessary and sufficient condition for the scanner to run,
    and section 4 confirms it really does.
    """
    _project(
        tmp_path,
        "api",
        f"scanners:\n  {SCANNER}:\n    enabled: false\n",
    )
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    # Control: the classifier did its half, so a failure below is the wiring's.
    assert plan.projects[0].policy_scanners == [SCANNER], (
        f"the plan does not carry the policy scanner; "
        f"policy_scanners={plan.projects[0].policy_scanners}"
    )

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]

    assert _scanner_entry(resolved).enabled is True, (
        "the project disabled the scanner and the workspace policy requires it, "
        "but the config handed to the scan still has it disabled -- so the "
        "policy adds no scanner at all"
    )


def test_the_project_config_alone_still_disables_the_scanner(tmp_path):
    """Control for the test above. Without a policy the disable must survive.

    A wiring that force-enabled every scanner would pass the previous test and
    break every project that turns one off.
    """
    _project(
        tmp_path,
        "api",
        f"scanners:\n  {SCANNER}:\n    enabled: false\n",
    )
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]

    assert _scanner_entry(resolved).enabled is False, (
        "with no workspace policy the project's own disable must stand"
    )


def test_the_policy_does_not_enable_a_scanner_it_did_not_name(tmp_path):
    """Second control: the enable is scoped to the named scanner."""
    _project(
        tmp_path,
        "api",
        f"scanners:\n  {SCANNER}:\n    enabled: false\n  bandit:\n    enabled: false\n",
    )
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]

    assert _scanner_entry(resolved).enabled is True
    assert _scanner_entry(resolved, "bandit").enabled is False, (
        "the policy named one scanner and enabled two"
    )


def test_the_alias_spelling_and_the_field_spelling_reach_the_same_entry(tmp_path):
    """``cdk-nag`` in the policy must enable the ``cdk_nag`` config field.

    The two spellings are one scanner -- ``policy.normalise_scanner_name``
    already folds them for the classifier. A wiring that matched raw strings
    would silently enable nothing for every aliased scanner, and the aliased
    ones are exactly the multi-word names an operator is most likely to type.
    """
    _project(tmp_path, "api", "scanners:\n  cdk-nag:\n    enabled: false\n")
    _policy(tmp_path, "workspace:\n  additional_scanners:\n    - cdk-nag\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    assert plan.projects[0].policy_scanners == ["cdk-nag"]

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]

    assert _scanner_entry(resolved, "cdk_nag").enabled is True, (
        "the policy named 'cdk-nag' and the config field is 'cdk_nag'; the "
        "enable did not cross the spelling"
    )


def test_a_scanner_the_project_already_runs_is_left_completely_alone(tmp_path):
    """The fixture control the audit's own test set was missing.

    Every built-in scanner defaults to enabled, so a project that never mentions
    one already runs it and ``policy_scanners`` is empty. If that ever stopped
    being true, the tests above would be asserting an enable that was already
    there -- passing without the feature. This is what tells the two apart.
    """
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    assert plan.projects[0].policy_scanners == [], (
        "a project that does not disable the scanner already runs it, so the "
        "policy must classify it as the project's own"
    )

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]
    assert _scanner_entry(resolved).enabled is True


def test_an_explicit_scanner_selection_still_bounds_the_run(tmp_path):
    """``--scanners`` wins over policy. Pinned so the decision is deliberate.

    Policy cannot widen a run the operator narrowed by hand: ``enabled_scanners``
    is their own command line, and a scanner appearing in it unasked is the one
    direction they cannot anticipate. The scanner is still enabled in the
    config; it is the allowlist that leaves it out.
    """
    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    _run(tmp_path, plan, enabled_scanners=("bandit",))
    kwargs = _kwargs_for("api")

    assert kwargs["enabled_scanners"] == ["bandit"], (
        "the operator's allowlist was widened by policy"
    )


# ---------------------------------------------------------------------------
# 2. Findings from a policy scanner carry origin: workspace-policy
# ---------------------------------------------------------------------------


def test_a_policy_scanners_findings_are_tagged_workspace_policy(tmp_path):
    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    RecordingOrchestrator.sarif_results = [_finding(SCANNER)]
    _run(tmp_path, plan)

    results = _unified_results(tmp_path)
    assert results, "the double's finding did not reach the unified results"
    origins = [(r.get("properties") or {}).get("origin") for r in results]
    assert origins == ["workspace-policy"], (
        f"the policy scanner's finding is not tagged; origins={origins}"
    )


def test_the_tag_also_lands_in_the_projects_own_results_file(tmp_path):
    """Both artefacts, because an operator reads whichever is nearer.

    ``projects/<key>/ash_aggregated_results.json`` is written from the results
    MODEL and the unified file from a dict extracted from it. Tagging only the
    dict would leave the per-project file claiming the finding is the project's.
    """
    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    RecordingOrchestrator.sarif_results = [_finding(SCANNER)]
    _run(tmp_path, plan)

    path = tmp_path / "out" / "projects" / "api" / "ash_aggregated_results.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    results = [
        r
        for run in (payload["sarif"]["runs"] or [])
        for r in (run.get("results") or [])
    ]
    assert [(r.get("properties") or {}).get("origin") for r in results] == [
        "workspace-policy"
    ]


def test_a_findings_existing_tags_are_kept_alongside_the_new_one(tmp_path):
    """Additive, like every other policy merge here.

    ``properties.tags`` already carries the scanner name, and a reporter that
    groups by it would lose the grouping if the list were replaced.
    """
    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    RecordingOrchestrator.sarif_results = [_finding(SCANNER)]
    _run(tmp_path, plan)

    tags = (_unified_results(tmp_path)[0].get("properties") or {}).get("tags") or []
    assert SCANNER in tags, f"the scanner tag was dropped: {tags}"
    assert "workspace-policy" in tags, f"the origin tag is missing from tags: {tags}"


def test_a_projects_own_scanners_findings_are_not_tagged(tmp_path):
    """The control that makes the tag mean something.

    A wiring that tagged every finding in a project with any policy scanner
    would pass every test above. bandit here is the project's own.
    """
    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    RecordingOrchestrator.sarif_results = [_finding("bandit"), _finding(SCANNER)]
    _run(tmp_path, plan)

    by_scanner = {
        (r["properties"]["scanner_name"]): (r.get("properties") or {}).get("origin")
        for r in _unified_results(tmp_path)
    }
    assert by_scanner["bandit"] is None, (
        f"the project's own bandit finding was tagged policy-origin: {by_scanner}"
    )
    assert by_scanner[SCANNER] == "workspace-policy", by_scanner


def test_with_no_policy_nothing_is_tagged(tmp_path):
    """Second control: no policy, no tag, on the identical finding."""
    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    RecordingOrchestrator.sarif_results = [_finding(SCANNER)]
    _run(tmp_path, plan)

    origins = [
        (r.get("properties") or {}).get("origin") for r in _unified_results(tmp_path)
    ]
    assert origins == [None], f"a finding was tagged with no policy in force: {origins}"


# ---------------------------------------------------------------------------
# 3. The gate flag, in both directions
# ---------------------------------------------------------------------------


def test_policy_findings_do_not_fail_the_project_by_default(tmp_path):
    """``policy_scanners_gate`` defaults false, so this finding is visibility.

    The finding is CRITICAL-shaped -- ``issue_severity: HIGH`` and ``level:
    error`` -- against a MEDIUM threshold, so it WOULD be actionable if it were
    the project's own. That is what makes this a test of the flag rather than of
    the threshold.
    """
    _project(
        tmp_path,
        "api",
        f"global_settings:\n  severity_threshold: MEDIUM\n"
        f"scanners:\n  {SCANNER}:\n    enabled: false\n",
    )
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    RecordingOrchestrator.sarif_results = [_finding(SCANNER)]
    outcome = _run(tmp_path, plan)
    entry = _results_of(outcome)

    assert entry.status.value == "completed", entry.error
    assert entry.finding_count == 1, (
        "a non-gating policy finding must still be REPORTED; only the verdict "
        f"is unaffected. finding_count={entry.finding_count}"
    )
    assert entry.actionable_finding_count == 0, (
        "policy_scanners_gate is false, so the policy scanner's finding must "
        f"not be actionable; got {entry.actionable_finding_count}"
    )
    assert entry.exceeds_threshold is False


def test_policy_findings_fail_the_project_when_the_operator_opts_in(tmp_path):
    """The other direction. Without this the flag could be implemented as
    'policy findings never gate', which passes the test above."""
    _project(
        tmp_path,
        "api",
        f"global_settings:\n  severity_threshold: MEDIUM\n"
        f"scanners:\n  {SCANNER}:\n    enabled: false\n",
    )
    _policy(
        tmp_path,
        f"workspace:\n"
        f"  additional_scanners:\n    - {SCANNER}\n"
        f"  policy_scanners_gate: true\n",
    )
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))
    assert plan.projects[0].policy_scanners_gate is True

    RecordingOrchestrator.sarif_results = [_finding(SCANNER)]
    outcome = _run(tmp_path, plan)
    entry = _results_of(outcome)

    assert entry.status.value == "completed", entry.error
    assert entry.actionable_finding_count == 1, (
        "policy_scanners_gate is true, so the policy scanner's finding must "
        f"count towards the verdict; got {entry.actionable_finding_count}"
    )
    assert entry.exceeds_threshold is True


def test_a_projects_own_finding_still_gates_while_a_policy_finding_does_not(tmp_path):
    """The mixed case, which is the one an exclusion can get wrong.

    Two findings, one each. Dropping policy findings from the count must not
    drop the project's own, and must not make the project pass.
    """
    _project(
        tmp_path,
        "api",
        f"global_settings:\n  severity_threshold: MEDIUM\n"
        f"scanners:\n  {SCANNER}:\n    enabled: false\n",
    )
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    RecordingOrchestrator.sarif_results = [_finding("bandit"), _finding(SCANNER)]
    outcome = _run(tmp_path, plan)
    entry = _results_of(outcome)

    assert entry.finding_count == 2
    assert entry.actionable_finding_count == 1, (
        "exactly the project's own finding should be actionable; got "
        f"{entry.actionable_finding_count}"
    )
    assert entry.exceeds_threshold is True


def test_the_policy_origin_count_is_reported_separately(tmp_path):
    """ "Reported separately" is a number an operator can read, not a tag alone.

    Without a count of its own, an operator comparing ``finding_count`` against
    ``actionable_finding_count`` cannot tell policy findings from findings the
    threshold excluded.
    """
    _project(
        tmp_path,
        "api",
        f"global_settings:\n  severity_threshold: MEDIUM\n"
        f"scanners:\n  {SCANNER}:\n    enabled: false\n",
    )
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    RecordingOrchestrator.sarif_results = [_finding("bandit"), _finding(SCANNER)]
    outcome = _run(tmp_path, plan)
    entry = _results_of(outcome)

    assert entry.policy_origin_finding_count == 1, (
        f"got {entry.policy_origin_finding_count}"
    )


def test_a_suppressed_policy_finding_is_not_counted_as_one(tmp_path):
    """Suppression is upstream of the origin split, as it is everywhere else."""
    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    suppressed = _finding(SCANNER)
    suppressed["suppressions"] = [{"kind": "external", "justification": "fixture"}]
    RecordingOrchestrator.sarif_results = [suppressed]
    outcome = _run(tmp_path, plan)
    entry = _results_of(outcome)

    assert entry.finding_count == 0
    assert entry.policy_origin_finding_count == 0


def test_a_non_gating_policy_scanner_cannot_fail_the_completeness_gate(tmp_path):
    """The other way ``policy_scanners_gate: false`` could be made vacuous.

    A policy scanner whose tool is absent reads MISSING, and MISSING fails the
    completeness gate -- so a workspace that added a scanner "for visibility"
    would fail every project on a host without that tool, exit code and all,
    with no finding involved. The flag says policy scanners do not affect the
    verdict; the completeness half of the verdict is still the verdict.
    """
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo

    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    class MissingToolOrchestrator(RecordingOrchestrator):
        def execute_scan(self, phases=None):
            results = super().execute_scan(phases)
            results.scanner_results = {
                SCANNER: ScannerTargetStatusInfo(
                    status=ScannerStatus.MISSING,
                    excluded=False,
                    dependencies_satisfied=False,
                ),
                # A project scanner that ran and passed. Without it the missing
                # policy scanner is the only entry, so nothing measured anything
                # and the no-scanner-ran gate fails the project on its own --
                # correctly, and pinned by the test below. This test is about the
                # policy exclusion, so the project has to have measured something
                # for the exclusion to be the only thing deciding the verdict.
                "bandit": ScannerTargetStatusInfo(
                    status=ScannerStatus.PASSED,
                    excluded=False,
                    dependencies_satisfied=True,
                ),
            }
            return results

    outcome = _run(tmp_path, plan, factory=MissingToolOrchestrator.create)
    entry = _results_of(outcome)

    assert SCANNER in entry.incomplete_scanners, (
        "the scanner's absence must still be REPORTED; "
        f"incomplete_scanners={entry.incomplete_scanners}"
    )
    assert entry.no_scanner_ran is False
    assert entry.scan_incomplete is False, (
        "a non-gating policy scanner that could not run must not fail the "
        "project, or policy_scanners_gate: false fails projects anyway"
    )


def test_a_missing_policy_scanner_alone_is_a_project_that_measured_nothing(tmp_path):
    """The exclusion excuses the policy scanner; it does not count it as having run.

    A non-gating policy scanner that is MISSING is dropped from the completeness
    verdict. When it is the only scanner the project recorded, what is left is a
    project in which no scanner reached a verdict, and that fails the same way
    ``ashx --source-dir P`` on it does. Pins the case the test above had to add a
    passing scanner to avoid.
    """
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo

    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    class OnlyTheMissingPolicyScanner(RecordingOrchestrator):
        def execute_scan(self, phases=None):
            results = super().execute_scan(phases)
            results.scanner_results = {
                SCANNER: ScannerTargetStatusInfo(
                    status=ScannerStatus.MISSING,
                    excluded=False,
                    dependencies_satisfied=False,
                )
            }
            return results

    entry = _results_of(
        _run(tmp_path, plan, factory=OnlyTheMissingPolicyScanner.create)
    )

    assert entry.no_scanner_ran is True
    assert entry.scan_incomplete is True, (
        "a project whose only recorded scanner never ran measured nothing, and "
        "must fail even though that scanner is a non-gating policy scanner"
    )


def test_a_gating_policy_scanner_does_fail_the_completeness_gate(tmp_path):
    """Control for the above, so the exclusion is not unconditional."""
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo

    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(
        tmp_path,
        f"workspace:\n"
        f"  additional_scanners:\n    - {SCANNER}\n"
        f"  policy_scanners_gate: true\n",
    )
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    class MissingToolOrchestrator(RecordingOrchestrator):
        def execute_scan(self, phases=None):
            results = super().execute_scan(phases)
            results.scanner_results = {
                SCANNER: ScannerTargetStatusInfo(
                    status=ScannerStatus.MISSING,
                    excluded=False,
                    dependencies_satisfied=False,
                )
            }
            return results

    outcome = _run(tmp_path, plan, factory=MissingToolOrchestrator.create)
    entry = _results_of(outcome)

    assert entry.scan_incomplete is True, (
        "with the gate on, a policy scanner that could not run must fail the "
        "project like any other incomplete scanner"
    )


# ---------------------------------------------------------------------------
# 3b. A policy scanner ASH's config schema does not know
# ---------------------------------------------------------------------------


def test_a_scanner_outside_the_config_schema_gets_an_entry_of_its_own(tmp_path):
    """A plugin-provided scanner needs a config entry to be enabled at all.

    ``ScannerConfigSegment`` declares the ten scanners ASH ships; anything a
    plugin contributes reaches the scan through ``extra="allow"``. So a policy
    naming one has nothing to switch on, and ``get_plugin_config`` would hand the
    plugin ``None``. Creating the entry is what makes the policy work for a
    plugin scanner, and it is indistinguishable here from creating one for a typo
    -- which is why the typo is reported after the scan instead (below).
    """
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    _policy(tmp_path, "workspace:\n  additional_scanners:\n    - my-plugin-scanner\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    assert plan.projects[0].policy_scanners == ["my-plugin-scanner"], (
        "a name no declared field matches must classify as policy-added"
    )

    _run(tmp_path, plan)
    resolved = _kwargs_for("api")["resolved_config"]
    dumped = resolved.scanners.model_dump(by_alias=True)

    assert "my-plugin-scanner" in dumped, (
        f"no config entry was created for the policy scanner; keys with a dash="
        f"{[k for k in dumped if '-' in k]}"
    )
    assert dumped["my-plugin-scanner"]["enabled"] is True


def test_a_policy_scanner_that_never_ran_is_named_in_a_warning(tmp_path):
    """The surfacing point ``policy.py`` promises and nothing delivered.

    ``additional_scanners`` is deliberately not validated at resolution time, and
    the documented consequence is that a typo "surfaces when execution cannot
    find the scanner". Nothing surfaced it: a misspelled scanner produced no
    entry, no message, and a project that PASSED while the operator believed a
    required scanner had run. That is the fail-open direction this whole feature
    exists to avoid, reached by a typo rather than by a bug.
    """
    _project(tmp_path, "api", "global_settings:\n  severity_threshold: HIGH\n")
    _policy(tmp_path, "workspace:\n  additional_scanners:\n    - detectsecrets\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    import logging

    with _capture_ash_warnings() as records:
        _run(tmp_path, plan)

    messages = [r.getMessage() for r in records if r.levelno >= logging.WARNING]
    assert any("detectsecrets" in m for m in messages), (
        f"the policy scanner that never ran was not named in any warning; "
        f"warnings={messages}"
    )


def test_a_policy_scanner_that_did_run_produces_no_warning(tmp_path):
    """Control. Without it the warning could fire unconditionally.

    An unconditional warning is worse than none: an operator who sees it on every
    healthy scan stops reading it, and the typo it exists to catch goes back to
    being invisible.
    """
    from automated_security_helper.core.enums import ScannerStatus
    from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo

    _project(tmp_path, "api", f"scanners:\n  {SCANNER}:\n    enabled: false\n")
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    class RanOrchestrator(RecordingOrchestrator):
        def execute_scan(self, phases=None):
            results = super().execute_scan(phases)
            results.scanner_results = {
                SCANNER: ScannerTargetStatusInfo(
                    status=ScannerStatus.PASSED,
                    excluded=False,
                    dependencies_satisfied=True,
                )
            }
            return results

    import logging

    with _capture_ash_warnings() as records:
        _run(tmp_path, plan, factory=RanOrchestrator.create)

    messages = [r.getMessage() for r in records if r.levelno >= logging.WARNING]
    assert not any(
        "never ran" in m or "no scanner of that name" in m for m in messages
    ), f"a policy scanner that ran was reported as missing; warnings={messages}"


# ---------------------------------------------------------------------------
# 4. A real scan. No double anywhere in this section.
# ---------------------------------------------------------------------------


def test_a_real_scan_runs_the_policy_scanner_and_tags_what_it_finds(tmp_path):
    """The assertion the classifier tests could not make.

    Everything above this line goes through a double, so all of it would still
    pass if ``ScanPhase`` ignored ``config.scanners.<name>.enabled`` entirely.
    This runs the real orchestrator over a real file with a real scanner and
    asserts the scanner RAN, REPORTED, and that its findings carry the tag.
    """
    pytest.importorskip(
        "detect_secrets",
        reason="the real-scan arm needs the scanner it claims to run",
    )

    _project(
        tmp_path,
        "api",
        f"global_settings:\n  severity_threshold: MEDIUM\n"
        f"scanners:\n  {SCANNER}:\n    enabled: false\n",
        secret=True,
    )
    _policy(tmp_path, f"workspace:\n  additional_scanners:\n    - {SCANNER}\n")
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    outcome = _run(tmp_path, plan, factory=None)
    entry = _results_of(outcome)

    assert entry.status.value == "completed", entry.error
    assert entry.scanners.get(SCANNER) not in (None, "SKIPPED"), (
        f"the policy scanner did not run: scanners={entry.scanners}"
    )
    findings = [
        r
        for r in _unified_results(tmp_path)
        if (r.get("properties") or {}).get("scanner_name") == SCANNER
    ]
    assert findings, (
        "the policy scanner ran and reported nothing, so this test cannot tell "
        "whether the tag is applied; the fixture secret is no longer detected"
    )
    origins = {(r.get("properties") or {}).get("origin") for r in findings}
    assert origins == {"workspace-policy"}, (
        f"a real policy-scanner finding is untagged; origins={origins}"
    )
    assert entry.policy_origin_finding_count == len(findings)


def test_a_real_scan_without_the_policy_does_not_run_the_scanner(tmp_path):
    """The control for the real-scan test, and the one that proves causation.

    Same project, same file, no policy. If the scanner reported here too, the
    test above would be measuring ASH's default enablement rather than the
    policy's effect.
    """
    pytest.importorskip("detect_secrets")

    _project(
        tmp_path,
        "api",
        f"global_settings:\n  severity_threshold: MEDIUM\n"
        f"scanners:\n  {SCANNER}:\n    enabled: false\n",
        secret=True,
    )
    plan = resolve_workspace(_workspace(tmp_path, ["api"]))

    outcome = _run(tmp_path, plan, factory=None)
    entry = _results_of(outcome)

    assert entry.status.value == "completed", entry.error
    findings = [
        r
        for r in _unified_results(tmp_path)
        if (r.get("properties") or {}).get("scanner_name") == SCANNER
    ]
    assert not findings, (
        "the project disabled this scanner and no policy re-enabled it, but it "
        f"reported {len(findings)} findings"
    )
