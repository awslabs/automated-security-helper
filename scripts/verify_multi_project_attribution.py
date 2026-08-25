# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove a workspace scan keeps its projects apart.

Run with: python scripts/verify_multi_project_attribution.py

Why this exists
---------------
``scripts/verify_external_target_scan.py`` proves ASH can scan one directory that
is not its working directory, and asserts on what came back. Workspace mode
multiplies that by N, and the failures it can produce are ones a single-directory
gate structurally cannot see:

* A finding from project A reported against project B. The counts still add up,
  the exit code is still plausible, and the operator fixes the wrong file.
* Project A's suppression silencing the same rule at the same relative path in
  project B. Silent, and a false negative in a security tool -- the worst
  direction for this to fail in.
* Both projects judged against one threshold. Every project then reports a
  verdict, and one of them is the wrong verdict.
* Two projects sharing an output directory, so the second scanner run overwrites
  the first's raw output.

None of those show up as an error. All four produce a complete, well-formed
results file, which is exactly why they need a positive gate rather than an exit
status check.

How the fixture is built to catch each one
------------------------------------------
Three projects, generated at runtime outside the repository:

* ``project-a`` -- threshold LOW, with a suppression for one rule at
  ``src/insecure.py``.
* ``project-b`` -- threshold LOW, byte-identical ``src/insecure.py``, no
  suppression. Same threshold as A on purpose, so the two are directly
  comparable: any difference between them is the suppression and nothing else.
* ``src`` -- threshold CRITICAL, byte-identical ``src/insecure.py``. Named ``src``
  deliberately: container mode mounts the workspace root at ``/src``, so this
  project is ``/src/src``, the shape that re-enters the basename heuristic in
  ``sarif_utils`` (#361). It also carries the looser threshold, so it produces
  the same findings as B and a different verdict.

Same file, three times. That is what makes attribution testable at all: if the
gate used three different files, "the finding is attributed to A" would be
satisfied by matching on the filename, and a broken attribution that credited
every finding to the project whose file it came from would pass.

Deliberate choices
------------------
* Assertions on thresholds are *relative*, not absolute. Bandit's per-rule
  severities move between releases, so asserting "project-b has 4 actionable
  findings" turns an upstream release into a red branch -- which has happened to
  this project before. What cannot move is that CRITICAL is looser than LOW over
  identical findings, so the gate asserts ``src <= project-b`` and that
  ``project-b`` is non-zero.
* Bandit is the only producer. It is Python-only, installed on every runner, and
  the fixture is Python. No credential-shaped literal appears anywhere, because
  detect-secrets matches line by line rather than on an AST and this file is
  itself scanned by ASH's own self-scan.
* ``--phases scan`` only. The report phase is the next PR's subject and would add
  minutes without adding signal here.
* The scan is invoked as ``<python> -m automated_security_helper.cli.main`` with
  ``cwd`` set to the repository root, so ``-m`` puts the working tree on
  ``sys.path`` rather than whatever copy is pip-installed on the runner.

Known limitations
-----------------
* Local mode only. There is no OCI runtime on these runners, so the containerised
  workspace path is covered by unit tests over the assembled command and the
  per-project basename guard, not by a real container run.
* A green gate is evidence about bandit. Other scanners return PASSED with zero
  findings on this fixture, so for them it asserts only "not ERROR".
* If bandit cannot be installed the gate fails rather than passing quietly. A
  gate that silently tests nothing is worse than a red one.
* The suppression assertion needs the suppressed rule to actually fire. If a
  bandit release stops reporting it at all, the gate says so explicitly rather
  than treating "absent everywhere" as "correctly suppressed".
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404 -- the gate runs ASH as a child process
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

RESULTS_FILENAME = "ash_aggregated_results.json"
WORKSPACE_FILENAME = "fixture.code-workspace"

STATUS_ERROR = "ERROR"
STATUS_MISSING = "MISSING"
STATUS_SKIPPED = "SKIPPED"

# Workspace exit codes: 0 success, 1 internal error, 2 either a definition error
# or actionable findings, 3 invalid project config. The fixture is built to
# produce actionable findings in project-a and project-b, so 2 is expected, and 0
# is tolerated in case a future default turns fail_on_findings off.
#
# 2 is ambiguous by design -- see automated_security_helper/models/workspace.py.
# The gate disambiguates it the way that module documents: a refused workspace
# writes no results file, so reaching the assertions at all means this 2 is
# findings. check_workspace_status() then reads the payload's own status field as
# the second, independent check.
TOLERATED_EXIT_CODES = (0, 2)

JOB_TIMEOUT_BUDGET_SECONDS = 1500.0
DEFAULT_SCAN_TIMEOUT_SECONDS = 1200.0
LOG_TAIL_LINES = 60


# ---------------------------------------------------------------------------
# Fixture content
#
# Written to disk at runtime, never committed: ASH scans its own repository in
# CI, so a committed fixture would fail the repository scan. Every construct is a
# stable bandit finding. They appear here as string literals, which is safe --
# bandit parses an AST, so a string constant in this file is not a finding.
# ---------------------------------------------------------------------------

FIXTURE_PYTHON = '''"""Deliberately insecure module. Scan fixture only -- never imported."""

import hashlib
import subprocess


def weak_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def run_untrusted(command: str) -> int:
    return subprocess.call(command, shell=True)


def evaluate(expression: str):
    return eval(expression)
'''

#: The rule project-a suppresses. B324 is hashlib.md5 -- present in every bandit
#: release this project has run against, and independent of the other two
#: findings so suppressing it does not change whether project-a has a verdict.
SUPPRESSED_RULE_ID = "B324"

#: Where the fixture file lives inside every project. Identical across all three,
#: which is what makes the suppression scoping testable.
FIXTURE_RELATIVE_PATH = "src/insecure.py"

CONFIG_TEMPLATE = """project_name: {name}
global_settings:
  severity_threshold: {threshold}
"""

CONFIG_WITH_SUPPRESSION_TEMPLATE = """project_name: {name}
global_settings:
  severity_threshold: {threshold}
  suppressions:
    - rule_id: {rule_id}
      path: {path}
      reason: Fixture-only finding, suppressed to prove per-project scoping
"""

#: Read by the workspace root's config. Exercises that the execution knobs are
#: picked up from the root rather than from a project.
WORKSPACE_ROOT_CONFIG = """project_name: multi-project-gate
workspace:
  max_parallel_projects: 3
  project_timeout: 600
"""


@dataclass(frozen=True)
class FixtureProject:
    """One project in the generated workspace."""

    key: str
    threshold: str
    suppress_rule: str | None = None


FIXTURE_PROJECTS: Tuple[FixtureProject, ...] = (
    FixtureProject(key="project-a", threshold="LOW", suppress_rule=SUPPRESSED_RULE_ID),
    FixtureProject(key="project-b", threshold="LOW"),
    # Named 'src' on purpose: the workspace root is /src in container mode, so
    # this is the folder-inside-its-own-name shape from #361.
    FixtureProject(key="src", threshold="CRITICAL"),
)

#: The pair whose only difference is the suppression.
SUPPRESSION_PAIR = ("project-a", "project-b")

#: The pair whose only difference is the threshold.
THRESHOLD_PAIR = ("project-b", "src")


# ---------------------------------------------------------------------------
# Parsed views of the results file
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProjectOutcome:
    """One entry of ``workspace.projects``, normalized."""

    key: str
    status: str
    threshold: str
    finding_count: int
    actionable_finding_count: int
    exceeds_threshold: bool
    output_path: str
    sarif_run_index: int | None
    error: str | None


@dataclass(frozen=True)
class RunEvidence:
    """One SARIF run, reduced to what the gate asserts on."""

    index: int
    attributed_project: str | None
    uri_base: str | None
    #: rule id -> (unsuppressed count, suppressed count)
    rules: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    #: every workspace_uri seen, in encounter order
    workspace_uris: Tuple[str, ...] = ()
    #: every raw artifact uri seen, in encounter order
    raw_uris: Tuple[str, ...] = ()
    #: project keys named by results inside this run
    result_projects: Tuple[str, ...] = ()


@dataclass
class GateOutcome:
    violations: List[str] = field(default_factory=list)
    projects: Tuple[ProjectOutcome, ...] = ()
    runs: Tuple[RunEvidence, ...] = ()
    scanner_statuses: Dict[str, str] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return not self.violations


# ---------------------------------------------------------------------------
# Pure assertion logic
#
# Everything below takes an already-parsed results dict and returns violation
# strings. No subprocesses, no filesystem, no global state -- so every check is
# unit-testable without running a scan.
# ---------------------------------------------------------------------------


def normalize_status(raw: Any) -> str:
    text = str(raw if raw is not None else "").strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text.upper()


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def check_results_shape(results: Any) -> List[str]:
    """Verify the keys every other check reads actually exist.

    Without this, a renamed key makes every downstream assertion vacuously true
    and the gate reports success having inspected nothing.
    """
    if not isinstance(results, Mapping):
        return [
            f"results is not a JSON object (got {type(results).__name__}); expected "
            f"the parsed contents of {RESULTS_FILENAME}"
        ]

    violations: List[str] = []
    workspace = results.get("workspace")
    if not isinstance(workspace, Mapping):
        violations.append(
            "results has no 'workspace' object. Either the scan ran in "
            "single-directory mode, or the payload moved. Top-level keys: "
            f"{sorted(str(key) for key in results)}"
        )
    else:
        if not isinstance(workspace.get("projects"), list):
            violations.append(
                "'workspace.projects' is not a list -- every per-project "
                "assertion below would inspect nothing"
            )
        elif not workspace["projects"]:
            violations.append("'workspace.projects' is empty -- no project ran")

    if not isinstance(results.get("sarif"), Mapping):
        violations.append(
            "results has no top-level 'sarif' object -- the attribution "
            "assertions below would inspect nothing"
        )
    return violations


def parse_projects(results: Mapping[str, Any]) -> Tuple[ProjectOutcome, ...]:
    workspace = results.get("workspace") or {}
    outcomes: List[ProjectOutcome] = []
    for entry in workspace.get("projects") or []:
        record: Mapping[str, Any] = entry if isinstance(entry, Mapping) else {}
        outcomes.append(
            ProjectOutcome(
                key=str(record.get("project") or ""),
                status=str(record.get("status") or "").lower(),
                threshold=str(record.get("severity_threshold") or ""),
                finding_count=_as_int(record.get("finding_count")),
                actionable_finding_count=_as_int(
                    record.get("actionable_finding_count")
                ),
                exceeds_threshold=bool(record.get("exceeds_threshold", False)),
                output_path=str(record.get("output_path") or ""),
                sarif_run_index=(
                    _as_int(record.get("sarif_run_index"))
                    if record.get("sarif_run_index") is not None
                    else None
                ),
                error=(
                    str(record["error"]) if record.get("error") is not None else None
                ),
            )
        )
    return tuple(outcomes)


def _result_property(result: Mapping[str, Any], name: str) -> str | None:
    properties = result.get("properties")
    if not isinstance(properties, Mapping):
        return None
    raw = properties.get(name)
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _location_uri(location: Any) -> str | None:
    if not isinstance(location, Mapping):
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return None
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, Mapping):
        return None
    uri = artifact.get("uri")
    if uri is None:
        return None
    text = str(uri).strip()
    return text or None


def collect_runs(results: Mapping[str, Any]) -> Tuple[RunEvidence, ...]:
    """One RunEvidence per SARIF run, in file order."""
    sarif = results.get("sarif")
    if not isinstance(sarif, Mapping):
        return ()

    evidence: List[RunEvidence] = []
    for index, run in enumerate(sarif.get("runs") or []):
        if not isinstance(run, Mapping):
            continue

        properties = run.get("properties")
        attributed = None
        if isinstance(properties, Mapping) and properties.get("workspace_project"):
            attributed = str(properties["workspace_project"])

        uri_base = None
        bases = run.get("originalUriBaseIds")
        if isinstance(bases, Mapping):
            for value in bases.values():
                if isinstance(value, Mapping) and value.get("uri"):
                    uri_base = str(value["uri"])
                    break

        rules: Dict[str, Tuple[int, int]] = {}
        workspace_uris: List[str] = []
        raw_uris: List[str] = []
        result_projects: List[str] = []

        for result in run.get("results") or []:
            if not isinstance(result, Mapping):
                continue
            rule_id = result.get("ruleId")
            if rule_id is not None:
                key = str(rule_id)
                live, suppressed = rules.get(key, (0, 0))
                if result.get("suppressions"):
                    rules[key] = (live, suppressed + 1)
                else:
                    rules[key] = (live + 1, suppressed)
            workspace_uri = _result_property(result, "workspace_uri")
            if workspace_uri:
                workspace_uris.append(workspace_uri)
            project = _result_property(result, "workspace_project")
            if project:
                result_projects.append(project)
            for location in result.get("locations") or []:
                uri = _location_uri(location)
                if uri:
                    raw_uris.append(uri)

        evidence.append(
            RunEvidence(
                index=index,
                attributed_project=attributed,
                uri_base=uri_base,
                rules=rules,
                workspace_uris=tuple(workspace_uris),
                raw_uris=tuple(raw_uris),
                result_projects=tuple(result_projects),
            )
        )
    return tuple(evidence)


def collect_scanner_statuses(results: Mapping[str, Any]) -> Dict[str, str]:
    """The workspace-level per-scanner rollup, normalized."""
    statuses: Dict[str, str] = {}
    for name, entry in (results.get("scanner_results") or {}).items():
        record: Mapping[str, Any] = entry if isinstance(entry, Mapping) else {}
        statuses[str(name)] = normalize_status(record.get("status"))
    return statuses


def check_every_project_ran(projects: Sequence[ProjectOutcome]) -> List[str]:
    """Each fixture project must appear, and must have completed."""
    by_key = {project.key: project for project in projects}
    violations: List[str] = []
    for fixture in FIXTURE_PROJECTS:
        outcome = by_key.get(fixture.key)
        if outcome is None:
            violations.append(
                f"project '{fixture.key}' is missing from workspace.projects; "
                f"present: {sorted(by_key)}"
            )
            continue
        if outcome.status != "completed":
            violations.append(
                f"project '{fixture.key}' has status '{outcome.status}' rather "
                f"than 'completed'" + (f": {outcome.error}" if outcome.error else "")
            )
    return violations


def check_no_scanner_errors(statuses: Mapping[str, str]) -> List[str]:
    """No scanner may report ERROR in the workspace rollup.

    ERROR means a scanner was invoked and broke. MISSING means the tool is not
    installed on this runner, which is tolerated.
    """
    return [
        f"scanner '{name}' reported status ERROR in the workspace rollup"
        for name, status in sorted(statuses.items())
        if status == STATUS_ERROR
    ]


def check_one_run_per_project(
    projects: Sequence[ProjectOutcome], runs: Sequence[RunEvidence]
) -> List[str]:
    """Every scanned project contributes exactly one run, with its own root.

    A consumer that ingests SARIF against a single repository root -- GitHub code
    scanning above all -- mis-locates or rejects a result whose path is relative
    to a different root than its run declares. One run per project is what keeps
    each run coherent with exactly one root.
    """
    violations: List[str] = []
    scanned = [p for p in projects if p.status == "completed"]

    attributed = [run.attributed_project for run in runs]
    if len(runs) != len(scanned):
        violations.append(
            f"{len(scanned)} project(s) completed but the aggregated SARIF has "
            f"{len(runs)} run(s). Runs are attributed to: {attributed}"
        )

    if len(set(attributed)) != len(attributed):
        violations.append(
            f"two SARIF runs claim the same project: {attributed}. Per-project "
            "extraction by run index is then ambiguous"
        )

    for run in runs:
        if run.attributed_project is None:
            violations.append(
                f"SARIF run {run.index} carries no properties.workspace_project, "
                "so nothing can say which project it describes"
            )
        if run.uri_base is None:
            violations.append(
                f"SARIF run {run.index} declares no originalUriBaseIds entry, so "
                "its project-relative result paths have no root to resolve against"
            )

    roots = [run.uri_base for run in runs if run.uri_base]
    if len(set(roots)) != len(roots):
        violations.append(
            f"two SARIF runs declare the same project root: {roots}. Two projects "
            "sharing a root is the shape one merged run would have produced"
        )

    for project in scanned:
        if project.sarif_run_index is None:
            violations.append(
                f"project '{project.key}' completed but records no "
                "sarif_run_index, so its run cannot be selected"
            )
            continue
        if project.sarif_run_index >= len(runs):
            violations.append(
                f"project '{project.key}' records sarif_run_index "
                f"{project.sarif_run_index} but there are only {len(runs)} run(s)"
            )
            continue
        named = runs[project.sarif_run_index].attributed_project
        if named != project.key:
            violations.append(
                f"project '{project.key}' records sarif_run_index "
                f"{project.sarif_run_index}, but that run is attributed to "
                f"'{named}'"
            )
    return violations


def check_findings_are_attributed_to_their_own_project(
    runs: Sequence[RunEvidence],
) -> List[str]:
    """No finding may be credited to a project other than the one it came from.

    The property the job is named for. The fixture puts a byte-identical file in
    every project, so a broken attribution cannot hide behind distinct filenames.
    """
    violations: List[str] = []
    for run in runs:
        if run.attributed_project is None:
            continue
        foreign = sorted(
            {
                project
                for project in run.result_projects
                if project != run.attributed_project
            }
        )
        if foreign:
            violations.append(
                f"SARIF run {run.index} is attributed to "
                f"'{run.attributed_project}' but contains finding(s) credited to "
                f"{foreign}"
            )
        if run.result_projects and not run.workspace_uris:
            violations.append(
                f"SARIF run {run.index} has findings but none carry a "
                "workspace_uri, so no finding has a workspace-relative path"
            )
        wrong_prefix = sorted(
            {
                uri
                for uri in run.workspace_uris
                if not uri.startswith(f"{run.attributed_project}/")
            }
        )
        if wrong_prefix:
            violations.append(
                f"SARIF run {run.index} is attributed to "
                f"'{run.attributed_project}' but has workspace_uri value(s) "
                f"outside that project: {wrong_prefix[:5]}"
            )
    return violations


def _uri_base_to_path(uri_base: str) -> Path:
    """Turn a ``file://`` directory URI back into a local path.

    Textual rather than via ``urlsplit`` so a Windows ``file:///C:/x`` reduces to
    ``C:/x`` rather than to a path with a stray leading separator.
    """
    text = uri_base
    if text.lower().startswith("file://"):
        text = text[len("file://") :]
        if len(text) > 2 and text[0] == "/" and text[2] == ":":
            text = text[1:]
    return Path(text)


def check_result_paths_resolve_against_their_run_root(
    runs: Sequence[RunEvidence],
) -> List[str]:
    """Result URIs must resolve to a real file under their run's declared root.

    This is the direct statement of "one run, one root": inside a run the paths
    are relative to that run's ``originalUriBaseIds`` entry, so joining the two
    has to land on a file that exists. Rewriting the paths to workspace-relative
    would break it, and so would a run declaring the wrong root.

    An earlier version of this check tested whether a URI started with the
    project key, and the ``src`` project in this very fixture proved it wrong:
    that project's file is at ``src/insecure.py``, which legitimately begins with
    ``src/``. A string-prefix test cannot tell a wrongly-prefixed path from a file
    that happens to sit in a directory named after its project -- which is
    precisely the collision the ``src`` project exists to surface. Resolving
    against the declared root has no such ambiguity.
    """
    violations: List[str] = []
    for run in runs:
        if run.uri_base is None:
            # check_one_run_per_project already reports the missing root.
            continue
        root = _uri_base_to_path(run.uri_base)
        unresolvable: List[str] = []
        for uri in run.raw_uris:
            normalized = uri.replace("\\", "/")
            while normalized.startswith("./"):
                normalized = normalized[2:]
            if not normalized:
                continue
            if not (root / normalized).exists():
                unresolvable.append(uri)
        if unresolvable:
            violations.append(
                f"SARIF run {run.index} (project "
                f"'{run.attributed_project}') has artifact URI(s) that do not "
                f"resolve to a file under its own declared root '{root}': "
                f"{sorted(set(unresolvable))[:5]}. Inside a run the paths must be "
                "relative to that run's originalUriBaseIds entry"
            )
    return violations


def _rule_counts(
    runs: Sequence[RunEvidence], project: str
) -> Dict[str, Tuple[int, int]]:
    for run in runs:
        if run.attributed_project == project:
            return dict(run.rules)
    return {}


def check_suppression_is_project_scoped(runs: Sequence[RunEvidence]) -> List[str]:
    """Project A's suppression must not silence the same rule in project B.

    Both projects carry a byte-identical file at the same relative path and the
    same threshold, so the only difference between them is A's suppression. If it
    leaks, B's copy of the rule goes quiet -- a false negative that leaves no
    trace anywhere in the output.
    """
    suppressing, other = SUPPRESSION_PAIR
    violations: List[str] = []

    suppressing_rules = _rule_counts(runs, suppressing)
    other_rules = _rule_counts(runs, other)

    if not suppressing_rules and not other_rules:
        return [
            f"neither '{suppressing}' nor '{other}' produced any rule, so the "
            "suppression assertion could not be evaluated. bandit probably did "
            "not run"
        ]

    live_in_other, suppressed_in_other = other_rules.get(SUPPRESSED_RULE_ID, (0, 0))
    live_in_suppressing, suppressed_in_suppressing = suppressing_rules.get(
        SUPPRESSED_RULE_ID, (0, 0)
    )

    if live_in_other == 0 and suppressed_in_other == 0:
        violations.append(
            f"rule {SUPPRESSED_RULE_ID} does not appear in '{other}' at all, so "
            f"the gate cannot tell a working suppression from a rule that no "
            f"longer fires. Update SUPPRESSED_RULE_ID to a rule the fixture still "
            f"trips. Rules seen in '{other}': {sorted(other_rules)}"
        )
        return violations

    if suppressed_in_other:
        violations.append(
            f"rule {SUPPRESSED_RULE_ID} is suppressed in '{other}', which "
            f"configures no suppression. '{suppressing}' suppression has leaked "
            f"across the project boundary -- a silent false negative"
        )
    if live_in_other == 0:
        violations.append(
            f"rule {SUPPRESSED_RULE_ID} has no unsuppressed occurrence in "
            f"'{other}' even though it fires there. Its finding has been silenced "
            f"by another project's configuration"
        )
    if live_in_suppressing:
        violations.append(
            f"rule {SUPPRESSED_RULE_ID} has {live_in_suppressing} unsuppressed "
            f"occurrence(s) in '{suppressing}', which does configure a "
            f"suppression for it at '{FIXTURE_RELATIVE_PATH}'. The project's own "
            f"suppression did not apply"
        )
    return violations


def check_thresholds_are_per_project(
    projects: Sequence[ProjectOutcome],
) -> List[str]:
    """Each project's verdict comes from its own threshold.

    Asserted relatively rather than against absolute counts: bandit's per-rule
    severities move between releases, and pinning them turns an upstream release
    into a red branch. What cannot move is that CRITICAL gates fewer findings
    than LOW over an identical file.
    """
    by_key = {project.key: project for project in projects}
    strict_key, lax_key = THRESHOLD_PAIR
    strict = by_key.get(strict_key)
    lax = by_key.get(lax_key)
    violations: List[str] = []

    if strict is None or lax is None:
        return [
            f"cannot compare thresholds: '{strict_key}' or '{lax_key}' is missing "
            f"from workspace.projects (present: {sorted(by_key)})"
        ]

    if strict.threshold == lax.threshold:
        violations.append(
            f"'{strict_key}' and '{lax_key}' both report threshold "
            f"'{strict.threshold}'. Each project's own config is not reaching its "
            f"scan, so the per-project verdict is untested"
        )

    if strict.finding_count == 0:
        violations.append(
            f"'{strict_key}' reported zero findings. The fixture contains known "
            f"insecure Python, so zero means scanning is broken, not that the "
            f"project is clean"
        )

    if strict.actionable_finding_count == 0:
        violations.append(
            f"'{strict_key}' has threshold '{strict.threshold}' and "
            f"{strict.finding_count} finding(s) but zero actionable. At the "
            f"stricter of the two thresholds at least one finding must qualify"
        )

    if lax.actionable_finding_count > strict.actionable_finding_count:
        violations.append(
            f"'{lax_key}' (threshold {lax.threshold}) has "
            f"{lax.actionable_finding_count} actionable finding(s), more than "
            f"'{strict_key}' (threshold {strict.threshold}) with "
            f"{strict.actionable_finding_count}, over an identical file. The "
            f"looser threshold cannot gate more findings than the stricter one"
        )
    return violations


def check_verdicts_match_their_counts(
    projects: Sequence[ProjectOutcome],
) -> List[str]:
    """Every project's verdict must agree with its own actionable count.

    Applied to all projects rather than only the threshold pair, because the
    invariant is per project and the two fields are written from the same place:
    if they can disagree anywhere, a consumer reading one gets a different answer
    than one reading the other. ``fail_on_findings: false`` would break this
    legitimately, and the fixture does not set it.
    """
    return [
        f"'{project.key}' reports exceeds_threshold={project.exceeds_threshold} "
        f"with {project.actionable_finding_count} actionable finding(s); the two "
        f"disagree"
        for project in projects
        if project.status == "completed"
        and project.exceeds_threshold != (project.actionable_finding_count > 0)
    ]


def check_per_project_subtrees(
    projects: Sequence[ProjectOutcome], output_dir: Path
) -> List[str]:
    """Each project owns its own output subtree, and no two share one.

    Two projects sharing a scanner output directory means the second run silently
    overwrites the first's raw output, and the aggregated counts still add up.
    """
    violations: List[str] = []
    seen: Dict[str, str] = {}

    for project in projects:
        if project.status != "completed":
            continue
        if not project.output_path:
            violations.append(f"project '{project.key}' records no output_path")
            continue
        if project.output_path in seen:
            violations.append(
                f"projects '{seen[project.output_path]}' and '{project.key}' "
                f"share the output path '{project.output_path}'"
            )
        seen[project.output_path] = project.key

        subtree = output_dir / project.output_path
        if not subtree.is_dir():
            violations.append(
                f"project '{project.key}' names output_path "
                f"'{project.output_path}' but '{subtree}' is not a directory"
            )
            continue
        if not (subtree / RESULTS_FILENAME).is_file():
            violations.append(
                f"project '{project.key}' has no {RESULTS_FILENAME} of its own at "
                f"'{subtree}', so its subtree is not a usable single-project "
                f"output tree"
            )
        scanners_dir = subtree / "scanners"
        if not scanners_dir.is_dir():
            violations.append(
                f"project '{project.key}' has no 'scanners' directory at "
                f"'{scanners_dir}', so its raw scanner output went somewhere else"
            )
    return violations


def check_workspace_status(results: Mapping[str, Any], exit_code: int) -> List[str]:
    """The payload's own status must agree with having scanned something.

    This is the discriminator for the ambiguous exit code 2. See
    automated_security_helper/models/workspace.py.
    """
    workspace = results.get("workspace") or {}
    status = str(workspace.get("status") or "")
    violations: List[str] = []
    if status != "completed":
        violations.append(
            f"workspace.status is '{status}' rather than 'completed', but a "
            f"results file exists and projects ran. Exit code {exit_code} is then "
            f"indistinguishable from a refused workspace"
        )
    recorded = _as_int(workspace.get("exit_code"))
    if recorded != exit_code:
        violations.append(
            f"workspace.exit_code is {recorded} but the process exited "
            f"{exit_code}; a consumer reading the payload would draw a different "
            f"conclusion than one reading the status"
        )
    return violations


def check_findings_are_from_the_fixture(
    runs: Sequence[RunEvidence], repo_root: Path
) -> List[str]:
    """Every finding must point at the generated fixture, not this checkout.

    The inverse regression: workspace mode ignores its projects and scans the
    process working directory. Every other assertion would still pass.
    """
    root = repo_root.resolve()
    expected_basename = PurePosixPath(FIXTURE_RELATIVE_PATH).name
    wrong_basename: List[str] = []
    inside_repository: List[str] = []

    for run in runs:
        for uri in run.raw_uris:
            normalized = uri.replace("\\", "/")
            while normalized.startswith("./"):
                normalized = normalized[2:]
            if not normalized:
                continue
            if PurePosixPath(normalized).name != expected_basename:
                wrong_basename.append(uri)
            candidate = Path(root, normalized)
            with suppress(OSError, ValueError):
                candidate = candidate.resolve()
            if candidate.is_relative_to(root) and candidate.exists():
                inside_repository.append(uri)

    violations: List[str] = []
    if wrong_basename:
        violations.append(
            f"finding(s) name a file that is not the fixture. Expected basename "
            f"'{expected_basename}'; got {sorted(set(wrong_basename))[:5]}"
        )
    if inside_repository:
        violations.append(
            "finding(s) name files inside the repository, which means the scan "
            "read the process working directory instead of the workspace "
            f"projects: {sorted(set(inside_repository))[:5]}"
        )
    return violations


def check_exit_code(exit_code: int) -> List[str]:
    if exit_code in TOLERATED_EXIT_CODES:
        return []
    return [
        f"the workspace scan exited {exit_code}; expected one of "
        f"{list(TOLERATED_EXIT_CODES)} (0 success, 2 actionable findings). "
        "1 is an internal error and 3 is an invalid project config"
    ]


def check_paths_outside_repo(repo_root: Path, *paths: Path) -> List[str]:
    root = repo_root.resolve()
    violations: List[str] = []
    for path in paths:
        resolved = path.resolve()
        if resolved == root or resolved.is_relative_to(root):
            violations.append(
                f"'{resolved}' is inside the repository at '{root}'. The gate "
                "must build its workspace outside the repository, or ASH's own "
                "self-scan finds the fixture"
            )
    return violations


def evaluate_results(
    results: Any,
    output_dir: Path,
    exit_code: int | None = None,
    repo_root: Path | None = None,
) -> GateOutcome:
    """Run every assertion against a parsed results dict.

    Shape violations short-circuit: if the keys are not where they should be, the
    remaining checks pass by inspecting nothing, which is worse than failing.
    """
    outcome = GateOutcome()
    shape_violations = check_results_shape(results)
    if shape_violations:
        outcome.violations.extend(shape_violations)
        return outcome

    projects = parse_projects(results)
    runs = collect_runs(results)
    statuses = collect_scanner_statuses(results)
    outcome.projects = projects
    outcome.runs = runs
    outcome.scanner_statuses = statuses

    outcome.violations.extend(check_every_project_ran(projects))
    outcome.violations.extend(check_no_scanner_errors(statuses))
    outcome.violations.extend(check_one_run_per_project(projects, runs))
    outcome.violations.extend(check_findings_are_attributed_to_their_own_project(runs))
    outcome.violations.extend(check_result_paths_resolve_against_their_run_root(runs))
    outcome.violations.extend(check_suppression_is_project_scoped(runs))
    outcome.violations.extend(check_thresholds_are_per_project(projects))
    outcome.violations.extend(check_verdicts_match_their_counts(projects))
    outcome.violations.extend(check_per_project_subtrees(projects, output_dir))
    if exit_code is not None:
        outcome.violations.extend(check_workspace_status(results, exit_code))
        outcome.violations.extend(check_exit_code(exit_code))
    if repo_root is not None:
        outcome.violations.extend(check_findings_are_from_the_fixture(runs, repo_root))
    return outcome


def format_project_table(projects: Sequence[ProjectOutcome]) -> str:
    """A plain-ASCII table. Windows consoles cannot encode box-drawing or emoji."""
    headers = (
        "project",
        "status",
        "threshold",
        "findings",
        "actionable",
        "verdict",
        "run",
    )
    rows = [
        (
            project.key,
            project.status or "-",
            project.threshold or "-",
            str(project.finding_count),
            str(project.actionable_finding_count),
            "FAIL" if project.exceeds_threshold else "pass",
            "-" if project.sarif_run_index is None else str(project.sarif_run_index),
        )
        for project in projects
    ]
    widths = [
        max(len(headers[column]), *(len(row[column]) for row in rows))
        if rows
        else len(headers[column])
        for column in range(len(headers))
    ]

    def render(values: Sequence[str]) -> str:
        cells = [values[column].ljust(widths[column]) for column in range(3)]
        cells.extend(
            values[column].rjust(widths[column]) for column in range(3, len(headers))
        )
        return "  ".join(cells).rstrip()

    lines = [render(headers), "  ".join("-" * width for width in widths)]
    lines.extend(render(row) for row in rows)
    return "\n".join(lines)


def format_attribution_evidence(runs: Sequence[RunEvidence]) -> str:
    """Which rules landed in which run, from the same source the checks read."""
    lines: List[str] = []
    for run in runs:
        live = {
            rule: counts[0] for rule, counts in sorted(run.rules.items()) if counts[0]
        }
        muted = {
            rule: counts[1] for rule, counts in sorted(run.rules.items()) if counts[1]
        }
        lines.append(
            f"run {run.index} -> {run.attributed_project}: "
            f"live {live or '{}'}, suppressed {muted or '{}'}"
        )
        lines.append(f"    root: {run.uri_base}")
        lines.append(
            f"    paths: raw {sorted(set(run.raw_uris))[:3]}, "
            f"workspace {sorted(set(run.workspace_uris))[:3]}"
        )
    return "\n".join(lines) or "no SARIF runs"


# ---------------------------------------------------------------------------
# Fixture and subprocess wrappers
# ---------------------------------------------------------------------------


def write_fixture(workspace_root: Path) -> Path:
    """Materialize the workspace and return the definition path."""
    workspace_root.mkdir(parents=True, exist_ok=True)

    for project in FIXTURE_PROJECTS:
        project_dir = workspace_root / project.key
        source_file = project_dir / FIXTURE_RELATIVE_PATH
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text(FIXTURE_PYTHON, encoding="utf-8")

        config_dir = project_dir / ".ash"
        config_dir.mkdir(parents=True, exist_ok=True)
        if project.suppress_rule:
            content = CONFIG_WITH_SUPPRESSION_TEMPLATE.format(
                name=project.key,
                threshold=project.threshold,
                rule_id=project.suppress_rule,
                path=FIXTURE_RELATIVE_PATH,
            )
        else:
            content = CONFIG_TEMPLATE.format(
                name=project.key, threshold=project.threshold
            )
        (config_dir / "ash.yaml").write_text(content, encoding="utf-8")

    root_config = workspace_root / ".ash"
    root_config.mkdir(parents=True, exist_ok=True)
    (root_config / "ash.yaml").write_text(WORKSPACE_ROOT_CONFIG, encoding="utf-8")

    definition = workspace_root / WORKSPACE_FILENAME
    definition.write_text(
        json.dumps(
            {"folders": [{"path": project.key} for project in FIXTURE_PROJECTS]},
            indent=2,
        ),
        encoding="utf-8",
    )
    return definition


def build_scan_command(definition: Path, output_dir: Path) -> List[str]:
    """The scan invocation, as a list -- never a shell string."""
    return [
        sys.executable,
        "-m",
        "automated_security_helper.cli.main",
        "scan",
        "--workspace",
        str(definition),
        "--output-dir",
        str(output_dir),
        "--phases",
        "scan",
        "--no-progress",
        "--simple",
    ]


def run_scan(
    repo_root: Path, definition: Path, output_dir: Path, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run one workspace scan from a working directory that is not the workspace.

    ``cwd=repo_root`` is load-bearing: it is passed to the child rather than set
    with ``os.chdir``, because this project deliberately removed process-wide cwd
    dependence.
    """
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONUTF8", "1")
    return subprocess.run(  # nosec B603 -- list args, no shell, argv[0] is sys.executable
        build_scan_command(definition, output_dir),
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def load_results(output_dir: Path) -> Any:
    results_path = output_dir / RESULTS_FILENAME
    if not results_path.exists():
        raise FileNotFoundError(str(results_path))
    return json.loads(results_path.read_text(encoding="utf-8"))


def sanitize_for_console(text: str) -> str:
    """Make captured child output safe to print on a cp1252 console."""
    import re

    plain = re.sub(
        r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])",
        "",
        text or "",
    )
    return plain.encode("ascii", "replace").decode("ascii")


def _tail(text: str, limit: int = LOG_TAIL_LINES) -> str:
    lines = (text or "").splitlines()
    if len(lines) <= limit:
        return "\n".join(lines)
    return "\n".join(
        [f"... {len(lines) - limit} earlier line(s) omitted ..."] + lines[-limit:]
    )


def _as_text(stream: Any) -> str:
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", "replace")
    return str(stream)


def _print_block(title: str, body: Any) -> None:
    text = _as_text(body)
    if not text.strip():
        return
    print(f"--- {title} ---")
    print(sanitize_for_console(text))


def _configure_stdout_for_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


def _remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        print(f"WARNING: could not fully remove temp directory '{path}'")


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a generated multi-project workspace outside this repository and "
            "assert that its projects stay apart."
        )
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help=(
            "seconds to allow the scan subprocess (default: "
            f"{DEFAULT_SCAN_TIMEOUT_SECONDS:g}; must stay under the job's "
            f"{JOB_TIMEOUT_BUDGET_SECONDS:g}s timeout-minutes budget so this "
            "script's own diagnostics win the race)"
        ),
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help=(
            "leave the workspace and output directories behind for inspection. "
            "They are kept automatically whenever the gate fails"
        ),
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    _configure_stdout_for_utf8()

    repo_root = Path(__file__).resolve().parents[1]
    temp_root = Path(tempfile.mkdtemp(prefix="ash-multi-project-"))
    workspace_root = temp_root / "workspace"
    output_dir = temp_root / "output"

    succeeded = False
    try:
        precondition_violations = check_paths_outside_repo(
            repo_root, workspace_root, output_dir
        )
        if precondition_violations:
            print("FAIL: the gate's own preconditions are not met")
            for violation in precondition_violations:
                print(f"  - {violation}")
            return 1

        definition = write_fixture(workspace_root)
        output_dir.mkdir(parents=True, exist_ok=True)

        print("ASH multi-project attribution gate")
        print(f"  repository root (subprocess cwd): {repo_root}")
        print(f"  workspace definition:             {definition}")
        print(f"  scan output (--output-dir):       {output_dir}")
        print(
            "  projects:                         "
            + ", ".join(
                f"{p.key}@{p.threshold}"
                + (f" (suppresses {p.suppress_rule})" if p.suppress_rule else "")
                for p in FIXTURE_PROJECTS
            )
        )
        print(
            f"  every project holds a byte-identical {FIXTURE_RELATIVE_PATH}, which "
            "is what makes attribution testable"
        )
        print()

        try:
            completed = run_scan(repo_root, definition, output_dir, args.timeout)
        except subprocess.TimeoutExpired as expired:
            print(f"FAIL: the scan did not finish within {args.timeout:g} seconds")
            _print_block("partial scan stdout (tail)", _tail(_as_text(expired.stdout)))
            _print_block("partial scan stderr (tail)", _tail(_as_text(expired.stderr)))
            return 1

        print(f"scan exited {completed.returncode}")

        try:
            results = load_results(output_dir)
        except FileNotFoundError as missing:
            print(f"FAIL: the scan wrote no results file at '{missing}'")
            _print_block("scan stdout (tail)", _tail(completed.stdout))
            _print_block("scan stderr (tail)", _tail(completed.stderr))
            return 1
        except json.JSONDecodeError as bad_json:
            print(f"FAIL: the results file is not valid JSON: {bad_json}")
            return 1

        outcome = evaluate_results(
            results,
            output_dir,
            exit_code=completed.returncode,
            repo_root=repo_root,
        )

        print()
        print(format_project_table(outcome.projects))
        print()
        print(format_attribution_evidence(outcome.runs))
        print()

        if outcome.passed:
            print(
                f"PASS: {len(outcome.projects)} project(s), one SARIF run each, "
                "findings attributed to their own project, one project's "
                "suppression scoped to it, and each verdict from its own threshold"
            )
            succeeded = True
            return 0

        print(f"FAIL: {len(outcome.violations)} problem(s) found")
        for violation in outcome.violations:
            print(f"  - {violation}")
        print()
        _print_block("scan stdout (tail)", _tail(completed.stdout))
        _print_block("scan stderr (tail)", _tail(completed.stderr))
        return 1
    finally:
        if succeeded and not args.keep_temp:
            _remove_tree(temp_root)
        else:
            reason = "--keep-temp" if succeeded else "the gate failed"
            print()
            print(f"EVIDENCE KEPT ({reason}):")
            print(f"  workspace:   {workspace_root}")
            print(f"  scan output: {output_dir}")
            print(f"  remove with: rm -rf {temp_root}")


if __name__ == "__main__":
    raise SystemExit(main())
