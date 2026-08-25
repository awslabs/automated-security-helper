# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Merge N per-project scans into one result set without changing any verdict.

Why this module exists
----------------------
A workspace scan produces one ``AshAggregatedResults`` per project, each written
against that project's own root and judged against that project's own threshold.
Something has to combine them into a single file a consumer can read, and the
combining is where the design can quietly go wrong in three ways. This module
exists to make each of the three explicit and testable.

1. The verdict must not move. For any project P, the findings reported for P and
   the pass/fail verdict for P must be identical to what ``ash --source-dir P``
   would produce. So the actionable count here is derived exactly the way
   ``run_ash_scan._compute_exit_code`` derives it -- same precedence of
   ``properties.issue_severity`` over ``level``, same suppression skip, same
   ``min_severity`` gate -- and
   ``tests/unit/workspace/test_aggregation.py::TestParityWithComputeExitCode``
   asserts the agreement against that function rather than reasoning about it.
2. Path conversion must happen once, in one direction, through Phase 0's
   ``to_workspace_pattern``. String concatenation produces ``api//src/x.py`` the
   first time a scanner emits a rooted path, and joining a rooted path onto a
   prefix with ``PurePosixPath`` silently *discards* the prefix.
3. Peak memory must not scale with project count.

One SARIF run per project, and why not one merged run
-----------------------------------------------------
ASH's own ``SarifReport.merge_sarif_report`` collapses everything into
``runs[0]``, because in single-directory mode there is exactly one root and one
run is the honest shape. In workspace mode there are N roots, and a run can only
declare one. Consumers that ingest SARIF against a single repository root --
GitHub code scanning above all, and this repository ships
``github_ghas_reporter`` -- either mis-locate or reject a result whose path is
relative to a different root than the run claims.

So each project contributes its own run, carrying its own
``originalUriBaseIds`` entry for its root, with result URIs left
*project-relative* inside it. Rewriting those URIs to workspace-relative would
have broken exactly the coherence the split is for. The workspace-relative
coordinate is carried alongside, on ``properties.workspace_uri``, computed once.

That also makes per-project extraction a selection rather than a filter:
``workspace.projects[i].sarif_run_index`` names the run, and taking that run
whole yields a valid single-root SARIF document for one project.

Streaming, and what "peak memory" actually means here
-----------------------------------------------------
``add()`` takes one project's run, rewrites it, writes it to a spool file and
returns holding no reference to it. ``write()`` assembles the unified file by
copying the spool files through, so the writer never holds more than one run.

Peak memory is therefore bounded by ``max_parallel_projects``, not by the number
of projects: a 20-project workspace at the default bound of 4 peaks at roughly
four single-project scans, not twenty. That bound is inherent to running projects
concurrently at all, and it is the operator's knob.

The cost is that the unified file is assembled by hand rather than by
``json.dump`` of one object. That is a real correctness risk, so two tests read
the written file back -- one with ``json.loads`` and one with
``AshAggregatedResults.model_validate_json`` -- rather than trusting the writer.

An unconvertible path is counted, never dropped
-----------------------------------------------
``to_workspace_pattern`` refuses a path containing ``..`` or anchored to a drive.
Some scanners emit exactly those: ``scripts/verify_external_target_scan.py``
records three different URI shapes observed from one healthy run, including a
``../../../..``-prefixed one. A refused path leaves the finding in place without a
``workspace_uri`` and increments ``unconvertible_finding_paths``. Dropping the
finding would be a silent false negative, which is the failure mode this whole
feature is designed against; failing the scan would red-build a workspace over a
cosmetic path shape.

Failure modes and known limitations
-----------------------------------
* The workspace-level ``scanner_results`` sums counts per scanner and takes the
  worst status across projects. That is lossy on purpose -- it exists so
  consumers that already read ``scanner_results`` keep working -- and the
  per-project truth is in ``workspace.projects``. A scanner that ran on one
  project and is missing from another reports the worse of the two.
* ``exceeds_threshold`` is decided by the caller, not here, because it depends on
  ``fail_on_findings``, which is not a property of the findings.
* The unified file carries no ``cyclonedx``. SBOM merging across projects is a
  separate question with its own component-identity problems, and the
  per-project SBOM is intact under ``projects/<key>/``.
* Nothing here validates that a spool file is well-formed JSON. It was written by
  ``json.dump`` in this same process, so a malformed fragment means the process
  is already broken in a way this check would not help with.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from automated_security_helper.core.exceptions import WorkspacePatternError
from automated_security_helper.models.workspace import (
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    sarif_level_fails_threshold,
    severity_fails_threshold,
)
from automated_security_helper.utils.workspace_paths import to_workspace_pattern
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

#: The ``originalUriBaseIds`` key each project's run declares for its own root.
#: Spelled the SARIF way (no separator, uppercase) so it reads like the
#: conventional SRCROOT rather than like an ASH-specific identifier.
PROJECT_ROOT_URI_BASE_ID = "PROJECTROOT"

#: Where per-project runs are spooled while the workspace runs. Under the
#: workspace output directory rather than the work directory, because the work
#: directory is ``converted`` and is itself a scan target.
SPOOL_DIR_NAME = ".workspace-spool"

RESULTS_FILENAME = "ash_aggregated_results.json"

# min_severity ranks, as run_ash_scan._SEVERITY_RANK defines them. Kept as a
# separate table from the severity ladder because this is the --min-severity
# scale, which has no "info" and treats critical and high as equal -- SARIF
# cannot distinguish them.
_MIN_SEVERITY_RANK: Dict[str, int] = {
    "critical": 3,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
}
_SARIF_LEVEL_TO_MIN_SEVERITY: Dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
}

# Worst-first, so the workspace-level rollup can pick a status without ordering
# assumptions about the enum. ERROR outranks FAILED because FAILED is a verdict
# and ERROR is the absence of one.
_SCANNER_STATUS_SEVERITY: Sequence[str] = (
    "ERROR",
    "FAILED",
    "MISSING",
    "SKIPPED",
    "PASSED",
)


def project_root_uri(project_path: str) -> str:
    """The ``file://`` URI of a project root, with the trailing separator SARIF wants.

    A directory URI in SARIF ends with a separator so a consumer can join a
    relative artifact path onto it. ``Path.as_uri()`` does not add one.
    """
    uri = Path(project_path).as_uri()
    return uri if uri.endswith("/") else uri + "/"


def _strip_file_scheme(uri: str) -> str:
    """Reduce a possibly ``file://``-schemed URI to a bare path.

    Handled textually rather than with ``urlsplit`` because a SARIF artifact URI
    is frequently not a valid URI at all -- relative, Windows-separated, or
    ``../``-prefixed -- and parsing one as a URI silently produces an empty path.
    """
    text = uri.strip()
    if text.lower().startswith("file://"):
        text = text[len("file://") :]
        # file:///C:/x -> /C:/x. Drop the separator before a drive letter, which
        # to_workspace_pattern would otherwise read as a rooted path.
        if len(text) > 2 and text[0] == "/" and text[2] == ":":
            text = text[1:]
    return text


def to_workspace_uri(uri: str, project_relative_path: str) -> Optional[str]:
    """Express a project-relative finding URI in workspace-relative coordinates.

    The single place the conversion happens. Goes through Phase 0's
    ``to_workspace_pattern`` rather than concatenating, because a rooted path
    joined onto a prefix with ``PurePosixPath`` discards the prefix rather than
    doubling a separator -- a pattern that has escaped its project, not a
    cosmetic defect.

    Args:
        uri: A SARIF artifact URI as a scanner emitted it. May carry a
            ``file://`` scheme, may use backslashes, may be rooted.
        project_relative_path: The project's path below the workspace root.

    Returns:
        The workspace-relative path, or ``None`` when the URI cannot be expressed
        that way. ``None`` is a routine outcome, not an error: see "An
        unconvertible path is counted, never dropped" in the module docstring.
    """
    text = _strip_file_scheme(uri)
    if not text:
        return None
    try:
        return to_workspace_pattern(text, project_relative_path)
    except WorkspacePatternError:
        return None


def _artifact_location(location: Any) -> Optional[Dict[str, Any]]:
    """The mutable ``artifactLocation`` dict of one SARIF location, or None."""
    if not isinstance(location, Mapping):
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return None
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        return None
    return artifact


def rebase_run_for_project(
    run: Mapping[str, Any], project: ProjectPlan
) -> tuple[Dict[str, Any], int]:
    """Attribute one project's SARIF run to that project and anchor it to its root.

    Deep-copies rather than mutating: the caller may still be holding the model
    the dict came from, and a scan that reported its own findings differently
    after aggregation would be very hard to explain.

    Args:
        run: The project's single SARIF run, as a plain dict.
        project: The project's entry in the resolved plan.

    Returns:
        ``(run, unconvertible)`` -- the attributed run, and how many of its
        findings could not be given a workspace-relative path.
    """
    rebased: Dict[str, Any] = copy.deepcopy(dict(run))

    rebased["originalUriBaseIds"] = {
        PROJECT_ROOT_URI_BASE_ID: {"uri": project_root_uri(project.path)}
    }

    run_properties = rebased.get("properties")
    if not isinstance(run_properties, dict):
        run_properties = {}
    run_properties.update(
        {
            "workspace_project": project.key,
            "workspace_project_path": project.relative_path,
            "workspace_project_label": project.display_label,
        }
    )
    rebased["properties"] = run_properties

    unconvertible = 0
    for result in rebased.get("results") or []:
        if not isinstance(result, dict):
            continue
        properties = result.get("properties")
        if not isinstance(properties, dict):
            properties = {}
        properties["workspace_project"] = project.key

        workspace_uri: Optional[str] = None
        for location in result.get("locations") or []:
            artifact = _artifact_location(location)
            if artifact is None:
                continue
            uri = artifact.get("uri")
            if not uri:
                continue
            # Anchor to the project root so the run stays coherent with exactly
            # one root. A scanner that already anchored its own output knows
            # something we do not, so leave that alone.
            artifact.setdefault("uriBaseId", PROJECT_ROOT_URI_BASE_ID)
            if workspace_uri is None:
                converted = to_workspace_uri(str(uri), project.relative_path)
                if converted is None:
                    unconvertible += 1
                else:
                    workspace_uri = converted

        if workspace_uri is not None:
            properties["workspace_uri"] = workspace_uri
        result["properties"] = properties

    return rebased, unconvertible


def count_actionable_results(
    results: Iterable[Mapping[str, Any]], threshold: Optional[str]
) -> int:
    """Count findings at or above *threshold*, the way ``_compute_exit_code`` does.

    Mirrors ``run_ash_scan._compute_exit_code``'s SARIF pass exactly:
    ``properties.issue_severity`` decides when it names a severity ASH knows,
    otherwise the SARIF ``level`` does, and a suppressed finding never counts.
    Both arms go through Phase 0's severity ladder, which was verified to gate
    identically to the inline tables in ``_compute_exit_code`` for all five real
    threshold values.

    Args:
        results: The SARIF results of one run.
        threshold: A configured severity threshold. Upper-cased here because
            ``_compute_exit_code`` upper-cases the configured value and the
            ladder is case-sensitive; without this a lowercase threshold would
            gate like CRITICAL in one path and MEDIUM in the other.

    Returns:
        The number of actionable findings. Zero when *threshold* is falsy, which
        is how an operator turns the gate off.
    """
    if not threshold:
        return 0
    normalized = threshold.upper()

    actionable = 0
    for result in results:
        if not isinstance(result, Mapping):
            continue
        if result.get("suppressions"):
            continue
        properties = result.get("properties")
        issue_severity = ""
        if isinstance(properties, Mapping):
            issue_severity = str(properties.get("issue_severity") or "").upper()
        if issue_severity in SEVERITIES:
            if severity_fails_threshold(issue_severity, normalized):
                actionable += 1
        elif sarif_level_fails_threshold(result.get("level"), normalized):
            actionable += 1
    return actionable


def has_finding_at_min_severity(
    results: Iterable[Mapping[str, Any]], min_severity: str
) -> bool:
    """Whether any finding meets ``--min-severity``, the way ``_compute_exit_code`` does.

    A separate gate from the threshold, and a coarser one: it zeroes the whole
    actionable count when no single finding qualifies. Kept separate rather than
    folded into ``count_actionable_results`` because that is how the shipped
    behaviour works -- ``--min-severity`` is a whole-scan switch, not a per-
    finding filter that changes the count.

    Note that this scale is not the severity ladder's. It has no ``info``, and it
    treats ``critical`` and ``high`` as equal because SARIF's ``error`` covers
    both.
    """
    min_rank = _MIN_SEVERITY_RANK.get(min_severity.lower(), 1)
    if min_rank <= 0:
        return True
    for result in results:
        if not isinstance(result, Mapping):
            continue
        if result.get("suppressions"):
            continue
        level = str(result.get("level") or "note").lower()
        mapped = _SARIF_LEVEL_TO_MIN_SEVERITY.get(level, "low")
        if _MIN_SEVERITY_RANK.get(mapped, 1) >= min_rank:
            return True
    return False


def _worse_status(left: Optional[str], right: Optional[str]) -> Optional[str]:
    """Whichever scanner status is worse news, for the workspace-level rollup."""
    if left is None:
        return right
    if right is None:
        return left
    for candidate in _SCANNER_STATUS_SEVERITY:
        if candidate in (left, right):
            return candidate
    return left


class WorkspaceAggregator:
    """Collects per-project runs and writes the unified workspace results file.

    Not thread-safe by design: ``add`` is called from the outer pool's completion
    loop on one thread, never from the workers. Locking it would invite a caller
    to hand it work from several threads, which would interleave the spool files
    and lose the deterministic project ordering ``write`` depends on.
    """

    def __init__(self, plan: WorkspacePlan, output_dir: Path) -> None:
        self.plan = plan
        self.output_dir = Path(output_dir)
        self.spool_dir = self.output_dir / SPOOL_DIR_NAME
        self._outcomes: Dict[str, WorkspaceProjectResult] = {}
        self._spooled: Dict[str, Path] = {}
        self._scanner_findings: Dict[str, int] = {}
        self._scanner_actionable: Dict[str, int] = {}
        self._scanner_status: Dict[str, Optional[str]] = {}
        self._unconvertible = 0

    def add(
        self,
        outcome: WorkspaceProjectResult,
        run: Optional[Mapping[str, Any]],
        project: ProjectPlan,
    ) -> None:
        """Record one project's outcome and spool its SARIF run to disk.

        Returns holding no reference to *run*, so the caller can drop the model
        it came from. That is what keeps peak memory proportional to
        ``max_parallel_projects`` rather than to the number of projects.

        Args:
            outcome: The project's outcome. ``sarif_run_index`` is filled in by
                ``write``, which is the only place the ordering is known.
            run: The project's single SARIF run, or ``None`` for a project that
                produced none (skipped, or failed before scanning).
            project: The project's entry in the resolved plan.
        """
        self._outcomes[outcome.project] = outcome

        for scanner, status in (outcome.scanners or {}).items():
            self._scanner_status[scanner] = _worse_status(
                self._scanner_status.get(scanner), status
            )
            self._scanner_findings.setdefault(scanner, 0)
            self._scanner_actionable.setdefault(scanner, 0)

        if run is None:
            return

        rebased, unconvertible = rebase_run_for_project(run, project)
        self._unconvertible += unconvertible

        # Credit findings to the scanner that produced them, so the rollup sums
        # what the per-project files say rather than re-deriving it.
        for result in rebased.get("results") or []:
            if not isinstance(result, Mapping):
                continue
            properties = result.get("properties")
            scanner = None
            if isinstance(properties, Mapping):
                scanner = properties.get("scanner_name")
            name = str(scanner) if scanner else "unattributed"
            if result.get("suppressions"):
                continue
            self._scanner_findings[name] = self._scanner_findings.get(name, 0) + 1
            self._scanner_status.setdefault(name, None)

        self.spool_dir.mkdir(parents=True, exist_ok=True)
        # The project key is a path-derived value with separators already
        # replaced by dashes, so it is safe as a filename by construction.
        spool_path = self.spool_dir / f"{outcome.project}.run.json"
        with open(spool_path, "w", encoding="utf-8") as handle:
            json.dump(rebased, handle)
        self._spooled[outcome.project] = spool_path

    def _ordered_outcomes(self) -> List[WorkspaceProjectResult]:
        """The outcomes in workspace-file order, whatever order they completed in.

        A parallel run delivers them by completion time, which is not
        reproducible. Reporting them in the operator's stated order keeps two
        runs of the same workspace comparable.
        """
        ordered: List[WorkspaceProjectResult] = []
        for project in self.plan.projects:
            outcome = self._outcomes.get(project.key)
            if outcome is not None:
                ordered.append(outcome)
        # A project the plan does not know about cannot happen today, but
        # silently dropping one would hide a real bug rather than report it.
        for key, outcome in self._outcomes.items():
            if all(entry.project != key for entry in ordered):
                ASH_LOGGER.warning(
                    f"Workspace outcome for '{key}' is not in the resolved plan; "
                    "appending it rather than dropping it"
                )
                ordered.append(outcome)
        return ordered

    def _scanner_results_payload(self) -> Dict[str, Dict[str, Any]]:
        """The lossy workspace-level rollup. Per-project truth is in ``projects``."""
        payload: Dict[str, Dict[str, Any]] = {}
        for scanner in sorted(set(self._scanner_status) | set(self._scanner_findings)):
            payload[scanner] = {
                "status": self._scanner_status.get(scanner) or "PASSED",
                "finding_count": self._scanner_findings.get(scanner, 0),
                "actionable_finding_count": self._scanner_actionable.get(scanner, 0),
                "dependencies_satisfied": True,
                "excluded": False,
                "exit_code": 0,
            }
        return payload

    def results_payload(
        self,
        exit_code: int,
        wall_clock_seconds: float,
        *,
        status: str = "completed",
        max_parallel_projects: Optional[int] = None,
        project_timeout: Optional[float] = None,
    ) -> WorkspaceResults:
        """The ``workspace`` block, with each project's run index filled in."""
        ordered = self._ordered_outcomes()
        run_index = 0
        for outcome in ordered:
            if outcome.project in self._spooled:
                outcome.sarif_run_index = run_index
                run_index += 1
            else:
                outcome.sarif_run_index = None
        return WorkspaceResults(
            workspace_file=self.plan.workspace_file,
            workspace_root=self.plan.workspace_root,
            status=status,
            exit_code=exit_code,
            projects=ordered,
            max_parallel_projects=max_parallel_projects,
            project_timeout=project_timeout,
            wall_clock_seconds=wall_clock_seconds,
            unconvertible_finding_paths=self._unconvertible,
        )

    def write(
        self,
        exit_code: int,
        wall_clock_seconds: float,
        *,
        status: str = "completed",
        max_parallel_projects: Optional[int] = None,
        project_timeout: Optional[float] = None,
        project_name: Optional[str] = None,
    ) -> Path:
        """Stream the unified results file and return its path.

        Assembled by hand rather than by dumping one object, so that no more than
        one project's SARIF is in memory at a time. Two tests read the result back
        -- one as JSON, one as ``AshAggregatedResults`` -- because hand-assembled
        JSON is exactly the kind of thing that is subtly wrong.
        """
        payload = self.results_payload(
            exit_code,
            wall_clock_seconds,
            status=status,
            max_parallel_projects=max_parallel_projects,
            project_timeout=project_timeout,
        )
        ordered_spools = [
            self._spooled[outcome.project]
            for outcome in payload.projects
            if outcome.project in self._spooled
        ]

        header: Dict[str, Any] = {
            "name": f"ASH Workspace Scan: {project_name or Path(self.plan.workspace_root).name}",
            "description": (
                "Automated Security Helper - aggregated workspace report. One "
                "SARIF run per project; see the 'workspace' block for "
                "attribution and per-project verdicts."
            ),
            "metadata": {
                "report_id": f"ASH-WORKSPACE-{Path(self.plan.workspace_file).stem}",
                "project_name": project_name
                or Path(self.plan.workspace_root).name
                or "ash-workspace",
                "tool_version": get_ash_version(),
                "description": (
                    "Automated Security Helper workspace-mode aggregated report"
                ),
            },
            "workspace": payload.model_dump(mode="json"),
            "scanner_results": self._scanner_results_payload(),
            "converter_results": {},
            "additional_reports": {},
            "validation_checkpoints": [],
            "used_suppressions": [],
        }

        self.output_dir.mkdir(parents=True, exist_ok=True)
        target = self.output_dir / RESULTS_FILENAME
        try:
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("{\n")
                for key, value in header.items():
                    handle.write(f"{json.dumps(key)}: {json.dumps(value)},\n")
                handle.write('"sarif": {"version": "2.1.0", "runs": [')
                for position, spool in enumerate(ordered_spools):
                    if position:
                        handle.write(",")
                    with open(spool, "r", encoding="utf-8") as fragment:
                        shutil.copyfileobj(fragment, handle)
                handle.write("]}\n}\n")
        finally:
            # Unconditional: a spool left behind would be scanned as output on the
            # next run and would grow without bound across runs.
            shutil.rmtree(self.spool_dir, ignore_errors=True)

        return target
