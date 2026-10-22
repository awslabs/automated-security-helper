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

Absolute scanner URIs are relativized, not prefixed
--------------------------------------------------
A scanner-emitted URI is not an operator-written pattern, and the difference
matters. ``to_workspace_pattern`` reads a leading separator as *project-rooted*
and prefixes it, which is deliberate for a pattern -- prefixing makes escape from
the project structurally impossible. Applied to an absolute URI it relocates a
real file: ``/ws/api/src/app.py`` became ``api/ws/api/src/app.py``, naming
nothing, and without being counted as a failure.

So every URI passes through :func:`project_relative_uri` first, which reduces an
absolute path to its remainder inside the project or refuses it. checkov's shape
makes this more than a leading-separator test: it emits
``ws/api/src/insecure_bucket.tf``, absolute with the separator already stripped
upstream, so an unrooted URI is also tried with a separator restored.

These shapes are the default in workspace mode rather than an edge case.
``scripts/verify_external_target_scan.py`` records three of them from one healthy
run, and they appear whenever the process working directory differs from
``source_dir`` -- which in workspace mode it must, for all but one project.

An unconvertible path is counted, never dropped
-----------------------------------------------
A URI that is absolute and outside its project, or that contains ``..``, cannot
be placed. It keeps the text the scanner wrote, gets no ``workspace_uri``, gets
no ``uriBaseId`` -- an ``artifactLocation`` carrying both an absolute ``uri`` and
a base ID contradicts itself, and GitHub code scanning mis-locates or rejects it
-- and increments ``unconvertible_finding_paths``.

That counter counts *findings*, one per finding that ended with no
workspace-relative path at all. A finding offering three locations of which one
converts is located, and counting the other two would overstate the loss.

Dropping the finding would be a silent false negative, which is the failure mode
this whole feature is designed against; failing the scan would red-build a
workspace over a cosmetic path shape.

Failure modes and known limitations
-----------------------------------
* The workspace-level ``scanner_results`` sums both finding and actionable counts
  per scanner and takes the worst status across projects. That is lossy on
  purpose -- it exists so consumers that already read ``scanner_results`` keep
  working, and ``core/resource_management/result_filters.py`` is one of them --
  and the per-project truth is in ``workspace.projects``. A scanner that ran on
  one project and is missing from another reports the worse of the two.
  Per-scanner actionable counts are judged against each project's own threshold
  and then summed, so the rollup total equals the sum of the per-project totals.
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
import os
import re
import shutil
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from automated_security_helper.core.committed_output import WORKSPACE_SPOOL_DIR_NAME
from automated_security_helper.core.exceptions import WorkspacePatternError
from automated_security_helper.models.asharp_model import new_report_id
from automated_security_helper.models.core import merged_honoring
from automated_security_helper.models.workspace import (
    SCANNER_EXIT_CODE_UNRECORDED,
    ProjectInputNotScanned,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.uri_separators import (
    root_text,
    sanitized_uri_text,
)
from automated_security_helper.utils.severity_ladder import (
    SEVERITIES,
    result_severity,
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
#: directory is ``converted`` and is itself a scan target. Named in
#: core/committed_output.py, whose check before a workspace starts covers it.
SPOOL_DIR_NAME = WORKSPACE_SPOOL_DIR_NAME

RESULTS_FILENAME = "ash_aggregated_results.json"

#: The header line :meth:`WorkspaceAggregator.write` emits for the results' validation
#: checkpoints, which :func:`stamp_run_record` fills.
_EMPTY_CHECKPOINTS_LINE = f"{json.dumps('validation_checkpoints')}: {json.dumps([])},\n"

#: The most of a results file ``stamp_run_record`` reads at once.
_STAMP_READ_LIMIT = 1 << 20

#: A Windows drive at the start of a path, e.g. ``C:/ws/api``. Matched on the raw
#: text rather than via ``PureWindowsPath.drive``, whose value for unusual inputs
#: changed between 3.11 and 3.12 and this project supports 3.10 through 3.14.
_DRIVE_ANCHOR = re.compile(r"^[A-Za-z]:[/\\]")

#: Stands in for a backslash that is part of a file name while a URI passes
#: through the pattern converter (see to_workspace_uri).
_NAME_BACKSLASH = "\x00"

#: The component that makes ``relative_to`` unable to answer containment.
_PARENT_COMPONENT = ".."

#: Characters a workspace file name may not contribute to the report id; each run
#: of them becomes "-". ``ReportMetadata.report_id`` must match
#: ``^[A-Za-z][\/\.\w-]+$``, and an id built from ``my workspace.code-workspace``
#: did not, so the unified results file failed to load in every merged reporter.
#: ASCII only, not ``\w``: Python's ``\w`` takes characters such as "²" and "①"
#: that the pattern's ``\w`` (pydantic's Rust regex engine) refuses.
_REPORT_ID_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")

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


#: Returned by :func:`project_relative_uri` when the URI is not an absolute path
#: naming a file inside the project, so the caller should read it as
#: project-relative. Distinct from ``None``, which means "absolute and outside".
NOT_ABSOLUTE = object()


def _posix_text(uri: str, project_path: Optional[str] = None) -> str:
    """A scanner URI reduced to bare POSIX-shaped text.

    The backslashes of a drive-letter or UNC path, or of any URI in a project
    whose path is a Windows path, become separators, and a Windows drive that
    arrived with a leading separator (``/C:/x``, as ``file:///C:/x`` reduces to)
    loses it, so a drive is always spelled the same way before anything
    compares paths. Any other backslash is part of a POSIX file name and is
    kept: the project's scan sanitized the URI, which wrote ``/`` for its
    separators (``utils/uri_separators.py``).
    """
    text = sanitized_uri_text(_strip_file_scheme(uri), project_path)
    if len(text) > 2 and text[0] == "/" and text[2] == ":":
        text = text[1:]
    return text


def project_relative_uri(uri: str, project_path: str) -> Any:
    """Reduce an absolute scanner URI to a path relative to its own project.

    Why this exists
    ---------------
    ``to_workspace_pattern`` reads a leading separator as *project-rooted* and
    prefixes it. That is correct and deliberate for an operator-written pattern:
    prefixing makes escape from the project structurally impossible. It is wrong
    for a scanner-emitted URI, which names a real file that the prefix then
    relocates -- ``/ws/api/src/app.py`` became ``api/ws/api/src/app.py``, a path
    naming nothing, silently and without being counted.

    These shapes are the default in workspace mode, not an edge case.
    ``scripts/verify_external_target_scan.py`` records three different URI
    shapes from one healthy run, and they appear whenever the process working
    directory differs from ``source_dir``. In workspace mode each project's
    ``source_dir`` is ``<workspace>/<project>``, so the working directory cannot
    coincide with more than one of them.

    The separator-stripped shape, and why a leading-separator test is not enough
    ---------------------------------------------------------------------------
    checkov emits ``ws/api/src/insecure_bucket.tf`` -- absolute, with the leading
    separator already gone upstream. No test on the leading character can catch
    it. So an unrooted URI is also tried with a separator restored, and is read
    as absolute only when that lands inside the project.

    The residual ambiguity is a project that contains a directory tree mirroring
    its own absolute path -- project ``/ws/api`` holding ``ws/api/src/`` -- where
    a genuinely project-relative ``ws/api/src/x.py`` would be misread as
    absolute. Resolved textually and in favour of the absolute reading, because
    that nesting is pathological while the checkov shape is routine. Deliberately
    no filesystem check: aggregation would then depend on the tree still being
    present, and reading the same SARIF twice could give two answers.

    Args:
        uri: A SARIF artifact URI as a scanner emitted it.
        project_path: The project's canonical absolute path.

    Returns:
        The project-relative path when the URI is absolute and inside the
        project; ``None`` when it is absolute and outside; :data:`NOT_ABSOLUTE`
        when it does not look like an absolute path at all.
    """
    text = _posix_text(uri, project_path)
    if not text:
        return None

    root = PurePosixPath(root_text(project_path))
    rooted = text.startswith("/") or bool(_DRIVE_ANCHOR.match(text))

    candidates = [text] if rooted else [text, "/" + text]
    for candidate in candidates:
        # ".." would make relative_to lie about containment, and Phase 0 rejects
        # it anyway; leave those to the pattern converter, which returns None.
        if _PARENT_COMPONENT in PurePosixPath(candidate).parts:
            continue
        try:
            remainder = PurePosixPath(candidate).relative_to(root)
        except ValueError:
            continue
        # relative_to succeeds for the root itself, whose remainder is "."; that
        # names a directory, not a finding location.
        return remainder.as_posix() if remainder.parts else None

    if rooted:
        # Absolute, and not inside this project. Counted, never prefixed: a
        # prefix would invent a path that names nothing.
        return None
    return NOT_ABSOLUTE


def to_workspace_uri(
    uri: str, project_relative_path: str, project_path: Optional[str] = None
) -> Optional[str]:
    """Express a finding URI in workspace-relative coordinates.

    The single place the conversion happens. A URI that is already
    project-relative goes through Phase 0's ``to_workspace_pattern`` rather than
    string concatenation, because a rooted path joined onto a prefix with
    ``PurePosixPath`` discards the prefix rather than doubling a separator -- a
    path that has escaped its project, not a cosmetic defect.

    An absolute URI is reduced to project-relative first; see
    :func:`project_relative_uri` for why that step cannot be skipped.

    Args:
        uri: A SARIF artifact URI as a scanner emitted it. May carry a
            ``file://`` scheme, may use backslashes, may be rooted, may be
            absolute with its leading separator already stripped.
        project_relative_path: The project's path below the workspace root.
        project_path: The project's absolute path. Optional only so that callers
            with no absolute path can still convert an already-relative URI;
            without it an absolute URI cannot be recognised and will be refused
            rather than mis-prefixed.

    Returns:
        The workspace-relative path, or ``None`` when the URI cannot be expressed
        that way. ``None`` is a routine outcome, not an error: see "An
        unconvertible path is counted, never dropped" in the module docstring.
    """
    text = _posix_text(uri, project_path)
    if not text:
        return None

    if project_path is not None:
        reduced = project_relative_uri(text, project_path)
        if reduced is None:
            return None
        if reduced is not NOT_ABSOLUTE:
            text = reduced
    elif text.startswith("/") or _DRIVE_ANCHOR.match(text):
        # No project path to relativize against, so an absolute URI cannot be
        # placed. Refusing beats prefixing it into a path that names nothing.
        return None

    # to_workspace_pattern reads its argument as a pattern, where a backslash is
    # a separator (docs/content/docs/suppressions.md). A backslash left in this
    # URI is part of a file name, so it is carried through as NUL, which no file
    # name can hold, and put back.
    try:
        rebased = to_workspace_pattern(
            text.replace("\\", _NAME_BACKSLASH), project_relative_path
        )
    except WorkspacePatternError:
        return None
    return rebased.replace(_NAME_BACKSLASH, "\\")


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

    An absolute artifact URI is rewritten to the project-relative remainder, so
    that every path inside the run really is relative to the one root the run
    declares. Leaving it absolute while also tagging it with a ``uriBaseId``
    produces a self-contradictory ``artifactLocation`` that GitHub code scanning
    mis-locates or rejects, which is the whole thing one-run-per-project exists
    to avoid. A URI that cannot be placed inside the project keeps its original
    text, gets no ``uriBaseId``, and is counted.

    Args:
        run: The project's single SARIF run, as a plain dict.
        project: The project's entry in the resolved plan.

    Returns:
        ``(run, unconvertible)`` -- the attributed run, and how many of its
        *findings* could not be given a workspace-relative path. Findings, not
        locations: a finding with three locations of which one converts is
        located, and counting it as two failures would overstate the loss.
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
        had_locatable_uri = False
        for location in result.get("locations") or []:
            artifact = _artifact_location(location)
            if artifact is None:
                continue
            uri = artifact.get("uri")
            if not uri:
                continue
            had_locatable_uri = True

            reduced = project_relative_uri(str(uri), project.path)
            if reduced is NOT_ABSOLUTE:
                placed: Optional[str] = str(uri)
            elif reduced is None:
                # Absolute and outside the project. Left exactly as the scanner
                # wrote it, and deliberately NOT anchored: an artifactLocation
                # carrying both an absolute uri and a uriBaseId contradicts
                # itself.
                placed = None
            else:
                placed = reduced
                artifact["uri"] = reduced

            if placed is not None:
                # Anchor to the project root so the run stays coherent with
                # exactly one root. A scanner that already anchored its own
                # output knows something we do not, so leave that alone.
                artifact.setdefault("uriBaseId", PROJECT_ROOT_URI_BASE_ID)
                if workspace_uri is None:
                    workspace_uri = to_workspace_uri(
                        placed, project.relative_path, project.path
                    )

        if workspace_uri is not None:
            properties["workspace_uri"] = workspace_uri
        elif had_locatable_uri:
            # One increment per finding that ended up with no workspace-relative
            # path at all, however many locations it offered.
            unconvertible += 1
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
    # No default for a value the scale does not rank. A default of "low" is what
    # turned a mistyped --min-severity into the strictest gate short of "none".
    min_rank = _MIN_SEVERITY_RANK.get(min_severity.lower())
    if min_rank is None:
        raise ValueError(
            f"min_severity must be one of {', '.join(_MIN_SEVERITY_RANK)}, "
            f"not {min_severity!r}"
        )
    if min_rank <= 0:
        return True
    for result in results:
        if not isinstance(result, Mapping):
            continue
        if result.get("suppressions"):
            continue
        # The resolver run_ash_scan._severity_filters_finding uses: the
        # declared issue_severity first, a missing level as
        # MISSING_SARIF_LEVEL, and INFO (absent from the scale) as low. This
        # read the level alone, with a missing one as note.
        if _MIN_SEVERITY_RANK.get(result_severity(result).lower(), 1) >= min_rank:
            return True
    return False


def stale_content_databases_for_project(results: Any) -> List[Dict[str, Any]]:
    """This project's content databases past their bound under ``fail``.

    In the shape the single-scan MCP payload reports them
    (``ContentDbAgeRecord.to_dict``), so a workspace project's coverage and a
    single scan's read the same. Empty for ``None`` and under ``warn``.
    """
    from automated_security_helper.utils.content_db_staleness import (
        stale_content_databases,
    )

    if results is None:
        return []
    return [
        record.to_dict()
        for record in stale_content_databases(results, enforced_only=True)
    ]


def incomplete_scanners_for_project(results: Any) -> List[str]:
    """Names of the scanners this project ran that did not complete.

    The completeness half of the parity this module exists to hold. The threshold
    half is ``count_actionable_results`` above, and the two are written in
    opposite styles on purpose.

    ``count_actionable_results`` MIRRORS ``_compute_exit_code``, because that
    function derives the threshold count inline from a SARIF document it re-reads
    from disk -- there is no function to call, so a copy was the only option, and
    ``TestParityWithComputeExitCode`` exists to keep the copy honest.

    This one DELEGATES, because the completeness pass already is a function.
    Copying it would put one decision in two places, and the decision is subtler
    than it looks: ``incomplete_scanners`` reads through
    ``get_unified_scanner_metrics``, where an excluded scanner is SKIPPED even
    when its tool is also absent. Read straight off ``results.scanner_results``
    the same entry is MISSING. So a mirrored version would fail a workspace for a
    scanner the operator excluded -- and since sharding excludes the scanners the
    other shards own, it would fail every shard of a healthy sharded scan.

    Imported inside the function. ``run_ash_scan`` imports this package's
    ``execution`` module for workspace mode, so a module-level import here closes
    that into a cycle.

    Args:
        results: One project's ``AshAggregatedResults``, or ``None``.

    Returns:
        Scanner names in the order ``incomplete_scanners`` reports them, which is
        scanner-name order. Empty when every selected scanner completed.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        incomplete_scanners,
    )

    return [name for name, _status in incomplete_scanners(results)]


def incomplete_converters_for_project(results: Any) -> Dict[str, str]:
    """Converter name to reason, for each converter of this project that lost coverage.

    The converter question ``_compute_exit_code`` asks beside the scanner ones: a
    converter that crashed, one that could not convert some of its inputs, or one
    whose tool was absent with something to convert. Delegates to
    ``run_ash_scan.incomplete_converters`` for the reason its scanner siblings
    delegate -- one decision, one place -- and is imported inside the function
    for the same import-cycle reason.

    Args:
        results: One project's ``AshAggregatedResults``, or ``None``.

    Returns:
        ``{name: reason}`` in the order the rows were recorded; empty when every
        converter ran cleanly or was excluded, and for ``None``.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        incomplete_converters,
    )

    # IncompleteConverter rows carry (name, reason, kinds); this mapping keeps
    # its documented {name: reason} shape.
    return {item.name: item.reason for item in incomplete_converters(results)}


def no_scanner_ran_for_project(results: Any) -> bool:
    """Whether this project recorded scanners and none of them reached a verdict.

    The set-level counterpart to ``incomplete_scanners_for_project`` above, and not
    implied by it. That function asks the question of each entry, and it has to
    tolerate SKIPPED one entry at a time -- SKIPPED is how ``--exclude-scanners``
    and another shard's ownership are recorded -- so a project in which *every*
    entry is SKIPPED clears it having measured nothing. Single-project mode asks
    both questions, in this order, inside ``_compute_exit_code``; the workspace
    layer asked only the first, so such a project reported zero findings, COMPLETED
    and exit 0 while ``ash --source-dir P`` on the same project exited 1.

    Delegates for the same reason its sibling does, and the delegation carries one
    decision that is easy to get wrong by copying: an *empty* scanner set is not
    this condition **on its own**. It is what ``--phases convert`` legitimately
    produces, and a mirrored version that tested emptiness would fail every
    convert-only project in a workspace.

    Emptiness alone cannot separate that from the silent zero, though, which is why
    ``no_scanner_ran`` takes a second argument. An empty set covers both "the scan
    phase was not requested" and "the scan phase ran and had nothing to run", and
    ``metadata.expected_scanners`` is what tells them apart: ``ScanPhase`` is what
    records the roster, so a roster means the phase ran. The roster is passed here
    for the same reason ``_compute_exit_code`` passes it -- reading it from the same
    field in both places is what keeps this layer's answer and ``ash --source-dir
    P``'s from diverging, which is the whole point of the sibling above. A project
    with no roster and no scanners keeps the benign reading.

    Imported inside the function because ``run_ash_scan`` imports this package's
    ``execution`` module for workspace mode; a module-level import closes that into
    a cycle.

    Args:
        results: One project's ``AshAggregatedResults``, or ``None``.

    Returns:
        True when at least one scanner was recorded and not one of them reached a
        verdict, and when no scanner was recorded but a roster says the scan phase
        ran. False for ``None``, which is the crashed-scan case the caller already
        reports as FAILED.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        no_scanner_ran,
        scanner_statuses,
    )

    expected = list(
        getattr(getattr(results, "metadata", None), "expected_scanners", None) or []
    )
    return no_scanner_ran(scanner_statuses(results), expected)


def inputs_not_scanned_for_project(
    results: Any, relative_path: str
) -> List[ProjectInputNotScanned]:
    """This project's inputs that a scanner found and did not scan, workspace-relative.

    Read through ``unified_metrics.inputs_not_scanned``, the reader the
    single-directory summaries use, so the two modes list the same entries. A path
    the scanner recorded relative to the project gets the project's
    ``relative_path`` in front; one it could only record as absolute is kept as it
    is.

    The reader is imported inside the function for the reason its siblings above
    give.

    Args:
        results: One project's ``AshAggregatedResults``, or ``None``.
        relative_path: The project's workspace-relative path.

    Returns:
        The entries, in the reader's order.
    """
    from automated_security_helper.core.unified_metrics import inputs_not_scanned

    if results is None:
        return []
    entries = []
    for scanner, path, reason in inputs_not_scanned(results):
        recorded = PurePosixPath(path)
        shown = (
            path
            if recorded.is_absolute()
            else (PurePosixPath(relative_path) / recorded).as_posix()
        )
        entries.append(
            ProjectInputNotScanned(scanner=scanner, path=shown, reason=reason)
        )
    return entries


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


def workspace_ignore_file_exclusions(
    outcomes: Iterable[WorkspaceProjectResult],
) -> Optional[Dict[str, Any]]:
    """The merged results' ``metadata.ignore_file_exclusions``, from every project's.

    The workspace summaries render this record like a single scan's, so the line
    they print is the workspace total. Each ignore file is keyed by its path
    relative to the workspace root (the project's ``relative_path`` joined to the
    project-relative key), so two projects' root ``.gitignore`` files stay apart.
    ``honored`` is True only when every project that built a scan set honored its
    ignore files; the switch is the operator's, so the projects agree unless their
    configs were resolved from different operator sources. When they disagree,
    ``honored_scan_count`` and ``scan_count`` say how many did, and the summaries
    print that instead of either one-scan sentence. None when no project built a
    scan set.
    """
    # Each project's relative path with its record, for the projects that have one.
    recorded = [
        (outcome.relative_path, record)
        for outcome in outcomes
        if (record := outcome.ignore_file_exclusions) is not None
    ]
    if not recorded:
        return None
    by_ignore_file: Dict[str, int] = {}
    for relative_path, record in recorded:
        prefix = PurePosixPath(relative_path)
        for path, count in record.by_ignore_file.items():
            key = path if str(prefix) == "." else (prefix / path).as_posix()
            by_ignore_file[key] = by_ignore_file.get(key, 0) + count
    records = [record for _, record in recorded]
    aggregate: Dict[str, Any] = {
        "excluded_file_count": sum(record.excluded_file_count for record in records),
        "by_ignore_file": by_ignore_file,
        "output_dir_file_count": sum(
            record.output_dir_file_count for record in records
        ),
    }
    # honored, and when the projects disagree the counts that give them their own
    # sentence: neither "excluded N files" nor "excluded no files" is true of the
    # workspace then (IgnoreFileExclusions.summary_text).
    aggregate.update(merged_honoring(records))
    return aggregate


def _workspace_report_id(workspace_file: str) -> str:
    """The unified report's id: ``ASH-WORKSPACE-<file name>-<time>-<random>``.

    The file name tells a reader which workspace the report covers; the rest is a
    scan's id (see ``new_report_id``), so each run of a workspace gets its own.
    """
    stem = _REPORT_ID_UNSAFE.sub("-", Path(workspace_file).stem).strip("-")
    return new_report_id(prefix=f"ASH-WORKSPACE-{stem or 'workspace'}")


def _larger_code(first: Optional[int], second: Optional[int]) -> Optional[int]:
    """The larger of two rolled-up codes, where null (no code) is below any code."""
    if first is None:
        return second
    if second is None:
        return first
    return max(first, second)


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
        self._scanner_exit_code: Dict[str, Optional[int]] = {}
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
            code = outcome.carried_scanner_exit_codes.get(
                scanner, SCANNER_EXIT_CODE_UNRECORDED
            )
            held = self._scanner_status.get(scanner)
            worse = _worse_status(held, status)
            # The code travels with the status it was recorded beside: a strictly
            # worse status brings its own code, an equal one keeps the larger, a
            # better one leaves the held code alone. One decision, so the pair
            # cannot disagree and the order the projects arrive in does not matter.
            if scanner not in self._scanner_exit_code or worse != held:
                self._scanner_exit_code[scanner] = code
            elif status == held:
                self._scanner_exit_code[scanner] = _larger_code(
                    self._scanner_exit_code[scanner], code
                )
            self._scanner_status[scanner] = worse
            self._scanner_findings.setdefault(scanner, 0)
            self._scanner_actionable.setdefault(scanner, 0)

        if run is None:
            return

        rebased, unconvertible = rebase_run_for_project(run, project)
        self._unconvertible += unconvertible

        # Credit findings to the scanner that produced them, so the rollup sums
        # what the per-project files say rather than re-deriving it.
        by_scanner: Dict[str, List[Mapping[str, Any]]] = {}
        for result in rebased.get("results") or []:
            if not isinstance(result, Mapping):
                continue
            properties = result.get("properties")
            scanner = None
            if isinstance(properties, Mapping):
                scanner = properties.get("scanner_name")
            name = str(scanner) if scanner else "unattributed"
            by_scanner.setdefault(name, []).append(result)
            self._scanner_status.setdefault(name, None)
            if result.get("suppressions"):
                continue
            self._scanner_findings[name] = self._scanner_findings.get(name, 0) + 1

        # Actionable counts, per scanner, against THIS project's own threshold.
        #
        # Derived here rather than carried on the outcome, because the outcome
        # holds one number for the whole project and the rollup needs it split.
        # Zeroed wholesale when the project's own actionable count is zero: that
        # is how the --min-severity gate reaches this layer, since it is a
        # whole-scan switch in _compute_exit_code rather than a per-finding
        # filter, and a per-scanner sum that ignored it would exceed the
        # project's own total.
        if outcome.actionable_finding_count:
            for name, results in by_scanner.items():
                # gate_threshold, matching what the project's own verdict was
                # computed from. Using severity_threshold here made the two
                # derivations of one number disagree the moment a workspace
                # ceiling tightened anything: the project reported 1 actionable
                # and this split summed to 0, with no rule for which to trust.
                actionable = count_actionable_results(results, project.gate_threshold)
                self._scanner_actionable[name] = (
                    self._scanner_actionable.get(name, 0) + actionable
                )
        else:
            for name in by_scanner:
                self._scanner_actionable.setdefault(name, 0)

        self._make_spool_dir()
        # The project key is a path-derived value with separators already
        # replaced by dashes, so it is safe as a filename by construction.
        spool_path = self.spool_dir / f"{outcome.project}.run.json"
        from automated_security_helper.utils.sandbox.fs_guard import (
            open_for_atomic_write,
        )

        # Guarded below the workspace output directory whether or not a
        # PluginContext registered it: a link at the spool or at the file name is
        # refused rather than written through. Renamed into place, so write()
        # never copies a spool file that is still being written.
        with open_for_atomic_write(spool_path, root=self.output_dir) as handle:
            json.dump(rebased, handle)
        self._spooled[outcome.project] = spool_path

    def _make_spool_dir(self) -> None:
        """Create the spool directory, replacing anything else at its name.

        A link there, or a file, is removed and never followed. Through a link to
        a directory elsewhere, every project's run was written into that
        directory, and the ``rmtree`` in :meth:`write` refused the link and left
        them there. A committed entry at the spool stops the workspace before it
        starts (core/committed_output.py); this covers one git does not track.

        Read with ``os.lstat`` and ``scanned_tree._is_link_stat``, not
        ``Path.is_symlink()``, which is False for a Windows junction: one at
        this name was taken for the spool directory and written through.
        ``unlink`` removes a directory link or junction without entering it.
        """
        from automated_security_helper.utils.scanned_tree import _is_link_stat

        try:
            info: Optional[os.stat_result] = os.lstat(self.spool_dir)
        except FileNotFoundError:
            info = None
        if info is not None and (_is_link_stat(info) or not stat.S_ISDIR(info.st_mode)):
            self.spool_dir.unlink()
        self.spool_dir.mkdir(parents=True, exist_ok=True)

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
        """The lossy workspace-level rollup. Per-project truth is in ``projects``.

        Lossy about counts, which is what "lossy" meant here, and it must not be
        lossy about whether a scanner ran. ``dependencies_satisfied`` and
        ``excluded`` were written as constants, and the pair contradicted the
        ``status`` beside them: ``ScannerStatisticsCalculator`` derives "this
        scanner is missing" from ``dependencies_satisfied`` and not from
        ``status``, so anything re-deriving a verdict from this file -- ``ash
        report`` over a workspace output, or the completeness gate itself -- read
        a MISSING scanner as present and reported a complete scan.

        Derived from the rolled-up status rather than carried separately, because
        the status is already the worst across projects and a second rollup of the
        same fact could disagree with it. The exit code is carried the same way: it
        is picked in :meth:`add` by the decision that picks the status, from the row
        the status came from, so an entry never pairs a status with another
        project's code. A scanner no row recorded a code for reads
        ``SCANNER_EXIT_CODE_UNRECORDED``, unless it is SKIPPED, which reads what
        its own row carries (null).

        A SKIPPED or MISSING row says why, as a single scan's row does: for each
        project at the rolled-up status, in workspace-file order, the project key
        and that project's reason, ``<project>: <reason>`` joined with ``; ``. A
        project at another status is not named, since its reason is not why the
        scanner has this one; it stays on that project's own entry.
        """
        outcomes = self._ordered_outcomes()
        payload: Dict[str, Dict[str, Any]] = {}
        for scanner in sorted(set(self._scanner_status) | set(self._scanner_findings)):
            status = self._scanner_status.get(scanner) or "PASSED"
            row: Dict[str, Any] = {
                "status": status,
                "finding_count": self._scanner_findings.get(scanner, 0),
                "actionable_finding_count": self._scanner_actionable.get(scanner, 0),
                "dependencies_satisfied": status != "MISSING",
                "excluded": status == "SKIPPED",
                "exit_code": self._scanner_exit_code.get(
                    scanner, SCANNER_EXIT_CODE_UNRECORDED
                ),
            }
            if status in ("SKIPPED", "MISSING"):
                named = [
                    f"{outcome.project}: {outcome.scanner_reasons[scanner]}"
                    for outcome in outcomes
                    if (outcome.scanners or {}).get(scanner) == status
                    and (outcome.scanner_reasons or {}).get(scanner)
                ]
                if named:
                    field = (
                        "skipped_reason" if status == "SKIPPED" else "missing_reason"
                    )
                    row[field] = "; ".join(named)
            payload[scanner] = row
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
        secret_value_shapes: Optional[Sequence[Any]] = None,
        plugin_load_errors: Optional[Mapping[str, str]] = None,
    ) -> Path:
        """Stream the unified results file and return its path.

        Assembled by hand rather than by dumping one object, so that no more than
        one project's SARIF is in memory at a time. Two tests read the result back
        -- one as JSON, one as ``AshAggregatedResults`` -- because hand-assembled
        JSON is exactly the kind of thing that is subtly wrong.

        ``secret_value_shapes`` are the shapes of the values every project's
        secret findings exposed (``AshAggregatedResults.secret_value_shapes``),
        written only when there are any, as the model writes them.

        ``plugin_load_errors`` are the plugin modules any project's scan could not
        import (``plugins.loader.combined_plugin_load_errors`` of each project's
        ``metadata.plugin_load_errors``), written to ``metadata`` when there are
        any. The completeness gate reads a module missing from it as one that
        loaded.
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

        metadata: Dict[str, Any] = {
            "report_id": _workspace_report_id(self.plan.workspace_file),
            "project_name": project_name
            or Path(self.plan.workspace_root).name
            or "ash-workspace",
            "tool_version": get_ash_version(),
            "description": (
                "Automated Security Helper workspace-mode aggregated report"
            ),
        }
        ignore_file_exclusions = workspace_ignore_file_exclusions(payload.projects)
        if ignore_file_exclusions is not None:
            metadata["ignore_file_exclusions"] = ignore_file_exclusions
        if plugin_load_errors:
            metadata["plugin_load_errors"] = dict(plugin_load_errors)

        header: Dict[str, Any] = {
            "name": f"ASH Workspace Scan: {project_name or Path(self.plan.workspace_root).name}",
            "description": (
                "Automated Security Helper - aggregated workspace report. One "
                "SARIF run per project; see the 'workspace' block for "
                "attribution and per-project verdicts."
            ),
            "metadata": metadata,
            "workspace": payload.model_dump(mode="json"),
            "scanner_results": self._scanner_results_payload(),
            # Empty on purpose. Converter rows are per project -- their paths are
            # relative to that project's tree and two projects run converters of
            # the same name -- so one top-level map keyed by converter cannot hold
            # them. Each project's converter verdict is in its entry under
            # "workspace": incomplete_converters, and scan_incomplete when the gate
            # is on.
            "converter_results": {},
            "additional_reports": {},
            "validation_checkpoints": [],
            "used_suppressions": [],
        }
        if secret_value_shapes:
            header["secret_value_shapes"] = [
                shape.model_dump(mode="json") if hasattr(shape, "model_dump") else shape
                for shape in secret_value_shapes
            ]

        self.output_dir.mkdir(parents=True, exist_ok=True)
        target = self.output_dir / RESULTS_FILENAME
        from automated_security_helper.utils.sandbox.fs_guard import (
            open_for_atomic_write,
        )

        try:
            # Streamed into a staging file renamed over the target at the end: the
            # MCP progress reader parses this file while the scan runs, and sees the
            # previous complete file until the new one is.
            with open_for_atomic_write(target, root=self.output_dir) as handle:
                handle.write("{\n")
                handle.writelines(
                    f"{json.dumps(key)}: {json.dumps(value)},\n"
                    for key, value in header.items()
                )
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


def stamp_run_record(results_path: Path, record: Dict[str, Any]) -> bool:
    """Put ``record`` into the validation checkpoints of a file :meth:`write` wrote.

    For the inner run of a container scan, which records its completion after the
    report step and its refusal when the report step refuses (see
    utils/inner_run_outcome.py). The file is copied once: header lines up to the
    ``"validation_checkpoints": [],`` line that ``write`` emits, that line with the
    record, then the rest, SARIF runs included, unchanged. Nothing is loaded or
    serialized whole, so ``write``'s memory bound holds. The copy replaces the file
    atomically, with the mode a plain write would give it, through
    ``fs_guard.open_for_atomic_write``: a link at the file or at a directory below
    the output directory is refused, not written through.

    Returns False, with the file unchanged, when it cannot be read or replaced or
    is not one ``write`` wrote.
    """
    from automated_security_helper.utils.sandbox.fs_guard import (
        open_for_atomic_write,
    )

    class _NotWritten(Exception):
        """Raised inside the copy, which discards the staging file."""

    try:
        path = Path(results_path)
        with (
            open(path, "r", encoding="utf-8") as source,
            open_for_atomic_write(path) as target,
        ):
            # In pieces of at most _STAMP_READ_LIMIT, so a long header line is
            # copied without being held whole, and a file that is not one write()
            # wrote is given up on without reading its SARIF line whole.
            at_line_start = True
            while True:
                piece = source.readline(_STAMP_READ_LIMIT)
                if not piece:
                    raise _NotWritten
                if at_line_start:
                    if piece == _EMPTY_CHECKPOINTS_LINE:
                        target.write(
                            f"{json.dumps('validation_checkpoints')}: "
                            f"{json.dumps([record])},\n"
                        )
                        break
                    if piece.startswith('"sarif": '):
                        raise _NotWritten
                target.write(piece)
                at_line_start = piece.endswith("\n")
            shutil.copyfileobj(source, target)
        return True
    except (_NotWritten, OSError, TypeError, ValueError):
        return False


def rewrite_workspace_block(results_path: Path, payload: WorkspaceResults) -> bool:
    """Replace the ``workspace`` block of a results file ``write`` produced.

    For the one change that comes after the file is written: the report step fails
    on a run whose projects did not already fail, and the process then exits with a
    status the block's ``exit_code`` must also carry, so the file never holds a
    different answer from the exit. Copied the way :func:`stamp_run_record` copies:
    the block is one header line, replaced; every other line, SARIF runs included,
    is unchanged and nothing is loaded whole. The copy replaces the file atomically
    through ``fs_guard.open_for_atomic_write``.

    Returns False, with the file unchanged, when it cannot be read or replaced or
    is not one ``write`` wrote.
    """
    from automated_security_helper.utils.sandbox.fs_guard import (
        open_for_atomic_write,
    )

    class _NotWritten(Exception):
        """Raised inside the copy, which discards the staging file."""

    key = json.dumps("workspace")
    replacement = f"{key}: {json.dumps(payload.model_dump(mode='json'))},\n"
    try:
        path = Path(results_path)
        with (
            open(path, "r", encoding="utf-8") as source,
            open_for_atomic_write(path) as target,
        ):
            at_line_start = True
            while True:
                piece = source.readline(_STAMP_READ_LIMIT)
                if not piece:
                    raise _NotWritten
                if at_line_start:
                    if piece.startswith(f"{key}: "):
                        # The old block is dropped unread beyond its first piece:
                        # its line can be as long as the project list.
                        while not piece.endswith("\n"):
                            piece = source.readline(_STAMP_READ_LIMIT)
                            if not piece:
                                raise _NotWritten
                        target.write(replacement)
                        break
                    if piece.startswith('"sarif": '):
                        raise _NotWritten
                target.write(piece)
                at_line_start = piece.endswith("\n")
            shutil.copyfileobj(source, target)
        return True
    except (_NotWritten, OSError, TypeError, ValueError):
        return False
