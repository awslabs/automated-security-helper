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
absolute path to its remainder inside the project or refuses it. The leading
character decides: rooted text is absolute, and an unrooted URI is the
project-relative path it is. checkov's separator-stripped absolute shape
(``ws/api/src/insecure_bucket.tf``) is not tried as absolute: in workspace mode
the project is scanned with its own path as ``source_dir`` and the URI reaches
the aggregator already relativized, while a src-layout project's ordinary
relative URI spells its own absolute path and was being relocated.

An absolute URI is the ordinary shape in workspace mode, not an edge case:
``scripts/verify_external_target_scan.py`` records it from one healthy run, and
it appears whenever the process working directory differs from ``source_dir``,
which in workspace mode it must for all but one project. The separator-stripped
shape is NOT tried as absolute (above), and the cost of that choice is named
here: an unrooted URI that does spell an absolute path with its separator gone
is read as project-relative, placed at ``<project>/<uri>``, and not counted as a
failure. That shape does not reach the aggregator from the scans ASH runs
(``sanitize_sarif_paths`` relativizes it against the project's own
``source_dir`` first); a reader that meets it in a results file fed from
elsewhere sees a workspace_uri that names nothing, with no count beside it.

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
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import unquote

from automated_security_helper.core.committed_output import WORKSPACE_SPOOL_DIR_NAME
from automated_security_helper.core.exceptions import WorkspacePatternError
from automated_security_helper.models.asharp_model import new_report_id
from automated_security_helper.models.core import merged_honoring
from automated_security_helper.models.workspace import (
    SCANNER_EXIT_CODE_UNRECORDED,
    ProjectConverterRefusal,
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
    ScannerThresholdResolver,
    result_fails_scanner_threshold,
    result_scanner_name,
    result_severity,
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

#: Marks a finding that came from a scanner only ``workspace.additional_scanners``
#: asked for, rather than one the project enables itself. Written to
#: ``properties.origin`` on the SARIF result and added to ``properties.tags`` by
#: the executor; the verdict and the rollup exclude such findings unless the
#: policy gate is on. The spelling is the one the CLI reference and
#: ``AshWorkspaceConfig.json`` document. One home: ``execution`` imports this
#: module, so the constant and the predicate live here and it imports them
#: (a second copy let the two drift with no test failing on the drift).
POLICY_ORIGIN = "workspace-policy"


def is_policy_origin(result: Mapping[str, Any]) -> bool:
    """Whether this SARIF result came from a scanner only the policy added."""
    properties = result.get("properties")
    if not isinstance(properties, Mapping):
        return False
    return properties.get("origin") == POLICY_ORIGIN


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


def _slash_before_a_drive(text: str) -> bool:
    """Whether *text* is ``/C:/...`` or ``/C:``: a drive letter behind one separator.

    ``file:///C:/x`` reduces to ``/C:/x``, and that leading separator is dropped so
    a drive is spelled one way. The test is a drive's shape, an ASCII letter at
    [1] and a separator or the end of the text at [3], never only the colon at
    [2]: ``/x:legacy/src/x.py`` is a rooted POSIX path whose first component holds
    a colon, and dropping its separator made it ``x:legacy/src/x.py``, which
    nothing read as a drive, so it was rebased under the project as if relative.
    ``utils/workspace_paths.py`` reads a drive letter at the start of text whose
    separators are already stripped, so it never sees this shape; this predicate
    is the one place the leading separator is judged.
    """
    if len(text) < 3 or text[0] != "/" or text[2] != ":":
        return False
    if not (text[1].isascii() and text[1].isalpha()):
        return False
    return len(text) == 3 or text[3] in "/\\"


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
        if _slash_before_a_drive(text):
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
    separators (``utils/uri_separators.py``). A ``file:``-schemed URI is
    percent-decoded first (``Path.as_uri`` writes ``My%20Repo`` for ``My Repo``,
    and the project's path is never encoded), as :func:`_absolute_base` decodes a
    declared base; a scheme-less name keeps its ``%``, which is part of it.
    """
    text = uri.strip()
    if text.lower().startswith("file:"):
        text = unquote(text)
    text = sanitized_uri_text(_strip_file_scheme(text), project_path)
    if _slash_before_a_drive(text):
        text = text[1:]
    return text


def _rooted(text: str) -> bool:
    """Whether recorded path text is absolute on either platform's spelling.

    A leading ``/`` (POSIX, or a Windows path written with ``/``), a UNC path's
    ``\\\\server\\share``, or a drive anchor (``C:\\`` or ``C:/``).
    ``PurePosixPath(text).is_absolute()`` reads a Windows absolute path as
    relative, so a converter's or scanner's ``C:\\ws\\api\\nb.ipynb`` was shown
    as ``api/C:\\ws\\api\\nb.ipynb``, against the fields' contract that an
    absolute recorded path is kept as recorded. A single leading backslash is
    not a root: ``uri_separators`` classes it as a file-name character on a
    POSIX project (only a drive or a UNC spelling is Windows-only), and a
    Windows project's separators are already ``/`` when the text reaches here.
    """
    return text.startswith(("/", "\\\\")) or bool(_DRIVE_ANCHOR.match(text))


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

    An unrooted URI is project-relative, and is never tried as an absolute path
    ------------------------------------------------------------------------
    An earlier form also tried an unrooted URI with a separator restored, and
    read it as absolute when that landed inside the project, for a shape checkov
    emits when the process working directory differs from ``source_dir``:
    ``ws/api/src/insecure_bucket.tf``, absolute with the leading separator
    already gone. That reading relocated routine findings. In workspace mode a
    project is scanned with its own path as ``source_dir``, so
    ``sanitize_sarif_paths`` has already relativized checkov's URI before the
    aggregator sees it (measured; ``scripts/verify_multi_project_attribution.py``
    records that both scanners hand over ``src/...``), and the separator-stripped
    shape does not reach this function. What does reach it is the ordinary
    project-relative URI of a project whose own files spell its absolute path:
    the container mounts the workspace at ``/src``, so a Python src-layout
    project at ``/src/api`` holds ``src/api/__init__.py``, and a Next.js project
    at ``/src/app`` holds ``src/app/page.tsx``. Restoring a separator read those
    as ``/src/api/__init__.py`` and relocated the finding to ``__init__.py`` at
    the project root -- a different, existing file, silently. So the leading
    character decides: rooted text (a leading separator or a drive anchor) is
    absolute, and anything else is read as the project-relative path it is.
    Deliberately no filesystem check: aggregation would then depend on the tree
    still being present, and reading the same SARIF twice could give two answers.

    Args:
        uri: A SARIF artifact URI as a scanner emitted it.
        project_path: The project's canonical absolute path.

    Returns:
        The project-relative path when the URI is absolute and inside the
        project; ``None`` when it is absolute and outside; :data:`NOT_ABSOLUTE`
        when it is not rooted, which is to say project-relative.
    """
    text = _posix_text(uri, project_path)
    if not text:
        return None

    if not _rooted(text):
        return NOT_ABSOLUTE

    # ".." would make relative_to lie about containment, and Phase 0 rejects it
    # anyway; leave those to the pattern converter, which returns None.
    if _PARENT_COMPONENT in PurePosixPath(text).parts:
        return None
    root = PurePosixPath(root_text(project_path))
    try:
        remainder = PurePosixPath(text).relative_to(root)
    except ValueError:
        # Absolute, and not inside this project. Counted, never prefixed: a
        # prefix would invent a path that names nothing.
        return None
    # relative_to succeeds for the root itself, whose remainder is "."; that
    # names a directory, not a finding location.
    return remainder.as_posix() if remainder.parts else None


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
            ``file://`` scheme, may use backslashes, may be rooted. An unrooted
            URI is read as project-relative, never as an absolute path with its
            leading separator stripped (see :func:`project_relative_uri`).
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
    elif _rooted(text):
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


#: Answered by :func:`_declared_base` for a base the run anchors to a chain of
#: other bases it cannot resolve (an undeclared parent, a relative root, a cycle,
#: a chain deeper than ``_BASE_CHAIN_LIMIT``): the file the location names is
#: unknown, so the location is counted as unconvertible, and is NOT read as
#: project-relative, which placed it at the project root under the wrong name.
UNRESOLVED_BASE = object()

#: How many bases a chain may name, the location's own included: the walk gives
#: up once it has seen this many, so seven ``uriBaseId`` hops resolve and an
#: eighth is counted. SARIF puts no bound on chaining; one real-world chain is
#: two deep (``SRCROOT`` under ``REPOROOT``).
_BASE_CHAIN_LIMIT = 8


def _join_under_base(base_uri: str, uri: str) -> str:
    """*uri* placed under *base_uri* as a SARIF consumer joins them.

    3.4.4: a base ends with its separator. Not ``rstrip("/")`` on the base: that
    ate the scheme's own slashes of a filesystem-root base, ``file:///`` ->
    ``file:``, and the joined text then read as unrooted, so the uri was placed at
    the project root as if it had no base at all.
    """
    return (base_uri if base_uri.endswith("/") else base_uri + "/") + uri.lstrip("/")


def _absolute_base(uri: str) -> Optional[str]:
    """*uri* as an absolute base, its percent-escapes decoded, or None.

    A ``file:`` base is a URI, and ``Path.as_uri()`` (which ``project_root_uri``
    and the scanners' own writers use) percent-encodes it: a project at
    ``/Users/me/My Repo/api`` declares ``file:///Users/me/My%20Repo/api/``.
    Joined undecoded, the text ``/Users/me/My%20Repo/api/src/app.py`` is not
    under ``/Users/me/My Repo/api`` and the finding was counted unconvertible,
    where the project-relative reading before the base was honoured had placed
    it. Decoded here, once, before anything compares paths, and returned as a
    bare rooted path with the scheme stripped: a ``file:`` text handed on would
    be decoded a second time by :func:`_posix_text` when the joined location is
    read, which mis-read a directory named with a literal ``%xx`` and decoded a
    relative artifact's own ``%20`` that the same artifact keeps when it has no
    base. A base with no scheme is a path as written and is not decoded (a ``%``
    in a file name stays).
    """
    if uri.lower().startswith("file:"):
        decoded = _strip_file_scheme(unquote(uri))
    else:
        decoded = uri
    if not _rooted(_posix_text(decoded)):
        return None
    return decoded


def _declared_base(table: Mapping[str, Any], base_id: Any) -> Any:
    """The absolute ``uri`` *table* declares for *base_id*, None, or UNRESOLVED_BASE.

    None for the project root (the ordinary anchor, which the project-relative
    reading already assumes), for an id the run does not declare, and for an
    unanchored base whose own ``uri`` is relative: only an absolute base places a
    relative uri on disk. A base anchored to another (``uriBaseId`` on the base
    entry: ``SRCROOT`` -> ``{"uri": "src/", "uriBaseId": "REPOROOT"}``) is followed
    to its root and the chain joined, so the location is placed where a SARIF
    consumer places it; before this the chained base answered None and the
    location was placed at the project root, dropping the ``src/`` and naming
    another file. A chain this function cannot follow answers
    :data:`UNRESOLVED_BASE`, which the caller counts instead of placing.
    """
    if not base_id or base_id == PROJECT_ROOT_URI_BASE_ID:
        return None
    entry = table.get(str(base_id))
    if not isinstance(entry, Mapping):
        return None
    uri = entry.get("uri")
    if not isinstance(uri, str) or not uri:
        return None
    parent_id = entry.get("uriBaseId")
    if not parent_id:
        return _absolute_base(uri)

    segments = [uri]
    seen = {str(base_id)}
    while parent_id:
        key = str(parent_id)
        if key in seen or len(seen) >= _BASE_CHAIN_LIMIT:
            return UNRESOLVED_BASE
        seen.add(key)
        parent = table.get(key)
        if not isinstance(parent, Mapping):
            return UNRESOLVED_BASE
        parent_uri = parent.get("uri")
        if not isinstance(parent_uri, str) or not parent_uri:
            return UNRESOLVED_BASE
        segments.append(parent_uri)
        parent_id = parent.get("uriBaseId")
    root = _absolute_base(segments[-1])
    if root is None:
        return UNRESOLVED_BASE
    joined = root
    for segment in reversed(segments[:-1]):
        joined = _join_under_base(joined, segment)
    return joined


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

    # The project root joins the run's base-id table rather than replacing it. A
    # scanner that anchored its own locations (`uriBaseId: "%SRCROOT%"`) declared
    # that id here; dropping the table left those references dangling, and a
    # consumer resolving them found no base at all.
    base_ids = rebased.get("originalUriBaseIds")
    table: Dict[str, Any] = dict(base_ids) if isinstance(base_ids, Mapping) else {}
    table[PROJECT_ROOT_URI_BASE_ID] = {"uri": project_root_uri(project.path)}
    rebased["originalUriBaseIds"] = table

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
            rewritten = False
            if reduced is NOT_ABSOLUTE:
                placed: Optional[str] = str(uri)
                base_uri = _declared_base(table, artifact.get("uriBaseId"))
                if base_uri is UNRESOLVED_BASE:
                    # Anchored to a chain of bases the run does not resolve: the
                    # file it names is unknown. Counted below, and not read as
                    # project-relative, which named another file.
                    placed = None
                elif base_uri is not None:
                    # The scanner anchored this relative uri to a base of its
                    # own, which need not be the project root, and the file it
                    # names is base + uri. workspace_uri has to come from that
                    # path read back through the project, or the two
                    # coordinates name two files. The artifact itself stays as
                    # the scanner wrote it: its uri and its uriBaseId agree.
                    # Joined as a SARIF consumer joins them (_join_under_base).
                    joined = _join_under_base(base_uri, str(uri))
                    anchored = project_relative_uri(joined, project.path)
                    if anchored is None:
                        # Inside the base, outside this project: counted, and
                        # not placed in the workspace.
                        placed = None
                    elif anchored is not NOT_ABSOLUTE:
                        placed = anchored
            elif reduced is None:
                # Absolute and outside the project. Left exactly as the scanner
                # wrote it, and deliberately NOT anchored: an artifactLocation
                # carrying both an absolute uri and a uriBaseId contradicts
                # itself.
                placed = None
            else:
                placed = reduced
                artifact["uri"] = reduced
                rewritten = True

            if placed is None:
                continue
            converted = to_workspace_uri(placed, project.relative_path, project.path)
            if converted is None:
                # Relative, and still not placeable inside the project (a ".."
                # component, a shape the pattern converter refuses). Keeps its
                # text, gets no uriBaseId, and is counted below: anchoring it to
                # the project root would assert a location inside the project
                # for a path that escapes it.
                continue
            if rewritten:
                # The uri is now in the project root's coordinates, whatever
                # base the scanner wrote for the absolute form it replaced.
                artifact["uriBaseId"] = PROJECT_ROOT_URI_BASE_ID
            else:
                # Anchor to the project root so the run stays coherent with
                # exactly one root. A scanner that already anchored its own
                # relative output knows something we do not, so leave that alone.
                artifact.setdefault("uriBaseId", PROJECT_ROOT_URI_BASE_ID)
            if workspace_uri is None:
                workspace_uri = converted

        if workspace_uri is not None:
            properties["workspace_uri"] = workspace_uri
        elif had_locatable_uri:
            # One increment per finding that ended up with no workspace-relative
            # path at all, however many locations it offered.
            unconvertible += 1
        result["properties"] = properties

    return rebased, unconvertible


#: Resolves a scanner's OWN threshold (its ``options.severity_threshold``) from
#: the scanner's name as ``properties.scanner_name`` records it (``None`` for a
#: finding that names none). An answer of ``None`` means "no own threshold: the
#: project-wide one governs".
#:
#: The same call shape as ``severity_ladder.ScannerThresholdResolver`` with the
#: opposite meaning for a falsy answer: there a falsy answer turns the gate OFF
#: for that scanner. Python's structural typing cannot tell the two apart, so
#: the names do: a value of this type is never handed to the ladder's
#: ``result_fails_scanner_threshold`` as it is; :func:`effective_threshold_resolver`
#: is the one conversion, filling the project-wide threshold in for ``None`` and
#: returning a ``ScannerThresholdResolver``, and that resolver is the one the
#: counters below pass down.
OwnThresholdResolver = Callable[[Optional[str]], Optional[str]]

#: The scanner a finding with no ``properties.scanner_name`` is credited to, in
#: the per-scanner counts and in the rollup alike.
UNATTRIBUTED_SCANNER = "unattributed"


def result_is_suppressed(result: Mapping[str, Any]) -> bool:
    """Whether *result* carries a suppression that is in effect.

    The one reading every consumer makes (``utils.sarif_utils.suppressions_in_effect``):
    a suppression whose ``state`` is ``rejected`` or ``underReview`` has not taken
    effect (SARIF 3.35.4) and hides nothing; one whose state is ``accepted``, or
    that states none, does. Read as any-suppression, a finding whose only
    suppression awaited review was left out of a project's finding and actionable
    counts while the flat finding, the OCSF record and the per-scanner counts kept
    it. The answer is ``sarif_utils.is_result_suppressed``'s, the one the exit
    code, the ``--min-severity`` gate, the statistics calculator, the result
    filters and the JUnit reporter read too. Imported inside the function because
    ``sarif_utils`` imports the results model this module also imports, and the
    module-level order is not fixed.
    """
    from automated_security_helper.utils.sarif_utils import is_result_suppressed

    return is_result_suppressed(result)


def effective_threshold_resolver(
    threshold: Optional[str],
    threshold_for: Optional[OwnThresholdResolver] = None,
) -> ScannerThresholdResolver:
    """The threshold each scanner's findings are graded against, memoised.

    *threshold_for* answers a scanner's own ``options.severity_threshold`` (``None``
    for a scanner with none, and for a finding that names no scanner); the
    project-wide *threshold* governs those. Every answer is upper-cased, because
    ``_compute_exit_code`` upper-cases the configured value and the ladder is
    case-sensitive. One resolver for the actionable count and the
    ``--min-severity`` gate, so the two cannot grade one finding against two
    thresholds. The result is the ladder's type: it answers ``None`` only when the
    project-wide threshold is itself unset, which is the one case the gate is
    meant to be off.
    """
    resolved: Dict[Optional[str], Optional[str]] = {}

    def effective(scanner: Optional[str]) -> Optional[str]:
        if scanner not in resolved:
            own = threshold_for(scanner) if threshold_for is not None else None
            value = own or threshold
            resolved[scanner] = value.upper() if value else None
        return resolved[scanner]

    return effective


def actionable_results_by_scanner(
    results: Iterable[Mapping[str, Any]],
    threshold: Optional[str],
    *,
    threshold_for: Optional[OwnThresholdResolver] = None,
) -> Dict[str, int]:
    """Per scanner, the findings at or above that scanner's own threshold.

    Mirrors ``run_ash_scan._compute_exit_code``'s SARIF pass: the threshold is
    resolved per result from its scanner (``properties.scanner_name``), the
    project-wide *threshold* governing a scanner that has no setting of its own
    and a finding that names no scanner; ``properties.issue_severity`` decides
    when it names a severity ASH knows, otherwise the SARIF ``level`` does; and a
    suppressed finding never counts. Both arms go through Phase 0's severity
    ladder, which was verified to gate identically to the inline tables in
    ``_compute_exit_code`` for all five real threshold values.

    Every scanner that produced a result is a key, counted or not, so a caller
    can tell "no actionable findings" from "no findings".

    Args:
        results: The SARIF results of one run.
        threshold: The project-wide threshold. Upper-cased here, as every
            resolved value is, because ``_compute_exit_code`` upper-cases the
            configured value and the ladder is case-sensitive; without this a
            lowercase threshold would gate like CRITICAL in one path and MEDIUM
            in the other.
        threshold_for: Resolves a scanner's own threshold from its name; ``None``
            (the default, and the resolver's answer for a scanner with no setting
            of its own) falls back to *threshold*. Without one, every finding is
            judged against *threshold*, which is what the single-scan code did
            before it honoured per-scanner ``options.severity_threshold`` and what
            left a project's workspace verdict disagreeing with its own.

    Returns:
        Scanner name to actionable count. A falsy effective threshold counts
        nothing for that scanner, which is how an operator turns the gate off.

    One predicate with the ``--min-severity`` gate below:
    ``severity_ladder.result_fails_scanner_threshold`` grades the result, and
    ``result_scanner_name`` names its scanner, for both. This counter kept its
    own reading (``issue_severity`` upper-cased but not stripped, ``str()`` of a
    scanner name that is not a string, the level graded through its own table),
    so a result with ``issue_severity: " high "`` was graded by its level here and
    as HIGH by the gate: counted on one side and qualifying on the other, which is
    the split sharing one resolver was meant to close.
    """
    effective = effective_threshold_resolver(threshold, threshold_for)

    counts: Dict[str, int] = {}
    for result in results:
        if not isinstance(result, Mapping):
            continue
        scanner = result_scanner_name(result)
        name = scanner or UNATTRIBUTED_SCANNER
        counts.setdefault(name, 0)
        if result_is_suppressed(result):
            continue
        # A falsy effective threshold fails nothing (severity_fails_threshold),
        # which is the gate turned off for that scanner.
        if result_fails_scanner_threshold(result, effective):
            counts[name] += 1
    return counts


def count_actionable_results(
    results: Iterable[Mapping[str, Any]],
    threshold: Optional[str],
    *,
    threshold_for: Optional[OwnThresholdResolver] = None,
) -> int:
    """Count findings at or above their scanner's threshold, as ``_compute_exit_code`` does.

    The sum of :func:`actionable_results_by_scanner`; see it for the rules.

    Returns:
        The number of actionable findings. Zero when *threshold* is falsy and no
        resolver names a threshold, which is how an operator turns the gate off.
    """
    return sum(
        actionable_results_by_scanner(
            results, threshold, threshold_for=threshold_for
        ).values()
    )


def has_finding_at_min_severity(
    results: Iterable[Mapping[str, Any]],
    min_severity: str,
    threshold: Optional[str] = None,
    *,
    threshold_for: Optional[OwnThresholdResolver] = None,
) -> bool:
    """Whether any finding meets ``--min-severity``, the way ``_compute_exit_code`` does.

    A separate gate from the threshold, and a coarser one: it zeroes the whole
    actionable count when no single finding qualifies. Kept separate rather than
    folded into ``count_actionable_results`` because that is how the shipped
    behaviour works -- ``--min-severity`` is a whole-scan switch, not a per-
    finding filter that changes the count.

    A qualifying finding is an ACTIONABLE one at or above the minimum. Given the
    gate (*threshold*, the project-wide one, and *threshold_for*, each scanner's
    own; the same two :func:`actionable_results_by_scanner` takes), a finding its
    scanner's threshold made non-actionable does not qualify: it was not counted,
    so it cannot be the finding that keeps the count standing
    (``severity_ladder.result_fails_scanner_threshold``, the check the single scan
    makes). Without the gate, severity alone decides, which is what read a
    bandit MEDIUM under bandit's own CRITICAL as the finding that kept a semgrep
    LOW actionable: the same project exited 0 as ``ash --source-dir P`` and 2
    inside a workspace.

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
    gated = threshold is not None or threshold_for is not None
    effective = effective_threshold_resolver(threshold, threshold_for)
    for result in results:
        if not isinstance(result, Mapping):
            continue
        if result_is_suppressed(result):
            continue
        # The resolver run_ash_scan._severity_filters_finding uses: the
        # declared issue_severity first, a missing level as
        # MISSING_SARIF_LEVEL, and INFO (absent from the scale) as low. This
        # read the level alone, with a missing one as note.
        if _MIN_SEVERITY_RANK.get(result_severity(result).lower(), 1) < min_rank:
            continue
        if gated and not result_fails_scanner_threshold(result, effective):
            continue
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

    # A row is (name, reason, kinds): the mapping keeps the first two by field.
    return {row.name: row.reason for row in incomplete_converters(results)}


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
        shown = (
            path
            if _rooted(path)
            else (PurePosixPath(relative_path) / PurePosixPath(path)).as_posix()
        )
        entries.append(
            ProjectInputNotScanned(scanner=scanner, path=shown, reason=reason)
        )
    return entries


def converter_refusals_for_project(
    results: Any, relative_path: str
) -> List[ProjectConverterRefusal]:
    """This project's refused and failed converter inputs, workspace-relative.

    Read through ``utils.converter_refusals.converter_refusals``, the reader the
    single-directory summaries, the flat JSON report and the SARIF invocations
    use, so a workspace lists the same records a single scan does. The path is
    rebased as :func:`inputs_not_scanned_for_project` rebases a scanner's: a path
    recorded relative to the project gets the project's ``relative_path`` in
    front, one recorded absolute is kept as it is. ``incomplete_converters``
    carries the converter-level verdict; this carries the inputs behind it.

    Imported inside the function because ``converter_refusals`` imports the
    results model, which imports this package's models.

    Args:
        results: One project's ``AshAggregatedResults``, or ``None``.
        relative_path: The project's workspace-relative path.

    Returns:
        The records, in the reader's order (those leaving the scan incomplete
        first); empty for ``None`` and for a project whose converters refused
        nothing.
    """
    from automated_security_helper.utils.converter_refusals import (
        converter_refusals,
    )

    if results is None:
        return []
    records = []
    for refusal in converter_refusals(results):
        shown = (
            refusal.path
            if not refusal.path or _rooted(refusal.path)
            else (PurePosixPath(relative_path) / PurePosixPath(refusal.path)).as_posix()
        )
        records.append(
            ProjectConverterRefusal(
                converter=refusal.converter,
                path=shown,
                member=refusal.member,
                reason=refusal.reason,
                limit=refusal.limit,
                failed=refusal.failed,
                accepted=refusal.accepted,
                scan_incomplete=refusal.scan_incomplete,
                unlisted_members=refusal.unlisted_members,
            )
        )
    return records


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


def _fold_scanner_name(name: str) -> str:
    """The form two spellings of one scanner name are compared in.

    ``cli/merge`` documents that one results file records "Bandit" where another
    records "bandit", and compares every scanner name stripped and lowered for that
    reason. The rollup joins projects' rows by the same fold, so one scanner is
    one row however each project's config spelled it.
    """
    return name.strip().lower()


def _larger_code(first: Optional[int], second: Optional[int]) -> Optional[int]:
    """The larger of two rolled-up codes, where null (no code) is below any code."""
    if first is None:
        return second
    if second is None:
        return first
    return max(first, second)


def _workspace_report_id(workspace_file: str) -> str:
    """The unified report's id: ``ASH-WORKSPACE-<file name>-<time>-<random>``.

    The file name tells a reader which workspace the report covers; the rest is a
    scan's id (see ``new_report_id``), so each run of a workspace gets its own.
    """
    stem = _REPORT_ID_UNSAFE.sub("-", Path(workspace_file).stem).strip("-")
    return new_report_id(prefix=f"ASH-WORKSPACE-{stem or 'workspace'}")


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
        # Every per-scanner map below is keyed by the folded name (_rollup_key):
        # cli/merge documents that one shard records "Bandit" where another
        # records "bandit", and a project's config is written by the same hands.
        # Keyed by the raw name, one scanner split into two rows. The published
        # row is named by the first spelling in WORKSPACE-FILE order
        # (_display_names, read when the payload is built); this map remembers
        # the first spelling add() saw, which is completion order and is the
        # fallback for a scanner known only from its findings.
        self._scanner_display: Dict[str, str] = {}
        self._scanner_findings: Dict[str, int] = {}
        self._scanner_actionable: Dict[str, int] = {}
        self._scanner_status: Dict[str, Optional[str]] = {}
        self._scanner_exit_code: Dict[str, Optional[int]] = {}
        # The rollup's two flags, from the rows that carried them: excluded only
        # when every project that recorded the scanner excluded it, and
        # dependencies satisfied only when every one of them had its tool.
        self._scanner_excluded: Dict[str, bool] = {}
        self._scanner_dependencies: Dict[str, bool] = {}
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

        flags = outcome.carried_scanner_flags
        for raw_name, status in (outcome.scanners or {}).items():
            scanner = self._rollup_key(raw_name)
            code = outcome.carried_scanner_exit_codes.get(
                raw_name, SCANNER_EXIT_CODE_UNRECORDED
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
            name = self._rollup_key(str(scanner) if scanner else UNATTRIBUTED_SCANNER)
            by_scanner.setdefault(name, []).append(result)
            self._scanner_status.setdefault(name, None)
            if result_is_suppressed(result):
                continue
            self._scanner_findings[name] = self._scanner_findings.get(name, 0) + 1

        # Actionable counts, per scanner: the split the project's own verdict
        # carried, when it carried one. The verdict graded each finding against
        # its scanner's own threshold and saw only the findings it is allowed to
        # (a policy scanner's findings decide nothing unless policy_scanners_gate
        # is set), so summing the split here is the one derivation. Re-deriving it
        # from the run against one project-wide threshold made the two
        # derivations of one number disagree the moment a scanner had a threshold
        # of its own, and counted policy-origin findings the project's own total
        # excluded, so the rollup exceeded the per-project totals it claims to sum.
        #
        # Zeroed wholesale when the project's own actionable count is zero, which
        # the carried split already is: that is how the --min-severity gate reaches
        # this layer, since it is a whole-scan switch in _compute_exit_code rather
        # than a per-finding filter.
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
            # An outcome built without the split (a results file read back, a
            # caller that assembled it by hand): derived from the run the way the
            # verdict derived it. Each scanner's own threshold where the outcome
            # recorded one (threshold_for_scanner, the contract every regrading
            # reader follows), the project's gate_threshold otherwise, so a
            # workspace ceiling that tightened the project is honoured here too;
            # and a finding from a scanner only the policy added is left out
            # when the outcome says the policy gate was off, as the verdict left
            # it out. Without both, this path again exceeded the project's own
            # actionable_finding_count the comment above says the split fixed.
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
        # The project key is a path-derived value with separators already
        # replaced by dashes, so it is safe as a filename by construction. Two
        # keys that differ only in letter case are two projects on the filesystem
        # the workspace was read from, but one file name on a case-insensitive
        # output volume, where the second spool replaced the first project's run.
        # An ordinal prefix keeps the names apart; write() reads the paths it
        # recorded, never the names.
        spool_path = (
            self.spool_dir / f"{len(self._spooled):04d}-{outcome.project}.run.json"
        )
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

    def _rollup_key(self, name: str) -> str:
        """The key *name*'s rows roll up under, remembering its first spelling."""
        key = _fold_scanner_name(name)
        self._scanner_display.setdefault(key, name)
        return key

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
        same fact could disagree with it.

        A SKIPPED or MISSING row says why, as a single scan's row does: for each
        project at the rolled-up status, in workspace-file order, the project key
        and that project's reason, ``<project>: <reason>`` joined with ``; ``. A
        project at another status is not named, since its reason is not why the
        scanner has this one; it stays on that project's own entry.
        """
        outcomes = self._ordered_outcomes()
        display = self._display_names(outcomes)
        payload: Dict[str, Dict[str, Any]] = {}
        for scanner in sorted(set(self._scanner_status) | set(self._scanner_findings)):
            status = self._scanner_status.get(scanner) or "PASSED"
            row: Dict[str, Any] = {
                "status": status,
                "finding_count": self._scanner_findings.get(scanner, 0),
                "actionable_finding_count": self._scanner_actionable.get(scanner, 0),
                # From the rows that carried the flags; a scanner known only from
                # its findings (no row recorded it) keeps the status-derived answer.
                "dependencies_satisfied": self._scanner_dependencies.get(
                    scanner, status != "MISSING"
                ),
                "excluded": self._scanner_excluded.get(scanner, status == "SKIPPED"),
                "exit_code": self._scanner_exit_code.get(
                    scanner, SCANNER_EXIT_CODE_UNRECORDED
                ),
            }
            if status in ("SKIPPED", "MISSING"):
                named = []
                for outcome in outcomes:
                    for raw_name, raw_status in (outcome.scanners or {}).items():
                        if _fold_scanner_name(raw_name) != scanner:
                            continue
                        if raw_status != status:
                            continue
                        reason = (outcome.scanner_reasons or {}).get(raw_name)
                        if reason:
                            named.append(f"{outcome.project}: {reason}")
                if named:
                    field = (
                        "skipped_reason" if status == "SKIPPED" else "missing_reason"
                    )
                    row[field] = "; ".join(named)
            payload[display.get(scanner, scanner)] = row
        return payload

    def _display_names(
        self, outcomes: Sequence[WorkspaceProjectResult]
    ) -> Dict[str, str]:
        """The published spelling of each folded scanner name, by plan order.

        ``add()`` runs in completion order, which a parallel run does not
        reproduce, so a row named by the first spelling it saw (``Bandit`` from
        one project, ``bandit`` from another) could change its key between two
        runs of the same workspace, and a reader looking the row up by a
        project's own ``scanner_name`` found it one run and not the next. The
        name is the first spelling in workspace-file order (*outcomes* is
        ``_ordered_outcomes()``), read from each project's own rows; a scanner
        no row recorded (known from its findings alone) keeps the first spelling
        ``add()`` saw.
        """
        display: Dict[str, str] = {}
        for outcome in outcomes:
            for raw_name in outcome.scanners or {}:
                display.setdefault(_fold_scanner_name(raw_name), raw_name)
        for key, name in self._scanner_display.items():
            display.setdefault(key, name)
        return display

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
        # The staging file replaces ``path`` when this block ends, and Windows will
        # not replace a file that this process still holds open. So ``source`` is
        # opened inside the block and closed before it ends. A file that is not
        # there is given up on first, so the guard creates nothing for it.
        if not path.exists() and not path.is_symlink():
            return False
        with open_for_atomic_write(path) as target:
            with open(path, "r", encoding="utf-8") as source:
                # In pieces of at most _STAMP_READ_LIMIT, so a long header line is
                # copied without being held whole, and a file that is not one
                # write() wrote is given up on without reading its SARIF line whole.
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
