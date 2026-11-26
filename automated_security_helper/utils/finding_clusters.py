# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Duplicate clusters over flattened findings: which rows are one finding.

Two scanners often report the same underlying problem (grype and trivy on one
vulnerable package, two SAST engines on one line). This module groups such
rows into clusters and picks one primary per cluster. It is pure: it reads
:class:`~automated_security_helper.models.flat_vulnerability.FlatVulnerability`
rows and returns annotations; it changes no row, no id and no suppression.
Finding ids, SARIF results, per-scanner metrics, baselines and suppressions
stay keyed by the scanner-inclusive identity. A report emitter that wants to
show one row per cluster does that on top of these annotations.

Three classes, tried in this order; a finding joins at most one cluster, by
the first class whose required columns it carries:

``package``
    A CVE and a package: ``cve_id`` and ``package_name`` are both present.
    Members share the upper-cased CVE, the package name and the package's
    install path (the finding's file when it has no package path). A row with
    no location at all, or whose only location is an SBOM (which spans every
    ecosystem and carries no install path), has no package key: an unknown
    location never equals another unknown location.
    ``package_version`` is deliberately not part of the key, so two scanners
    that spell one copy's version differently still fold. The producer's unit
    is (advisory, package copy), though, so a key group is then split into
    copies: when a scanner reports two or more rows under one key those rows
    are distinct copies (or ones this module cannot tell apart), and the group
    clusters by installed version instead; a version that more than one row of
    one scanner shares, or a row with no version in such a group, clusters with
    nothing. Fail closed: a missed duplicate is shown twice, a wrong fold hides
    a finding.

``iac``
    ``resource_id`` is present. Members share the resource id, the resource
    type (or both lack one), the file and the set of CWEs. A row with no CWE
    is keyed by its rule id instead (a row with neither has no IaC key), so
    two different rules on one construct are never one finding. Exact equality
    only. Annotate-only: ``foldable`` is False until a measured
    cross-scanner collision shows the resource-id vocabulary is shared.

``location``
    ``file_path``, ``line_start`` and a CWE are all present. Members share the
    file, have overlapping line ranges (ends inclusive; a missing end is the
    start) and share at least one CWE. Both sides must carry a CWE: no CWE, no
    cluster. A row that names a package is a dependency finding and never
    joins this class (an advisory that is not a CVE has no package key, and
    the location class knows neither the advisory nor the package). Overlap is not transitive, so a cluster is a connected component
    of the overlap relation; a chain A-B-C joins A and C even when they do not
    overlap one another. That is order independent, which a sweep is not.
    The chaining is bounded by a split guard: two rows of one scanner and
    rule id are one finding only when they overlap each other directly, so a
    cluster never folds two findings of the same scanner and rule id that are
    connected only through a bridge row (a wide multi-CWE row spanning both).
    Such a component splits: the bridge rows cluster with nothing and the
    rest re-cluster; a chain with no single bridge leaves the two findings
    standing alone instead. Fail closed, as for the package class.

A class with only one matching row makes no cluster. Secrets (no CWE, a
masked value) never cluster.

The primary of a cluster is chosen among its unsuppressed members when the
members disagree on suppression, so a suppressed row is never the primary
that stands for a live one. Within the candidates: highest severity, then a
fingerprinted identity over one keyed by lines, then scanner name, then id.
An unrecognized severity ranks as most severe, as the severity ladder fails
closed. The outcome does not depend on input order.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.finding_identity import relative_path
from automated_security_helper.utils.severity_ladder import SEVERITIES

CLASS_PACKAGE = "package"
CLASS_IAC = "iac"
CLASS_LOCATION = "location"

#: Classes whose clusters may be folded into one row. The IaC class annotates
#: only (see the module docstring).
FOLDABLE_CLASSES = frozenset({CLASS_PACKAGE, CLASS_LOCATION})

_CWE = re.compile(r"cwe-(\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class FindingCluster:
    """One cluster of two or more rows.

    ``members`` are positions in the input list, ascending. ``sources`` are the
    other members of the cluster as provenance of the primary, one dict of
    ``scanner``, ``rule_id``, ``id`` and ``severity`` each, in a fixed order.
    """

    cluster_id: str
    finding_class: str
    foldable: bool
    members: Tuple[int, ...]
    primary: int
    sources: Tuple[Dict[str, Any], ...]


@dataclass(frozen=True)
class ClusterAssignment:
    """The annotation of one input row.

    A row in no cluster has ``cluster_id`` None, ``is_primary`` False and
    ``duplicate_of`` None. A primary has ``duplicate_of`` None and its
    ``duplicate_sources``; any other member names the primary's finding id.
    """

    cluster_id: Optional[str] = None
    finding_class: Optional[str] = None
    foldable: bool = False
    is_primary: bool = False
    duplicate_of: Optional[str] = None
    duplicate_sources: Tuple[Dict[str, Any], ...] = ()


def _text(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _cwes(value: Any) -> frozenset[str]:
    """The CWE numbers a ``cwe_id`` column names, as ``CWE-<n>`` (empty if none)."""
    if not isinstance(value, str):
        return frozenset()
    return frozenset(f"CWE-{int(n)}" for n in _CWE.findall(value))


def _severity_rank(severity: Any) -> int:
    """Lower is more severe; an unrecognized severity is most severe."""
    name = severity.strip().upper() if isinstance(severity, str) else ""
    return SEVERITIES.index(name) if name in SEVERITIES else -1


_SBOM_NAME = re.compile(
    r"(^|[._-])(bom|sbom|cyclonedx|cdx|spdx)([._-]|$)|\.(spdx|cdx)\b", re.IGNORECASE
)


def _is_sbom(path: str) -> bool:
    return bool(_SBOM_NAME.search(path.rsplit("/", 1)[-1]))


def _package_key(row: FlatVulnerability) -> Optional[Tuple[Any, ...]]:
    cve = _text(row.cve_id)
    package = _text(row.package_name)
    if cve is None or package is None:
        return None
    install_path = _text(row.package_path)
    where = relative_path(install_path or _text(row.file_path))
    if where is None:
        return None
    if install_path is None and _is_sbom(where):
        return None
    return (CLASS_PACKAGE, cve.upper(), package, where)


def _package_copies(
    rows: Sequence[FlatVulnerability], members: List[int]
) -> List[List[int]]:
    """Split one package key group into clusters of one copy each."""
    per_scanner: Dict[str, int] = {}
    for i in members:
        scanner = rows[i].scanner or ""
        per_scanner[scanner] = per_scanner.get(scanner, 0) + 1
    if max(per_scanner.values()) == 1:
        return [members]
    by_version: Dict[str, List[int]] = {}
    for i in members:
        version = _text(rows[i].package_version)
        if version is not None:
            by_version.setdefault(version, []).append(i)
    lanes: List[List[int]] = []
    for lane in by_version.values():
        scanners = [rows[i].scanner or "" for i in lane]
        if len(set(scanners)) == len(scanners):
            lanes.append(lane)
    return lanes


def _iac_key(row: FlatVulnerability) -> Optional[Tuple[Any, ...]]:
    resource = _text(row.resource_id)
    if resource is None:
        return None
    cwes = tuple(sorted(_cwes(row.cwe_id)))
    rule = None
    if not cwes:
        rule = _text(row.rule_id)
        if rule is None:
            return None
    return (
        CLASS_IAC,
        resource,
        _text(row.resource_type),
        relative_path(_text(row.file_path)),
        cwes,
        rule,
    )


def _span(row: FlatVulnerability) -> Optional[Tuple[str, int, int, frozenset[str]]]:
    if _text(row.package_name) is not None:
        return None
    path = relative_path(_text(row.file_path))
    cwes = _cwes(row.cwe_id)
    start = row.line_start
    if path is None or start is None or not cwes:
        return None
    end = row.line_end if row.line_end is not None and row.line_end >= start else start
    return (path, start, end, cwes)


def _location_groups(
    spans: Dict[int, Tuple[str, int, int, frozenset[str]]],
) -> List[List[int]]:
    """Connected components of the overlap relation, per file, ascending."""
    by_file: Dict[str, List[int]] = {}
    for index, span in spans.items():
        by_file.setdefault(span[0], []).append(index)
    groups: List[List[int]] = []
    for indexes in by_file.values():
        parent = {i: i for i in indexes}

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        for pos, a in enumerate(indexes):
            _, a_start, a_end, a_cwes = spans[a]
            for b in indexes[pos + 1 :]:
                _, b_start, b_end, b_cwes = spans[b]
                if a_start <= b_end and b_start <= a_end and a_cwes & b_cwes:
                    parent[find(a)] = find(b)
        components: Dict[int, List[int]] = {}
        for i in sorted(indexes):
            components.setdefault(find(i), []).append(i)
        groups.extend(components.values())
    return groups


def _overlaps(
    spans: Dict[int, Tuple[str, int, int, frozenset[str]]], a: int, b: int
) -> bool:
    """Whether two rows of one file overlap directly and share a CWE."""
    _, a_start, a_end, a_cwes = spans[a]
    _, b_start, b_end, b_cwes = spans[b]
    return a_start <= b_end and b_start <= a_end and bool(a_cwes & b_cwes)


def _location_split_guard(
    rows: Sequence[FlatVulnerability],
    spans: Dict[int, Tuple[str, int, int, frozenset[str]]],
    members: List[int],
) -> List[List[int]]:
    """Bound the chaining: the clusters one connected component yields.

    Two rows of one scanner and rule id are one finding only when they overlap
    each other directly; a wide multi-CWE row can bridge two separate findings
    into one component, and folding them would hide one. A component with such
    a pair splits: the bridge rows (each directly connected to both sides of a
    pair) cluster with nothing, the rest re-cluster, and this guard runs again
    on each part. A chain with no single bridge leaves the pair's rows standing
    alone instead. A missing scanner or rule id compares equal to another
    missing one, failing closed. A component with no such pair is returned
    whole, so the documented A-B-C chaining is otherwise unchanged.
    """
    by_key: Dict[Tuple[str, str], List[int]] = {}
    for i in members:
        key = (rows[i].scanner or "", rows[i].rule_id or "")
        by_key.setdefault(key, []).append(i)
    violations = [
        (a, b)
        for same in by_key.values()
        for position, a in enumerate(same)
        for b in same[position + 1 :]
        if not _overlaps(spans, a, b)
    ]
    if not violations:
        return [members]
    bridges = {
        w
        for w in members
        for a, b in violations
        if w != a and w != b and _overlaps(spans, w, a) and _overlaps(spans, w, b)
    }
    removed = bridges or {i for pair in violations for i in pair}
    rest = {i: spans[i] for i in members if i not in removed}
    return [
        part
        for group in _location_groups(rest)
        for part in _location_split_guard(rows, spans, group)
    ]


def _primary(rows: Sequence[FlatVulnerability], members: Iterable[int]) -> int:
    members = list(members)
    live = [i for i in members if not rows[i].is_suppressed]
    candidates = live if live and len(live) != len(members) else members
    return min(
        candidates,
        key=lambda i: (
            _severity_rank(rows[i].severity),
            not rows[i].has_fingerprint_identity,
            rows[i].scanner or "",
            rows[i].id or "",
        ),
    )


def _cluster_id(finding_class: str, rows: Sequence[FlatVulnerability]) -> str:
    # The members' project is part of the id: clusters never span projects, and
    # identity-derived finding ids already embed theirs, but a plugin-supplied
    # id on an identity-less finding can repeat across two projects of one
    # workspace, and two different clusters must never share an id.
    project = next((r.workspace_project for r in rows), None) or ""
    material = "\x1f".join([finding_class, project, *sorted(r.id or "" for r in rows)])
    return "dup-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _build(
    rows: Sequence[FlatVulnerability], finding_class: str, members: List[int]
) -> FindingCluster:
    members = sorted(members)
    primary = _primary(rows, members)
    others = sorted(
        (i for i in members if i != primary),
        key=lambda i: (
            rows[i].scanner or "",
            rows[i].rule_id or "",
            rows[i].id or "",
        ),
    )
    sources = tuple(
        {
            "scanner": rows[i].scanner,
            "rule_id": rows[i].rule_id,
            "id": rows[i].id,
            "severity": rows[i].severity,
        }
        for i in others
    )
    return FindingCluster(
        cluster_id=_cluster_id(finding_class, [rows[i] for i in members]),
        finding_class=finding_class,
        foldable=finding_class in FOLDABLE_CLASSES,
        members=tuple(members),
        primary=primary,
        sources=sources,
    )


def cluster_findings(rows: Sequence[FlatVulnerability]) -> List[FindingCluster]:
    """The clusters of *rows*, each of two or more members, in a fixed order.

    Ordered by the position of each cluster's first member. Pure: *rows* is not
    changed, and shuffling it yields the same clusters (the same ids, primaries
    and sources) with positions that follow the shuffle.
    """
    clusters: List[FindingCluster] = []
    grouped: Dict[Tuple[Any, ...], List[int]] = {}
    unclaimed: Dict[int, Tuple[str, int, int, frozenset[str]]] = {}
    for index, row in enumerate(rows):
        key = _package_key(row) or _iac_key(row)
        if key is not None:
            grouped.setdefault(key, []).append(index)
            continue
        if _text(row.package_name) is not None:
            continue
        span = _span(row)
        if span is not None:
            unclaimed[index] = span
    for key, members in grouped.items():
        if len(members) < 2:
            continue
        copies = (
            _package_copies(rows, members) if key[0] == CLASS_PACKAGE else [members]
        )
        for copy in copies:
            if len(copy) > 1:
                clusters.append(_build(rows, key[0], copy))
    for group in _location_groups(unclaimed):
        for members in _location_split_guard(rows, unclaimed, group):
            if len(members) > 1:
                clusters.append(_build(rows, CLASS_LOCATION, members))
    clusters.sort(key=lambda c: c.members[0])
    return clusters


def assign_clusters(rows: Sequence[FlatVulnerability]) -> List[ClusterAssignment]:
    """One :class:`ClusterAssignment` per row of *rows*, in input order."""
    assignments = [ClusterAssignment() for _ in rows]
    for cluster in cluster_findings(rows):
        primary_id = rows[cluster.primary].id
        for index in cluster.members:
            is_primary = index == cluster.primary
            assignments[index] = ClusterAssignment(
                cluster_id=cluster.cluster_id,
                finding_class=cluster.finding_class,
                foldable=cluster.foldable,
                is_primary=is_primary,
                duplicate_of=None if is_primary else primary_id,
                duplicate_sources=cluster.sources if is_primary else (),
            )
    return assignments


#: The flat-report columns the annotation adds, in this order, after every other
#: column. Present only when ``global_settings.deduplication.annotate`` is on.
ANNOTATION_COLUMNS: Tuple[str, ...] = (
    "cluster_id",
    "duplicate_of",
    "duplicate_sources",
)


def annotation_values(assignment: ClusterAssignment) -> Dict[str, Any]:
    """The annotation columns of one row, each None when it does not apply.

    A row in no cluster is all None. A primary has a ``cluster_id`` and its
    ``duplicate_sources`` (a list of ``scanner`` / ``rule_id`` / ``id`` /
    ``severity`` dicts); any other member has a ``cluster_id`` and the primary's
    id as ``duplicate_of``.
    """
    return {
        "cluster_id": assignment.cluster_id,
        "duplicate_of": assignment.duplicate_of,
        "duplicate_sources": (
            [dict(source) for source in assignment.duplicate_sources] or None
        ),
    }


def annotate_enabled(model: Any) -> bool:
    """Whether *model*'s config turns the duplicate annotation on.

    Only a literal ``True`` counts, so a model with no recorded configuration, or
    a stand-in object, leaves every report as it has always been.
    """
    settings = getattr(getattr(model, "ash_config", None), "global_settings", None)
    dedup = getattr(settings, "deduplication", None)
    return getattr(dedup, "annotate", False) is True


def assign_clusters_by_project(
    rows: Sequence[FlatVulnerability],
) -> List[ClusterAssignment]:
    """:func:`assign_clusters`, run once per workspace project.

    Two projects of a workspace can hold the same CVE in the same relative
    package path; they are two findings, not one, so clusters never span
    projects. A single-directory scan has one group and is the plain call.
    """
    groups: Dict[Optional[str], List[int]] = {}
    for index, row in enumerate(rows):
        groups.setdefault(row.workspace_project, []).append(index)
    if len(groups) <= 1:
        return assign_clusters(rows)
    assignments = [ClusterAssignment() for _ in rows]
    for indexes in groups.values():
        for index, assigned in zip(
            indexes, assign_clusters([rows[i] for i in indexes]), strict=True
        ):
            assignments[index] = assigned
    return assignments


def fold_enabled(model: Any) -> bool:
    """Whether *model*'s config turns the fold of duplicates on in human reports.

    Only a literal ``True`` counts, as for :func:`annotate_enabled`.
    """
    settings = getattr(getattr(model, "ash_config", None), "global_settings", None)
    dedup = getattr(settings, "deduplication", None)
    return getattr(dedup, "fold", False) is True


def clusters_by_project(rows: Sequence[FlatVulnerability]) -> List[FindingCluster]:
    """:func:`cluster_findings`, run once per workspace project.

    The positions in each cluster are positions in *rows*, not in the project's
    slice, so the clusters read directly against the full list. Clusters never
    span projects, as for :func:`assign_clusters_by_project`.
    """
    groups: Dict[Optional[str], List[int]] = {}
    for index, row in enumerate(rows):
        groups.setdefault(row.workspace_project, []).append(index)
    if len(groups) <= 1:
        return cluster_findings(rows)
    clusters: List[FindingCluster] = []
    for indexes in groups.values():
        for found in cluster_findings([rows[i] for i in indexes]):
            clusters.append(
                FindingCluster(
                    cluster_id=found.cluster_id,
                    finding_class=found.finding_class,
                    foldable=found.foldable,
                    members=tuple(indexes[m] for m in found.members),
                    primary=indexes[found.primary],
                    sources=found.sources,
                )
            )
    clusters.sort(key=lambda c: c.members[0])
    return clusters


def fold_positions(
    rows: Sequence[FlatVulnerability],
    clusters: Sequence[FindingCluster],
    shown: Sequence[int],
    prefer: Iterable[int] = (),
) -> List[Tuple[int, Tuple[int, ...]]]:
    """The rows of a view, one per foldable cluster, each with what it stands for.

    *shown* is the view as positions in *rows*, in display order (a list of
    actionable findings, a table of every finding). Each returned pair is a
    position that stays in the view and the positions folded under it, ascending;
    a row in no foldable cluster stays alone. The order of *shown* is kept.

    Three rules keep a fold honest. Only the members that are in the view fold,
    so a cluster half hidden by a filter folds what is left of it, and its
    representative is the cluster's primary when that is in the view, else the
    best of the rest by the primary's own ranking. Suppressed and live members
    never fold together: a suppressed duplicate is not hidden under a live row,
    and a live row is not hidden under a suppressed one. And *prefer*, when
    given, names the positions a representative is chosen among while any of
    them is present: the report emitter passes its actionable rows, because the
    gate is per scanner, so a cluster can hold an actionable row and a
    higher-severity row another scanner's threshold leaves below it, and the
    severity ranking alone then hid the actionable finding under a card the
    default view does not show. Clusters that do not fold (``foldable`` False,
    the IaC class) leave every row in place.
    """
    in_view = set(shown)
    preferred = set(prefer)
    stands_for: Dict[int, Tuple[int, ...]] = {}
    folded_away: set[int] = set()
    for cluster in clusters:
        if not cluster.foldable:
            continue
        for suppressed in (False, True):
            present = [
                m
                for m in cluster.members
                if m in in_view and bool(rows[m].is_suppressed) is suppressed
            ]
            if len(present) < 2:
                continue
            candidates = [m for m in present if m in preferred] or present
            representative = (
                cluster.primary
                if cluster.primary in candidates
                else _primary(rows, candidates)
            )
            others = tuple(m for m in present if m != representative)
            stands_for[representative] = others
            folded_away.update(others)
    return [
        (position, stands_for.get(position, ()))
        for position in shown
        if position not in folded_away
    ]


def provenance_entries(
    rows: Sequence[FlatVulnerability], others: Iterable[int]
) -> List[Dict[str, Any]]:
    """The provenance of a folded row: one dict per row it stands for.

    ``scanner``, ``rule_id`` and ``severity`` of each, in a fixed order (scanner,
    rule, id), so the same view always reads the same.
    """
    ordered = sorted(
        others,
        key=lambda i: (rows[i].scanner or "", rows[i].rule_id or "", rows[i].id or ""),
    )
    return [
        {
            "scanner": rows[i].scanner,
            "rule_id": rows[i].rule_id,
            "severity": rows[i].severity,
        }
        for i in ordered
    ]


def provenance_note(entries: Sequence[Dict[str, Any]]) -> Optional[str]:
    """The sentence a folded row carries, or None when it stands for no other row.

    Each entry reads ``scanner rule (SEVERITY)``; a missing part is left out.
    """
    if not entries:
        return None
    parts = []
    for entry in entries:
        label = " ".join(
            str(part) for part in (entry.get("scanner"), entry.get("rule_id")) if part
        )
        severity = entry.get("severity")
        if severity:
            label = f"{label} ({severity})" if label else f"({severity})"
        parts.append(label or "unknown")
    return "Also reported by " + "; ".join(parts)
