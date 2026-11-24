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
    install path (the finding's file when it has no package path).
    ``package_version`` is deliberately not part of the key.

``iac``
    ``resource_id`` is present. Members share the resource id, the resource
    type (or both lack one), the file and the set of CWEs (empty when none).
    Exact equality only. Annotate-only: ``foldable`` is False until a measured
    cross-scanner collision shows the resource-id vocabulary is shared.

``location``
    ``file_path``, ``line_start`` and a CWE are all present. Members share the
    file, have overlapping line ranges (ends inclusive; a missing end is the
    start) and share at least one CWE. Both sides must carry a CWE: no CWE, no
    cluster. Overlap is not transitive, so a cluster is a connected component
    of the overlap relation; a chain A-B-C joins A and C even when they do not
    overlap one another. That is order independent, which a sweep is not.

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


def _package_key(row: FlatVulnerability) -> Optional[Tuple[Any, ...]]:
    cve = _text(row.cve_id)
    package = _text(row.package_name)
    if cve is None or package is None:
        return None
    where = relative_path(_text(row.package_path) or _text(row.file_path))
    return (CLASS_PACKAGE, cve.upper(), package, where)


def _iac_key(row: FlatVulnerability) -> Optional[Tuple[Any, ...]]:
    resource = _text(row.resource_id)
    if resource is None:
        return None
    return (
        CLASS_IAC,
        resource,
        _text(row.resource_type),
        relative_path(_text(row.file_path)),
        tuple(sorted(_cwes(row.cwe_id))),
    )


def _span(row: FlatVulnerability) -> Optional[Tuple[str, int, int, frozenset[str]]]:
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
    material = "\x1f".join([finding_class, *sorted(r.id or "" for r in rows)])
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
        span = _span(row)
        if span is not None:
            unclaimed[index] = span
    for key, members in grouped.items():
        if len(members) > 1:
            clusters.append(_build(rows, key[0], members))
    for members in _location_groups(unclaimed):
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
ANNOTATION_COLUMNS: Tuple[str, ...] = ("cluster_id", "duplicate_of", "duplicate_sources")


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
