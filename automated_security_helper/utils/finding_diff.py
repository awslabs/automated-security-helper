# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from automated_security_helper.utils.finding_identity import canonical

if TYPE_CHECKING:
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability


@dataclass(frozen=True)
class FindingMatch:
    exact: list[tuple[FlatVulnerability, FlatVulnerability]]
    moved: list[tuple[FlatVulnerability, FlatVulnerability]]
    new: list[FlatVulnerability]
    absent: list[FlatVulnerability]


@dataclass(frozen=True)
class FindingDiff:
    new: list[FlatVulnerability]
    absent_after: list[FlatVulnerability]
    moved: list[tuple[FlatVulnerability, FlatVulnerability]]
    severity_changed: list[tuple[FlatVulnerability, FlatVulnerability]]
    suppression_changed: list[tuple[FlatVulnerability, FlatVulnerability]]


def fallback_key(finding: FlatVulnerability) -> tuple | None:
    if finding._identity is None or finding.source_report is not None:
        return None
    if any(
        kind in (finding._assigned_identity_key or {})
        for kind in ("fingerprints", "partialFingerprints")
    ):
        return None
    base = dict(finding._identity.base)
    if finding._assigned_identity_key is not None:
        base["project"] = finding._assigned_identity_key.get(
            "project", base.get("project")
        )
    return (
        canonical(base),
        finding._identity_message or "",
        (finding.severity or "").upper(),
    )


def _order(finding: FlatVulnerability) -> tuple:
    return (
        finding.line_start if finding.line_start is not None else -1,
        finding.line_end if finding.line_end is not None else -1,
        finding.id,
    )


def match_findings(
    before: Iterable[FlatVulnerability], after: Iterable[FlatVulnerability]
) -> FindingMatch:
    before = list(before)
    after = list(after)
    before_ids = defaultdict(list)
    after_ids = defaultdict(list)
    for index, finding in enumerate(before):
        before_ids[finding.id].append(index)
    for index, finding in enumerate(after):
        after_ids[finding.id].append(index)
    matched_before = set()
    matched_after = set()
    exact = []
    exact_indices = []
    for finding_id in sorted(before_ids.keys() & after_ids.keys()):
        if len(before_ids[finding_id]) != 1 or len(after_ids[finding_id]) != 1:
            continue
        i, j = before_ids[finding_id][0], after_ids[finding_id][0]
        previous, current = before[i], after[j]
        if previous._identity is not None and current._identity is not None:
            fingerprinted = all(
                any(
                    kind in (finding._assigned_identity_key or {})
                    for kind in ("fingerprints", "partialFingerprints")
                )
                for finding in (previous, current)
            )
            if (
                not fingerprinted
                and previous._identity_message != current._identity_message
            ):
                continue
        exact.append((previous, current))
        exact_indices.append((i, j))
        matched_before.add(i)
        matched_after.add(j)

    def loose_key(finding):
        key = fallback_key(finding)
        return None if key is None else key[:2]

    partner = {j: i for i, j in exact_indices}
    whole_before = defaultdict(list)
    whole_after = defaultdict(list)
    for index, finding in enumerate(before):
        key = loose_key(finding)
        if key is not None:
            whole_before[key].append(index)
    for index, finding in enumerate(after):
        key = loose_key(finding)
        if key is not None:
            whole_after[key].append(index)
    ambiguous = {
        key
        for key in whole_before.keys() & whole_after.keys()
        if len({before[i].is_suppressed for i in whole_before[key]}) > 1
        and not (
            len(whole_before[key]) == len(whole_after[key])
            and all(
                j in partner and loose_key(before[partner[j]]) == key
                for j in whole_after[key]
            )
        )
    }
    if ambiguous:
        kept = []
        for i, j in exact_indices:
            if loose_key(before[i]) in ambiguous or loose_key(after[j]) in ambiguous:
                matched_before.discard(i)
                matched_after.discard(j)
            else:
                kept.append((before[i], after[j]))
        exact = kept
    groups_before = defaultdict(list)
    groups_after = defaultdict(list)
    for index, finding in enumerate(before):
        key = fallback_key(finding)
        if index not in matched_before and key is not None:
            groups_before[key].append(index)
    for index, finding in enumerate(after):
        key = fallback_key(finding)
        if index not in matched_after and key is not None:
            groups_after[key].append(index)
    moved = []
    for key in sorted(groups_before.keys() & groups_after.keys()):
        if key[:2] in ambiguous:
            continue
        old, new = groups_before[key], groups_after[key]
        if len(new) > len(old) or len({before[i].is_suppressed for i in old}) > 1:
            continue
        for i, j in zip(
            sorted(old, key=lambda n: _order(before[n])),
            sorted(new, key=lambda n: _order(after[n])),
        ):
            moved.append((before[i], after[j]))
            matched_before.add(i)
            matched_after.add(j)
    return FindingMatch(
        exact,
        moved,
        sorted(
            (f for i, f in enumerate(after) if i not in matched_after),
            key=lambda f: (f.id, _order(f)),
        ),
        sorted(
            (f for i, f in enumerate(before) if i not in matched_before),
            key=lambda f: (f.id, _order(f)),
        ),
    )


def compare_findings(
    before: Iterable[FlatVulnerability], after: Iterable[FlatVulnerability]
) -> FindingDiff:
    match = match_findings(before, after)
    pairs = match.exact + match.moved
    return FindingDiff(
        new=match.new,
        absent_after=match.absent,
        moved=match.moved,
        severity_changed=[
            (a, b)
            for a, b in pairs
            if (a.severity or "").upper() != (b.severity or "").upper()
        ],
        suppression_changed=[
            (a, b) for a, b in pairs if a.is_suppressed != b.is_suppressed
        ],
    )
