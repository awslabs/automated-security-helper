# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability


@dataclass(frozen=True)
class FindingDiff:
    new: list[FlatVulnerability]
    absent_after: list[FlatVulnerability]
    severity_changed: list[tuple[FlatVulnerability, FlatVulnerability]]
    suppression_changed: list[tuple[FlatVulnerability, FlatVulnerability]]


def compare_findings(
    before: Iterable[FlatVulnerability], after: Iterable[FlatVulnerability]
) -> FindingDiff:
    before_by_id = {finding.id: finding for finding in before}
    after_by_id = {finding.id: finding for finding in after}
    severity_changed = []
    suppression_changed = []
    for finding_id in sorted(before_by_id.keys() & after_by_id.keys()):
        previous, current = before_by_id[finding_id], after_by_id[finding_id]
        if (previous.severity or "").upper() != (current.severity or "").upper():
            severity_changed.append((previous, current))
        if previous.is_suppressed != current.is_suppressed:
            suppression_changed.append((previous, current))
    return FindingDiff(
        new=[after_by_id[key] for key in sorted(after_by_id.keys() - before_by_id)],
        absent_after=[
            before_by_id[key] for key in sorted(before_by_id.keys() - after_by_id)
        ],
        severity_changed=severity_changed,
        suppression_changed=suppression_changed,
    )
