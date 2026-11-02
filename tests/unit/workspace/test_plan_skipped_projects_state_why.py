# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A skipped plan entry carries its reason, or the plan refuses it.

``WorkspacePlan.skipped_projects`` is derived from each project's skip reason
and ``active_projects`` from its skip flag. An entry with the flag set and no
reason fell between the two: the payload did not list it, the dry-run header
counted it in neither figure, and the body still printed it as skipped. The
resolver never builds that shape, so the model refuses it at construction, where
a hand-built plan would otherwise carry it silently.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.models.workspace import SkippedProjectReason
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

pytestmark = pytest.mark.unit


def _entry(**fields) -> ProjectPlan:
    values = {
        "key": "api",
        "relative_path": "api",
        "path": "/ws/api",
        "label": "api",
        "display_label": "api",
    }
    values.update(fields)
    return ProjectPlan(**values)


def test_a_skipped_entry_without_a_reason_is_refused():
    with pytest.raises(ValidationError, match="skip_reason"):
        _entry(skipped=True)


def test_a_skipped_entry_with_a_reason_is_accepted_and_counted():
    entry = _entry(
        skipped=True, skip_reason=SkippedProjectReason.ERROR, skip_detail="gone"
    )
    plan = WorkspacePlan(workspace_file="/ws/dev.code-workspace", workspace_root="/ws")
    plan.projects.append(entry)

    assert [skipped.project for skipped in plan.skipped_projects] == ["api"]
    assert plan.active_projects == []
    assert "1 to scan" not in plan.render()
    assert "0 to scan, 1 skipped" in plan.render()


def test_an_active_entry_needs_no_reason():
    entry = _entry()
    assert entry.skipped is False
    assert entry.as_skipped_project() is None
