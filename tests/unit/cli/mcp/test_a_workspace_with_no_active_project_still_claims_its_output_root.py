# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan with no active project still holds its output root.

A workspace scan writes its unified results and reports into the output root
whether or not a project runs, and the registry knows a root only through an
entry. With every project missing (``allow_missing_projects``) nothing was
registered, so a second workspace scan of the same root passed the check that
asks the registry whether a live scan shares the root, and the two wrote beside
each other, each run's cleanup removing the other's files.

The scan now registers one entry for the workspace root in that case. It is a
claim and not a scan a client can poll, so the responses leave it out of
``scan_ids``.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.workspace.plan import WorkspacePlan

pytestmark = pytest.mark.unit

_MODULE = "automated_security_helper.cli.mcp.workspace"


def _plan_with_no_active_project(tmp_path: Path) -> WorkspacePlan:
    root = tmp_path / "workspace"
    root.mkdir(parents=True, exist_ok=True)
    workspace_file = root / "fixture.code-workspace"
    workspace_file.write_text('{"folders": []}', encoding="utf-8")
    return WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=root.as_posix(),
        projects=[],
    )


def _register(plan, registry, output):
    with patch(f"{_MODULE}.get_scan_registry", return_value=registry):
        return workspace_module._register_projects(
            plan, {}, "session-a", output_dir=output
        )


def test_a_second_workspace_scan_of_the_same_root_is_refused(tmp_path):
    plan = _plan_with_no_active_project(tmp_path)
    registry = ScanRegistry()
    output = tmp_path / "out"
    _register(plan, registry, output)

    # RED at the base: the first call registered nothing, so the root check found
    # no live scan and this one was admitted beside it.
    with pytest.raises(MCPResourceError, match="being written by another scan"):
        _register(plan, registry, output)


def test_the_claim_is_given_back_when_the_scan_closes(tmp_path):
    plan = _plan_with_no_active_project(tmp_path)
    registry = ScanRegistry()
    output = tmp_path / "out"
    registered = _register(plan, registry, output)
    with patch(f"{_MODULE}.get_scan_registry", return_value=registry):
        workspace_module._close_registrations(registered, None)
        workspace_module._release_projects(registered)

    (scan_id,) = registered.values()
    assert registry.get_scan(scan_id).status is MCScanStatus.COMPLETED
    assert registry.scan_writing_within(str(output)) is None
    assert _register(plan, registry, output)


def test_the_claim_is_not_a_scan_a_client_can_poll():
    registered = {"": "claim-id"}

    assert workspace_module._scan_ids_of(registered) == {}
    assert workspace_module._scan_ids_of({"api": "scan-1", "": "claim-id"}) == {
        "api": "scan-1"
    }
