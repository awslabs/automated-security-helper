# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Project confinement applies before any project's config is read.

``run_ash_workspace_scan`` refused a workspace with a project outside the
permitted roots, but only after resolving the plan, which reads every project's
own ``.ash.yaml``; ``resolve_ash_workspace`` did not confine projects at all and
returned the plan. So both tools read a config file outside the roots, and the
resolve tool reported what it said (each project's label, scanners and
threshold) while a config that did not parse came back as a validation error
quoting it. Both now refuse such a workspace with the confinement refusal
(exit 4) before any project config is read.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from automated_security_helper.cli.mcp.workspace import (
    mcp_resolve_workspace,
    mcp_scan_workspace,
)

MARKER = "OUTSIDE-THE-ROOTS-4c1d"


@pytest.fixture
def layout(tmp_path, monkeypatch):
    granted = tmp_path / "granted"
    (granted / "inside").mkdir(parents=True)
    outside = tmp_path / "outside"
    (outside / ".ash").mkdir(parents=True)
    workspace = tmp_path / "dev.code-workspace"
    workspace.write_text(
        json.dumps({"folders": [{"path": "granted/inside"}, {"path": "outside"}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(granted))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    return {"workspace": workspace, "outside_config": outside / ".ash" / ".ash.yaml"}


@pytest.mark.parametrize(
    "config_text",
    [
        f"project_name: {MARKER}\n",
        f"project_name: [unclosed {MARKER}\n",
    ],
    ids=["valid-config", "malformed-config"],
)
@pytest.mark.parametrize("tool", [mcp_resolve_workspace, mcp_scan_workspace])
def test_a_project_outside_the_roots_is_refused_before_its_config_is_read(
    layout, tool, config_text
) -> None:
    layout["outside_config"].write_text(config_text, encoding="utf-8")

    result = asyncio.run(
        tool(workspace_file=str(layout["workspace"]), session_id="session-a")
    )

    assert result.get("success") is False, result
    assert result.get("exit_code") == 4, result
    assert MARKER not in json.dumps(result, default=str), (
        "the response carries what the out-of-root config says"
    )


@pytest.mark.parametrize("tool", [mcp_resolve_workspace, mcp_scan_workspace])
def test_no_project_config_is_read_when_a_project_is_outside(
    layout, tool, monkeypatch
) -> None:
    from automated_security_helper.workspace import resolver

    layout["outside_config"].write_text(f"project_name: {MARKER}\n", encoding="utf-8")
    read = []
    monkeypatch.setattr(
        resolver,
        "_resolve_project_config",
        lambda candidate, *a, **k: read.append(candidate.key),
    )

    result = asyncio.run(
        tool(workspace_file=str(layout["workspace"]), session_id="session-a")
    )

    assert result.get("exit_code") == 4, result
    assert read == [], f"project configs were read before confinement: {read}"
