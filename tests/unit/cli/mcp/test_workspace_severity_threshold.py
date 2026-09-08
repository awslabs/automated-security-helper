#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project's severity threshold survives the MCP round trip unchanged.

Why this file exists
--------------------
``validate_severity_threshold`` accepted LOW, MEDIUM, HIGH and CRITICAL.
``AshConfig.global_settings.severity_threshold`` is
``Literal['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']``. So a threshold read
straight out of a valid ASH config could be refused by the registry, and the
workspace MCP path had two options for a project declaring ``ALL``: fail the whole
scan, or register something else.

Both are wrong, and the second is the more dangerous. Nothing *gates* on the
threshold held in the scan registry -- the only reads are two echoes into response
payloads and one log line -- so substituting a value changes no verdict. But
``get_scan_progress`` reports it, so a client polling a project configured at the
strictest available setting was told ``MEDIUM``. A stricter setting reported as a
looser one, in a security tool, is the failure direction that matters.

The fix is in the validator, not in the workspace layer: ``ALL`` is a legal value
and the validator was missing it. Widening an accepted set cannot break an input
that already worked, which is what makes this safe on a path the single-project
MCP flow also uses.

Why the accepted set is derived rather than restated
----------------------------------------------------
:meth:`TestTheValidatorAcceptsEveryLegalConfigValue.test_every_config_literal_value_is_accepted`
reads the values out of the ``AshConfig`` field annotation instead of listing them.
A hardcoded list here would pass while drifting: adding a sixth value to the config
Literal would leave the registry refusing it and this file green. Deriving the set
means the two cannot disagree without failing.

The refusal still has to work
-----------------------------
Widening an allowlist has one obvious failure mode -- widening it into a no-op --
so :meth:`TestTheValidatorAcceptsEveryLegalConfigValue.test_a_value_outside_the_config_literal_is_still_refused`
is the control. Without it, deleting the check entirely would satisfy everything
above.
"""

from __future__ import annotations

import importlib
import json
import typing
from pathlib import Path
from typing import Any, List, Tuple

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.resource_management.error_handling import (
    validate_severity_threshold,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)

MODULE_UNDER_TEST = "automated_security_helper.cli.mcp.workspace"

#: The strictest value, and the one the registry used to refuse. Named rather than
#: inlined because every assertion below turns on it being the *same* value end to
#: end.
STRICTEST_THRESHOLD = "ALL"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _config_threshold_values() -> Tuple[str, ...]:
    """Every value ASH's own config permits for ``severity_threshold``."""
    annotation = (
        type(AshConfig().global_settings).model_fields["severity_threshold"].annotation
    )
    return typing.get_args(annotation)


def _tool(name: str):
    return getattr(importlib.import_module(MODULE_UNDER_TEST), name)


def _workspace(root: Path, folders, name: str = "dev.code-workspace") -> Path:
    path = root / name
    path.write_text(
        json.dumps({"folders": [{"path": entry} for entry in folders]}),
        encoding="utf-8",
    )
    return path


def _project(root: Path, relative: str, config: str | None = None) -> Path:
    project = root / relative
    project.mkdir(parents=True, exist_ok=True)
    if config is not None:
        ash_dir = project / ".ash"
        ash_dir.mkdir(exist_ok=True)
        (ash_dir / "ash.yaml").write_text(config, encoding="utf-8")
    return project


@pytest.fixture(autouse=True)
def _clear_policy_env(monkeypatch):
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture
def isolated_registry(monkeypatch):
    """A fresh registry, whose global the accessor reads at call time."""
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.fixture
def executions(monkeypatch) -> List[Tuple[Any, Any]]:
    """Record ``execute_workspace`` and hand back a real-shaped result.

    Faked because this file measures what the MCP layer records about a project,
    not what a scanner finds in one. The registry is the real thing, because the
    value under test is the one it stores.
    """
    from automated_security_helper.models.workspace import (
        ProjectRunStatus,
        WorkspaceProjectResult,
        WorkspaceResults,
    )
    from automated_security_helper.workspace import execution as execution_module
    from automated_security_helper.workspace.execution import WorkspaceRunResult

    calls: List[Tuple[Any, Any]] = []

    def _record(plan, settings, **kwargs):
        calls.append((plan, settings))
        payload = WorkspaceResults(
            workspace_file=plan.workspace_file,
            workspace_root=plan.workspace_root,
            status="completed",
            exit_code=0,
            projects=[
                WorkspaceProjectResult(
                    project=project.key,
                    relative_path=project.relative_path,
                    display_label=project.display_label,
                    status=ProjectRunStatus.COMPLETED,
                    severity_threshold=project.gate_threshold,
                    output_path=f"projects/{project.key}",
                )
                for project in plan.projects
            ],
            unconvertible_finding_paths=0,
        )
        return WorkspaceRunResult(
            results_path=Path(settings.output_dir) / "ash_workspace_results.json",
            exit_code=0,
            payload=payload,
        )

    monkeypatch.setattr(execution_module, "execute_workspace", _record)
    module = importlib.import_module(MODULE_UNDER_TEST)
    if hasattr(module, "execute_workspace"):
        monkeypatch.setattr(module, "execute_workspace", _record)
    return calls


# ---------------------------------------------------------------------------
# 1. The validator's accepted set is ASH's own
# ---------------------------------------------------------------------------


class TestTheValidatorAcceptsEveryLegalConfigValue:
    """The registry and the config schema have to agree on what a threshold is."""

    def test_the_strictest_value_is_accepted(self):
        """``ALL`` specifically, since that is the one that was missing."""
        assert validate_severity_threshold(STRICTEST_THRESHOLD) is None

    def test_every_config_literal_value_is_accepted(self):
        """Derived from the config annotation, so the two sets cannot drift.

        A sixth value added to ``AshConfig.global_settings.severity_threshold``
        fails here until the validator accepts it, rather than surfacing as an
        MCP scan refused for a config ASH itself considers valid.
        """
        values = _config_threshold_values()
        assert values, "the config annotation yielded no values to check"

        refused = {
            value: str(error)
            for value in values
            if (error := validate_severity_threshold(value)) is not None
        }
        assert refused == {}, (
            "these are legal AshConfig severity thresholds that the MCP scan "
            f"registry refuses: {refused}"
        )

    def test_a_value_outside_the_config_literal_is_still_refused(self):
        """The control. Widening the set must not empty it.

        Deleting the membership check outright satisfies every other assertion in
        this class; only this one separates a wider allowlist from no allowlist.
        """
        error = validate_severity_threshold("SOMEWHAT-BAD")

        assert error is not None
        assert "Invalid severity threshold" in str(error)

    def test_the_empty_and_non_string_refusals_are_unchanged(self):
        """Widening the value set touched neither of the other two guards."""
        assert validate_severity_threshold("") is not None
        assert validate_severity_threshold(None) is not None


# ---------------------------------------------------------------------------
# 2. The registry stores it, rather than refusing or substituting
# ---------------------------------------------------------------------------


class TestTheRegistryStoresTheStrictestThreshold:
    """``register_scan`` is the caller that was refusing a legal value."""

    def test_registering_at_all_succeeds_and_keeps_the_value(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        registry = ScanRegistry()

        scan_id = registry.register_scan(
            directory_path=str(project),
            output_directory=str(output),
            severity_threshold=STRICTEST_THRESHOLD,
        )

        entry = registry.get_scan(scan_id)
        assert entry is not None
        assert entry.severity_threshold == STRICTEST_THRESHOLD

    def test_an_illegal_threshold_still_raises(self, tmp_path):
        """Control at the registry level, matching the validator's."""
        project = tmp_path / "proj"
        project.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        registry = ScanRegistry()

        with pytest.raises(MCPResourceError) as excinfo:
            registry.register_scan(
                directory_path=str(project),
                output_directory=str(output),
                severity_threshold="SOMEWHAT-BAD",
            )

        assert "Invalid severity threshold" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 3. End to end: what the project declared is what the client is told
# ---------------------------------------------------------------------------


class TestTheProjectThresholdReachesTheProgressPayload:
    """The assertion the substituting implementation failed.

    ``get_scan_progress`` echoes ``entry.severity_threshold`` straight back to the
    caller, so this is the observable a client actually sees. Going through the
    real tool and the real registry rather than asserting on the argument means a
    future implementation that substitutes somewhere else still fails.
    """

    @pytest.mark.asyncio
    async def test_a_project_declaring_all_is_reported_as_all(
        self, tmp_path, isolated_registry, executions
    ):
        from automated_security_helper.cli.mcp_tools import mcp_get_scan_progress

        root = tmp_path / "work"
        _project(
            root,
            "api",
            config=f"global_settings:\n  severity_threshold: {STRICTEST_THRESHOLD}\n",
        )
        workspace = _workspace(root, ["api"])

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is True, response.get("error")
        # Guard the premise: resolution really did read the project's config. If
        # it had not, the plan would carry the default and this test would pass
        # while measuring nothing.
        plan, _settings = executions[0]
        assert plan.projects[0].gate_threshold == STRICTEST_THRESHOLD

        scan_id = response["scan_ids"]["api"]
        progress = await mcp_get_scan_progress(scan_id=scan_id)

        assert progress["severity_threshold"] == STRICTEST_THRESHOLD, (
            "the threshold reported to the client is not the one the project "
            f"declared: got {progress['severity_threshold']!r}"
        )

    @pytest.mark.asyncio
    async def test_a_project_with_no_config_is_reported_at_the_ash_default(
        self, tmp_path, isolated_registry, executions
    ):
        """Positive control: the value tracks the project, it is not hardcoded.

        Without this, an implementation that reported ``ALL`` unconditionally
        would satisfy the test above.
        """
        from automated_security_helper.cli.mcp_tools import mcp_get_scan_progress

        root = tmp_path / "work"
        _project(root, "api")
        workspace = _workspace(root, ["api"])

        response = await _tool("mcp_scan_workspace")(workspace_file=str(workspace))

        assert response["success"] is True, response.get("error")
        plan, _settings = executions[0]
        declared = plan.projects[0].gate_threshold
        assert declared != STRICTEST_THRESHOLD, (
            "the no-config project resolved to the same threshold as the "
            "configured one, so this control distinguishes nothing"
        )

        scan_id = response["scan_ids"]["api"]
        progress = await mcp_get_scan_progress(scan_id=scan_id)

        assert progress["severity_threshold"] == declared
