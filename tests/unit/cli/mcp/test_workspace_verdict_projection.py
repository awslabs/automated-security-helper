#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP workspace response must carry every field the model declares.

Why a key-set assertion rather than a list of fields
---------------------------------------------------
``_project_verdicts`` hand-builds a closed dictionary from a
``WorkspaceProjectResult``. A hand-maintained projection of a declared model is a
standing invitation to add a field to the model and forget the projection, and
that is what happened: ``scanners``, ``incomplete_scanners``, ``scan_incomplete``
and ``ceiling_unreachable_findings`` were all declared on the model and absent
from the response, so an MCP client could not learn that a project's scanners did
not run. Nothing else under ``cli/mcp/`` mentioned either completeness field.

Asserting the key *set* against ``model_fields`` is the class fix. A test that
listed the four missing names would pass again the next time a field is added.
The exclusion list is deliberately empty -- every declared field is projected --
so a future field has to be either projected or explicitly excused here, and the
excusing is visible in the diff.

The envelope carries the aggregate too
--------------------------------------
A client that reads only the top level of the response, which is the common shape
for a gate, sees ``exit_code`` and no reason for it. ``scan_incomplete`` is
surfaced there as well so that reason is available without walking ``projects``.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    WorkspaceResults,
)

MODULE_UNDER_TEST = "automated_security_helper.cli.mcp.workspace"

#: Declared fields deliberately kept out of the MCP response. Empty on purpose:
#: see the module docstring. An entry here needs a comment saying why a client
#: must not see that field.
PROJECTED_EXCLUSIONS: frozenset[str] = frozenset()

#: The one response key that is not a model field. It joins a verdict to the
#: registry entry the client was handed, which the model knows nothing about.
NON_MODEL_KEYS = frozenset({"scan_id"})


def _module():
    return importlib.import_module(MODULE_UNDER_TEST)


def _outcome(key: str, **overrides: Any) -> WorkspaceProjectResult:
    """One completed project, with every optional field given a distinct value.

    Distinct rather than defaulted so that a projection which reads the wrong
    attribute is visible as a wrong value and not merely as a present key.
    """
    fields: Dict[str, Any] = {
        "project": key,
        "relative_path": key,
        "display_label": key.upper(),
        "status": ProjectRunStatus.COMPLETED,
        "severity_threshold": "MEDIUM",
        "finding_count": 3,
        "actionable_finding_count": 1,
        "exceeds_threshold": True,
        "duration_seconds": 1.5,
        "output_path": f"projects/{key}",
        "sarif_run_index": 0,
        "scanners": {"bandit": "PASSED", "cfn-nag": "MISSING"},
        "incomplete_scanners": ["cfn-nag"],
        "no_scanner_ran": False,
        "scan_incomplete": True,
        "ceiling_unreachable_findings": {"grype": 2},
    }
    fields.update(overrides)
    return WorkspaceProjectResult(**fields)


def _payload(*outcomes: WorkspaceProjectResult) -> WorkspaceResults:
    return WorkspaceResults(
        workspace_file="/ws/dev.code-workspace",
        workspace_root="/ws",
        exit_code=int(WorkspaceExitCode.INTERNAL_ERROR),
        projects=list(outcomes),
    )


class TestTheProjectionCarriesEveryDeclaredField:
    def test_the_response_key_set_is_the_model_field_set(self):
        """The class fix. A missing projection is a missing key, and this sees it."""
        payload = _payload(_outcome("api"))

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        assert len(verdicts) == 1
        expected = set(WorkspaceProjectResult.model_fields) - PROJECTED_EXCLUSIONS
        assert set(verdicts[0]) == expected | NON_MODEL_KEYS

    @pytest.mark.parametrize(
        "field,expected",
        [
            ("scanners", {"bandit": "PASSED", "cfn-nag": "MISSING"}),
            ("incomplete_scanners", ["cfn-nag"]),
            ("scan_incomplete", True),
            ("no_scanner_ran", False),
            ("ceiling_unreachable_findings", {"grype": 2}),
        ],
    )
    def test_the_completeness_fields_carry_their_values(self, field, expected):
        """Presence is not enough: a projection can read the wrong attribute.

        These five are the ones that were dropped, so they are asserted on their
        values rather than left to the key-set test above.
        """
        payload = _payload(_outcome("api"))

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        assert verdicts[0][field] == expected

    def test_a_projected_enum_is_a_plain_value(self):
        """The response is serialized to a client, so an enum member would leak.

        ``status`` already went through ``_enum_value``; the assertion is here so
        that adding a field of enum type cannot quietly ship a member.
        """
        payload = _payload(_outcome("api"))

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        json.dumps(verdicts)
        assert verdicts[0]["status"] == ProjectRunStatus.COMPLETED.value


class TestTheEnvelopeSurfacesTheAggregate:
    """A client reading only the top level still learns the scan was incomplete."""

    @pytest.fixture(autouse=True)
    def _clear_policy_env(self, monkeypatch):
        monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
        monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)

    @staticmethod
    def _workspace(root: Path, folders: List[str]) -> Path:
        for entry in folders:
            (root / entry).mkdir(parents=True, exist_ok=True)
        path = root / "dev.code-workspace"
        path.write_text(
            json.dumps({"folders": [{"path": entry} for entry in folders]}),
            encoding="utf-8",
        )
        return path

    def _stub_execution(self, monkeypatch, tmp_path, payload: WorkspaceResults):
        from automated_security_helper.workspace.execution import WorkspaceRunResult

        results_path = tmp_path / "out" / "ash_aggregated_results.json"
        results_path.parent.mkdir(parents=True, exist_ok=True)
        results_path.write_text("{}", encoding="utf-8")

        def _execute(plan, settings, *args, **kwargs):
            return WorkspaceRunResult(
                results_path=results_path,
                exit_code=payload.exit_code,
                payload=payload,
            )

        monkeypatch.setattr(_module(), "execute_workspace", _execute)

    @pytest.mark.asyncio
    async def test_an_incomplete_project_sets_the_top_level_flag(
        self, tmp_path, monkeypatch
    ):
        workspace = self._workspace(tmp_path, ["api", "web"])
        self._stub_execution(
            monkeypatch,
            tmp_path,
            _payload(
                _outcome("api", scan_incomplete=False, incomplete_scanners=[]),
                _outcome("web"),
            ),
        )

        response = await _module().mcp_scan_workspace(
            workspace_file=str(workspace),
            output_dir=str(tmp_path / "out"),
        )

        assert response["success"] is True
        assert response["scan_incomplete"] is True

    @pytest.mark.asyncio
    async def test_a_complete_workspace_does_not_set_the_flag(
        self, tmp_path, monkeypatch
    ):
        """The control. Without it, a hardcoded True satisfies the test above."""
        workspace = self._workspace(tmp_path, ["api"])
        self._stub_execution(
            monkeypatch,
            tmp_path,
            _payload(_outcome("api", scan_incomplete=False, incomplete_scanners=[])),
        )

        response = await _module().mcp_scan_workspace(
            workspace_file=str(workspace),
            output_dir=str(tmp_path / "out"),
        )

        assert response["success"] is True
        assert response["scan_incomplete"] is False

    @pytest.mark.asyncio
    async def test_the_ceiling_disclosure_reaches_the_envelope(
        self, tmp_path, monkeypatch
    ):
        """Why it is echoed: a client reading only the envelope cannot see a
        per-project mapping, and a tightened ceiling that could not reach some
        findings changes what the verdict means."""
        workspace = self._workspace(tmp_path, ["api"])
        self._stub_execution(
            monkeypatch,
            tmp_path,
            _payload(_outcome("api", ceiling_unreachable_findings={"grype": 2})),
        )

        response = await _module().mcp_scan_workspace(
            workspace_file=str(workspace),
            output_dir=str(tmp_path / "out"),
        )

        assert response["ceiling_unreachable_findings"] == {"grype": 2}
