# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan refusal answers a structured response whatever its context holds.

``mcp_scan_directory``'s MCPResourceError arm redacts the error's context
before building the response. A context shape the redactor cannot rebuild (a
namedtuple), a redaction value that happens to match inside the ``suggestions``
key, or the redactor itself failing must each still answer the structured
refusal dict: the arm is the error handler, so an escape from it turns a
refusal into a raw exception at the transport.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, NamedTuple, Tuple

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"
SECRET = "/opt/qz4b/config"


class _Spec(NamedTuple):
    path: str
    port: int


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    roots = tmp_path / "roots"
    roots.mkdir()
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(roots))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    target = roots / "project"
    target.mkdir()
    return target


class _RefusingRegistry:
    """A registry whose registration refuses with the given error."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    def register_scan(self, **kwargs: Any) -> str:
        raise self._error


def _scan_refused_with(
    monkeypatch: pytest.MonkeyPatch,
    project: Path,
    context: Dict[Any, Any],
    values: Tuple[str, ...] = (),
) -> Dict[str, Any]:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.exceptions import (
        MCPResourceError,
    )

    error = MCPResourceError("the registry refused this scan", context=context)
    monkeypatch.setattr(
        mcp_tools, "get_scan_registry", lambda: _RefusingRegistry(error)
    )
    monkeypatch.setattr(
        mcp_tools, "_operator_environment_values", lambda limits: values
    )
    return asyncio.run(
        mcp_tools.mcp_scan_directory(directory_path=str(project), session_id=SESSION)
    )


def test_a_namedtuple_in_the_context_still_answers_a_refusal(
    monkeypatch: pytest.MonkeyPatch, project: Path
) -> None:
    response = _scan_refused_with(
        monkeypatch,
        project,
        {"error_category": "validation_error", "spec": _Spec(SECRET, 1)},
        values=(SECRET,),
    )

    assert response["success"] is False
    assert response["error_type"] == "MCPResourceError"
    assert response["exit_code"] == 1
    assert "qz4b" not in json.dumps(response)


def test_the_producers_suggestions_reach_the_response_redacted(
    monkeypatch: pytest.MonkeyPatch, project: Path
) -> None:
    # "ggestion" is replaced anywhere it appears, the "suggestions" KEY
    # included; the response must still carry the producer's suggestions,
    # never the generic fallback, and no read value anywhere.
    response = _scan_refused_with(
        monkeypatch,
        project,
        {
            "error_category": "validation_error",
            "suggestions": ["Remove the stale lock"],
            "detail": f"could not read {SECRET}",
        },
        values=("ggestion", "r_ca", SECRET),
    )

    assert response["success"] is False
    assert response["suggestions"] == ["Remove the stale lock"]
    assert response["error_category"] == "validation_error"
    assert "qz4b" not in json.dumps(response)


def test_a_redactor_failure_still_answers_a_structured_refusal(
    monkeypatch: pytest.MonkeyPatch, project: Path
) -> None:
    from automated_security_helper.cli import mcp_tools

    def broken(value: Any, values: Tuple[str, ...]) -> Any:
        raise RuntimeError("the redactor broke")

    monkeypatch.setattr(mcp_tools, "_context_without_values", broken)
    response = _scan_refused_with(
        monkeypatch,
        project,
        {"error_category": "validation_error", "detail": f"read {SECRET}"},
        values=(SECRET,),
    )

    assert response["success"] is False
    assert response["error_type"] == "MCPResourceError"
    assert response["exit_code"] == 1
    # The context could not be redacted, so the response does not carry it.
    assert "qz4b" not in json.dumps(response)
