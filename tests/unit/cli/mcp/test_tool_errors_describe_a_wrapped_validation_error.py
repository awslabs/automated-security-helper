# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool's answer describes a validation error inside another error too.

The results readers (explain_finding, diff_scan_results, suggest_suppression)
answer any error reading a results file with its description. An error raised
from a pydantic ValidationError, whose message quotes it (``f"... {error}"``),
carries pydantic's text, and that text quotes each refused input. The answer
describes the ValidationError where the message quotes it
(utils/error_text.error_text), as it does a ValidationError on its own: the
model, the field and the problem, never the input.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import BaseModel

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ReportMetadata,
)

pytestmark = pytest.mark.unit

TOKEN = "tok-0123456789abcdef"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


class _ResultsThatQuoteInputs(BaseModel):
    """A results-shaped model whose validation errors quote the input.

    AshAggregatedResults is read from results files and hides inputs in its own
    errors (``hide_input_in_errors``), so an error built from it would carry no
    token to strip, and the tools' description of the wrapped error would be
    untested. This model keeps pydantic's default, so the control below holds.
    """

    metadata: ReportMetadata


def _wrapped() -> RuntimeError:
    """An error raised from a ValidationError, quoting it."""
    try:
        _ResultsThatQuoteInputs.model_validate({"metadata": TOKEN})
    except ValueError as refused:
        try:
            raise RuntimeError(f"could not read the results: {refused}") from refused
        except RuntimeError as error:
            return error
    raise AssertionError("the model accepted the input")


def test_the_wrapped_error_quotes_the_input():
    """Control: the error's own text carries the token."""
    assert TOKEN in str(_wrapped())


@pytest.fixture
def results_file(tmp_path: Path) -> Path:
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(json.dumps(AshAggregatedResults().model_dump(mode="json")))
    return path


def _assert_described(answer: dict) -> None:
    assert answer["success"] is False, answer
    assert TOKEN not in json.dumps(answer, default=str), answer
    assert "could not read the results" in answer["error"], answer
    assert "validation error" in answer["error"], answer
    assert "metadata" in answer["error"], answer


def test_explain_finding(results_file: Path):
    with patch.object(
        mcp_tools, "_load_flat_vulns_for_explain", side_effect=_wrapped()
    ):
        answer = mcp_tools.mcp_explain_finding(
            finding_id="any", results_path=str(results_file.parent)
        )
    _assert_described(answer)


def test_diff_scan_results(results_file: Path):
    with patch.object(AshAggregatedResults, "from_json", side_effect=_wrapped()):
        answer = mcp_tools.mcp_diff_scan_results(
            before_path=str(results_file), after_path=str(results_file)
        )
    _assert_described(answer)


def test_suggest_suppression(results_file: Path):
    with patch.object(AshAggregatedResults, "from_json", side_effect=_wrapped()):
        answer = mcp_tools.mcp_suggest_suppression(
            finding_id="any", results_path=str(results_file)
        )
    _assert_described(answer)
