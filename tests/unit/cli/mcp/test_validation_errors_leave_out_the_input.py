# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool that reports a validation error does not quote the value that failed.

str() of a pydantic ValidationError quotes each failing value
(``input_value='...'``), and ``errors()`` holds each value under ``input``. The
results readers (explain_finding, diff_scan_results, suggest_suppression) parse
ash_aggregated_results.json, whose findings carry scanner output, the secret a
finding is about included, so an answer built from either would send a piece of a
results file that failed to parse to the client. Each error is
described by where it is and what is wrong (``errors(include_input=False)``),
never by the value.

Every case here puts a 20-character token in a field that fails validation and
checks the tool's whole answer for it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import (
    mcp_diff_scan_results,
    mcp_explain_finding,
    mcp_select_profile,
    mcp_suggest_suppression,
)

pytestmark = pytest.mark.unit

TOKEN = "tok-0123456789abcdef"
assert len(TOKEN) == 20


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def results_file(tmp_path: Path) -> Path:
    """A results file whose metadata is the token, where an object belongs."""
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(json.dumps({"metadata": TOKEN}), encoding="utf-8")
    return path


def _assert_described_without_the_token(answer: dict) -> None:
    assert answer["success"] is False, answer
    text = json.dumps(answer, default=str)
    assert TOKEN not in text, answer
    # Still says what failed and where.
    assert "metadata" in answer["error"], answer
    assert "validation error" in answer["error"], answer


def test_explain_finding(results_file: Path) -> None:
    answer = mcp_explain_finding(
        finding_id="any", results_path=str(results_file.parent)
    )
    _assert_described_without_the_token(answer)


def test_diff_scan_results(results_file: Path) -> None:
    answer = mcp_diff_scan_results(
        before_path=str(results_file), after_path=str(results_file)
    )
    _assert_described_without_the_token(answer)


def test_suggest_suppression(results_file: Path) -> None:
    answer = mcp_suggest_suppression(finding_id="any", results_path=str(results_file))
    _assert_described_without_the_token(answer)


def test_select_profile_override_yaml(tmp_path: Path) -> None:
    profile = tmp_path / "op.yaml"
    profile.write_text(
        yaml.safe_dump({"project_name": "operator", "fail_on_findings": True}),
        encoding="utf-8",
    )
    set_profile_registry(register_profiles([f"op={profile}"]))

    answer = mcp_select_profile(
        "op", override_yaml=yaml.safe_dump({"fail_on_findings": TOKEN})
    )

    assert answer["success"] is False, answer
    assert TOKEN not in json.dumps(answer, default=str), answer
    assert "fail_on_findings" in answer["error"], answer
