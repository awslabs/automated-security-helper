# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``select_profile`` refuses an invalid change without quoting the value.

An MCP client changes a profile's config with ``override_yaml`` or
``patch_ops``, and a change the config model refuses comes back as the tool's
error. Both routes put pydantic's ``errors()`` in that error, and each entry
of ``errors()`` holds the refused input, whether or not the model hides its
inputs in its own text. The response goes to the client, and from there to a
model's context or a log. Each route is driven with a canary the model
refuses, and the canary must not be in the response.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile
from tests.unit.cli.mcp.test_select_profile_override_gate import (
    _install,
    _profile,
    _restated,
)

CANARY = "ash-canary-7f3e"


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """As in test_select_profile_override_gate.py."""
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    clear_profile_registry()
    clear_session_state()
    yield
    clear_profile_registry()
    clear_session_state()


@pytest.mark.parametrize("route", ["override_yaml", "patch_ops"])
def test_a_refused_value_is_not_in_the_response(tmp_path: Path, route):
    document = _profile(allowed_paths=["/**"], denied_paths=[])
    _install(tmp_path, document)
    if route == "override_yaml":
        change = {"override_yaml": _restated(document, fail_on_findings=CANARY)}
    else:
        change = {
            "patch_ops": [
                {"op": "replace", "path": "/fail_on_findings", "value": CANARY}
            ]
        }

    response = mcp_select_profile("op", session_id="s1", **change)

    shown = json.dumps(response)
    # The control: the change was refused by the model, naming the field.
    assert response.get("success") is False, response
    assert "fail_on_findings" in shown, shown
    assert CANARY not in shown, shown
