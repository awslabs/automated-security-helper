# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A patch op the configuration cannot take is refused without its values.

jsonpatch's own text for an op it cannot apply quotes the configuration: a
``test`` op that guesses wrong gets the current value ("<value> is not equal
to tested value ..."), and one whose path names a missing member gets the
whole mapping it looked in ("member 'x' not found in {...}"). The MCP tools
return the refusal to the client, and the configuration's values can be ones
its files read from the environment, so a ``test`` op would tell a client more
than whether its guess was right. The refusal names the op and the kind of
failure instead.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_patch,
)
from automated_security_helper.models.core import IgnorePathWithReason

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"


def _shows_the_value(text: str) -> bool:
    return CANARY in text or CANARY[:12] in text


def _base() -> AshConfig:
    base = AshConfig(project_name=CANARY)
    base.global_settings.ignore_paths = [
        IgnorePathWithReason(path=f"{CANARY}/**", reason="vendored")
    ]
    return base


ALLOWLIST = RuntimeOverridesConfig(
    enabled=True,
    allowed_paths=["/project_name", "/global_settings/**"],
    denied_paths=[],
)


@pytest.mark.parametrize(
    ("op", "kind"),
    [
        pytest.param(
            {"op": "test", "path": "/project_name", "value": "guess"},
            "JsonPatchTestFailed",
            id="test-op-that-guesses-wrong",
        ),
        pytest.param(
            {"op": "test", "path": "/global_settings/no_such_key", "value": 1},
            "JsonPatchTestFailed",
            id="test-op-on-a-missing-member",
        ),
        pytest.param(
            {"op": "replace", "path": "/global_settings/no_such_key", "value": 1},
            "JsonPatchConflict",
            id="replace-of-a-missing-member",
        ),
    ],
)
def test_the_refusal_names_the_op_not_the_values(op, kind):
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(_base(), [op], allowlist=ALLOWLIST)
    text = str(refused.value)
    # Booleans, so a failure does not print the value it found.
    shown = _shows_the_value(text)
    assert not shown, "the refusal quotes the configuration's value"
    # Not chained either: a traceback of the refusal would show jsonpatch's text.
    raised = refused.value
    unchained = raised.__cause__ is None and raised.__context__ is None
    assert unchained, "the refusal carries jsonpatch's error with it"
    # The control: the refusal says which op failed, and how.
    named = raised.op == op and op["path"] in text and kind in text
    assert named, "the refusal does not name the op and the kind of failure"


def test_ops_before_the_one_refused_do_not_apply():
    """All or nothing: the base is unchanged by a refused patch."""
    base = _base()
    ops = [
        {"op": "replace", "path": "/project_name", "value": "renamed"},
        {"op": "test", "path": "/project_name", "value": "guess"},
    ]
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(base, ops, allowlist=ALLOWLIST)
    unchanged = base.project_name == CANARY
    assert unchanged, "the base was changed"
    assert refused.value.op == ops[1]


@pytest.mark.parametrize("op_shape", ["value", "path"])
def test_select_profile_s_denial_reads_the_same_for_a_right_and_a_wrong_guess(
    tmp_path, monkeypatch, op_shape
):
    """A denied op is named by its op and path as the client wrote them, and
    never by its value: one that equals a value the profile read from the
    environment reads the same as one that does not."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(
        "project_name: ${ASH_PROBE_VALUE}\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /project_name\n"
        "      denied_paths: []\n",
        encoding="utf-8",
    )
    other = "ash-canary-0000-9876543210"
    answers = {}
    for guess in (CANARY, other):
        op = (
            {"op": "replace", "path": "/output_dir", "value": guess}
            if op_shape == "value"
            else {"op": "remove", "path": f"/scanners/{guess}"}
        )
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()
        profile_registry.set_profile_registry(
            profile_registry.register_profiles([f"op={profile}"])
        )
        try:
            result = mcp_select_profile("op", patch_ops=[op], session_id="session-a")
        finally:
            profile_registry.clear_profile_registry()
            profile_registry.clear_all_session_state()
        refused = result["success"] is False
        assert refused, "the control: the op is denied"
        # A guess in the op's path is quoted as written, and one in its value is
        # not quoted at all, for either guess. A boolean, so a failure does not
        # print the value.
        quoted = guess in result.get("error", "")
        assert quoted == (op_shape == "path"), (
            "the denial quotes the op's value, or not its path, as written"
        )
        answers[guess] = json.dumps(result, sort_keys=True).replace(guess, "GUESS")
    # A boolean, so a failure does not print the value.
    same = answers[CANARY] == answers[other]
    assert same, "the denial tells a right guess from a wrong one"


def test_select_profile_s_response_holds_no_value(tmp_path, monkeypatch):
    """The MCP tool, as a client calls it: a profile that reads project_name
    from the environment and allows /project_name, and a test op that guesses."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(
        "project_name: ${ASH_PROBE_VALUE}\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /project_name\n"
        "      denied_paths: []\n",
        encoding="utf-8",
    )
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    try:
        result = mcp_select_profile(
            "op",
            patch_ops=[{"op": "test", "path": "/project_name", "value": "guess"}],
            session_id="session-a",
        )
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()
    refused = result["success"] is False
    assert refused, "the guess was not refused"
    shown = _shows_the_value(str(result))
    assert not shown, "the response quotes the value"
    named = "JsonPatchTestFailed" in result["error"]
    assert named, "the refusal does not say a test op failed"
