# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A patch op that is not a JSON-Patch op is refused, not raised.

Splitting an op's ``path`` as a string before any rule checks its type would let a
path that is a number, a list or a mapping escape ``select_profile`` as a
TypeError, an AttributeError or a KeyError, where a client gets a refusal for
every other malformed op; a path that is null would be refused by whichever rule
first read it as the root, and an op that is not a mapping, or an ``op`` member
that is not a string, would escape the same way. Each is refused with the
denial jsonpatch gives such an op, ``patch apply failed: InvalidJsonPatch``,
before any rule reads it, and nothing is applied.
"""

from __future__ import annotations

import pytest

PROFILE = (
    "project_name: demo\n"
    "global_settings:\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /**\n"
    "      denied_paths: []\n"
)

DENIAL = "denied by rule: patch apply failed: InvalidJsonPatch"


@pytest.fixture
def select(tmp_path, monkeypatch):
    """select_profile with ``patch_ops`` on a profile that allows every path:
    the response, and the config path the session was bound to, or None."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(PROFILE, encoding="utf-8")

    def _select(patch_ops):
        profile_registry.clear_profile_registry()
        profile_registry.clear_session_state()
        try:
            profile_registry.set_profile_registry(
                profile_registry.register_profiles([f"op={profile}"])
            )
            result = mcp_select_profile(
                "op", patch_ops=patch_ops, session_id="session-a"
            )
            bound = profile_registry.resolve_session_config_path("session-a")
        finally:
            profile_registry.clear_profile_registry()
            profile_registry.clear_session_state()
        return result, bound

    return _select


def _refused(select, patch_ops) -> bool:
    result, bound = select(patch_ops)
    return result["success"] is False and DENIAL in result["error"] and bound is None


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(5, id="a-number"),
        pytest.param(["a"], id="a-list"),
        pytest.param({"a": 1}, id="a-mapping"),
        pytest.param(None, id="null"),
    ],
)
@pytest.mark.parametrize("op", ["remove", "test"])
def test_a_path_that_is_not_a_string_is_refused(select, op, path):
    patch = {"op": op, "path": path}
    if op == "test":
        patch["value"] = "x"
    refused = _refused(select, [patch])
    assert refused, "the op was not refused with the malformed-op denial"


@pytest.mark.parametrize(
    "patch",
    [
        pytest.param("remove /project_name", id="an-op-that-is-text"),
        pytest.param(["remove", "/project_name"], id="an-op-that-is-a-list"),
        pytest.param({"op": ["remove"], "path": "/project_name"}, id="an-op-name-list"),
    ],
)
def test_an_op_that_is_not_a_json_patch_op_is_refused(select, patch):
    refused = _refused(select, [patch])
    assert refused, "the op was not refused with the malformed-op denial"


def test_a_well_formed_op_after_a_malformed_one_is_not_applied(select):
    """The whole patch is refused: the well-formed op before it is not applied
    either."""
    refused = _refused(
        select,
        [
            {"op": "replace", "path": "/project_name", "value": "client"},
            {"op": "remove", "path": 5},
        ],
    )
    assert refused, "the patch was not refused whole"


@pytest.mark.parametrize(
    "patch",
    [
        pytest.param({"op": "ADD", "path": "/project_name", "value": "x"}, id="ADD"),
        pytest.param(
            {"op": "Replace", "path": "/project_name", "value": "x"}, id="Replace"
        ),
        pytest.param({"op": "TEST", "path": "/project_name", "value": "x"}, id="TEST"),
        pytest.param({"op": "MOVE", "from": "/project_name", "path": "/x"}, id="MOVE"),
        pytest.param(
            {"op": "merge", "path": "/project_name", "value": "x"}, id="merge"
        ),
        pytest.param({"op": "", "path": "/project_name"}, id="empty"),
        pytest.param({"path": "/project_name", "value": "x"}, id="no-op-member"),
    ],
)
def test_an_op_name_outside_json_patch_s_six_is_refused_before_any_rule(
    select, monkeypatch, patch
):
    """RFC 6902 has six ops, add, remove, replace, move, copy and test, spelled
    in lower case. Any other name, or none, is refused with the malformed-op
    denial before any rule reads the op, as jsonpatch would refuse it."""
    from automated_security_helper.config import runtime_patch

    read = []
    real = runtime_patch._check_op_paths

    def reading(op, **kwargs):
        read.append(op)
        return real(op, **kwargs)

    monkeypatch.setattr(runtime_patch, "_check_op_paths", reading)
    refused = _refused(select, [patch])
    assert refused, "the op was not refused with the malformed-op denial"
    assert read == [], "a rule read the op before it was refused"


def test_a_well_formed_op_is_applied(select):
    """The control: the same profile takes a well-formed op."""
    result, bound = select(
        [{"op": "replace", "path": "/project_name", "value": "client"}]
    )
    applied = result["success"] is True and bound is not None
    assert applied, "a well-formed op was refused"
