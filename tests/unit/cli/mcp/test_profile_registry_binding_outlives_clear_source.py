# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A profile binding is the source of truth; its file is written again when gone.

``clear_source`` removes the whole session workspace, the profile
``select_profile`` materialized in its ``config/`` directory included, and
leaves the binding recorded. ``resolve_session_config_path`` then answered None
for the gone file, so the session's next scan ran under in-tree discovery (or
``ASH_CONFIG``) and reported success, while the bound profile's client rules
stayed in force. The resolver now writes the bound profile again from the
recorded binding, both the registered copy and a client-patched copy, and
refuses the scan when it cannot.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    ProfileRegistryError,
    clear_all_session_state,
    clear_profile_registry,
    get_session_state,
    register_profiles,
    resolve_session_config_path,
    resolve_session_trusted_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp.source_delivery import clear_source
from automated_security_helper.cli.mcp_tools import mcp_select_profile

pytestmark = pytest.mark.unit

SESSION = "bound-then-cleared"
REGISTERED_NAME = "operator-registered"
PATCHED_NAME = "client-patched"
PATCH_OPS = [{"op": "replace", "path": "/project_name", "value": PATCHED_NAME}]


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    document: Dict[str, Any] = {
        "project_name": REGISTERED_NAME,
        "global_settings": {
            "mcp": {
                "runtime_overrides": {"enabled": True, "allowed_paths": ["/**"]},
            },
        },
    }
    profile = tmp_path / "op.yaml"
    profile.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"op={profile}"]))
    yield
    clear_profile_registry()
    clear_all_session_state()


def _bind(patched: bool) -> None:
    result = mcp_select_profile(
        "op", patch_ops=PATCH_OPS if patched else None, session_id=SESSION
    )
    assert result["success"] is True, result


def _project_name(path: str) -> str:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))["project_name"]


def test_the_registered_profile_is_written_again_after_a_clear(tmp_path) -> None:
    _bind(patched=False)
    before = resolve_session_config_path(SESSION)
    assert before is not None and Path(before).is_file()

    clear_source(SESSION)
    assert not Path(before).exists(), "the clear left the materialized profile"

    after = resolve_session_config_path(SESSION)

    assert after is not None, "a bound session resolved no config after the clear"
    assert Path(after).is_file()
    assert _project_name(after) == REGISTERED_NAME
    assert resolve_session_trusted_config_path(SESSION) == after
    assert get_session_state(SESSION).config_path == after


def test_a_patched_binding_writes_both_copies_again(tmp_path) -> None:
    _bind(patched=True)
    clear_source(SESSION)

    config_path = resolve_session_config_path(SESSION)
    trusted = resolve_session_trusted_config_path(SESSION)

    assert config_path is not None and trusted is not None
    assert config_path != trusted
    assert _project_name(config_path) == PATCHED_NAME
    assert _project_name(trusted) == REGISTERED_NAME
    assert Path(config_path).parent.name == "client-config"
    assert Path(trusted).parent.name == "config"


def test_a_binding_whose_profile_is_gone_refuses_rather_than_unbinding(
    tmp_path,
) -> None:
    _bind(patched=False)
    clear_source(SESSION)
    clear_profile_registry()

    with pytest.raises(ProfileRegistryError) as refused:
        resolve_session_config_path(SESSION)

    assert "select_profile" in str(refused.value)
    # Refused, not unbound: asked again, the session is still bound to the
    # profile that is gone and the same refusal comes back. A refusal that also
    # dropped the binding would answer None here, and the scan would run under
    # in-tree discovery, the shape this file exists to refuse.
    with pytest.raises(ProfileRegistryError):
        resolve_session_config_path(SESSION)


def test_an_unbound_session_still_resolves_nothing() -> None:
    assert resolve_session_config_path("never-bound") is None
    assert resolve_session_trusted_config_path("never-bound") is None
