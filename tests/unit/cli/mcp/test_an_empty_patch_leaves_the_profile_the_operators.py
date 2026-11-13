# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session profile bound with an empty ``patch_ops`` is still the operator's.

``select_profile`` writes a profile a client changed (a non-empty ``patch_ops``, or
any ``override_yaml``) to the session's ``client-config/``, which counts as the
client's. An empty ``patch_ops`` changes nothing, so the binding names the
registered profile's own copy in ``config/``.

``session_config_was_patched`` answered ``patch_ops is not None`` for a binding
that names a file outside ``client-config/``, so that operator copy was reported as
patched. Everything that asks it (``path_trust.operator_reason``, the
delivered-file denials) then treated the operator's own file as a client's. The
predicate now reads a non-empty ``patch_ops``, which is the rule ``select_profile``
writes the two copies by.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.cli.mcp import profile_registry as _registry
from automated_security_helper.cli.mcp.profile_registry import (
    bind_session_config,
    clear_all_session_state,
    clear_profile_registry,
    get_profile_registry,
    get_session_state,
    register_profiles,
    session_config_was_patched,
    set_profile_registry,
)
from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
from automated_security_helper.cli.mcp_tools import mcp_select_profile
from automated_security_helper.config.ash_config import (
    AshConfig,
    AshMcpConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.path_trust import operator_reason
from automated_security_helper.config.sandbox_grants import in_any_checkout

pytestmark = pytest.mark.unit

SESSION = "empty-patch"
OP = {"op": "replace", "path": "/project_name", "value": "client"}


@pytest.fixture(autouse=True)
def _isolate_state() -> None:
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


def _bound_profile(tmp_path: Path, monkeypatch, **binding) -> Path:
    """A session's ``config/ash.yaml`` in a real workspace root, bound with ``binding``.

    The file sits where ``select_profile`` writes the registered profile, so only the
    recorded binding can make ``session_config_was_patched`` answer True for it.
    """
    root = tmp_path / "workspace-root"
    profile = root / SESSION / "config" / "ash.yaml"
    profile.parent.mkdir(parents=True)
    profile.write_text("project_name: registered\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    assert not config_is_client_supplied(profile)
    bind_session_config(
        SESSION,
        config=AshConfig(project_name="registered"),
        profile_name="p",
        config_path=profile.as_posix(),
        trusted_config_path=profile.as_posix(),
        **binding,
    )
    return profile


@pytest.mark.parametrize(
    ("binding", "patched"),
    [
        pytest.param({}, False, id="no-patch"),
        pytest.param({"patch_ops": []}, False, id="empty-patch"),
        pytest.param({"patch_ops": [OP]}, True, id="one-op"),
        pytest.param({"override_yaml": "project_name: client\n"}, True, id="override"),
    ],
)
def test_only_a_binding_with_a_client_change_is_patched(
    tmp_path: Path, monkeypatch, binding, patched
) -> None:
    profile = _bound_profile(tmp_path, monkeypatch, **binding)

    assert session_config_was_patched(profile) is patched


@pytest.mark.parametrize(
    ("binding", "patched"),
    [
        pytest.param({}, False, id="no-patch"),
        pytest.param({"patch_ops": []}, False, id="empty-patch"),
        pytest.param({"patch_ops": [OP]}, True, id="one-op"),
    ],
)
def test_the_operator_tier_judges_the_profile_by_the_same_rule(
    tmp_path: Path, monkeypatch, binding, patched
) -> None:
    """``operator_reason`` is what ``resolve_config._operator_wrote`` asks of each
    config file before the tool paths it names count as the operator's."""
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    scan_root = tmp_path / "repo"
    scan_root.mkdir()
    profile = _bound_profile(tmp_path, monkeypatch, **binding)

    reason = operator_reason(profile, scan_root)

    if patched:
        assert reason is not None
        assert "patch changed" in reason
    else:
        assert reason is None


@pytest.mark.parametrize(
    ("binding", "changed"),
    [
        pytest.param({}, False, id="no-patch"),
        pytest.param({"patch_ops": []}, False, id="empty-patch"),
        pytest.param({"patch_ops": [OP]}, True, id="one-op"),
        pytest.param({"override_yaml": "project_name: client\n"}, True, id="override"),
        pytest.param({"override_yaml": ""}, True, id="empty-override"),
    ],
)
def test_a_binding_says_whether_a_client_changed_the_profile(
    tmp_path: Path, monkeypatch, binding, changed
) -> None:
    """``client_changed`` is the one reading of a binding every reader goes by: a
    non-empty ``patch_ops``, or any ``override_yaml``, an empty one included."""
    profile = _bound_profile(tmp_path, monkeypatch, **binding)

    state = get_session_state(SESSION)
    assert state is not None
    assert state.client_changed is changed
    assert session_config_was_patched(profile) is state.client_changed


def _install_profile(tmp_path: Path) -> None:
    """Register ``default`` with a runtime allowlist that permits ``/project_name``."""
    config = AshConfig(
        project_name="registered",
        global_settings={
            "mcp": AshMcpConfig(
                runtime_overrides=RuntimeOverridesConfig(
                    enabled=True,
                    allowed_paths=["/project_name"],
                    denied_paths=[],
                )
            )
        },
    )
    file = tmp_path / "default.yaml"
    file.write_text(yaml.safe_dump(config.model_dump(by_alias=True)), encoding="utf-8")
    set_profile_registry(register_profiles([f"default={file}"]))
    assert "default" in get_profile_registry()


def _keep_select_profile_off_the_host(tmp_path: Path, monkeypatch) -> None:
    """The session workspace root is under ``tmp_path``, and no operator config or
    allowed config root from the host's environment reaches ``select_profile``."""
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspace-root"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def test_select_profile_with_no_ops_binds_the_operators_copy(
    tmp_path: Path, monkeypatch
) -> None:
    _keep_select_profile_off_the_host(tmp_path, monkeypatch)
    _install_profile(tmp_path)
    session_id = f"empty-ops-{tmp_path.name}"

    result = mcp_select_profile("default", patch_ops=[], session_id=session_id)

    assert result["success"] is True
    assert result["mode"] == "inherit_and_patch"
    state = get_session_state(session_id)
    assert state is not None
    assert state.patch_ops == ()
    # No client copy was written: the file the scan is handed is the registered
    # profile's own copy, which is also the trusted base.
    assert state.config_path == state.trusted_config_path
    assert session_config_was_patched(result["config_path"]) is False


@pytest.mark.parametrize(
    ("patch_ops", "override_yaml", "changed"),
    [
        pytest.param(None, None, False, id="static"),
        pytest.param([], None, False, id="empty-patch"),
        pytest.param([OP], None, True, id="one-op"),
        pytest.param(None, "project_name: client\n", True, id="override"),
        pytest.param(None, "", True, id="empty-override"),
    ],
)
def test_one_predicate_says_whether_a_client_changed_the_profile(
    patch_ops, override_yaml, changed
) -> None:
    """``client_values_present`` is the reading a stored binding and ``select_profile``
    both go by: a non-empty ``patch_ops``, or any ``override_yaml``, an empty one
    included."""
    from automated_security_helper.cli.mcp.profile_registry import (
        SessionState,
        client_values_present,
    )

    assert client_values_present(patch_ops, override_yaml) is changed
    state = SessionState(
        session_id="s",
        patch_ops=None if patch_ops is None else tuple(patch_ops),
        override_yaml=override_yaml,
    )
    assert state.client_changed is changed


def _client_copies_written_by_select_profile(
    tmp_path: Path, monkeypatch, patch_ops
) -> list:
    """What ``select_profile`` hands ``materialize_session_binding`` as the client copy."""
    _keep_select_profile_off_the_host(tmp_path, monkeypatch)
    _install_profile(tmp_path)
    written_for: list = []
    real = _registry.materialize_session_binding

    def record(session_id, registered, patched=None):
        written_for.append(patched)
        return real(session_id, registered, patched)

    monkeypatch.setattr(_registry, "materialize_session_binding", record)

    result = mcp_select_profile(
        "default", patch_ops=patch_ops, session_id=f"predicate-{tmp_path.name}"
    )

    assert result["success"] is True
    return written_for


@pytest.mark.parametrize(
    ("patch_ops", "client_copy_written"),
    [pytest.param([], False, id="empty-patch"), pytest.param([OP], True, id="one-op")],
)
def test_select_profile_writes_a_client_copy_only_for_a_patch_with_an_op(
    tmp_path: Path, monkeypatch, patch_ops, client_copy_written: bool
) -> None:
    written_for = _client_copies_written_by_select_profile(
        tmp_path, monkeypatch, patch_ops
    )

    assert len(written_for) == 1
    assert (written_for[0] is not None) is client_copy_written


@pytest.mark.parametrize(
    ("patch_ops", "reading", "client_copy_written"),
    [
        pytest.param([OP], False, False, id="op-read-as-unchanged"),
        pytest.param([], True, True, id="empty-patch-read-as-changed"),
    ],
)
def test_select_profile_goes_by_the_one_reading_of_whether_a_client_changed_it(
    tmp_path: Path, monkeypatch, patch_ops, reading: bool, client_copy_written: bool
) -> None:
    """Whether the client's copy is written is ``client_values_present``'s answer and
    no other: with the reading forced the other way, the copy follows it."""
    monkeypatch.setattr(
        _registry, "client_values_present", lambda patch_ops, override_yaml: reading
    )

    written_for = _client_copies_written_by_select_profile(
        tmp_path, monkeypatch, patch_ops
    )

    assert len(written_for) == 1
    assert (written_for[0] is not None) is client_copy_written


def test_select_profile_with_an_op_binds_the_clients_copy(
    tmp_path: Path, monkeypatch
) -> None:
    """Control: the same call with one op writes a client copy, which is patched."""
    _keep_select_profile_off_the_host(tmp_path, monkeypatch)
    _install_profile(tmp_path)
    session_id = f"one-op-{tmp_path.name}"

    result = mcp_select_profile("default", patch_ops=[OP], session_id=session_id)

    assert result["success"] is True
    state = get_session_state(session_id)
    assert state is not None
    assert state.config_path != state.trusted_config_path
    assert session_config_was_patched(result["config_path"]) is True
