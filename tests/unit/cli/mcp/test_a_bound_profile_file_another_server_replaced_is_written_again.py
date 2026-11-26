# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two stdio servers share the default session's files; neither runs the other's profile.

A stdio client that exposes no session id is the ``__default__`` session, whose
``config/`` and ``client-config/`` directories every stdio server on one workspace
root shares, and each writes the one fixed name ``ash.yaml`` there. Server A bound
``strict``; server B then bound ``dev`` and replaced the file. A's next read found
both files present and answered them, so A's scan ran under B's profile while A's
client rules and patched-config checks still read A's ``strict``. An unpatched bind
in B also removed A's client copy, and A then wrote its own over B's operator copy.

A binding now records the digest of the bytes it wrote (``SessionState.config_sha256``
and ``trusted_config_sha256``), and a file holding other bytes reads as a gone one:
the binding's own files are written again before the path is answered. B is another
process here, so it is simulated by writing the shared name directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import session_profiles
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _owned_workspace_root(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    session_profiles.clear_profile_registry()
    session_profiles.clear_all_session_state()
    yield
    session_profiles.clear_profile_registry()
    session_profiles.clear_all_session_state()


def _register(name: str) -> AshConfig:
    config = AshConfig(project_name=name)
    registry = dict(session_profiles.get_profile_registry())
    registry[name] = session_profiles.ProfileEntry(
        name=name,
        path=Path(f"/registered/{name}.yaml"),
        config=config,
        path_sha256="0" * 64,
    )
    session_profiles.set_profile_registry(registry)
    return config


def _bind(name: str, patched: AshConfig | None = None):
    """What ``select_profile`` does for the stdio session, for profile ``name``."""
    registered = _register(name)
    config_path, trusted = session_profiles.materialize_session_binding(
        None, registered, patched
    )
    session_profiles.bind_session_config(
        None,
        config=patched if patched is not None else registered,
        profile_name=name,
        patch_ops=(
            [{"op": "replace", "path": "/project_name", "value": patched.project_name}]
            if patched is not None
            else None
        ),
        config_path=config_path,
        trusted_config_path=trusted,
    )
    return config_path, trusted


def _another_server_binds(name: str, config_path: str, trusted: str) -> None:
    """Server B's bind of profile ``name``: the same fixed names, its own bytes."""
    other = AshConfig(project_name=name)
    other.save(Path(trusted), exclude_unset=True)
    if config_path != trusted:
        other.save(Path(config_path), exclude_unset=False)


def test_control_untouched_files_are_answered_without_a_write(monkeypatch):
    """Control: the check reads the digest and finds the bytes it wrote, so a
    binding nobody replaced is answered as it was, with no write."""
    config_path, trusted = _bind("strict")
    writes = []
    real = session_profiles._replace_staged
    monkeypatch.setattr(
        session_profiles,
        "_replace_staged",
        lambda partial, target: (writes.append(target), real(partial, target))[1],
    )

    assert session_profiles.resolve_session_config_path(None) == config_path
    assert session_profiles.resolve_session_trusted_config_path(None) == trusted
    assert writes == []


def test_a_file_the_other_server_replaced_is_written_again_from_the_binding():
    """Red at the base: the answer was the other server's file."""
    config_path, trusted = _bind("strict")
    own_bytes = Path(config_path).read_bytes()
    _another_server_binds("dev", config_path, trusted)
    assert Path(config_path).read_bytes() != own_bytes, "control: B did replace it"

    answered = session_profiles.resolve_session_config_path(None)

    assert answered == config_path
    assert Path(answered).read_bytes() == own_bytes


def test_the_replacement_is_undone_each_time_it_is_made():
    """Two servers taking turns: each answer is the binding's own profile."""
    config_path, trusted = _bind("strict")
    own_bytes = Path(config_path).read_bytes()

    for _ in range(3):
        _another_server_binds("dev", config_path, trusted)
        assert session_profiles.resolve_session_config_path(None) == config_path
        assert Path(config_path).read_bytes() == own_bytes


def test_a_patched_binding_whose_operator_copy_was_replaced_is_written_again():
    """The pair is rewritten together: the client's copy is the patched profile and
    the operator's copy the registered one, and a scan reads both."""
    patched = AshConfig(project_name="strict-patched")
    config_path, trusted = _bind("strict", patched)
    assert config_path != trusted, "control: a patched binding has two files"
    client_bytes = Path(config_path).read_bytes()
    trusted_bytes = Path(trusted).read_bytes()
    AshConfig(project_name="dev").save(Path(trusted), exclude_unset=True)

    answered = session_profiles._bound_config_paths(None)

    assert answered == (config_path, trusted)
    assert Path(config_path).read_bytes() == client_bytes
    assert Path(trusted).read_bytes() == trusted_bytes


def test_a_binding_for_files_this_process_did_not_write_is_checked_for_presence_only(
    tmp_path,
):
    """A path bound without a write here has no digest: it is as it was."""
    elsewhere = tmp_path / "written-by-another-process.yaml"
    elsewhere.write_text("project_name: elsewhere\n", encoding="utf-8")
    registered = _register("strict")
    session_profiles.bind_session_config(
        None,
        config=registered,
        profile_name="strict",
        config_path=str(elsewhere),
        trusted_config_path=str(elsewhere),
    )

    state = session_profiles.get_session_state(None)
    assert state is not None
    assert state.config_sha256 is None and state.trusted_config_sha256 is None
    assert session_profiles.resolve_session_config_path(None) == str(elsewhere)


def test_ending_a_session_drops_the_digests_kept_for_its_files():
    config_path, trusted = _bind("strict")
    assert Path(config_path).as_posix() in session_profiles._written_digests

    session_profiles.clear_session_state(None)

    assert Path(config_path).as_posix() not in session_profiles._written_digests
    assert Path(trusted).as_posix() not in session_profiles._written_digests
