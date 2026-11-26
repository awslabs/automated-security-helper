# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Rewriting a gone binding file does not stat and hash files under the session lock.

``_binding_intact`` stats each recorded file and reads and hashes it. Run under
``_session_lock`` from ``_rematerialize_binding`` it held up every other session's
state read (``get_session_state``, ``bind_session_config``) for the length of a
file read. The state is copied under the lock and the checks run outside it, as
``_bound_config_paths`` already did; the binding's own write lock
(``binding_writes``) is what keeps another bind from writing meanwhile.
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


def _bind(name: str):
    config = AshConfig(project_name=name)
    registry = dict(session_profiles.get_profile_registry())
    registry[name] = session_profiles.ProfileEntry(
        name=name,
        path=Path(f"/registered/{name}.yaml"),
        config=config,
        path_sha256="0" * 64,
    )
    session_profiles.set_profile_registry(registry)
    config_path, trusted = session_profiles.materialize_session_binding(
        None, config, None
    )
    session_profiles.bind_session_config(
        None,
        config=config,
        profile_name=name,
        config_path=config_path,
        trusted_config_path=trusted,
    )
    return config_path, trusted


def _record_lock_ownership(monkeypatch) -> list[bool]:
    owned: list[bool] = []
    real = session_profiles._binding_intact

    def watching(state):
        owned.append(session_profiles._session_lock._is_owned())
        return real(state)

    monkeypatch.setattr(session_profiles, "_binding_intact", watching)
    return owned


def test_control_the_watcher_sees_the_lock_when_it_is_held(monkeypatch):
    owned = _record_lock_ownership(monkeypatch)
    _bind("strict")

    with session_profiles._session_lock:
        session_profiles._binding_intact(session_profiles.get_session_state(None))

    assert owned == [True]


def test_a_gone_file_is_written_again_without_the_session_lock_held(monkeypatch):
    """Red at the base: ``_binding_intact`` ran with the lock held."""
    config_path, _trusted = _bind("strict")
    Path(config_path).unlink()
    owned = _record_lock_ownership(monkeypatch)

    answered = session_profiles.resolve_session_config_path(None)

    assert answered == config_path and Path(answered).is_file()
    assert owned, "control: the intact check ran"
    assert not any(owned)


def test_a_file_another_thread_wrote_while_this_one_waited_is_the_answer(monkeypatch):
    """The 'same binding, files already there' branch answers without a write."""
    config_path, trusted = _bind("strict")
    state = session_profiles.get_session_state(None)
    writes = []
    real = session_profiles._replace_staged
    monkeypatch.setattr(
        session_profiles,
        "_replace_staged",
        lambda partial, target: (writes.append(target), real(partial, target))[1],
    )
    owned = _record_lock_ownership(monkeypatch)

    assert session_profiles._rematerialize_binding(
        session_profiles.DEFAULT_SESSION_ID
    ) == (config_path, trusted)
    assert writes == []
    assert state is session_profiles.get_session_state(None)
    assert not any(owned)
