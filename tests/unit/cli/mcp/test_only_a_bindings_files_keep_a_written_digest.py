# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A written-file digest is kept for a binding's files and for nothing else.

``_replace_staged`` recorded the digest of every file it moved into place, while
``clear_session_state`` dropped the two entries of the binding being cleared.
The per-call profile files ``materialize_session_config`` writes
(``call_profile_filename``) are never part of a binding, so their entries were
read by nobody and dropped by nobody: a long-lived server kept one per call per
session for as long as it ran. Only ``materialize_session_binding`` keeps a
digest now, and clearing a session drops every one it kept.
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


def test_control_a_bindings_files_keep_a_digest():
    config_path, trusted = session_profiles.materialize_session_binding(
        None, AshConfig(project_name="strict"), AshConfig(project_name="patched")
    )

    assert Path(config_path).as_posix() in session_profiles._written_digests
    assert Path(trusted).as_posix() in session_profiles._written_digests


def test_a_per_call_profile_file_keeps_no_digest():
    """Red at the base: the digest of the written file stayed in the table."""
    path = session_profiles.materialize_session_config(
        None,
        AshConfig(project_name="one-call"),
        filename=session_profiles.call_profile_filename("strict"),
    )

    assert Path(path).is_file()
    assert Path(path).as_posix() not in session_profiles._written_digests


def test_a_per_call_write_must_name_its_file():
    """Red at the tip it was found on: ``filename`` defaulted to the binding's
    own file name, so a per-call write that named nothing overwrote a live
    binding's ``config/ash.yaml`` and the collision was cured by digest
    ordering rather than removed."""
    with pytest.raises(TypeError, match="filename"):
        session_profiles.materialize_session_config(
            None, AshConfig(project_name="plain")
        )


def test_a_binding_named_materialization_keeps_no_digest_either():
    path = session_profiles.materialize_session_config(
        None,
        AshConfig(project_name="plain"),
        filename=session_profiles.SESSION_CONFIG_FILENAME,
    )

    assert Path(path).as_posix() not in session_profiles._written_digests


def test_a_binding_named_materialization_cannot_take_a_bindings_digest_away():
    """Red at the tip it was found on: the per-call write recorded a digest for the
    path the binding had just written, then removed it, so a bind that followed
    copied nothing and the binding was checked for presence only.

    The file name is the binding's own (``config/ash.yaml``, which a caller now
    has to name), and ``materialize_session_config`` takes no binding lock, so
    the two can meet."""
    registered = AshConfig(project_name="strict")
    config_path, trusted = session_profiles.materialize_session_binding(
        None, registered, None
    )
    session_profiles.materialize_session_config(
        None,
        AshConfig(project_name="other"),
        filename=session_profiles.SESSION_CONFIG_FILENAME,
    )

    session_profiles.bind_session_config(
        None,
        config=registered,
        profile_name="strict",
        config_path=config_path,
        trusted_config_path=trusted,
    )

    state = session_profiles.get_session_state(None)
    assert state is not None
    assert state.config_sha256 is not None
    assert state.trusted_config_sha256 is not None


def test_a_wrapper_that_swallows_the_move_return_does_not_drop_the_digest(monkeypatch):
    """Red at the tip it was found on: the digest was ``_replace_staged``'s
    return, so a test wrapper that forgot to pass it through recorded None,
    which dropped the entry and reduced the binding to a presence-only check --
    indistinguishable from a staged file that could not be read back."""
    real = session_profiles._replace_staged

    def swallows_the_return(partial, target):
        real(partial, target)

    monkeypatch.setattr(session_profiles, "_replace_staged", swallows_the_return)

    config_path, trusted = session_profiles.materialize_session_binding(
        None, AshConfig(project_name="strict"), AshConfig(project_name="patched")
    )

    assert Path(config_path).as_posix() in session_profiles._written_digests
    assert Path(trusted).as_posix() in session_profiles._written_digests


def test_a_binding_that_fails_between_its_moves_records_no_digest(monkeypatch):
    """Both digests are recorded once both files are in place, so a failed second
    move leaves neither behind."""
    real = session_profiles._replace_staged
    moves = []

    def refuse_the_second(partial, target):
        moves.append(target)
        if len(moves) == 2:
            raise PermissionError(13, "refused", str(target))
        return real(partial, target)

    monkeypatch.setattr(session_profiles, "_replace_staged", refuse_the_second)

    with pytest.raises(PermissionError):
        session_profiles.materialize_session_binding(
            None, AshConfig(project_name="strict"), AshConfig(project_name="patched")
        )

    assert session_profiles._written_digests == {}


def test_clearing_a_session_leaves_none_of_its_digests():
    config_path, trusted = session_profiles.materialize_session_binding(
        None, AshConfig(project_name="strict"), AshConfig(project_name="patched")
    )
    session_profiles.materialize_session_config(
        None, AshConfig(project_name="x"), filename="call-1.yaml"
    )
    session_profiles.bind_session_config(
        None,
        config=AshConfig(project_name="strict"),
        profile_name="strict",
        config_path=config_path,
        trusted_config_path=trusted,
    )

    session_profiles.clear_session_state(None)

    assert session_profiles._written_digests == {}
