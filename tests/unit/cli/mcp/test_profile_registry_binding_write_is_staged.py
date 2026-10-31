# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A binding's files are staged before any of them is replaced.

``materialize_session_binding`` writes two files for a client-patched binding,
the client's copy in ``client-config/`` and the operator's in ``config/``, and
for an unpatched one removes the client copy and writes the operator's. It used
to replace the first before writing the second, so a write that failed in
between left the session's previous binding recorded over one profile's client
copy and another profile's operator copy, or over no client copy at all. Now
every copy is written to a temporary file first, and only then moved into place.

The rename itself is tried again when Windows refuses it while a reader holds
the file open; the stand-ins here refuse it the way Windows does, and stand in
for the platform too, because on every other platform the refusal is the
directory's and is raised at once (a retry there only delayed it).
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.profile_registry import (
    SESSION_CONFIG_FILENAME,
    materialize_session_binding,
    materialize_session_config,
)
from automated_security_helper.cli.mcp.sandbox import (
    CLIENT_CONFIG_DIR_NAME,
    CONFIG_DIR_NAME,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

SESSION = "staged-binding-session"


@pytest.fixture(autouse=True)
def _owned_workspace_root(monkeypatch, tmp_path: Path):
    """A workspace root under tmp_path, with the operator grant covering it."""
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()


def _refuse_the_operator_copy(monkeypatch) -> None:
    """``AshConfig.save`` fails for the operator's copy and writes the client's.

    The operator's copy is the one saved with ``exclude_unset`` (it holds only
    what the registered profile sets); the client's copy is written whole.
    """
    real_save = AshConfig.save

    def save(self, config_path, exclude_unset: bool = False, **kwargs):
        if exclude_unset:
            raise OSError(errno.ENOSPC, "no space left on device", str(config_path))
        return real_save(self, config_path, exclude_unset=exclude_unset, **kwargs)

    monkeypatch.setattr(AshConfig, "save", save)


def _no_partial_left(*directories: Path) -> None:
    left = [path for directory in directories for path in directory.glob(".*.tmp")]
    assert left == [], left


def test_a_failed_operator_copy_leaves_the_client_copy_as_it_was(monkeypatch) -> None:
    registered = AshConfig(project_name="registered")
    config_path, trusted_path = materialize_session_binding(
        SESSION, registered, AshConfig(project_name="first-patch")
    )
    client_before = Path(config_path).read_bytes()
    trusted_before = Path(trusted_path).read_bytes()
    _refuse_the_operator_copy(monkeypatch)

    with pytest.raises(OSError):
        materialize_session_binding(
            SESSION, registered, AshConfig(project_name="second-patch")
        )

    assert Path(config_path).read_bytes() == client_before
    assert Path(trusted_path).read_bytes() == trusted_before
    _no_partial_left(Path(config_path).parent, Path(trusted_path).parent)


def test_a_failed_operator_move_leaves_no_client_copy_of_the_new_profile(
    monkeypatch,
) -> None:
    """Red at the base: the client's copy had already been moved into place when
    the operator's move failed, so the session held the new profile's client copy
    over the old profile's operator copy, both present, and nothing repaired them."""
    registered = AshConfig(project_name="registered")
    config_path, trusted_path = materialize_session_binding(
        SESSION, registered, AshConfig(project_name="first-patch")
    )
    trusted_before = Path(trusted_path).read_bytes()
    real_replace_staged = profile_registry._replace_staged
    moves: list = []

    def refuse_the_second_move(partial, target):
        # The directory as well as the name: both copies are called by the same
        # file name, so the name alone cannot say which of them was moved.
        moves.append((Path(target).parent.name, Path(target).name))
        if len(moves) == 2:
            raise PermissionError(errno.EACCES, "refused", str(target))
        return real_replace_staged(partial, target)

    monkeypatch.setattr(profile_registry, "_replace_staged", refuse_the_second_move)

    # Another registered profile: with the same one in both calls the operator's
    # copy would read the same bytes whether it was replaced or not.
    with pytest.raises(PermissionError):
        materialize_session_binding(
            SESSION,
            AshConfig(project_name="second-registered"),
            AshConfig(project_name="second-patch"),
        )

    assert [directory for directory, _ in moves] == [
        CLIENT_CONFIG_DIR_NAME,
        CONFIG_DIR_NAME,
    ], moves
    assert not Path(config_path).exists(), "the new profile's client copy was kept"
    assert Path(trusted_path).read_bytes() == trusted_before
    _no_partial_left(Path(config_path).parent, Path(trusted_path).parent)


def test_a_failed_unpatched_rebind_keeps_the_client_copy(monkeypatch) -> None:
    registered = AshConfig(project_name="registered")
    config_path, _trusted_path = materialize_session_binding(
        SESSION, registered, AshConfig(project_name="patched")
    )
    assert Path(config_path).name == SESSION_CONFIG_FILENAME
    _refuse_the_operator_copy(monkeypatch)

    with pytest.raises(OSError):
        materialize_session_binding(SESSION, registered, None)

    assert Path(config_path).is_file()
    _no_partial_left(Path(config_path).parent)


def _session_directories() -> list:
    root = Path(os.environ["ASH_MCP_WORKSPACE_ROOT"]) / SESSION
    return [root, *(path for path in root.rglob("*") if path.is_dir())]


def test_a_rename_refused_once_is_tried_again(monkeypatch) -> None:
    """Windows refuses the rename while a reader holds the file; one refusal is
    not the outcome."""
    real_replace = os.replace
    refused: list = []

    def replace(src, dst, *args, **kwargs):
        if Path(dst).name == SESSION_CONFIG_FILENAME and not refused:
            refused.append(str(dst))
            raise PermissionError(errno.EACCES, "held open by a reader", str(dst))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(profile_registry.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(profile_registry, "_rename_waits_on_readers", lambda: True)

    path = materialize_session_config(SESSION, AshConfig(project_name="retried"))

    assert refused, "the stand-in never saw the rename"
    assert "retried" in Path(path).read_text(encoding="utf-8")
    _no_partial_left(*_session_directories())


def test_a_refusal_where_the_rename_never_waits_is_raised_at_once(
    monkeypatch,
) -> None:
    """Red at the base: a POSIX PermissionError (the directory's) was tried ten
    times over half a second before it was raised; nothing changes between tries
    there, so the retries only held the scan that waited on the answer."""
    real_replace = os.replace
    attempts: list = []
    slept: list = []

    def replace(src, dst, *args, **kwargs):
        if Path(dst).name == SESSION_CONFIG_FILENAME:
            attempts.append(str(dst))
            raise PermissionError(errno.EACCES, "the directory refuses it", str(dst))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(profile_registry.time, "sleep", slept.append)
    monkeypatch.setattr(profile_registry, "_rename_waits_on_readers", lambda: False)

    with pytest.raises(PermissionError):
        materialize_session_config(SESSION, AshConfig(project_name="at-once"))

    assert len(attempts) == 1, attempts
    assert slept == [], slept
    _no_partial_left(*_session_directories())


def test_a_rename_refused_every_time_is_raised_without_a_partial(monkeypatch) -> None:
    real_replace = os.replace

    def replace(src, dst, *args, **kwargs):
        if Path(dst).name == SESSION_CONFIG_FILENAME:
            raise PermissionError(errno.EACCES, "held open by a reader", str(dst))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(profile_registry.time, "sleep", lambda seconds: None)

    with pytest.raises(PermissionError):
        materialize_session_config(SESSION, AshConfig(project_name="never"))

    _no_partial_left(*_session_directories())
