# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A bound profile whose file is gone and cannot be rewritten refuses the scan as a refusal.

``resolve_session_config_path`` writes a bound profile's file again when it is
gone, and raises when it cannot (the profile is no longer registered, or the
workspace cannot be written). Every caller has to turn that raise into the
tool's own refusal:

* ``run_ash_scan`` (``cli/mcp_server.py``) answers with a stable
  ``error_type``, not the catch-all's internal error: a config refusal, exit 3,
  when the profile is no longer registered; the server's own failure, exit 1
  with the cause logged, when the session's workspace could not be written
  (the two are told apart by the error's chained cause; before, both were a
  config refusal and nothing was logged for the operator).
* the scan runner (``_run_scan`` in ``cli/mcp_tools.py``) records the entry
  FAILED with the reason; the runner's own ``try`` begins later, so a raise
  there would otherwise leave the entry PENDING, which reads as running.
* the workspace tools catch ``RuntimeError`` for a bound profile whose
  registered copy is missing (``_resolve_session_config``), so the error is a
  ``RuntimeError`` as well as a ``ProfileRegistryError``.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from mcp.server.mcpserver import Context
from typing_extensions import Self

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    BoundProfileUnavailableError,
    ProfileRegistryError,
    clear_all_session_state,
    clear_profile_registry,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile

pytestmark = pytest.mark.unit

SESSION = "bound-then-orphaned"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    document: Dict[str, Any] = {
        "project_name": "operator-registered",
        "global_settings": {
            "mcp": {"runtime_overrides": {"enabled": True, "allowed_paths": ["/**"]}}
        },
    }
    profile = tmp_path / "op.yaml"
    profile.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"op={profile}"]))
    yield
    clear_profile_registry()
    clear_all_session_state()


def _bind_then_orphan(session_id: str | None) -> None:
    """Bind the profile, remove its materialized file, unregister the profile."""
    result = mcp_select_profile("op", session_id=session_id)
    assert result["success"] is True, result
    bound = resolve_session_config_path(session_id)
    assert bound is not None and Path(bound).is_file()
    Path(bound).unlink()
    clear_profile_registry()


def _project(tmp_path: Path) -> Path:
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return source


def test_the_refusal_is_a_registry_error_and_a_runtime_error() -> None:
    """The type the workspace tools' handler catches (RuntimeError) and the
    registry's own (ProfileRegistryError) are one error here."""
    _bind_then_orphan(SESSION)

    with pytest.raises(BoundProfileUnavailableError) as refused:
        resolve_session_config_path(SESSION)

    assert isinstance(refused.value, ProfileRegistryError)
    assert isinstance(refused.value, RuntimeError)
    assert "select_profile" in str(refused.value)


def test_a_workspace_that_cannot_be_written_is_the_same_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second cause the module docstring names: the profile stays registered
    but the session's workspace cannot be written again. The writer's OSError is
    wrapped into the same BoundProfileUnavailableError (a ProfileRegistryError
    and a RuntimeError), naming the cause, so every caller's refusal arm catches
    it instead of the catch-all reporting an internal error."""
    from automated_security_helper.cli.mcp import profile_registry

    _bind_then_remove_the_copy(SESSION)

    def cannot_write(sid, config, patched):
        raise PermissionError(13, "Permission denied", "config")

    monkeypatch.setattr(profile_registry, "materialize_session_binding", cannot_write)

    with pytest.raises(BoundProfileUnavailableError) as refused:
        resolve_session_config_path(SESSION)

    assert isinstance(refused.value, ProfileRegistryError)
    assert isinstance(refused.value, RuntimeError)
    assert "could not be written" in str(refused.value), str(refused.value)
    assert "Permission denied" in str(refused.value), str(refused.value)


def test_the_scan_runner_records_the_refusal_instead_of_leaving_the_entry_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    _bind_then_orphan(SESSION)
    source = _project(tmp_path)
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    started: List[str] = []

    def never_runs(*args: Any, **kwargs: Any) -> Any:
        started.append("scan")
        raise RuntimeError("the scan must not start")

    monkeypatch.setattr(ras, "run_ash_scan", never_runs)
    with patch.object(mcp_tools, "get_scan_registry", return_value=registry):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=None,
                session_id=SESSION,
            )
        )

    entry = registry.get_scan(scan_id)
    assert entry is not None
    assert entry.status is MCScanStatus.FAILED, entry.status
    assert "select_profile" in (entry.error_message or ""), entry.error_message
    assert started == [], "the scan started although its profile was unusable"


@pytest.mark.asyncio
async def test_run_ash_scan_answers_a_config_refusal_not_an_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.cli import mcp_server

    # The stdio session: the tool resolves the caller to the default session,
    # which is the one bound here.
    _bind_then_orphan(DEFAULT_SESSION_ID)
    source = _project(tmp_path)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    response = await mcp_server.run_ash_scan(ctx, source_dir=str(source))

    assert response["success"] is False, response
    assert response["error_type"] == "bound_profile_unavailable", response
    assert response["exit_code"] == 3, response
    assert "select_profile" in response["error"], response


@pytest.mark.asyncio
async def test_run_ash_scan_reports_an_unwritable_workspace_as_the_servers_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    """Red at the base: a workspace that could not be written was answered as a
    config refusal, exit 3, the caller's own fault, and nothing was logged for
    the operator, who is the one that can act on a workspace permission."""
    from automated_security_helper.cli import mcp_server
    from automated_security_helper.cli.mcp import profile_registry

    _bind_then_remove_the_copy(DEFAULT_SESSION_ID)
    source = _project(tmp_path)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())

    def cannot_write(sid, config, patched):
        raise PermissionError(13, "Permission denied", "config")

    monkeypatch.setattr(profile_registry, "materialize_session_binding", cannot_write)
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    with caplog.at_level(logging.WARNING, logger=ASH_LOGGER.name):
        response = await mcp_server.run_ash_scan(ctx, source_dir=str(source))

    assert response["success"] is False, response
    assert response["error_type"] == "bound_profile_unavailable", response
    assert response["exit_code"] == 1, response
    assert response["error_category"] == "permission_denied", response
    assert "Permission denied" in response["error"], response
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("could not be written" in text for text in warnings), warnings


def _bind_then_remove_the_copy(session_id: str | None) -> Path:
    """Bind the profile and remove its materialized file; the profile stays
    registered, so the file can be written again."""
    result = mcp_select_profile("op", session_id=session_id)
    assert result["success"] is True, result
    bound = resolve_session_config_path(session_id)
    assert bound is not None and Path(bound).is_file()
    Path(bound).unlink()
    return Path(bound)


class _Held:
    """The session's workspace held as its removal holds it (the TTL sweep, a
    clear, the end of the session): a change that removes the workspace, which
    refuses every write that comes meanwhile."""

    def __init__(self, session_id: str) -> None:
        from automated_security_helper.cli.mcp.sessions import get_default_registry

        self._session = get_default_registry().session_for(session_id)

    def __enter__(self) -> Self:
        assert self._session.try_begin_change() is None
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._session.end_change()


def test_the_rewrite_is_refused_while_the_sessions_workspace_is_being_removed(
    tmp_path: Path,
) -> None:
    """The file is written again under the session's write hold, the one
    select_profile takes, so a removal of the workspace in progress (end of the
    session on its worker thread, the sweep, a clear) refuses the rewrite
    instead of letting it recreate the directory the removal is deleting: that
    left a marked orphan the sweep kept for a whole TTL. The refusal is the
    hold's own error, never a profile that "could not be written"."""
    from automated_security_helper.cli.mcp.sessions import SessionWorkspaceBusyError

    gone = _bind_then_remove_the_copy(SESSION)

    with _Held(SESSION):
        with pytest.raises(SessionWorkspaceBusyError):
            resolve_session_config_path(SESSION)
        assert not gone.exists(), "the profile was written under the removal"

    # The hold ended without removing anything here: the next ask writes it.
    # Compared as paths: the resolver spells a Windows path with forward
    # slashes, str() of the Path with backslashes.
    assert Path(resolve_session_config_path(SESSION)) == gone
    assert gone.is_file()


def test_the_new_paths_land_on_the_binding_that_was_read_not_on_a_rebind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """While the files are written again, the client can bind the same profile
    with a patch. The paths written for the OLD binding must not be recorded
    on the NEW one, whose own config path is the patched copy: compared by
    profile name, the two bindings looked the same."""
    from automated_security_helper.cli.mcp import profile_registry

    _bind_then_remove_the_copy(SESSION)
    real_write = profile_registry.materialize_session_binding
    rebound: Dict[str, Any] = {}
    rebinding: List[str] = []

    def write_then_rebind(sid, config, patched):
        paths = real_write(sid, config, patched)
        if not rebinding:
            # Once: the rebind below writes through this same name.
            rebinding.append("once")
            rebound.update(
                mcp_select_profile(
                    "op",
                    patch_ops=[
                        {"op": "replace", "path": "/project_name", "value": "re"}
                    ],
                    session_id=sid,
                )
            )
        return paths

    monkeypatch.setattr(
        profile_registry, "materialize_session_binding", write_then_rebind
    )

    rewritten = resolve_session_config_path(SESSION)

    assert rebound.get("success") is True, rebound
    recorded = profile_registry.resolve_session_config_path(SESSION)
    assert recorded == rebound["config_path"], (recorded, rebound["config_path"])
    assert rewritten != rebound["config_path"], "the rebind's own path was overwritten"


@pytest.mark.asyncio
async def test_run_ash_scan_answers_the_hold_as_busy_not_as_an_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.cli import mcp_server

    _bind_then_remove_the_copy(DEFAULT_SESSION_ID)
    source = _project(tmp_path)
    monkeypatch.setattr(mcp_server, "monitor_scan_progress", AsyncMock())
    ctx = MagicMock(spec=Context)
    ctx.headers = {}

    with _Held(DEFAULT_SESSION_ID):
        response = await mcp_server.run_ash_scan(ctx, source_dir=str(source))

    assert response["success"] is False, response
    assert response["error_type"] == "session_workspace_busy", response
    assert "exit_code" not in response, response


def test_the_scan_runner_records_the_hold_instead_of_leaving_the_entry_pending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    _bind_then_remove_the_copy(SESSION)
    source = _project(tmp_path)
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    started: List[str] = []

    def never_runs(*args: Any, **kwargs: Any) -> Any:
        started.append("scan")
        raise RuntimeError("the scan must not start")

    monkeypatch.setattr(ras, "run_ash_scan", never_runs)
    with (
        _Held(SESSION),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=None,
                session_id=SESSION,
            )
        )

    entry = registry.get_scan(scan_id)
    assert entry is not None
    assert entry.status is MCScanStatus.FAILED, entry.status
    assert "holds this session's workspace" in (entry.error_message or ""), (
        entry.error_message
    )
    assert started == []
