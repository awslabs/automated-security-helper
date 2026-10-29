# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's trusted base is the registered profile, never the client's patched copy.

Why this file exists
--------------------
``select_profile`` with ``patch_ops`` or ``override_yaml`` writes two files: the
profile as the operator registered it, in the session's ``config/`` directory,
and the profile after the client's patch, in ``client-config/``, which counts as
the client's. A scan the server starts with no config named is handed the patched
copy and resolves it restrict-only against the registered profile as its trusted
base (``resolve_session_trusted_config_path``). The runner also takes a per-scan
snapshot of the profile file it loads, so a rebind while the scan waits for the
session lock cannot change what it runs.

The snapshot was made from the session's config path, which for a patched binding
is the patched copy, and installed as the trusted base. The restrict-only check
then compared the client's settings with a copy of themselves, and the values
the redaction set reads from the trusted base came from the patched copy. The
runner now copies the file it loads in each role: the registered profile as the
trusted base, the session's profile as the scan's own config.

Each case runs ``mcp_scan_directory`` for a real session sandbox with the scan
itself replaced by a double, which reads the files it was handed at the moment it
is called.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
import yaml

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
    register_profiles,
    resolve_session_config_path,
    resolve_session_trusted_config_path,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"

PATCHED = "client-patched"
REGISTERED_NAME = "operator-registered"
PATCH_OPS = [{"op": "replace", "path": "/project_name", "value": PATCHED}]

#: A scan id spelled as a scan does (``str(uuid.uuid4())``), for a leftover copy's
#: name, which the sweep parses.
_A_SCAN_ID = str(uuid.uuid4())


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A registered profile that lets a client patch any path, and a workspace
    root under the allowed roots, as the select_profile cells set one up."""
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


def _bind(session_id: str, patched: bool) -> None:
    result = mcp_select_profile(
        "op", patch_ops=PATCH_OPS if patched else None, session_id=session_id
    )
    assert result["success"] is True, result


def _session_dirs(tmp_path: Path, session_id: str) -> Dict[str, Path]:
    root = tmp_path / "ws" / session_id
    return {"config": root / "config", "client-config": root / "client-config"}


def _scan_copies(tmp_path: Path, session_id: str) -> List[str]:
    return sorted(
        f"{directory.name}/{path.name}"
        for directory in _session_dirs(tmp_path, session_id).values()
        if directory.is_dir()
        for path in directory.iterdir()
        if path.name.startswith(".ash-scan-")
    )


def _scan_the_session(tmp_path: Path, session_id: str) -> Dict[str, Any]:
    """Scan with no config named but the session's own, as run_ash_scan does, and
    return what the scan was handed, read at the moment it is called."""
    target = tmp_path / "ws" / session_id / "source" / "repo"
    target.mkdir(parents=True)
    bound = resolve_session_config_path(session_id)
    assert bound is not None
    seen: Dict[str, Any] = {}

    def a_run_that_reads_what_it_was_handed(*args: Any, **kwargs: Any) -> Any:
        trusted = kwargs.get("trusted_config_path")
        seen["trusted"] = trusted
        if trusted is not None:
            seen["trusted_dir"] = Path(trusted).parent.name
            seen["trusted_text"] = Path(trusted).read_text(encoding="utf-8")
        seen["config"] = kwargs.get("config")
        seen["config_text"] = Path(kwargs["config"]).read_text(encoding="utf-8")
        raise RuntimeError("the tool stopped")

    registry = ScanRegistry()

    async def start_and_wait_for_the_runner() -> Any:
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=bound, session_id=session_id
        )
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        await asyncio.gather(*pending, return_exceptions=True)
        return started

    with (
        patch.object(ras, "run_ash_scan", a_run_that_reads_what_it_was_handed),
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(f"{_MGMT}.get_scan_registry", return_value=registry),
        patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
    ):
        started = asyncio.run(start_and_wait_for_the_runner())
    assert started.get("success") is True, started
    assert "config_text" in seen, seen
    return seen


def test_a_patched_binding_scans_under_the_registered_profile_as_its_trusted_base(
    tmp_path,
):
    _bind("patched", patched=True)
    registered = Path(resolve_session_trusted_config_path("patched") or "")
    patched = Path(resolve_session_config_path("patched") or "")
    registered_text = registered.read_text(encoding="utf-8")
    # Controls: the binding holds two files, and they differ by the patch.
    assert registered.parent.name == "config", registered
    assert patched.parent.name == "client-config", patched
    assert PATCHED in patched.read_text(encoding="utf-8")
    assert PATCHED not in registered_text

    seen = _scan_the_session(tmp_path, "patched")

    assert seen["trusted"] is not None, seen
    assert seen["trusted_text"] == registered_text, seen
    assert PATCHED not in seen["trusted_text"], seen
    assert seen["trusted_dir"] == "config", seen
    # The scan's own config stays the client's patched copy, resolved against it.
    assert PATCHED in seen["config_text"], seen
    assert Path(seen["config"]).parent.name == "client-config", seen
    assert _scan_copies(tmp_path, "patched") == []


def test_control_an_unpatched_binding_scans_a_copy_of_the_registered_profile(
    tmp_path,
):
    _bind("plain", patched=False)
    registered = Path(resolve_session_trusted_config_path("plain") or "")
    assert resolve_session_config_path("plain") == registered.as_posix()

    seen = _scan_the_session(tmp_path, "plain")

    assert seen["config_text"] == registered.read_text(encoding="utf-8"), seen
    assert PATCHED not in seen["config_text"], seen
    assert Path(seen["config"]).name.startswith(".ash-scan-"), seen
    assert _scan_copies(tmp_path, "plain") == []


def _leftover_beside(profile: Path) -> Path:
    """A scan copy of ``profile`` that no scan holds and that is older than the
    sweep keeps a copy whose process it cannot place."""
    leftover = mcp_tools._scan_snapshot_path(
        profile, _A_SCAN_ID, writer_pid=1, writer_host=None
    )
    leftover.write_text("project_name: leftover\n", encoding="utf-8")
    old = time.time() - mcp_tools._foreign_scan_copy_max_age_seconds() - 3600
    os.utime(leftover, (old, old))
    return leftover


def test_a_rebind_sweeps_leftover_copies_beside_both_files_of_a_patched_binding():
    _bind("swept", patched=True)
    registered = Path(resolve_session_trusted_config_path("swept") or "")
    patched = Path(resolve_session_config_path("swept") or "")
    beside_the_registered = _leftover_beside(registered)
    beside_the_patched = _leftover_beside(patched)

    _bind("swept", patched=True)

    assert not beside_the_patched.exists(), beside_the_patched
    assert not beside_the_registered.exists(), beside_the_registered
