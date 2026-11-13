# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session's ``config/`` holds only what the server writes there.

The server writes a session's bound profile to ``config/ash.yaml`` and a
workspace tool's per-call profile to ``config/call-profile-<digest>.yaml``, one
per profile (``profile_registry.materialize_session_config`` and
``call_profile_filename``), and only files named so, directly in ``config/``, are
treated as the operator's. Before this, every file under ``config/`` was, and
the session's own sandbox was a scan root, so a workspace scan could take
``<session>/config/out`` as its ``output_dir`` and the archive converter would
extract a delivered YAML file there. That file was then read as the operator's
config: no denied-field check, and ``!ENV`` resolved from the server's
environment for a remote caller.

Two rules close it, each tested here: neither ``config/`` nor ``client-config/``
may be a scan target or an output directory on any route, and only the files the
server writes in ``config/`` are set aside.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    CALL_PROFILE_FILENAME,
    DEFAULT_SESSION_ID,
    SESSION_CONFIG_FILENAME,
    call_profile_filename,
    clear_profile_registry,
    clear_all_session_state,
)

pytestmark = pytest.mark.unit

REMOTE = "client-1"
#: A name of the shape ``call_profile_filename`` writes: 16 lowercase hex digits.
PER_CALL = "call-profile-0123456789abcdef.yaml"
PROBE_VAR = "ASH_ENV_PROBE"
DENIED = "project_name: whose\nfail_on_findings: false\n"
REFERENCE = f"project_name: ${{{PROBE_VAR}}}\n"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspaces"
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv(PROBE_VAR, "probe-value")
    clear_profile_registry()
    clear_all_session_state()
    yield {"workspace": workspace, "session": workspace / REMOTE}
    clear_profile_registry()
    clear_all_session_state()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _upload(files: Dict[str, str], session_id: str = REMOTE) -> Path:
    from automated_security_helper.cli.mcp.source_delivery import (
        set_source_zip_chunk,
        set_source_zip_finalize,
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    data = buffer.getvalue()
    set_source_zip_chunk(
        "u1", 0, base64.b64encode(data).decode("ascii"), True, session_id=session_id
    )
    return set_source_zip_finalize(
        "u1", hashlib.sha256(data).hexdigest(), session_id=session_id
    )


def _error_types(result: Dict[str, Any]) -> List[str]:
    return [error["type"] for error in result["errors"]]


# ---------------------------------------------------------------------------
# Neither directory is a scan target or an output directory
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("directory", ["config", "client-config"])
@pytest.mark.parametrize("below", ["", "out", "out/projects"])
def test_a_config_directory_is_not_a_scan_target(
    _server, directory: str, below: str
) -> None:
    from automated_security_helper.cli.mcp.scan_target import validate_scan_target

    target = _server["session"] / directory / below

    assert validate_scan_target(target, session_id=REMOTE) is not None


def test_the_rest_of_the_sandbox_is_still_a_scan_target(_server) -> None:
    from automated_security_helper.cli.mcp.scan_target import validate_scan_target

    assert validate_scan_target(_server["session"] / "source", REMOTE) is None
    assert validate_scan_target(_server["session"], REMOTE) is None


def test_the_local_fallback_refuses_it_too(_server, monkeypatch) -> None:
    """Without grants a stdio caller gets the legacy net, which permits nearly
    everything; the config directories are refused before it applies."""
    from automated_security_helper.cli.mcp.scan_target import validate_scan_target

    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS")
    own = _server["workspace"] / DEFAULT_SESSION_ID

    assert validate_scan_target(own / "source", DEFAULT_SESSION_ID) is None
    assert validate_scan_target(own / "config" / "out", DEFAULT_SESSION_ID) is not None


def test_run_ash_scan_refuses_a_config_directory(_server) -> None:
    from automated_security_helper.cli import mcp_tools

    target = _server["session"] / "config"
    target.mkdir(parents=True)
    with patch.object(mcp_tools, "_run_scan_async") as started:
        result = asyncio.run(
            mcp_tools.mcp_scan_directory(str(target), session_id=REMOTE)
        )

    assert result["success"] is False, result
    assert not started.called
    assert not (target / ".ash").exists()


def test_a_workspace_scan_cannot_write_into_config(_server) -> None:
    """The route the archive converter used: output_dir under config/."""
    from automated_security_helper.cli.mcp import workspace as workspace_module

    source = _upload(
        {
            "dev.code-workspace": '{"folders": [{"path": "app"}]}',
            "app/main.py": "x = 1\n",
        }
    )
    output_dir = _server["session"] / "config" / "out"

    def must_not_run(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the workspace ran with an output_dir under config/")

    with patch.object(workspace_module, "execute_workspace", must_not_run):
        result = asyncio.run(
            workspace_module.mcp_scan_workspace(
                str(source / "dev.code-workspace"),
                output_dir=str(output_dir),
                session_id=REMOTE,
            )
        )

    assert result["success"] is False, result
    assert not output_dir.exists()


# ---------------------------------------------------------------------------
# Only the files the server writes are set aside
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "relative", ["out/projects/proj/converted/evil.yaml", "other.yaml"]
)
def test_another_file_in_config_is_the_clients(_server, relative: str) -> None:
    from automated_security_helper.cli.mcp_tools import (
        mcp_get_config,
        mcp_scan_directory,
        mcp_validate_config,
    )

    denied = _write(_server["session"] / "config" / relative, DENIED)
    reference = _write(denied.with_name("ref.yaml"), REFERENCE)

    assert "denied_by_runtime_policy" in _error_types(
        mcp_validate_config(config_path=str(denied), session_id=REMOTE)
    )
    assert _error_types(
        mcp_validate_config(config_path=str(reference), session_id=REMOTE)
    ) == ["config_env_not_resolved"]
    got = mcp_get_config(config_path=str(denied), session_id=REMOTE)
    assert got.get("error_type") == "config_field_denied", got
    got = mcp_get_config(config_path=str(reference), session_id=REMOTE)
    assert got.get("error_type") == "config_env_not_resolved", got

    target = _upload({"main.py": "x = 1\n"})
    scanned = asyncio.run(
        mcp_scan_directory(str(target), config_path=str(denied), session_id=REMOTE)
    )
    assert scanned.get("error_type") == "config_field_denied", scanned


@pytest.mark.parametrize(
    "filename",
    [SESSION_CONFIG_FILENAME, CALL_PROFILE_FILENAME, call_profile_filename("ci")],
    ids=["bound profile", "call profile", "per-profile call profile"],
)
def test_the_files_the_server_writes_are_set_aside(_server, filename: str) -> None:
    from automated_security_helper.cli.mcp.profile_registry import (
        materialize_session_config,
    )
    from automated_security_helper.cli.mcp_tools import (
        mcp_get_config,
        mcp_validate_config,
    )
    from automated_security_helper.config.ash_config import AshConfig

    written = Path(
        materialize_session_config(
            REMOTE,
            AshConfig(project_name="operator", fail_on_findings=False),
            filename=filename,
        )
    )

    assert written == _server["session"] / "config" / filename
    assert mcp_validate_config(config_path=str(written), session_id=REMOTE) == {
        "valid": True,
        "errors": [],
        "warnings": [],
    }
    got = mcp_get_config(config_path=str(written), session_id=REMOTE)
    assert "error_type" not in got, got
    assert got["project_name"] == "operator"


def _whose(path: Path) -> tuple:
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
        config_is_client_supplied,
    )

    return (
        config_is_client_supplied(path),
        client_named_config_is_untrusted(path, REMOTE),
    )


def test_a_per_call_profile_name_is_set_aside_by_its_shape(_server) -> None:
    """Control for the lookalikes below."""
    assert _whose(_write(_server["session"] / "config" / PER_CALL, DENIED)) == (
        False,
        False,
    )


@pytest.mark.parametrize(
    "name",
    [
        "call-profile-xyz.yaml",
        "call-profile-0123456789abcde.yaml",
        "call-profile-0123456789abcdef0.yaml",
        "call-profile-0123456789ABCDEF.yaml",
        "call-profile-0123456789abcdef.yml",
        "call-profile-0123456789abcdef.yaml.bak",
        "x-call-profile-0123456789abcdef.yaml",
        f"nested/{PER_CALL}",
    ],
    ids=[
        "not hex",
        "15 hex digits",
        "17 hex digits",
        "uppercase hex",
        "another suffix",
        "a trailing suffix",
        "a leading prefix",
        "a nested directory",
    ],
)
def test_a_lookalike_of_a_per_call_profile_name_is_the_clients(
    _server, name: str
) -> None:
    assert _whose(_write(_server["session"] / "config" / name, DENIED)) == (
        True,
        True,
    )


def test_a_per_call_profile_name_linking_to_a_client_file_is_the_clients(
    _server,
) -> None:
    delivered = _write(_server["session"] / "upload" / "ash.yaml", DENIED)
    link = _server["session"] / "config" / PER_CALL
    link.parent.mkdir(parents=True)
    link.symlink_to(delivered)

    assert _whose(link) == (True, True)


def test_a_client_link_to_a_per_call_profile_is_the_clients(_server) -> None:
    written = _write(_server["session"] / "config" / PER_CALL, DENIED)
    link = _server["session"] / "source" / "ash.yaml"
    link.parent.mkdir(parents=True)
    link.symlink_to(written)

    assert _whose(link) == (True, True)
