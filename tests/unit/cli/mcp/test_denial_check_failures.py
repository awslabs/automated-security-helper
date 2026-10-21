# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A denial check that cannot finish refuses the config instead of passing it.

``validate_config`` caught every exception from its runtime-override check and
returned no denials, so a config whose ``ash_plugin_modules`` was not a list
(``5``) made the check raise and the config, ``fail_on_findings: false``
included, validated as valid. ``run_ash_scan``'s pre-check raised a
``TypeError`` on the same file instead of returning a response. These tests
call both with that file, and with a check that raises for any other reason.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
)

REMOTE = "client-1"
NOT_A_LIST = "project_name: x\nfail_on_findings: false\nash_plugin_modules: 5\n"
DENIED = "project_name: x\nfail_on_findings: false\n"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "scan-root"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


def _upload(files: Dict[str, str]) -> Path:
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
        "u1", 0, base64.b64encode(data).decode("ascii"), True, session_id=REMOTE
    )
    return set_source_zip_finalize(
        "u1", hashlib.sha256(data).hexdigest(), session_id=REMOTE
    )


def _types(result: Dict[str, Any]) -> List[str]:
    return [error["type"] for error in result["errors"]]


def _ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": REMOTE}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


@pytest.mark.parametrize("given", ["content", "path"])
def test_a_module_list_that_is_not_a_list_still_reports_the_denials(
    given: str,
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    if given == "content":
        result = mcp_validate_config(config_content=NOT_A_LIST, session_id=REMOTE)
    else:
        path = _upload({"ash.yaml": NOT_A_LIST}) / "ash.yaml"
        result = mcp_validate_config(config_path=str(path), session_id=REMOTE)

    assert result["valid"] is False, result
    assert "denied_by_runtime_policy" in _types(result), result
    fields = [e["field"] for e in result["errors"]]
    assert "fail_on_findings" in fields, result


@pytest.mark.parametrize("given", ["content", "path"])
def test_a_denial_check_that_raises_makes_the_config_invalid(given: str) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config
    from automated_security_helper.config import client_config_policy

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("check broke")

    path = _upload({"ash.yaml": DENIED}) / "ash.yaml"
    with patch.object(client_config_policy, "client_file_denials", broken):
        if given == "content":
            result = mcp_validate_config(config_content=DENIED, session_id=REMOTE)
        else:
            result = mcp_validate_config(config_path=str(path), session_id=REMOTE)

    assert result["valid"] is False, result
    assert _types(result) == ["validation_error"], result
    assert "check broke" in result["errors"][0]["message"], result


def test_the_scan_pre_check_refuses_a_module_list_that_is_not_a_list() -> None:
    from automated_security_helper.cli import mcp_tools

    source = _upload({"ash.yaml": NOT_A_LIST})
    with patch.object(mcp_tools, "_run_scan_async") as started:
        result = asyncio.run(
            mcp_tools.mcp_scan_directory(
                str(source), config_path=str(source / "ash.yaml"), session_id=REMOTE
            )
        )

    assert result.get("error_type") == "config_field_denied", result
    assert not started.called


def test_a_pre_check_that_raises_is_a_scan_start_failure() -> None:
    from automated_security_helper.cli import mcp_server, mcp_tools
    from automated_security_helper.config import client_config_policy

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("check broke")

    source = _upload({"ash.yaml": DENIED})
    with (
        patch.object(client_config_policy, "apply_client_config_rules", broken),
        patch.object(mcp_tools, "_run_scan_async") as started,
    ):
        direct = asyncio.run(
            mcp_tools.mcp_scan_directory(
                str(source), config_path=str(source / "ash.yaml"), session_id=REMOTE
            )
        )
        through_the_tool = asyncio.run(
            mcp_server.run_ash_scan(
                _ctx(), source_dir=str(source), config_path=str(source / "ash.yaml")
            )
        )

    assert direct["success"] is False, direct
    assert "check broke" in direct["error"], direct
    assert through_the_tool["success"] is False, through_the_tool
    assert through_the_tool["error_type"] == "scan_start_failure", through_the_tool
    assert not started.called
