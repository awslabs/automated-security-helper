# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MCP resolve_workspace reads the workspace root's config by the caller's rule.

resolve_workspace reads the workspace root's config, as a workspace scan does,
so that it refuses a plan the scan would refuse. It read that file with the
local caller's rule, whoever was calling, while the scan reads it with the
caller's own rule (``config_sources.env_refused_for``). For a remote caller the
scan refuses a root config in the scanned tree that uses ``!ENV``; planning
resolved its ``${VAR}`` references from the server's environment instead. A
field the value did not fit then failed validation with the value in the
message, and a field it did fit passed. Both now meet the refusal the scan
gives, and no value from the server's environment is in the reply, the error,
the exception chain or the log.

The other callers of ``resolve_workspace_execution_config`` were checked:

* ``interactions/run_ash_scan._resolve_workspace_execution_config``, the scan
  path, already passes the session's gate, the caller and the session.
* ``cli/scan.py``'s ``ash scan --workspace --dry-run`` is the operator's own
  command, run where the operator runs the scan, so the local rule and no gate
  are what its run uses, and are intended.

``cli/mcp/workspace._gate_client_overrides`` also reads a config with the local
rule, but only the session's own config: the bound profile or ``ASH_CONFIG``,
never a file the client named. That is intended too.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
)

SESSION = "client-1"
PROBE_VAR = "ASH_ENV_PROBE"
PROBE = "probe-value-91c4"
ENV_REFUSED = "config_env_not_resolved"
# A field the value does not fit, and one it does.
ROOT_CONFIGS = {
    "int-field": f"workspace:\n  max_parallel_projects: ${{{PROBE_VAR}:unset}}\n",
    "str-field": f"project_name: ${{{PROBE_VAR}:unset}}\n",
}


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A scan root holding a workspace, an operator config root elsewhere, and
    ``ASH_ENV_PROBE`` in the server's environment."""
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv(PROBE_VAR, PROBE)
    clear_profile_registry()
    clear_all_session_state()
    workspace_file = scan_root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "target"}]}), encoding="utf-8"
    )
    yield {"scan_root": scan_root, "workspace_file": workspace_file, "tmp": tmp_path}
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def stdio_workspace(_server, monkeypatch) -> Path:
    """A local install with no grants: the user's own workspace."""
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    return _server["workspace_file"]


@pytest.fixture
def records(monkeypatch) -> List[logging.LogRecord]:
    """Every record any logger is asked to log, at every level."""
    seen: List[logging.LogRecord] = []
    monkeypatch.setattr(logging.Logger, "isEnabledFor", lambda self, level: True)
    monkeypatch.setattr(
        logging.Logger, "handle", lambda self, record: seen.append(record)
    )
    return seen


@pytest.fixture
def errors(monkeypatch) -> List[BaseException]:
    """Every exception resolve_workspace turns into its error reply."""
    from automated_security_helper.cli.mcp import workspace

    seen: List[BaseException] = []
    real = workspace._error_response

    def recording(error, operation, **kwargs):
        seen.append(error)
        return real(error, operation, **kwargs)

    monkeypatch.setattr(workspace, "_error_response", recording)
    return seen


def _root_config(scan_root: Path, text: str) -> Path:
    path = scan_root / ".ash" / ".ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _resolve(workspace_file: Path, session_id: Optional[str]) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    return asyncio.run(
        mcp_resolve_workspace(workspace_file=str(workspace_file), session_id=session_id)
    )


class _SettingsBuilt(Exception):
    """The scan read every config it reads before running anything."""


def _scan(workspace_file: Path, session_id: Optional[str]) -> Dict[str, Any]:
    """The workspace scan up to its settings, which read the root config."""
    from automated_security_helper.cli.mcp import workspace

    real = workspace.build_project_scan_settings

    def built(opts):
        real(opts)
        raise _SettingsBuilt

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(workspace, "build_project_scan_settings", built)
        return asyncio.run(
            workspace._scan_workspace(str(workspace_file), session_id=session_id)
        )


def _chain(error: BaseException) -> List[BaseException]:
    found: List[BaseException] = []
    stack: List[Optional[BaseException]] = [error]
    while stack:
        current = stack.pop()
        if current is None or any(current is seen for seen in found):
            continue
        found.append(current)
        stack += [current.__cause__, current.__context__]
    return found


def _message(record: logging.LogRecord) -> str:
    try:
        return record.getMessage()
    except Exception:  # noqa: BLE001 -- a record whose args do not format
        return f"{record.msg!r} {record.args!r}"


@pytest.mark.parametrize("field", sorted(ROOT_CONFIGS))
def test_a_remote_callers_root_config_using_env_is_refused_without_its_value(
    _server, records, errors, field
):
    _root_config(_server["scan_root"], ROOT_CONFIGS[field])

    result = _resolve(_server["workspace_file"], SESSION)

    assert result["success"] is False, result
    assert result["error_type"] == ENV_REFUSED, result
    assert result["exit_code"] == 3, result
    assert PROBE not in json.dumps(result, default=str)
    assert errors, "resolve_workspace reported no error"
    for error in errors:
        for raised in _chain(error):
            assert PROBE not in str(raised), raised
            assert PROBE not in repr(raised.args), raised
            assert PROBE not in repr(vars(raised)), raised
    assert not [_message(r) for r in records if PROBE in _message(r)]


@pytest.mark.parametrize(
    "text, refused",
    [
        (ROOT_CONFIGS["int-field"], True),
        (ROOT_CONFIGS["str-field"], True),
        ("workspace:\n  max_parallel_projects: 2\n", False),
    ],
    ids=["int-field-env", "str-field-env", "no-env"],
)
def test_planning_and_the_scan_give_one_verdict_for_a_root_config(
    _server, text, refused
):
    _root_config(_server["scan_root"], text)

    planned = _resolve(_server["workspace_file"], SESSION)
    scanned = _scan(_server["workspace_file"], SESSION)

    if refused:
        assert planned["success"] is False, planned
        assert scanned["success"] is False, scanned
        assert planned["error_type"] == scanned["error_type"] == ENV_REFUSED
        assert planned["exit_code"] == scanned["exit_code"] == 3
    else:
        assert planned["success"] is True, planned
        # The scan got past every config it reads.
        assert scanned["success"] is False
        assert scanned["error_type"] == "_SettingsBuilt", scanned


def test_planning_and_the_scan_refuse_a_root_config_linked_outside_the_grant(_server):
    """The session's gate applies to the root config in planning as in the scan."""
    outside = _server["tmp"] / "outside" / "ash.yaml"
    outside.parent.mkdir()
    outside.write_text("workspace:\n  max_parallel_projects: 2\n", encoding="utf-8")
    link = _server["scan_root"] / ".ash" / ".ash.yaml"
    link.parent.mkdir()
    link.symlink_to(outside)

    planned = _resolve(_server["workspace_file"], SESSION)
    scanned = _scan(_server["workspace_file"], SESSION)

    assert planned["success"] is False, planned
    assert scanned["success"] is False, scanned
    assert planned["error_type"] == scanned["error_type"], (planned, scanned)
    assert planned["exit_code"] == scanned["exit_code"], (planned, scanned)
    assert scanned["error_type"] != "_SettingsBuilt", scanned


def test_control_a_local_callers_own_workspace_still_resolves_env(stdio_workspace):
    """A stdio caller launched the server and holds its environment already."""
    _root_config(stdio_workspace.parent, ROOT_CONFIGS["str-field"])

    planned = _resolve(stdio_workspace, None)
    scanned = _scan(stdio_workspace, None)

    assert planned["success"] is True, planned
    assert scanned["error_type"] == "_SettingsBuilt", scanned
