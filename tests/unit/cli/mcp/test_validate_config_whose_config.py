# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which input ``validate_config`` checks as the client's config, for each caller.

The tool reference (``scripts/generate_mcp_tool_reference.py``, ``validate_config``)
and ``mcp_validate_config``'s docstring state two rules, and these tests pin each
case they name:

* The runtime-override policy applies to a remote caller's ``config_content``, and
  to a ``config_path`` that a client delivered or that is outside the directories
  ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` names and a session's ``config/`` directory,
  from any caller. A stdio caller's ``config_content`` is its own.
* A ``${VAR}`` or ``${VAR:default}`` reference at the start of a plain value, or an
  ``!ENV`` tag, is ``config_env_not_resolved`` anywhere in a remote caller's
  client config, and for a stdio caller only in a file a client delivered
  (``config_sources.env_refused_for``).

The default-free ``${VAR}`` form and the quoted form are here because the
reference text names them; the other forms are covered in
``test_config_env_by_caller.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    clear_profile_registry,
    clear_session_state,
)

REMOTE = "client-1"
PROBE_VAR = "ASH_ENV_PROBE"
DENIED = "project_name: whose\nfail_on_findings: false\n"
NO_DEFAULT = f"project_name: ${{{PROBE_VAR}}}\n"
QUOTED = f"project_name: '${{{PROBE_VAR}}}'\n"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scan_root = tmp_path / "scan-root"
    (scan_root / "repo").mkdir(parents=True)
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv(PROBE_VAR, "probe-value")
    clear_profile_registry()
    clear_session_state()
    yield {"repo": scan_root / "repo", "operator": operator}
    clear_profile_registry()
    clear_session_state()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _types(result: Dict[str, Any]) -> List[str]:
    return [error["type"] for error in result["errors"]]


def _validate(**kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    return mcp_validate_config(**kwargs)


@pytest.mark.parametrize("session_id", [DEFAULT_SESSION_ID, REMOTE])
def test_a_named_config_outside_the_config_roots_is_the_clients(
    _server, session_id: str
) -> None:
    """From any caller, stdio included."""
    named = _write(_server["repo"] / "ash.yaml", DENIED)

    result = _validate(config_path=str(named), session_id=session_id)

    assert "denied_by_runtime_policy" in _types(result), result


@pytest.mark.parametrize("session_id", [DEFAULT_SESSION_ID, REMOTE])
def test_a_named_config_in_the_config_roots_is_not_the_clients(
    _server, session_id: str
) -> None:
    named = _write(_server["operator"] / "ash.yaml", DENIED)

    result = _validate(config_path=str(named), session_id=session_id)

    assert result["valid"] is True, result


def test_content_is_the_clients_only_from_a_remote_caller(_server) -> None:
    remote = _validate(config_content=DENIED, session_id=REMOTE)
    local = _validate(config_content=DENIED, session_id=DEFAULT_SESSION_ID)

    assert "denied_by_runtime_policy" in _types(remote), remote
    assert local["valid"] is True, local


def test_a_reference_without_a_default_is_refused_in_remote_content(_server) -> None:
    refused = _validate(config_content=NO_DEFAULT, session_id=REMOTE)
    quoted = _validate(config_content=QUOTED, session_id=REMOTE)

    assert _types(refused) == ["config_env_not_resolved"], refused
    assert quoted["valid"] is True, quoted


def test_a_named_file_no_client_delivered_resolves_references_on_stdio(
    _server,
) -> None:
    named = _write(_server["repo"] / "ash.yaml", NO_DEFAULT)

    local = _validate(config_path=str(named), session_id=DEFAULT_SESSION_ID)
    remote = _validate(config_path=str(named), session_id=REMOTE)

    assert local["valid"] is True, local
    assert "config_env_not_resolved" in _types(remote), remote


def test_a_delivered_file_is_refused_a_reference_on_stdio(_server) -> None:
    from automated_security_helper.cli.mcp.source_delivery import (
        resolve_workspace_root,
    )

    delivered = _write(
        resolve_workspace_root() / DEFAULT_SESSION_ID / "source" / "ash.yaml",
        NO_DEFAULT,
    )

    result = _validate(config_path=str(delivered), session_id=DEFAULT_SESSION_ID)

    assert "config_env_not_resolved" in _types(result), result
