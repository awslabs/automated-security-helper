# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client-patched copy of a profile that reads a denied list from the environment still scans.

``config_document_denials`` withholds the repeat exemption from a leaf the trusted
config read from the environment, and (since the list case was closed) from a
list holding such an entry. A session's client-patched profile copy is checked
with ``repeats_trusted`` against the registered profile, so the question this
pins: does an operator's profile whose default-denied ``ignore_paths`` entry is
written as ``${VAR}`` still scan after a client patches an allowed key? The copy
the server writes holds the reference as the file wrote it, not the value, and
the scan fills the value from the operator's copy; what reaches the policy check
is never the value, so the withholding changes no outcome here. Measured, not
read: the scan resolves an AshConfig with the client's change and the
operator's environment value.

The route is ``mcp_select_profile`` with ``patch_ops`` and then the real
``_run_scan_async`` up to config resolution, as tests/unit/cli/mcp/
test_select_profile_patch_is_the_clients.py drives it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
    register_profiles,
    resolve_session_config_path,
    set_profile_registry,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

SESSION = "client-u35"
CANARY = "ash-canary-x35c-qzvy-ignored"


class _QuietLogger:
    """Stands in for ``_setup_logger``'s logger, which configures global handlers."""

    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_X35_IGN", CANARY)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"target": target, "operator": operator}
    clear_profile_registry()
    clear_all_session_state()


def _register(operator: Path, text: str) -> None:
    path = operator / "op.yaml"
    path.write_text(text, encoding="utf-8")
    set_profile_registry(register_profiles([f"op={path}"]))


def _bind(patch_ops: List[Dict[str, Any]]) -> str:
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    result = mcp_select_profile("op", session_id=SESSION, patch_ops=patch_ops)
    assert result["success"] is True, result
    bound = resolve_session_config_path(SESSION)
    assert bound == result["config_path"]
    return bound


def _scan_outcome(target: Path) -> Any:
    """What a scan of ``target`` resolves with the config the session bound: the
    AshConfig, or the exception resolution raised."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management import scan_management
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    config_path = resolve_session_config_path(SESSION)
    assert config_path is not None
    resolved: List[Any] = []
    real = rc.resolve_config

    def recording(*args: Any, **kwargs: Any) -> AshConfig:
        try:
            resolved.append(real(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001 -- the outcome under test
            resolved.append(exc)
        raise _StopAfterResolution

    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    # The scan is the session's, as the directory tool registers it: the
    # sandbox admits the scan's own copy of the operator's profile only for a
    # scan its session holds (``session_holds_scan`` reads the registry through
    # ``scan_management``), so both bindings answer from this one registry.
    scan_id = registry.register_scan(
        directory_path=str(target),
        output_directory=str(output),
        session_id=SESSION,
    )
    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(orchestrator, "resolve_config", recording),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
        patch.object(scan_management, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(target),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=config_path,
                session_id=SESSION,
            )
        )
    assert len(resolved) == 1, "the scan never reached config resolution"
    return resolved[0]


PROFILE = (
    "project_name: operator\n"
    "global_settings:\n"
    "  ignore_paths:\n"
    "    - path: ${ASH_X35_IGN}\n"
    "      reason: environment\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /project_name\n"
)


def test_the_patched_copy_scans_with_the_operators_environment_value(server) -> None:
    _register(server["operator"], PROFILE)
    _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    outcome = _scan_outcome(server["target"])

    assert isinstance(outcome, AshConfig), outcome
    assert outcome.project_name == "patched"
    assert [entry.path for entry in outcome.global_settings.ignore_paths] == [CANARY]


def test_the_copy_holds_the_reference_not_the_value(server) -> None:
    """The fact the pin rests on: the client's copy is written with the
    reference as the profile wrote it; the value never reaches the file the
    policy check reads."""
    _register(server["operator"], PROFILE)
    bound = _bind([{"op": "replace", "path": "/project_name", "value": "patched"}])

    text = Path(bound).read_text(encoding="utf-8")

    assert "${ASH_X35_IGN}" in text, text
    assert CANARY not in text, text
