# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan tool's remaining refusal arms carry ``exit_code`` and its meaning.

The module documents one exit code per refusal (3 for a config the scan cannot
use, 5 for the request itself, 4 for a target, 1 for anything else), and
``run_ash_scan`` passes a ``scan_directory`` refusal on unchanged, promising that
code. Several arms returned without one: the unidentified-session refusal, an
empty ``config_path``, a discovered config that does not load, the busy-source
refusal, the per-session limit, the runtime-policy denials and the two arms of
the policy check that cannot run. A client branching on ``exit_code`` read a
missing key for one class of refusal and 3 for the same class reached another
way. Each arm now carries the code its class documents.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from automated_security_helper.core.constants import ASH_EXIT_CODES

pytestmark = pytest.mark.unit

CONFIG, TARGET, USAGE, INTERNAL = 3, 4, 5, 1
SESSION = "client-one"


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    from automated_security_helper.cli.mcp import sessions, source_delivery
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    monkeypatch.setattr(source_delivery, "_SESSION_SOURCE_DIRS", {})
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    sessions.reset_default_registry_for_tests()
    yield {"scan": scan, "tmp": tmp_path}
    sessions.reset_default_registry_for_tests()


@pytest.fixture
def no_scan_runs(monkeypatch) -> list:
    from automated_security_helper.cli import mcp_tools

    started: list = []

    def record(scan_id, coroutine, **kwargs) -> None:
        coroutine.close()
        started.append(scan_id)

    monkeypatch.setattr(mcp_tools, "_start_scan_task", record)
    return started


def _assert_refused_with(response: Dict[str, Any], code: int) -> None:
    assert response["success"] is False, response
    assert response["exit_code"] == code, response
    assert response["exit_code_meaning"] == ASH_EXIT_CODES[code], response


def _scan_directory(**kwargs: Any) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    kwargs.setdefault("session_id", SESSION)
    return asyncio.run(mcp_scan_directory(**kwargs))


def test_an_unidentified_session_is_refused_as_usage(layout, no_scan_runs) -> None:
    from automated_security_helper.cli.mcp.session_identity import (
        UNIDENTIFIED_SESSION_ID,
    )

    response = _scan_directory(
        directory_path=str(layout["scan"]), session_id=UNIDENTIFIED_SESSION_ID
    )

    assert response["error_type"] == "session_identity_required", response
    _assert_refused_with(response, USAGE)


def test_an_empty_config_path_is_refused_as_usage(layout, no_scan_runs) -> None:
    response = _scan_directory(directory_path=str(layout["scan"]), config_path="  ")

    assert "empty" in response["error"], response
    _assert_refused_with(response, USAGE)


def test_a_discovered_config_that_does_not_load_is_refused_as_a_config(
    layout, no_scan_runs, monkeypatch
) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.resource_management.error_handling import (
        ErrorCategory,
    )
    from automated_security_helper.core.resource_management.exceptions import (
        MCPResourceError,
    )

    not_discovered = MCPResourceError(
        "The configuration found in the target cannot be loaded: a syntax error",
        context={"error_category": ErrorCategory.INVALID_FORMAT.value},
    )
    monkeypatch.setattr(
        mcp_tools, "_discovered_config_path", lambda *a, **k: (None, not_discovered)
    )

    response = _scan_directory(directory_path=str(layout["scan"]))

    assert "cannot be loaded" in response["error"], response
    _assert_refused_with(response, CONFIG)


def test_a_busy_delivered_source_is_refused_with_the_code_for_anything_else(
    layout, no_scan_runs
) -> None:
    from automated_security_helper.cli.mcp import sessions

    session = sessions.get_default_registry().session_for(SESSION)
    assert session.try_begin_change() is None
    try:
        response = _scan_directory(directory_path=str(layout["scan"]))
    finally:
        session.end_change()

    assert response["error_type"] == "source_delivery_busy", response
    _assert_refused_with(response, INTERNAL)


def test_the_per_session_limit_is_refused_with_the_code_for_anything_else(
    layout, no_scan_runs, monkeypatch
) -> None:
    from automated_security_helper.cli.mcp import sessions

    operator = layout["tmp"] / "operator.yaml"
    operator.write_text(
        "project_name: operator\n"
        "mcp-resource-management:\n"
        "  max_concurrent_scans_per_session: 1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    session = sessions.get_default_registry().session_for(SESSION)
    assert session.try_start_scan(1)
    try:
        response = _scan_directory(directory_path=str(layout["scan"]))
    finally:
        session.scan_returned()

    assert response["error_type"] == "session_scan_limit", response
    _assert_refused_with(response, INTERNAL)


@pytest.mark.parametrize("kind", ["field_denied", "policy_unreadable"])
def test_a_runtime_policy_denial_is_refused_as_a_config(kind: str) -> None:
    from automated_security_helper.cli.mcp_tools import _denied_response
    from automated_security_helper.core.exceptions import (
        ASHConfigFieldDeniedError,
        ASHConfigPolicyUnreadableError,
    )

    error = (
        ASHConfigFieldDeniedError("global_settings.x may not be set")
        if kind == "field_denied"
        else ASHConfigPolicyUnreadableError("the bound profile is gone")
    )

    response = _denied_response(error, "scan_directory")

    assert response["error_type"] == (
        "config_field_denied" if kind == "field_denied" else "config_policy_unreadable"
    ), response
    _assert_refused_with(response, CONFIG)


def test_a_config_that_does_not_load_or_validate_is_refused_as_a_config(
    layout,
) -> None:
    from automated_security_helper.cli.mcp_tools import _load_error_response
    from automated_security_helper.core.resource_management.error_handling import (
        ErrorCategory,
    )
    from automated_security_helper.core.resource_management.exceptions import (
        MCPResourceError,
    )

    checked = SimpleNamespace(
        document=None,
        load_error=MCPResourceError(
            "Configuration file ash.yaml cannot be loaded: it could not be parsed",
            context={"error_category": ErrorCategory.INVALID_FORMAT.value},
        ),
    )

    response = _load_error_response(checked, None, layout["scan"], None)

    _assert_refused_with(response, CONFIG)


def test_session_rules_that_cannot_be_read_refuse_as_a_config(
    layout, no_scan_runs, monkeypatch
) -> None:
    from automated_security_helper.cli import mcp_tools

    def unreadable(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the registered profile could not be read")

    monkeypatch.setattr(mcp_tools, "_session_client_rules", unreadable)

    response = _scan_directory(directory_path=str(layout["scan"]))

    assert response["error_type"] == "config_policy_unreadable", response
    _assert_refused_with(response, CONFIG)


def test_a_policy_check_that_breaks_is_a_start_failure_with_the_internal_code(
    layout, no_scan_runs, monkeypatch
) -> None:
    from automated_security_helper.config import client_config_policy

    (layout["scan"] / ".ash.yaml").write_text("project_name: scan\n", encoding="utf-8")

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the check broke")

    monkeypatch.setattr(client_config_policy, "apply_client_config_rules", broken)

    response = _scan_directory(directory_path=str(layout["scan"]))

    assert response["error_type"] == "scan_start_failure", response
    _assert_refused_with(response, INTERNAL)
    assert no_scan_runs == []
