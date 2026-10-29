# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An MCP override that is refused is named by its op and path, or its key, never a value.

``select_profile``'s ``patch_ops`` and ``override_yaml``, and the workspace
tools' ``config_overrides``, change the operator's registered profile under its
``runtime_overrides`` allowlist. When one is refused, or does not apply, the
reply goes to the client and the message to the server's log. Neither holds
the value the client sent, which can be a credential, nor a value the profile
read from the server's environment (``!ENV``): not in the reply, not in what
the tool sends the client, and not in a log record at any level. The error
still names what was refused and where. Both values are made up when a cell
runs.

Every case runs through the MCP tool itself.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
    get_profile_registry,
    register_profiles,
    set_profile_registry,
)

pytestmark = pytest.mark.unit

SESSION = "override-values-client"

NARROW = ["/project_name", "/missing_parent/**", "/no_such_field"]


@pytest.fixture
def values() -> Dict[str, str]:
    """What the server's environment holds, and what the client's change carries."""
    return {
        "server": f"server-{secrets.token_hex(6)}",
        "client": f"client-{secrets.token_hex(6)}",
    }


class _Context:
    """The slice of ``Context`` the tools touch, keeping what they send the client."""

    def __init__(self) -> None:
        self.headers = {"mcp-session-id": SESSION}
        self.messages: List[str] = []

    async def info(self, message: str) -> None:
        self.messages.append(message)

    async def error(self, message: str) -> None:
        self.messages.append(message)

    async def warning(self, message: str) -> None:
        self.messages.append(message)

    async def debug(self, message: str) -> None:
        self.messages.append(message)

    async def report_progress(self, **kwargs: Any) -> None:
        return None


class _Keep(logging.Handler):
    def __init__(self, sink: List[str]) -> None:
        super().__init__(level=1)
        self.sink = sink
        self.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        # format() appends the traceback, chained causes included.
        self.sink.append(self.format(record))


@pytest.fixture
def logged() -> Iterator[List[str]]:
    """Every record at every level, from the root and every logger that does not
    propagate."""
    sink: List[str] = []
    handler = _Keep(sink)
    loggers = [logging.getLogger()] + [
        logger
        for logger in logging.Logger.manager.loggerDict.values()
        if isinstance(logger, logging.Logger) and not logger.propagate
    ]
    if logging.getLogger("ash") not in loggers:
        loggers.append(logging.getLogger("ash"))
    levels = [(logger, logger.level) for logger in loggers]
    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(1)
    try:
        yield sink
    finally:
        for logger, level in levels:
            logger.removeHandler(handler)
            logger.setLevel(level)


@pytest.fixture
def server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, values: Dict[str, str]
) -> Iterator[Dict[str, Path]]:
    monkeypatch.setenv("ASH_PROBE_VALUE", values["server"])
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    workspace = tmp_path / "ws"
    (workspace / "app").mkdir(parents=True)
    (workspace / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = workspace / "dev.code-workspace"
    workspace_file.write_text(json.dumps({"folders": [{"path": "app"}]}))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(workspace))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(workspace))
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    for name, allowed in (("narrow", NARROW), ("wide", ["/**"])):
        (profiles / f"{name}.yaml").write_text(
            "project_name: !ENV ${ASH_PROBE_VALUE}\n"
            "global_settings:\n"
            "  mcp:\n"
            "    runtime_overrides:\n"
            "      enabled: true\n"
            f"      allowed_paths: {json.dumps(allowed)}\n",
            encoding="utf-8",
        )
    clear_profile_registry()
    clear_all_session_state()
    set_profile_registry(
        register_profiles(
            [f"narrow={profiles / 'narrow.yaml'}", f"wide={profiles / 'wide.yaml'}"]
        )
    )
    # Every case rests on this: the registered profile holds the value the
    # server's environment gave it.
    assert get_profile_registry()["narrow"].config.project_name == values["server"]
    yield {"workspace_file": workspace_file}
    clear_profile_registry()
    clear_all_session_state()


def _select(
    profile: str,
    *,
    patch_ops: Optional[list] = None,
    override_yaml: Optional[str] = None,
) -> tuple[Dict[str, Any], _Context]:
    ctx = _Context()
    result = asyncio.run(
        mcp_server.select_profile(
            ctx, profile_name=profile, patch_ops=patch_ops, override_yaml=override_yaml
        )
    )
    return result, ctx


def _workspace_tool(
    tool: str, workspace_file: Path, profile: str, overrides: List[str]
) -> tuple[Dict[str, Any], _Context]:
    bound, _ = _select(profile)
    assert bound["success"] is True, bound
    ctx = _Context()
    result = asyncio.run(
        getattr(mcp_server, tool)(
            ctx, workspace_file=str(workspace_file), config_overrides=overrides
        )
    )
    return result, ctx


def _assert_refused_without_values(
    result: Dict[str, Any],
    ctx: _Context,
    logged: List[str],
    values: Dict[str, str],
    *named: str,
) -> None:
    assert result["success"] is False, result
    seen = {
        "the reply": json.dumps(result, default=str),
        "what the tool sent the client": "\n".join(ctx.messages),
        "the server log": "\n".join(logged),
    }
    for where, text in seen.items():
        for whose, value in values.items():
            assert value not in text, f"{where} holds the {whose}'s value: {text}"
    # Still useful: the error names what was refused, and where.
    for part in named:
        assert part in str(result["error"]), result["error"]


@pytest.mark.parametrize(
    "op, named",
    [
        pytest.param(
            {"op": "test", "path": "/project_name"},
            ["'test'", "'/project_name'"],
            id="a-failing-test-op",
        ),
        pytest.param(
            {"op": "test", "path": "/no_such_field"},
            ["'test'", "'/no_such_field'"],
            id="a-test-op-at-a-missing-member",
        ),
        pytest.param(
            {"op": "add", "path": "/missing_parent/child"},
            ["'add'", "'/missing_parent/child'"],
            id="a-pointer-through-a-missing-member",
        ),
        pytest.param(
            {"op": "replace", "path": "/output_dir"},
            ["'replace'", "'/output_dir'", "allowed_paths"],
            id="a-denied-op",
        ),
    ],
)
def test_a_refused_patch_op_is_named_by_op_and_path(
    server, values, logged, op: Dict[str, Any], named: List[str]
) -> None:
    result, ctx = _select("narrow", patch_ops=[{**op, "value": values["client"]}])

    _assert_refused_without_values(result, ctx, logged, values, *named)


def test_a_refused_override_yaml_is_named_by_op_and_path(
    server, values, logged
) -> None:
    override = (
        "project_name: client-name\n"
        f"external_reports_to_include: [{values['client']}]\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        f"      allowed_paths: {json.dumps(NARROW)}\n"
    )

    result, ctx = _select("narrow", override_yaml=override)

    _assert_refused_without_values(
        result, ctx, logged, values, "'/external_reports_to_include", "allowed_paths"
    )


@pytest.mark.parametrize(
    "override, named",
    [
        pytest.param(
            "project_name: client-name\nfail_on_findings: {value}\n",
            ["fail_on_findings"],
            id="a-value-the-config-refuses",
        ),
        pytest.param(
            "project_name: client-name\nfail_on_findings: {value}: oops\n",
            ["line 2"],
            id="yaml-that-does-not-parse",
        ),
        pytest.param(
            "project_name: client-name\nfail_on_findings: [{value}\n",
            ["override_yaml parse error"],
            id="yaml-that-ends-early",
        ),
    ],
)
def test_an_override_yaml_that_does_not_load_is_described_without_its_values(
    server, values, logged, override: str, named: List[str]
) -> None:
    result, ctx = _select(
        "narrow", override_yaml=override.format(value=values["client"])
    )

    _assert_refused_without_values(result, ctx, logged, values, *named)


@pytest.mark.parametrize("tool", ["resolve_ash_workspace", "run_ash_workspace_scan"])
@pytest.mark.parametrize(
    "profile, override, named",
    [
        pytest.param(
            "narrow",
            "output_dir={value}",
            ["'add'", "'/output_dir'", "allowed_paths"],
            id="a-denied-override",
        ),
        pytest.param(
            "wide",
            "global_settings.not_a_field={value}",
            ["global_settings.not_a_field"],
            id="a-key-the-config-refuses",
        ),
        pytest.param(
            "wide",
            "fail_on_findings={value}",
            ["fail_on_findings"],
            id="a-value-the-config-refuses",
        ),
        pytest.param(
            "wide",
            "={value}",
            ["Invalid config override", "key.path=value"],
            id="no-key",
        ),
    ],
)
def test_a_refused_config_override_is_named_by_its_key(
    server,
    values,
    logged,
    tool: str,
    profile: str,
    override: str,
    named: List[str],
) -> None:
    result, ctx = _workspace_tool(
        tool,
        server["workspace_file"],
        profile,
        [override.format(value=values["client"])],
    )

    _assert_refused_without_values(result, ctx, logged, values, *named)


def test_control_a_patch_op_the_allowlist_permits_is_applied(server) -> None:
    result, _ = _select(
        "narrow",
        patch_ops=[{"op": "replace", "path": "/project_name", "value": "client-name"}],
    )

    assert result["success"] is True, result
    assert result["mode"] == "inherit_and_patch"
