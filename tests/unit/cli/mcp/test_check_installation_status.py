# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""check_installation reports what the scanners' own dependency checks find.

Why this file exists
--------------------
The agent plugins tell a client to call check_installation before the first
scan and to stop if it fails, so its answer is the one place a missing tool
can show up. Reading ASH's version and checking nothing else would return
``installed: True`` and ``ash_command_available: True`` whatever the host had,
and a server whose every scanner tool was missing would say it was ready.

So it runs each built-in scanner's dependency check, the one list_scanners
reports and a scan runs before starting a scanner, and says which enabled
scanners can run: ``installed`` (ASH plus at least one runnable scanner),
``ready`` (all of them), and the names in ``missing_dependencies`` and
``undetermined_dependencies``.

It asks only the scanners ASH ships in ash_builtin. list_scanners also imports
the community plugin packages and any installed ash_*_plugins distribution; an
installation check has no reason to run their code, so it does not.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from tests.utils.tool_guard import stub_tool_probes


def _entry(
    name: str, enabled: bool, satisfied: Optional[bool], first_scan: bool = False
) -> Dict[str, Any]:
    return {
        "name": name,
        "enabled": enabled,
        "dependencies_satisfied": satisfied,
        "version": "1.0" if satisfied else None,
        "offline_strategy": "bundled",
        "installs_on_first_scan": first_scan,
    }


async def _check(inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
    with patch.object(mcp_tools, "list_scanner_inventory", return_value=inventory):
        result = await mcp_tools.mcp_check_installation()
    assert result["success"] is True, result
    return result


@pytest.mark.asyncio
async def test_every_enabled_scanner_can_run():
    result = await _check([_entry("bandit", True, True), _entry("semgrep", True, True)])
    assert (result["installed"], result["ready"]) == (True, True)
    assert result["missing_dependencies"] == []
    assert [s["name"] for s in result["scanners"]] == ["bandit", "semgrep"]


@pytest.mark.asyncio
async def test_a_missing_tool_is_named_and_the_server_is_not_ready():
    result = await _check([_entry("bandit", True, True), _entry("grype", True, False)])
    assert (result["installed"], result["ready"]) == (True, False)
    assert result["missing_dependencies"] == ["grype"]


@pytest.mark.asyncio
async def test_no_runnable_scanner_is_not_installed():
    result = await _check([_entry("bandit", True, False), _entry("grype", True, False)])
    assert (result["installed"], result["ready"]) == (False, False)
    assert result["missing_dependencies"] == ["bandit", "grype"]


@pytest.mark.asyncio
async def test_a_disabled_scanner_does_not_count():
    result = await _check([_entry("bandit", True, True), _entry("snyk", False, False)])
    assert (result["installed"], result["ready"]) == (True, True)
    assert result["missing_dependencies"] == []


@pytest.mark.asyncio
async def test_a_tool_the_first_scan_installs_is_runnable_and_not_missing():
    """Not installed yet, but a scan installs it with uv: runnable, and ready.

    Only the real-host check below reached this rule, and on a host where every
    uv tool is already installed it never did.
    """
    result = await _check(
        [
            _entry("bandit", True, False, first_scan=True),
            _entry("grype", True, False),
        ]
    )
    assert result["installs_on_first_scan"] == ["bandit"], result
    assert result["missing_dependencies"] == ["grype"], result
    assert (result["installed"], result["ready"]) == (True, False)

    only_first_scan = await _check([_entry("semgrep", True, False, first_scan=True)])
    assert (only_first_scan["installed"], only_first_scan["ready"]) == (True, True)


@pytest.mark.asyncio
async def test_a_check_that_could_not_run_is_not_ready():
    result = await _check([_entry("bandit", True, True), _entry("cdk_nag", True, None)])
    assert result["ready"] is False
    assert result["undetermined_dependencies"] == ["cdk_nag"]


@pytest.mark.asyncio
async def test_only_the_built_in_scanners_are_asked():
    from automated_security_helper.plugin_modules.ash_builtin import ASH_SCANNERS

    seen = {}

    def inventory(provider, **kwargs):
        seen["classes"] = provider()
        return []

    def community_loader():
        raise AssertionError("check_installation imported the community plugins")

    with (
        patch.object(mcp_tools, "list_scanner_inventory", side_effect=inventory),
        patch.object(mcp_tools, "_loaded_scanner_classes", community_loader),
    ):
        await mcp_tools.mcp_check_installation()

    assert seen["classes"] == list(ASH_SCANNERS)


@pytest.mark.asyncio
async def test_the_ash_command_is_looked_up_not_assumed():
    with patch("shutil.which", return_value=None):
        result = await _check([_entry("bandit", True, True)])
    assert result["ash_command_available"] is False


#: Where the server's ash executable is, which a remote client must not learn.
HIDDEN_ASH = "/opt/operator-only/bin/ash"


def _ctx(headers: Dict[str, str]) -> MagicMock:
    from mcp.server.mcpserver import Context

    ctx = MagicMock(spec=Context)
    ctx.headers = headers
    ctx.info = AsyncMock()
    ctx.error = AsyncMock()
    return ctx


@pytest.mark.asyncio
async def test_a_remote_session_is_not_told_where_ash_is(monkeypatch):
    """A client the server did not launch learns that ash is there, not its path.

    An answer of shutil.which("ash") would hand every caller an absolute path
    on the server's filesystem. A stdio client is the operator's own process,
    which may see it; a session over the network may not.
    """
    from automated_security_helper.cli import mcp_server

    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    with (
        patch.object(
            mcp_tools,
            "list_scanner_inventory",
            return_value=[_entry("bandit", True, True)],
        ),
        patch("shutil.which", return_value=HIDDEN_ASH),
    ):
        remote = await mcp_server.check_installation(
            _ctx({"mcp-session-id": "client-session-1"})
        )
        local = await mcp_server.check_installation(_ctx({}))

    assert remote["success"] is True, remote
    assert remote["ash_command_available"] is True, remote
    assert "/opt/operator-only" not in json.dumps(remote), remote
    assert local["ash_command_output"] == HIDDEN_ASH, local


@pytest.mark.asyncio
async def test_concurrent_checks_do_not_run_their_probes_at_once(monkeypatch):
    """Each check starts one probe per scanner; two at once would double that.

    The inventory is serialized: a second call waits for the first one's
    probes to finish before it starts its own.
    """
    from automated_security_helper.core import scanner_inventory

    active = {"now": 0, "most": 0}
    lock = threading.Lock()

    def describe(provider, concurrent):
        with lock:
            active["now"] += 1
            active["most"] = max(active["most"], active["now"])
        try:
            time.sleep(0.3)
            return []
        finally:
            with lock:
                active["now"] -= 1

    monkeypatch.setattr(scanner_inventory, "_describe_scanners", describe)

    results = await asyncio.gather(
        mcp_tools.mcp_check_installation(),
        mcp_tools.mcp_check_installation(),
        mcp_tools.mcp_check_installation(),
    )

    assert all(result["success"] for result in results), results
    assert active["most"] == 1, f"{active['most']} inventories ran at once"


@pytest.fixture
def own_home(tmp_path, monkeypatch):
    """A home, uv tool directory and ASH bin directory of the test's own.

    The real checks look tools up there, so with the runner's own they answered
    from whatever that machine had installed, and the checks' caches landed in
    its home. Here the uv-installed tools are absent, so the scanners a scan would
    install with uv are reported as installing on the first scan.
    """
    from automated_security_helper.utils import subprocess_utils, uv_tool_runner

    for name in ("home", "config", "cache", "data", "uv-tools", "uv-bin", "uv-cache"):
        (tmp_path / name).mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("UV_TOOL_DIR", str(tmp_path / "uv-tools"))
    monkeypatch.setenv("UV_TOOL_BIN_DIR", str(tmp_path / "uv-bin"))
    monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "uv-cache"))
    monkeypatch.setattr(subprocess_utils, "ASH_BIN_PATH", tmp_path / "uv-bin")
    monkeypatch.delenv("ASH_OFFLINE", raising=False)

    def reset() -> None:
        subprocess_utils.clear_find_executable_cache()
        uv_tool_runner._reset_uv_tool_runner_caches()
        uv_tool_runner.reset_uv_tool_runner()

    reset()
    yield
    reset()


@pytest.mark.asyncio
async def test_on_this_host(own_home, monkeypatch):
    """No doubles: the real checks, for the real built-in scanners.

    The verdicts are checked against the scanners' own answers, by the rules the
    tool documents, including that a scanner whose tool the first scan installs
    counts as runnable and is never missing.

    The checks' probes answer as a host without uv would (``stub_tool_probes``):
    unanswered, they ran ``uv tool list`` and ``uv tool run --offline ... --version``
    for bandit, checkov, detect-secrets and semgrep.
    """
    stub_tool_probes(monkeypatch)
    result = await mcp_tools.mcp_check_installation()

    assert result["success"] is True
    scanners = result["scanners"]
    names = {s["name"] for s in scanners}
    assert {"bandit", "detect_secrets"} <= names, names
    for scanner in scanners:
        assert scanner["dependencies_satisfied"] in (True, False, None), scanner
    enabled = [s for s in scanners if s["enabled"]]
    first_scan = sorted(s["name"] for s in enabled if s["installs_on_first_scan"])
    missing = sorted(
        s["name"]
        for s in enabled
        if s["dependencies_satisfied"] is False and not s["installs_on_first_scan"]
    )
    undetermined = sorted(
        s["name"] for s in enabled if s["dependencies_satisfied"] is None
    )
    runnable = [
        s
        for s in enabled
        if s["dependencies_satisfied"] is True or s["installs_on_first_scan"]
    ]
    assert result["installs_on_first_scan"] == first_scan, result
    assert result["missing_dependencies"] == missing, result
    assert result["undetermined_dependencies"] == undetermined, result
    assert result["installed"] is bool(runnable), result
    assert result["ready"] is (bool(enabled) and not missing and not undetermined)
