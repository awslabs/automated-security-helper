#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A bound profile has to change which config a scan runs under.

Why this file exists
--------------------
``mcp_select_profile`` was implemented, tested, and documented, and did nothing
that any later call could observe. Three separate breaks, each of which alone was
enough to make the feature unreachable:

1. No CLI flag populated the registry. ``register_profiles`` and
   ``set_profile_registry`` had no production callers at all, so
   ``get_profile_registry()`` was ``{}`` on every real server and
   ``list_profiles`` always returned an empty list. Nothing could be registered,
   so nothing could be selected.
2. ``select_profile`` was never passed to ``@mcp.tool()``, so ``tools/list`` did
   not return it and no client could invoke it.
3. ``bind_session_config`` had no readers. ``SessionState.bound_config`` was
   written and never read, and the scan entry point takes a config *path* rather
   than a resolved ``AshConfig``, so a bound config had nowhere to go.

Fixing 1 and 2 without 3 would be worse than leaving it alone: it publishes a
call that returns ``success: True`` and changes nothing, which is the shape of
defect ``test_tool_surface_parity`` exists to catch. So the tests here assert the
*observable outcome* -- which config path a scan is actually started with -- and
not that a resolver returned a value.

How 3 is closed
---------------
By materializing the resolved config into the session's own sandbox and passing
that path. Not by teaching the orchestrator to accept an in-memory ``AshConfig``:
``ASHScanOrchestrator.__init__`` unconditionally overwrites its ``config`` field
by calling ``resolve_config`` itself, so that change reaches into the
single-project scan path for every caller, and ``workspace/execution.py``'s
docstring already records that as a larger job. Materializing costs one file
write, keeps one code path for config loading, and lands the file inside the
boundary that ``cli/mcp/sandbox.py`` now draws around the session -- so the scan
is permitted to read it and a sibling session is not.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml


@pytest.fixture(autouse=True)
def _isolated_session_state(monkeypatch, tmp_path):
    """A fresh profile registry, fresh session state, and an owned workspace root."""
    from automated_security_helper.cli.mcp import profile_registry

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    # These tests use a real session id, which makes them remote callers and
    # therefore subject to deny-by-default. They are about whether a bound profile
    # reaches the scan, not about confinement, so the operator grant covers
    # everything under tmp_path and the boundary stays out of the way. Without it
    # every scan here is refused before it can record a config path -- which is
    # correct behavior and a useless fixture.
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    yield
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()


def _register(tmp_path: Path, name: str, body: str) -> Path:
    """Register one profile from a YAML body, the way ``--profile`` does."""
    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        set_profile_registry,
    )

    path = tmp_path / f"{name}.ash.yaml"
    path.write_text(body, encoding="utf-8")
    set_profile_registry(register_profiles([f"{name}={path}"]))
    return path


# ---------------------------------------------------------------------------
# 1. The tool is reachable over the protocol
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_select_profile_is_a_registered_tool():
    """``tools/list`` must return it, or no client can call it.

    Derived from the live server object rather than a regex over the source, for
    the reason ``test_tool_surface_parity`` gives: a test that calls the function
    directly cannot see whether the tool is reachable.
    """
    from automated_security_helper.cli.mcp_server import mcp

    names = {tool.name for tool in await mcp.list_tools()}
    assert "select_profile" in names, (
        f"select_profile is not registered, so no client can bind a profile. "
        f"Registered: {sorted(names)}"
    )


def test_the_mcp_command_accepts_profile_specs():
    """Without a CLI flag nothing can ever be registered, so nothing can be bound.

    ``list_profiles`` returning an empty list on every real deployment is the
    visible symptom; this is the cause.
    """
    import inspect

    from automated_security_helper.cli.mcp import mcp_command

    assert "profile" in inspect.signature(mcp_command).parameters, (
        "ash mcp has no --profile option, so register_profiles has no production "
        "caller and the profile registry is empty on every real server"
    )


# ---------------------------------------------------------------------------
# 2. Binding changes which config a scan runs under
# ---------------------------------------------------------------------------


class TestABoundProfileReachesTheScan:
    """The outcome, not the resolver's return value."""

    def test_binding_materializes_a_config_inside_the_session_sandbox(self, tmp_path):
        """The bound config becomes a real file the scan can be handed.

        Inside the sandbox specifically, so the confinement boundary that now
        covers config inputs permits reading it. A config materialized anywhere
        else would be refused by the very gate that protects it.
        """
        from automated_security_helper.cli.mcp.profile_registry import (
            resolve_session_config_path,
        )
        from automated_security_helper.cli.mcp.sandbox import session_sandbox
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        _register(tmp_path, "strict", "project_name: strict-project\n")

        result = mcp_select_profile("strict", session_id="session-a")
        assert result["success"] is True

        bound = resolve_session_config_path("session-a")
        assert bound is not None, "binding recorded no config path for the session"
        assert Path(bound).is_file()
        assert Path(bound).is_relative_to(session_sandbox("session-a").root)

        on_disk = yaml.safe_load(Path(bound).read_text(encoding="utf-8"))
        assert on_disk["project_name"] == "strict-project"

    def test_a_patched_profile_materializes_the_patched_value(self, tmp_path):
        """Inherit-and-patch has to reach the scan too, not just static.

        The discriminator between "the profile's file was copied" and "the
        resolved config was written": the patched value appears in neither the
        profile on disk nor the defaults.
        """
        from automated_security_helper.cli.mcp.profile_registry import (
            resolve_session_config_path,
        )
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        # The runtime-override allowlist is off by default and its defaults deny
        # everything, so a profile that does not opt in cannot be patched at all.
        # Opting in here is what makes the patch reach the resolved config; the
        # denied case is already covered in test_select_profile.py.
        _register(
            tmp_path,
            "base",
            "project_name: before-patch\n"
            "global_settings:\n"
            "  mcp:\n"
            "    runtime_overrides:\n"
            "      enabled: true\n"
            "      allowed_paths:\n"
            "        - /project_name\n"
            "      denied_paths: []\n",
        )

        result = mcp_select_profile(
            "base",
            patch_ops=[
                {"op": "replace", "path": "/project_name", "value": "after-patch"}
            ],
            session_id="session-a",
        )
        assert result["success"] is True, result.get("error")
        assert result["mode"] == "inherit_and_patch"

        bound = Path(resolve_session_config_path("session-a"))
        on_disk = yaml.safe_load(bound.read_text(encoding="utf-8"))
        assert on_disk["project_name"] == "after-patch", (
            "the materialized config carries the unpatched value, so the scan "
            "would run under a config the client did not ask for"
        )

    def test_two_sessions_bind_independently(self, tmp_path):
        """One session's binding must not become another's config.

        A single process-global "current profile" would satisfy every assertion
        above and silently apply one tenant's config to another's scan.
        """
        from automated_security_helper.cli.mcp.profile_registry import (
            register_profiles,
            resolve_session_config_path,
            set_profile_registry,
        )
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        strict = tmp_path / "strict.yaml"
        strict.write_text("project_name: strict-one\n", encoding="utf-8")
        lax = tmp_path / "lax.yaml"
        lax.write_text("project_name: lax-one\n", encoding="utf-8")
        set_profile_registry(register_profiles([f"strict={strict}", f"lax={lax}"]))

        mcp_select_profile("strict", session_id="session-a")
        mcp_select_profile("lax", session_id="session-b")

        a = yaml.safe_load(
            Path(resolve_session_config_path("session-a")).read_text("utf-8")
        )
        b = yaml.safe_load(
            Path(resolve_session_config_path("session-b")).read_text("utf-8")
        )
        assert a["project_name"] == "strict-one"
        assert b["project_name"] == "lax-one"

    def test_an_unbound_session_has_no_config_path(self):
        """Negative control. Without it every assertion above could be a constant."""
        from automated_security_helper.cli.mcp.profile_registry import (
            resolve_session_config_path,
        )

        assert resolve_session_config_path("never-bound") is None


class TestTheScanUsesTheBoundConfig:
    """``run_ash_scan`` with no ``config_path`` picks up the session's binding."""

    @pytest.fixture
    def scan_calls(self, monkeypatch) -> List[Dict[str, Any]]:
        """Record what ``mcp_scan_directory`` is called with, and start no scan.

        The recorded ``config_path`` is the observable this whole file is about:
        it is the value that decides which config the scan actually runs under.
        """
        from automated_security_helper.cli import mcp_server

        calls: List[Dict[str, Any]] = []

        async def _record(**kwargs):
            calls.append(kwargs)
            return {"success": True, "scan_id": "scan-1"}

        monkeypatch.setattr(mcp_server, "mcp_scan_directory", _record)
        monkeypatch.setattr(
            mcp_server,
            "monitor_scan_progress",
            lambda *a, **k: _noop(),
        )
        return calls

    @pytest.mark.asyncio
    async def test_the_bound_config_is_passed_when_the_caller_names_none(
        self, tmp_path, scan_calls
    ):
        from automated_security_helper.cli.mcp.profile_registry import (
            resolve_session_config_path,
        )
        from automated_security_helper.cli.mcp_server import run_ash_scan
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        _register(tmp_path, "strict", "project_name: strict-project\n")
        mcp_select_profile("strict", session_id="session-a")

        target = tmp_path / "checkout"
        target.mkdir()
        ctx = _FakeContext({"mcp-session-id": "session-a"})

        await run_ash_scan(ctx, source_dir=str(target))

        assert len(scan_calls) == 1
        assert scan_calls[0]["config_path"] == resolve_session_config_path(
            "session-a"
        ), (
            "the scan was started without the session's bound config, so "
            "select_profile returned success and changed nothing"
        )

    @pytest.mark.asyncio
    async def test_an_explicit_config_path_still_wins(self, tmp_path, scan_calls):
        """A binding is a default, not an override.

        The caller naming a config on the call is the more specific statement, and
        silently replacing it with a session default would make the explicit
        argument a lie.
        """
        from automated_security_helper.cli.mcp_server import run_ash_scan
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        _register(tmp_path, "strict", "project_name: strict-project\n")
        mcp_select_profile("strict", session_id="session-a")

        target = tmp_path / "checkout"
        target.mkdir()
        explicit = target / ".ash.yaml"
        explicit.write_text("project_name: explicit\n", encoding="utf-8")
        ctx = _FakeContext({"mcp-session-id": "session-a"})

        await run_ash_scan(ctx, source_dir=str(target), config_path=str(explicit))

        assert scan_calls[0]["config_path"] == str(explicit)

    @pytest.mark.asyncio
    async def test_an_unbound_session_passes_no_config(self, tmp_path, scan_calls):
        """Negative control: the threading must not invent a path."""
        from automated_security_helper.cli.mcp_server import run_ash_scan

        target = tmp_path / "checkout"
        target.mkdir()
        ctx = _FakeContext({"mcp-session-id": "session-unbound"})

        await run_ash_scan(ctx, source_dir=str(target))

        assert scan_calls[0]["config_path"] is None


async def _noop() -> None:
    return None


class _FakeContext:
    """The slice of ``Context`` the tools under test touch."""

    def __init__(self, headers: Optional[Dict[str, str]] = None) -> None:
        self.headers = headers or {}
        self.messages: List[str] = []

    async def info(self, message: str) -> None:
        self.messages.append(f"info: {message}")

    async def error(self, message: str) -> None:
        self.messages.append(f"error: {message}")

    async def warning(self, message: str) -> None:
        self.messages.append(f"warning: {message}")

    async def debug(self, message: str) -> None:
        self.messages.append(f"debug: {message}")

    async def report_progress(self, **kwargs) -> None:
        return None
