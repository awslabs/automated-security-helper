# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan's redaction set is read under the scan's own resolution rules.

The runner reads the trusted profile's environment values into the redaction
set before the scan. If that read resolved the profile's ``extends`` chain
under different rules than the scan's own read, a chain the scan accepts
could be dropped from the set exactly when its values are in use. The runner
therefore reads the values through the same loader the scan uses for the
trusted base, with the scan's source directory and the session's base gate,
so a chain is in the set exactly when the scan runs with it.

Two arms pin the agreement from both sides. A base beside the profile is
accepted by both reads: its values are in the set and every failure surface
hides them. A base inside the scan target is refused by both reads -- config
bases must stay inside the profile's own directory when the profile sits
outside the scanned tree -- so the scan itself fails before any value is
read, and the refusal's text shows none.

Driven as the rebind cells are: a real session sandbox, the profile bound
through the registry, and only ``run_ash_scan`` replaced by a stand-in that
resolves its config exactly as the orchestrator would and then fails quoting
every value that resolution read.
"""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.log import ASHLogger
from tests.utils.tasks import drain

_TOOLS = "automated_security_helper.cli.mcp_tools"
_MGMT = "automated_security_helper.core.resource_management.scan_management"

_SID = "gates-session"
_PROFILE_VALUE = "a-profile-value-read-from-the-environment"
_BASE_VALUE = "a-base-value-the-profiles-chain-read"


@pytest.mark.parametrize("chain", ["accepted", "refused"])
def test_the_set_and_the_scan_judge_the_profiles_chain_together(
    tmp_path, monkeypatch, chain
):
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.resolve_config import (
        _load_operator_config,
        resolve_config,
    )

    ws = tmp_path / "ws"
    target = ws / _SID / "source" / "repo"
    target.mkdir(parents=True)
    config_dir = ws / _SID / "config"
    config_dir.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(ws))
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    monkeypatch.setenv("ASH_GATES_PROFILE", _PROFILE_VALUE)
    monkeypatch.setenv("ASH_GATES_BASE", _BASE_VALUE)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    delivered = target / "client.ash.yaml"
    delivered.write_text("project_name: delivered\n", encoding="utf-8")
    if chain == "accepted":
        base = config_dir / "base.ash.yaml"
        extends_ref = "base.ash.yaml"
    else:
        base = target / "base.ash.yaml"
        extends_ref = base.as_posix()
    base.write_text("project_name: ${ASH_GATES_BASE:unset}\n", encoding="utf-8")
    profile = config_dir / "ash.yaml"
    profile.write_text(
        f"extends:\n  - {extends_ref}\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: ${ASH_GATES_PROFILE:unset}\n"
        "      path: never-matched\n"
        "      reason: pinned by the gates cell\n",
        encoding="utf-8",
    )
    assert config_is_client_supplied(delivered)
    assert not config_is_client_supplied(profile)
    profile_registry.bind_session_config(
        _SID, config=AshConfig(), profile_name="gates", config_path=str(profile)
    )
    assert profile_registry.resolve_session_config_path(_SID) == str(profile)

    loaded = {}

    def a_run_that_resolves_as_the_orchestrator_would(*args, **kwargs):
        try:
            config = resolve_config(
                config_path=kwargs["config"],
                source_dir=kwargs["source_dir"],
                config_overrides=[],
                permit_base=kwargs["config_base_gate"],
                trusted_config_path=kwargs["trusted_config_path"],
                untrusted_config=kwargs["untrusted_config"],
            )
        except BaseException as trouble:
            loaded["resolve_trouble"] = repr(trouble)
            raise
        operator = _load_operator_config(
            kwargs["trusted_config_path"],
            kwargs["source_dir"],
            kwargs["config_base_gate"],
        )
        loaded["values"] = list(
            dict.fromkeys(
                [
                    *config._environment_values,
                    *(operator.config._environment_values if operator else []),
                ]
            )
        )
        raise RuntimeError("the tool quoted: " + " | ".join(loaded["values"]))

    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(delivered), session_id=_SID
        )
        await drain(return_exceptions=True)
        return started

    try:
        with (
            patch.object(
                ras, "run_ash_scan", a_run_that_resolves_as_the_orchestrator_would
            ),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", logger),
        ):
            started = asyncio.run(start_and_wait_for_the_runner())
            scans = registry.list_scans()
            if len(scans) != 1 or started.get("success") is not True:
                raise RuntimeError(("control: the scan did not start", started, scans))
            entry = registry.get_scan(scans[0]["scan_id"])
            progress = asyncio.run(
                mcp_tools.mcp_get_scan_progress(scans[0]["scan_id"], session_id=_SID)
            )
    finally:
        profile_registry.clear_session_state(_SID)

    if chain == "accepted":
        # Controls on the premise: the scan's own resolution accepted the
        # chain and read both values, so both are in use at the failure.
        assert "values" in loaded, (
            "control: the scan never resolved its config",
            loaded.get("resolve_trouble"),
            entry.error_message,
        )
        assert _BASE_VALUE in loaded["values"], loaded
        assert _PROFILE_VALUE in loaded["values"], loaded
    else:
        # Control on the premise: the scan's own resolution refused the chain
        # before any value was read, so nothing resolved and nothing ran.
        assert "values" not in loaded, loaded
        assert "resolve_trouble" in loaded, (loaded, entry.error_message)
    for surface, text in (
        ("the registry's error_message", entry.error_message or ""),
        ("the progress answer", json.dumps(progress, default=str)),
        ("the log", str(logger.mock_calls)),
    ):
        assert _BASE_VALUE not in text, (surface, text)
        assert _PROFILE_VALUE not in text, (surface, text)
    leftovers = [
        p.name for p in config_dir.iterdir() if p.name.startswith(".ash-scan-")
    ]
    assert leftovers == [], leftovers


def test_the_snapshot_and_its_read_run_off_the_event_loop(tmp_path, monkeypatch):
    """The profile's copy and the read of its values are file work, and every
    session's tool calls run on the one event loop: both must run on a worker
    thread, as the config pre-check does, or a slow or hung filesystem stalls
    the whole server."""
    import threading

    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    session_id = "gates-thread-session"
    ws = tmp_path / "ws"
    target = ws / session_id / "source" / "repo"
    target.mkdir(parents=True)
    config_dir = ws / session_id / "config"
    config_dir.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(ws))
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    delivered = target / "client.ash.yaml"
    delivered.write_text("project_name: delivered\n", encoding="utf-8")
    profile = config_dir / "ash.yaml"
    profile.write_text("project_name: held\n", encoding="utf-8")
    assert config_is_client_supplied(delivered)
    assert not config_is_client_supplied(profile)
    profile_registry.bind_session_config(
        session_id, config=AshConfig(), profile_name="held", config_path=str(profile)
    )

    idents: dict = {}
    real_snapshot = mcp_tools._snapshot_profile_for_scan
    real_read = mcp_tools._profile_environment_values

    def a_snapshot_that_records_its_thread(*args, **kwargs):
        idents["snapshot"] = threading.get_ident()
        return real_snapshot(*args, **kwargs)

    def a_read_that_records_its_thread(*args, **kwargs):
        idents["read"] = threading.get_ident()
        return real_read(*args, **kwargs)

    monkeypatch.setattr(
        mcp_tools, "_snapshot_profile_for_scan", a_snapshot_that_records_its_thread
    )
    monkeypatch.setattr(
        mcp_tools, "_profile_environment_values", a_read_that_records_its_thread
    )
    registry = ScanRegistry()

    def a_run_that_fails(*args, **kwargs):
        raise RuntimeError("the tool crashed")

    async def start_and_wait_for_the_runner():
        started = await mcp_tools.mcp_scan_directory(
            str(target), config_path=str(delivered), session_id=session_id
        )
        await drain(return_exceptions=True)
        return started

    # asyncio.run runs the loop on this thread, so this ident is the loop's.
    loop_thread = threading.get_ident()
    try:
        with (
            patch.object(ras, "run_ash_scan", a_run_that_fails),
            patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
            patch(f"{_MGMT}.get_scan_registry", return_value=registry),
            patch(f"{_TOOLS}._logger", MagicMock(spec=ASHLogger)),
        ):
            started = asyncio.run(start_and_wait_for_the_runner())
    finally:
        profile_registry.clear_session_state(session_id)

    if started.get("success") is not True:
        raise RuntimeError(("control: the scan did not start", started))
    assert set(idents) == {"snapshot", "read"}, idents
    assert idents["snapshot"] != loop_thread, idents
    assert idents["read"] != loop_thread, idents
