# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The binding lock lets the thread that holds it take it again, and no other.

``profile_registry.binding_writes`` is the one lock around every write of a
session's profile files: ``select_profile``'s materialize-and-bind, and the
rewrite of a gone file. The rewrite calls a writer that can bind a profile
itself, so a ``select_profile`` that runs on the thread already inside the
rewrite takes the lock a second time. A lock that cannot be taken twice by its
holder waits on itself, and the test that reaches it neither passes nor fails:
the run it belongs to ends only when its own budget does, with nothing printed
for the test that waited.

Two things are pinned. The holder takes the lock again and the nested call
completes. And another thread still waits for the holder, because the lock
exists to order two writers.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    binding_writes,
    clear_all_session_state,
    clear_profile_registry,
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_select_profile
from tests.utils.bounded_wait import finishes_within

pytestmark = pytest.mark.unit

SESSION = "binding-lock-holder"
WAIT_SECONDS = 30.0


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    document: Dict[str, Any] = {
        "project_name": "operator-registered",
        "global_settings": {
            "mcp": {"runtime_overrides": {"enabled": True, "allowed_paths": ["/**"]}}
        },
    }
    profile = tmp_path / "op.yaml"
    profile.write_text(yaml.safe_dump(document), encoding="utf-8")
    set_profile_registry(register_profiles([f"op={profile}"]))
    yield
    clear_profile_registry()
    clear_all_session_state()


def test_select_profile_on_the_thread_that_holds_the_binding_lock_completes() -> None:
    """Red at the base: the lock was a plain ``threading.Lock``, so the nested
    ``select_profile`` waited for the lock its own thread held and the bounded
    wait failed the test."""

    def nested() -> Dict[str, Any]:
        with binding_writes(SESSION):
            return mcp_select_profile(
                "op",
                patch_ops=[{"op": "replace", "path": "/project_name", "value": "re"}],
                session_id=SESSION,
            )

    result = finishes_within(WAIT_SECONDS, nested)

    assert result["success"] is True, result


def test_another_thread_still_waits_for_the_holder_of_the_binding_lock() -> None:
    """Taking the lock twice is for the holder alone: a second writer is held
    back until the first leaves, which is what the lock is for."""
    holding = threading.Event()
    leave = threading.Event()
    entered = threading.Event()

    def holder() -> None:
        with binding_writes(SESSION):
            holding.set()
            leave.wait(WAIT_SECONDS)

    def other() -> None:
        with binding_writes(SESSION):
            entered.set()

    first = threading.Thread(target=holder, daemon=True)
    second = threading.Thread(target=other, daemon=True)
    first.start()
    assert holding.wait(WAIT_SECONDS), "the holder never took the lock"
    second.start()

    assert not entered.wait(0.5), "a second writer got in while the first held the lock"

    leave.set()
    assert entered.wait(WAIT_SECONDS), (
        "the second writer never got in after the first left"
    )
    first.join(WAIT_SECONDS)
    second.join(WAIT_SECONDS)
    assert not first.is_alive() and not second.is_alive()
