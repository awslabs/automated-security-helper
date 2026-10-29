# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A clone is bounded in bytes, and source delivery leaves the event loop free.

``set_source_git`` stops a git command that runs past ``GIT_TIMEOUT_SECONDS``
(``test_set_source_git_times_out.py``), but a clone that writes without end stayed
inside the time limit and could fill the workspace volume, and the delivery tools
ran their work on the server's event loop, so every other session waited for it.

The git here is a stand-in script that writes a large file and then hangs.
"""

from __future__ import annotations

import asyncio
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, Iterator
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests
from automated_security_helper.cli.mcp_tools import mcp_set_source_git
from automated_security_helper.utils.subprocess_utils import clear_find_executable_cache

URL = "https://git.example.invalid/team/repo.git"
SESSION = "size-session"

_FAKE_GIT = """\
import os, sys, time
from pathlib import Path

argv = sys.argv[1:]
if "clone" not in argv:
    sys.exit(0)
target = Path(argv[-1])
target.mkdir(parents=True, exist_ok=True)
Path({pidfile!r}).write_text(str(os.getpid()))
(target / "blob").write_bytes(b"x" * {size})
if {hang!r}:
    time.sleep(3600)
"""


@pytest.fixture
def fake_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Dict[str, Any]]:
    state: Dict[str, Any] = {"pidfile": tmp_path / "git.pid"}
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    workspace = tmp_path / "ws"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    monkeypatch.setattr(sd, "GIT_TIMEOUT_SECONDS", 5)
    monkeypatch.setattr(sd, "GIT_POLL_SECONDS", 0.1, raising=False)
    monkeypatch.setattr(sd, "MAX_CLONE_BYTES", 1024 * 1024, raising=False)
    state["workspace"] = workspace
    reset_default_registry_for_tests()

    def install(*, size: int, hang: bool) -> None:
        if sys.platform == "win32":
            # The stand-in is an extensionless script with a shebang line.
            # CreateProcess starts only PE images, and the lookup prefers the
            # real git.exe further down PATH, so the stand-in is never the git
            # the delivery runs; the real git then clones the unresolvable
            # example host and fails.
            pytest.skip("a shebang stand-in for git cannot be started on Windows")
        script = bin_dir / "git"
        script.write_text(
            f"#!{sys.executable}\n"
            + textwrap.dedent(
                _FAKE_GIT.format(pidfile=str(state["pidfile"]), size=size, hang=hang)
            )
        )
        script.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
        clear_find_executable_cache()

    state["install"] = install
    yield state
    clear_find_executable_cache()
    if state["pidfile"].exists():
        try:
            os.kill(int(state["pidfile"].read_text()), 9)
        except OSError:
            pass
    reset_default_registry_for_tests()


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():
        try:
            return stat.read_text().rsplit(")", 1)[1].split()[0] != "Z"
        except OSError:
            return False
    return True


@pytest.mark.integration
def test_a_clone_inside_the_size_limit_succeeds(fake_git) -> None:
    """Positive control: the limit does not refuse a clone that stays under it."""

    fake_git["install"](size=1024, hang=False)

    result = mcp_set_source_git(url=URL, session_id=SESSION)

    assert result.get("success") is True, result


@pytest.mark.integration
def test_a_clone_past_the_size_limit_is_stopped_with_its_process(fake_git) -> None:
    fake_git["install"](size=3 * 1024 * 1024, hang=True)

    started = time.monotonic()
    result = mcp_set_source_git(url=URL, session_id=SESSION)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_too_large", result
    assert time.monotonic() - started < 4.5, "stopped by the time limit, not the size"
    assert not _alive(int(fake_git["pidfile"].read_text()))
    assert not (fake_git["workspace"] / SESSION / "source").exists()


@pytest.mark.integration
def test_a_clone_that_finishes_oversized_between_polls_is_refused(
    fake_git, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The size is also read once the command has exited, not only while it runs."""

    monkeypatch.setattr(sd, "GIT_POLL_SECONDS", 30.0, raising=False)
    fake_git["install"](size=3 * 1024 * 1024, hang=False)

    result = mcp_set_source_git(url=URL, session_id=SESSION)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_too_large", result
    assert not (fake_git["workspace"] / SESSION / "source").exists()


# ---------------------------------------------------------------------------
# The delivery tools leave the event loop free.
# ---------------------------------------------------------------------------


def _ctx() -> Any:
    ctx = MagicMock()
    ctx.headers = {"mcp-session-id": SESSION}

    async def anoop(*args: Any, **kwargs: Any) -> None:
        return None

    for name in ("info", "error", "debug", "warning", "report_progress"):
        setattr(ctx, name, MagicMock(side_effect=anoop))
    return ctx


@pytest.mark.parametrize(
    ("tool", "implementation", "arguments"),
    [
        ("set_source_git", "mcp_set_source_git", {"url": URL}),
        (
            "set_source_zip_chunk",
            "mcp_set_source_zip_chunk",
            {"upload_id": "u1", "sequence": 0, "data_b64": "", "last": False},
        ),
        (
            "set_source_zip_finalize",
            "mcp_set_source_zip_finalize",
            {"upload_id": "u1", "expected_sha256": "0" * 64},
        ),
        ("clear_source", "mcp_clear_source", {}),
    ],
)
@pytest.mark.unit
def test_delivery_tools_do_not_block_the_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    implementation: str,
    arguments: dict,
) -> None:
    from automated_security_helper.cli import mcp_server

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    reset_default_registry_for_tests()

    def slow(*args: Any, **kwargs: Any) -> dict:
        time.sleep(1.0)
        return {"success": True}

    async def scenario() -> int:
        ticks = 0

        async def ticker() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.05)
                ticks += 1

        task = asyncio.create_task(ticker())
        try:
            await getattr(mcp_server, tool)(_ctx(), **arguments)
        finally:
            task.cancel()
        return ticks

    with patch.object(mcp_server, implementation, slow):
        ticks = asyncio.run(scenario())
    reset_default_registry_for_tests()

    # A loop kept free for the second the implementation takes ticks about 20
    # times; one blocked for it ticks once at most.
    assert ticks >= 8, f"{tool} held the event loop: {ticks} ticks in 1 s"
