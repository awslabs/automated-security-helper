# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An output directory that cannot be created is refused as a usage error, exit 5.

A scan writes into ``<target>/.ash/ash_output``. When ``.ash`` is a file, so the
output directory cannot be made under it, creating it after the scan is
registered would have ``scan_directory`` and the ``run_ash_scan`` tool answer
"Unexpected error starting scan: [Errno 20] Not a directory", an internal error,
exit 1. They refuse it before it is registered, in the CLI's words
(``utils/directory_refusals.py``): ``Output directory cannot be created: <path>
(Not a directory)``, with ``error_type`` ``output_dir_not_usable`` and
``exit_code`` 5. One that only fails when it is made, such as under a ``.ash``
that cannot be written, is refused the same way when it is made, and the scan's
claim is given back.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"
CONTENT = "not a directory\n"


class _Context:
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


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.core.resource_management import scan_registry

    isolated = scan_registry.ScanRegistry()
    monkeypatch.setattr(scan_registry, "_scan_registry", isolated)
    return isolated


@pytest.fixture
def target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registry) -> Path:
    roots = tmp_path / "roots"
    roots.mkdir()
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(roots))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    project = roots / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return project.resolve()


def _scan_directory(target: Path) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    return asyncio.run(
        mcp_scan_directory(directory_path=str(target), session_id=SESSION)
    )


def _run_ash_scan(target: Path) -> Dict[str, Any]:
    from automated_security_helper.cli import mcp_server

    return asyncio.run(mcp_server.run_ash_scan(_Context(), source_dir=str(target)))


TOOLS = pytest.mark.parametrize(
    "tool", [_scan_directory, _run_ash_scan], ids=["scan_directory", "run_ash_scan"]
)


def _assert_refused(response: Dict[str, Any], text: str) -> None:
    assert response["success"] is False, response
    assert response["error"] == text, response
    assert response["error_type"] == "output_dir_not_usable", response
    assert response["exit_code"] == 5, response


@TOOLS
def test_a_file_on_the_way_is_refused_before_the_scan_is_registered(
    target: Path, registry, tool: Any
) -> None:
    blocker = target / ".ash"
    blocker.write_text(CONTENT, encoding="utf-8")
    output = blocker / "ash_output"

    response = tool(target)

    _assert_refused(
        response, f"Output directory cannot be created: {output} (Not a directory)"
    )
    assert blocker.read_text(encoding="utf-8") == CONTENT
    assert registry.list_scans() == []


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="root, and Windows, create a directory in one without write permission",
)
@TOOLS
def test_one_that_fails_when_it_is_made_is_refused_and_given_back(
    target: Path, registry, tool: Any
) -> None:
    """Under a ``.ash`` that cannot be written, the output directory looks makeable
    until it is made, after the scan is registered: the claim is given back."""
    parent = target / ".ash"
    parent.mkdir()
    parent.chmod(0o555)
    output = parent / "ash_output"
    try:
        response = tool(target)
    finally:
        parent.chmod(0o755)

    _assert_refused(
        response, f"Output directory cannot be created: {output} (Permission denied)"
    )
    assert not output.exists()
    assert registry.list_scans(active_only=True) == []


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="root, and Windows, write into a directory without write permission",
)
@TOOLS
def test_one_that_is_there_but_cannot_be_written_is_refused(
    target: Path, registry, tool: Any
) -> None:
    """The check makes and removes a file there, before the scan is registered."""
    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True)
    output.chmod(0o555)
    try:
        response = tool(target)
        left = list(output.iterdir())
    finally:
        output.chmod(0o755)

    _assert_refused(
        response, f"Output directory cannot be written: {output} (Permission denied)"
    )
    assert left == []
    assert registry.list_scans() == []


def test_control_a_missing_output_dir_under_a_directory_is_not_refused(
    target: Path,
) -> None:
    from automated_security_helper.cli.mcp_tools import output_directory_refusal

    (target / ".ash").mkdir()

    assert output_directory_refusal(target / ".ash" / "ash_output", "x") is None
    assert list((target / ".ash").iterdir()) == []
