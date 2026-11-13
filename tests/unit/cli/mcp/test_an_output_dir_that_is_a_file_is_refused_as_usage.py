# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An output directory that is a file is refused as a usage error, exit 5.

A scan writes into ``<target>/.ash/ash_output``. When that path is a file,
``scan_directory`` and the ``run_ash_scan`` tool refuse the scan before it is
registered, in the words the CLI uses for an ``--output-dir`` that is a file
(``utils/directory_refusals.py``): ``Output directory is not a directory:
<path>``, with ``error_type`` ``output_dir_not_usable`` and ``exit_code`` 5,
not as the registry's ``Not a directory: <path>`` with exit 1. The
file is left as it was, and a missing output directory is created.
"""

from __future__ import annotations

import asyncio
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
def target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
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


@pytest.mark.parametrize(
    "tool", [_scan_directory, _run_ash_scan], ids=["scan_directory", "run_ash_scan"]
)
def test_an_output_dir_that_is_a_file_is_refused(target: Path, tool: Any) -> None:
    from automated_security_helper.core.resource_management.scan_registry import (
        get_scan_registry,
    )

    output = target / ".ash" / "ash_output"
    output.parent.mkdir()
    output.write_text(CONTENT, encoding="utf-8")
    scans_before = len(get_scan_registry().list_scans())

    response = tool(target)

    assert response["success"] is False, response
    assert response["error"] == f"Output directory is not a directory: {output}"
    assert response["error_type"] == "output_dir_not_usable", response
    assert response["exit_code"] == 5, response
    assert output.read_text(encoding="utf-8") == CONTENT
    assert len(get_scan_registry().list_scans()) == scans_before


def test_register_scan_refuses_it_in_the_same_words(target: Path) -> None:
    from automated_security_helper.core.resource_management.exceptions import (
        MCPResourceError,
    )
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )

    output = target.parent / "out"
    output.write_text(CONTENT, encoding="utf-8")
    with pytest.raises(MCPResourceError) as refused:
        ScanRegistry().register_scan(
            directory_path=str(target),
            output_directory=str(output),
            session_id=SESSION,
        )

    assert str(refused.value) == f"Output directory is not a directory: {output}"


def test_control_the_cli_gives_the_same_text() -> None:
    from automated_security_helper.core.resource_management.error_handling import (
        validate_output_directory_path,
    )
    from automated_security_helper.utils.directory_refusals import (
        output_dir_refusal,
    )

    path = Path(__file__)

    error = validate_output_directory_path(path)

    assert error is not None
    assert str(error) == output_dir_refusal(path)


def test_control_a_missing_output_dir_is_not_refused(target: Path) -> None:
    from automated_security_helper.cli.mcp_tools import output_directory_refusal

    assert output_directory_refusal(target / ".ash" / "ash_output", "x") is None
    assert not (target / ".ash").exists()
