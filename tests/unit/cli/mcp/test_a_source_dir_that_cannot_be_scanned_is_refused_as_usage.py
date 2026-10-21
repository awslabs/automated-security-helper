# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A source directory that cannot be scanned is refused as a usage error, exit 5.

``scan_directory`` and the ``run_ash_scan`` tool refuse a source directory that
does not exist, is not a directory, or cannot be entered, in the words the CLI
uses for ``--source-dir``, with ``exit_code`` 5 and the path as the caller gave
it. A directory that cannot be entered used to raise PermissionError out of the
output-tree check below the target, and the other two were reported in the
words of the shared directory check that output-directory lookups use, which is
unchanged.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

SESSION = "client-one"


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
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    roots = tmp_path / "roots"
    roots.mkdir()
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(roots))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    return roots


def _missing(roots: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    yield roots / "project"


def _dangling(roots: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    link = roots / "project"
    link.symlink_to(roots / "gone", target_is_directory=True)
    yield link


def _file(roots: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    target = roots / "project"
    target.write_text("not a directory\n", encoding="utf-8")
    yield target


def _unenterable(roots: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    target = roots / "project"
    target.mkdir()
    real_access = os.access

    # The mode bits do not stop a process with CAP_DAC_OVERRIDE, so the check's
    # answer for this one path is fixed too, and the cell holds for any user.
    def access(path: Any, mode: int, *args: Any, **kwargs: Any) -> bool:
        if os.fspath(path) == str(target):
            return False
        return real_access(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "access", access)
    os.chmod(target, 0o600)
    try:
        yield target
    finally:
        os.chmod(target, 0o700)


CASES = {
    "missing": (_missing, "Source directory does not exist: "),
    "dangling-link": (_dangling, "Source directory does not exist: "),
    "not-a-directory": (_file, "Source directory is not a directory: "),
    "unenterable": (_unenterable, "Source directory cannot be entered: "),
}


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
@pytest.mark.parametrize("case", sorted(CASES))
def test_a_source_dir_that_cannot_be_scanned(
    roots: Path, monkeypatch: pytest.MonkeyPatch, case: str, tool: Any
) -> None:
    make, text = CASES[case]
    for target in make(roots, monkeypatch):
        response = tool(target)

        assert response["success"] is False, response
        assert response["error"] == f"{text}{target}", response
        assert response["error_type"] == "source_dir_not_usable", response
        assert response["exit_code"] == 5, response
        assert not (target.parent / ".ash").exists() or case == "missing"


def test_the_path_is_shown_as_given(roots: Path) -> None:
    target = roots / "pro\nject"

    response = _scan_directory(target)

    # A client decodes the reply's JSON and may display the error, so it is one
    # line: the newline the path holds is written as its escape, once.
    shown = str(target).replace("\n", "\\x0a")
    assert response["error"] == f"Source directory does not exist: {shown}"
    assert "\n" not in response["error"]


def test_register_scan_refuses_a_missing_source_dir_in_the_same_words(
    roots: Path,
) -> None:
    from automated_security_helper.core.resource_management.exceptions import (
        MCPResourceError,
    )
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )

    output = roots / "out"
    output.mkdir()
    with pytest.raises(MCPResourceError) as refused:
        ScanRegistry().register_scan(
            directory_path=str(roots / "project"),
            output_directory=str(output),
            session_id=SESSION,
        )

    assert str(refused.value) == f"Source directory does not exist: {roots / 'project'}"
    assert refused.value.context["error_category"] == "file_not_found"


def test_control_the_shared_directory_check_is_unchanged(roots: Path) -> None:
    from automated_security_helper.core.resource_management.error_handling import (
        validate_directory_path,
    )

    error = validate_directory_path(roots / "never-scanned")

    assert error is not None
    assert str(error) == (
        f"Directory not found or not a directory: {roots / 'never-scanned'}"
    )


def test_control_a_directory_that_can_be_scanned_is_not_refused(roots: Path) -> None:
    from automated_security_helper.core.resource_management.error_handling import (
        source_directory_error,
    )

    (roots / "project").mkdir()

    assert source_directory_error(roots / "project") is None
