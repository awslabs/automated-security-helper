# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's progress is read only from results files in its own output directory.

``get_scan_progress`` reads the scan's aggregated results and each scanner's
``ASH.ScanResults.json`` under ``scanners/<scanner>/<target>/``, and the MCP
tool returns what it read. Each of those files must resolve to a file in the
directory it is named in, as for the other results readers: a link to another
tree's results, or to a file that is not there, is refused with one message,
which names the file as it is named in the output directory and nothing the
link leads to.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults

SESSION = "client-one"
MARKER = "OTHER-TREE-MARKER"
AGGREGATED = "ash_aggregated_results.json"
SCANNER_RESULTS = Path("scanners", "bandit", "source", "ASH.ScanResults.json")


def _results_document(project_name: str) -> str:
    document = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
    document["metadata"]["project_name"] = project_name
    return json.dumps(document)


def _scanner_document(marker: str) -> str:
    return json.dumps({"marker": marker, "severity_counts": {"high": 1}})


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
def scan(tmp_path, monkeypatch) -> Dict[str, Any]:
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    roots = tmp_path / "roots"
    ours = roots / "ours" / ".ash" / "ash_output"
    other = roots / "other" / ".ash" / "ash_output"
    for output in (ours, other):
        (output / SCANNER_RESULTS).parent.mkdir(parents=True)
    (other / AGGREGATED).write_text(_results_document(MARKER), encoding="utf-8")
    (other / SCANNER_RESULTS).write_text(_scanner_document(MARKER), encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(roots))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    registry = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", registry)
    scan_id = registry.register_scan(
        directory_path=str(ours.parent.parent),
        output_directory=str(ours),
        session_id=SESSION,
    )
    return {"ours": ours, "other": other, "scan_id": scan_id}


def _progress(scan: Dict[str, Any]) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_get_scan_progress

    return asyncio.run(mcp_get_scan_progress(scan["scan_id"], session_id=SESSION))


def _assert_refused_naming_only_the_file(
    response: Dict[str, Any], scan: Dict[str, Any], *also: str
) -> None:
    assert response["success"] is False, response
    text = "\n".join([json.dumps(response, default=str), *also])
    assert "does not resolve to a file in that directory" in text, response
    assert MARKER not in text, text
    assert str(scan["other"]) not in text, text


@pytest.mark.parametrize("target", ["another tree", "nothing"])
@pytest.mark.parametrize("name", [AGGREGATED, str(SCANNER_RESULTS)])
def test_a_results_file_linked_out_of_the_output_directory(scan, name, target) -> None:
    link = scan["ours"] / name
    link.symlink_to(
        scan["other"] / name if target == "another tree" else scan["other"] / "gone"
    )

    _assert_refused_naming_only_the_file(_progress(scan), scan)


def _release(fifo: Path) -> None:
    """Open ``fifo`` for writing and close it, so a reader blocked in open returns."""
    with contextlib.suppress(OSError):
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")
@pytest.mark.parametrize("name", [AGGREGATED, str(SCANNER_RESULTS)])
def test_a_results_file_that_is_a_fifo_is_refused_without_waiting(scan, name) -> None:
    """A FIFO is not a file: opening one waits for a writer, and nothing writes."""
    fifo = scan["ours"] / name
    os.mkfifo(fifo)
    responses: List[Dict[str, Any]] = []
    thread = threading.Thread(
        target=lambda: responses.append(_progress(scan)), daemon=True
    )

    thread.start()
    thread.join(timeout=10)
    if thread.is_alive():
        _release(fifo)
        thread.join(timeout=10)
        pytest.fail(f"get_scan_progress waited on the FIFO at {name}")

    (response,) = responses
    _assert_refused_naming_only_the_file(response, scan)


def test_through_the_mcp_tool(scan) -> None:
    from automated_security_helper.cli import mcp_server

    (scan["ours"] / SCANNER_RESULTS).symlink_to(scan["other"] / SCANNER_RESULTS)
    ctx = _Context()

    response = asyncio.run(mcp_server.get_scan_progress(ctx, scan_id=scan["scan_id"]))

    _assert_refused_naming_only_the_file(response, scan, *ctx.messages)


def test_control_results_files_in_their_own_directory_are_read(scan) -> None:
    from automated_security_helper.cli import mcp_server

    (scan["ours"] / SCANNER_RESULTS).write_text(
        _scanner_document("ours"), encoding="utf-8"
    )
    ctx = _Context()

    response = asyncio.run(mcp_server.get_scan_progress(ctx, scan_id=scan["scan_id"]))

    assert "does not resolve" not in json.dumps(response, default=str), response
    assert response.get("success") is not False, response
