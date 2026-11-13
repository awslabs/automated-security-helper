# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A results file is read only from the output directory it names.

Why this exists
---------------
The MCP results readers (get_scan_results, explain_finding, suggest_suppression
and diff_scan_results) check the directory they read from, or the path they are
given, against the session's roots. The results file in that directory is
checked too: an ``ash_aggregated_results.json`` linked to another tree's results
is refused, so a client is answered only from the tree it named.

Each reader checks the file itself, with one helper: a results file that
resolves outside its own directory is refused, and so is a link to a file that is
not there, with the same message, which names the file as given and nothing it
leads to. A FIFO in its place is refused unopened, since opening one blocks the
reader; and a results file named directly (suggest_suppression,
diff_scan_results) that is a link out of the roots gets the same refusal, which
names nothing the link leads to.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

SESSION = "client-one"
MARKER = "OTHER-TREE-MARKER"
RESULTS = "ash_aggregated_results.json"


def _results_document(project_name: str) -> str:
    document = json.loads(AshAggregatedResults().model_dump_json(by_alias=True))
    document["metadata"]["project_name"] = project_name
    return json.dumps(document)


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    roots = tmp_path / "roots"
    ours = roots / "ours" / ".ash" / "ash_output"
    other = roots / "other" / ".ash" / "ash_output"
    for output in (ours, other):
        output.mkdir(parents=True)
    (other / RESULTS).write_text(_results_document(MARKER), encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(roots))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    return {"ours": ours, "other": other}


def _linked_to_the_other_tree(layout: Dict[str, Path]) -> Path:
    link = layout["ours"] / RESULTS
    link.symlink_to(layout["other"] / RESULTS)
    return link


def _linked_to_nothing(layout: Dict[str, Path]) -> Path:
    link = layout["ours"] / RESULTS
    link.symlink_to(layout["other"] / "not-there.json")
    return link


LINKS = {"to another tree": _linked_to_the_other_tree, "to nothing": _linked_to_nothing}


def _assert_refused_naming_only_the_file(
    response: Dict[str, Any], layout: Dict[str, Path]
) -> None:
    assert response["success"] is False, response
    text = json.dumps(response, default=str)
    assert "does not resolve to a file in that directory" in text, response
    assert MARKER not in text, response
    assert str(layout["other"]) not in text, response


def _get_scan_results(output: Path) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_get_scan_results

    return asyncio.run(mcp_get_scan_results(str(output), session_id=SESSION))


@pytest.mark.parametrize("link", LINKS.values(), ids=LINKS)
def test_get_scan_results(layout, link) -> None:
    link(layout)
    _assert_refused_naming_only_the_file(_get_scan_results(layout["ours"]), layout)


@pytest.mark.parametrize("link", LINKS.values(), ids=LINKS)
def test_explain_finding(layout, link) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_explain_finding

    link(layout)
    response = mcp_explain_finding(
        "any-id", results_path=str(layout["ours"]), session_id=SESSION
    )
    _assert_refused_naming_only_the_file(response, layout)


@pytest.mark.parametrize("link", LINKS.values(), ids=LINKS)
def test_suggest_suppression(layout, link) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_suggest_suppression

    results_file = link(layout)
    response = mcp_suggest_suppression(
        "any-id", results_path=str(results_file), session_id=SESSION
    )
    _assert_refused_naming_only_the_file(response, layout)


@pytest.mark.parametrize("link", LINKS.values(), ids=LINKS)
@pytest.mark.parametrize("side", ["before", "after"])
def test_diff_scan_results(layout, link, side) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_diff_scan_results

    results_file = link(layout)
    plain = layout["ours"].parent / "plain.json"
    plain.write_text(_results_document("plain"), encoding="utf-8")
    paths = {"before_path": str(plain), "after_path": str(plain)}
    paths[f"{side}_path"] = str(results_file)

    response = mcp_diff_scan_results(**paths, session_id=SESSION)

    _assert_refused_naming_only_the_file(response, layout)


def _readers(layout: Dict[str, Path]) -> Dict[str, Callable[[], Dict[str, Any]]]:
    """Each reader, and each side of diff_scan_results, over ``ours/RESULTS``."""
    from automated_security_helper.cli import mcp_tools

    results_file = str(layout["ours"] / RESULTS)
    plain = layout["ours"].parent / "plain.json"
    plain.write_text(_results_document("plain"), encoding="utf-8")
    return {
        "get_scan_results": lambda: _get_scan_results(layout["ours"]),
        "explain_finding": lambda: mcp_tools.mcp_explain_finding(
            "any-id", results_path=str(layout["ours"]), session_id=SESSION
        ),
        "suggest_suppression": lambda: mcp_tools.mcp_suggest_suppression(
            "any-id", results_path=results_file, session_id=SESSION
        ),
        "diff before": lambda: mcp_tools.mcp_diff_scan_results(
            before_path=results_file, after_path=str(plain), session_id=SESSION
        ),
        "diff after": lambda: mcp_tools.mcp_diff_scan_results(
            before_path=str(plain), after_path=results_file, session_id=SESSION
        ),
    }


READERS = [
    "get_scan_results",
    "explain_finding",
    "suggest_suppression",
    "diff before",
    "diff after",
]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")
@pytest.mark.parametrize("reader", READERS)
def test_a_fifo_is_refused_unopened(layout, reader) -> None:
    """A FIFO in place of the results file is refused, never opened.

    Opening one for reading blocks until something writes to it, so a reader
    that opened it would hang the tool. The reader runs on a thread here, and a
    reader still waiting after the timeout is let go by opening the FIFO for
    writing, so the cell fails rather than hangs.
    """
    fifo = layout["ours"] / RESULTS
    os.mkfifo(fifo)
    read = _readers(layout)[reader]
    answers: list = []
    thread = threading.Thread(target=lambda: answers.append(read()), daemon=True)
    thread.start()
    thread.join(timeout=10)
    blocked = thread.is_alive()
    if blocked:
        descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(descriptor)
        thread.join(timeout=10)

    assert not blocked, f"{reader} opened the FIFO and waited for a writer"
    (response,) = answers
    _assert_refused_naming_only_the_file(response, layout)


@pytest.fixture
def outside(tmp_path) -> Path:
    """A results file outside every root."""
    directory = tmp_path / "outside-the-roots"
    directory.mkdir()
    results = directory / RESULTS
    results.write_text(_results_document(MARKER), encoding="utf-8")
    return results


@pytest.mark.parametrize("target", ["a file", "nothing"])
@pytest.mark.parametrize("reader", ["suggest_suppression", "diff before", "diff after"])
def test_a_named_results_file_linked_out_of_the_roots(
    layout, outside, reader, target
) -> None:
    """The refusal names the results file, and nothing the link leads to.

    suggest_suppression and diff_scan_results are given the file itself, and a
    link out of the roots there is refused by the name given, without the
    outside path it resolves to.
    """
    link = layout["ours"] / RESULTS
    link.symlink_to(outside if target == "a file" else outside.parent / "gone.json")

    response = _readers(layout)[reader]()

    _assert_refused_naming_only_the_file(response, layout)
    assert str(outside.parent) not in json.dumps(response, default=str), response


def test_control_a_results_file_in_its_own_directory_is_read(layout) -> None:
    (layout["ours"] / RESULTS).write_text(_results_document("ours"), encoding="utf-8")

    response = _get_scan_results(layout["ours"])

    assert response["success"] is True, response
