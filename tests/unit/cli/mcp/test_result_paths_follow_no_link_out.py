# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``get_scan_result_paths`` lists a results file only as it is in its own directory.

The tool lists each report file, the aggregated results and each scanner's
results in an output directory, with whether it exists and its size. Through a
link, both would come from whatever the link leads to, so the reply would say
whether a path outside the output directory exists and how big it is, and a
linked directory would list another tree's names. A file that does not resolve
to a file in the directory it is named in, or one in a directory that does not
resolve to a directory in the output directory, is listed as not there, with no
size and the reason, and the link is not followed. A link to nothing is
answered the same way as a link to something.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List

import pytest

SESSION = "client-one"
#: A size no file of ours has, so it shows if the reply reports the other file.
OTHER_SIZE = 12345
#: A target only the other tree has, so it shows if the reply lists that tree.
OTHER_TARGET = "elsewhere-target"


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


FILES = {
    "sarif": Path("reports", "ash.sarif"),
    "aggregated_results": Path("ash_aggregated_results.json"),
    "scanner": Path("scanners", "bandit", "source", "ASH.ScanResults.json"),
}


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Dict[str, Path]:
    roots = tmp_path / "roots"
    ours = roots / "ours" / ".ash" / "ash_output"
    other = roots / "other" / ".ash" / "ash_output"
    other_target = Path("scanners", "bandit", OTHER_TARGET, "ASH.ScanResults.json")
    for output in (ours, other):
        for name in FILES.values():
            (output / name).parent.mkdir(parents=True, exist_ok=True)
    (other / other_target).parent.mkdir(parents=True)
    for name in [*FILES.values(), other_target]:
        (other / name).write_bytes(b"x" * OTHER_SIZE)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(roots))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    return {"ours": ours, "other": other}


def _paths(layout: Dict[str, Path]) -> Dict[str, Any]:
    from automated_security_helper.cli import mcp_server

    return asyncio.run(
        mcp_server.get_scan_result_paths(_Context(), output_dir=str(layout["ours"]))
    )


def _entry(response: Dict[str, Any], kind: str) -> Dict[str, Any]:
    if kind == "scanner":
        return response["scanner_results"]["bandit"]["source"]
    return response["files"][kind]


def _assert_nothing_of_the_other_tree(response: Dict[str, Any], layout) -> None:
    text = json.dumps(response, default=str)
    assert str(OTHER_SIZE) not in text, text
    assert OTHER_TARGET not in text, text
    assert str(layout["other"]) not in text, text


def _assert_listed_as_not_there(
    response: Dict[str, Any], kind: str, layout, reason: str
) -> None:
    assert response["success"] is True, response
    entry = _entry(response, kind)
    assert entry["exists"] is False, entry
    assert entry["size_bytes"] is None, entry
    assert reason in entry["error"], entry
    _assert_nothing_of_the_other_tree(response, layout)


FILE_REASON = "does not resolve to a file in that directory"
DIRECTORY_REASON = "does not resolve to a directory in that output directory"


@pytest.mark.parametrize("kind", sorted(FILES))
def test_a_file_linked_to_another_tree(layout, kind) -> None:
    (layout["ours"] / FILES[kind]).symlink_to(layout["other"] / FILES[kind])
    _assert_listed_as_not_there(_paths(layout), kind, layout, FILE_REASON)


@pytest.mark.parametrize("kind", sorted(FILES))
def test_a_file_linked_to_nothing_is_listed_as_a_link_elsewhere_is(
    layout, kind
) -> None:
    link = layout["ours"] / FILES[kind]
    link.symlink_to(layout["other"] / FILES[kind])
    elsewhere = _paths(layout)
    link.unlink()
    link.symlink_to(layout["other"] / "not-there")

    nothing = _paths(layout)

    _assert_listed_as_not_there(nothing, kind, layout, FILE_REASON)
    assert nothing == elsewhere


#: Each directory under the output directory the listing reads, and the entry
#: a link there leaves listed, or None where it leaves nothing to list.
DIRECTORIES = {
    "reports": (Path("reports"), "sarif"),
    "target": (Path("scanners", "bandit", "source"), "scanner"),
    "scanner": (Path("scanners", "bandit"), None),
    "scanners": (Path("scanners"), None),
}


def _link_directory(layout, name: Path, to: Path) -> None:
    directory = layout["ours"] / name
    shutil.rmtree(directory)
    directory.symlink_to(to, target_is_directory=True)


@pytest.mark.parametrize("level", sorted(DIRECTORIES))
def test_a_directory_linked_to_another_tree(layout, level) -> None:
    name, kind = DIRECTORIES[level]
    _link_directory(layout, name, layout["other"] / name)

    response = _paths(layout)

    assert response["success"] is True, response
    _assert_nothing_of_the_other_tree(response, layout)
    if kind is not None:
        _assert_listed_as_not_there(response, kind, layout, DIRECTORY_REASON)
    elif level == "scanner":
        assert response["scanner_results"] == {}, response
    else:
        assert "scanner_results" not in response, response


@pytest.mark.parametrize("level", sorted(DIRECTORIES))
def test_a_directory_linked_to_nothing_is_listed_as_a_link_elsewhere_is(
    layout, level
) -> None:
    name, _ = DIRECTORIES[level]
    _link_directory(layout, name, layout["other"] / name)
    elsewhere = _paths(layout)
    (layout["ours"] / name).unlink()
    (layout["ours"] / name).symlink_to(
        layout["other"] / "not-there", target_is_directory=True
    )

    nothing = _paths(layout)

    assert nothing == elsewhere
    _assert_nothing_of_the_other_tree(nothing, layout)


def test_control_files_in_their_own_directory_are_listed_as_they_are(layout) -> None:
    for name in FILES.values():
        (layout["ours"] / name).write_bytes(b"y" * 7)

    response = _paths(layout)

    for kind in FILES:
        entry = _entry(response, kind)
        assert entry == {
            "path": str(layout["ours"] / FILES[kind]),
            "exists": True,
            "size_bytes": 7,
        }, entry
    missing = response["files"]["html"]
    assert missing["exists"] is False and missing["size_bytes"] == 0, missing
    assert "error" not in missing, missing


def test_control_a_missing_reports_directory_is_reported_as_before(layout) -> None:
    shutil.rmtree(layout["ours"] / "reports")

    response = _paths(layout)

    assert response["success"] is False, response
    assert response["error_type"] == "DirectoryNotFound", response
