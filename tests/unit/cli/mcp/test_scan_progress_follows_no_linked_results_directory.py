# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's progress reads no results directory that leads out of its output.

``get_scan_progress`` reads each scanner's ``ASH.ScanResults.json`` under
``scanners/<scanner>/<target>/``. Through a linked scanners directory, a linked
scanner directory or a linked target directory, the poll would read another
tree's results as this scan's, and the reply would show whether that tree has
them. Two checks stop it, each on its own: the listings that find the files
(``_result_files_in`` and ``scan_tracking.find_scanner_result_files``) follow a
directory only when it resolves to a directory inside the output directory,
and the results-file check refuses a path below the output directory that
leads out of it, whether or not anything is at the far end. A link to nothing
is answered as a link to another tree is.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any, Dict

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"
MARKER = "OTHER-TREE-MARKER"
SCANNER_RESULTS = Path("scanners", "bandit", "source", "ASH.ScanResults.json")

#: Each directory on the way to a scanner's results, as the poll walks them.
LEVELS = {
    "target": Path("scanners", "bandit", "source"),
    "scanner": Path("scanners", "bandit"),
    "scanners": Path("scanners"),
}


def _scanner_document(marker: str) -> str:
    return json.dumps({"marker": marker, "severity_counts": {"high": 1}})


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


def _link(scan: Dict[str, Any], level: str, to: Path) -> Path:
    directory = scan["ours"] / LEVELS[level]
    shutil.rmtree(directory)
    directory.symlink_to(to, target_is_directory=True)
    return directory


def _progress(scan: Dict[str, Any]) -> Dict[str, Any]:
    from automated_security_helper.cli.mcp_tools import mcp_get_scan_progress

    response = asyncio.run(mcp_get_scan_progress(scan["scan_id"], session_id=SESSION))
    response.pop("timestamp", None)
    return response


def _assert_nothing_of_the_other_tree(response: Dict[str, Any], scan) -> None:
    text = json.dumps(response, default=str)
    assert MARKER not in text, text
    assert str(scan["other"]) not in text, text
    assert "bandit" not in text, text


@pytest.mark.parametrize("level", sorted(LEVELS))
def test_a_linked_directory_is_not_read_and_says_nothing_of_its_target(
    scan, level
) -> None:
    link = _link(scan, level, scan["other"] / LEVELS[level])
    elsewhere = _progress(scan)
    link.unlink()
    link.symlink_to(scan["other"] / "gone", target_is_directory=True)

    nothing = _progress(scan)

    _assert_nothing_of_the_other_tree(elsewhere, scan)
    assert nothing == elsewhere


@pytest.mark.parametrize("level", sorted(LEVELS))
def test_the_listings_follow_no_linked_directory(scan, level) -> None:
    from automated_security_helper.cli.mcp_tools import _result_files_in
    from automated_security_helper.core.resource_management.scan_tracking import (
        find_scanner_result_files,
    )

    _link(scan, level, scan["other"] / LEVELS[level])

    assert find_scanner_result_files(scan["ours"]).get("bandit", {}) == {}
    assert _result_files_in(scan["ours"]) == [
        scan["ours"] / "ash_aggregated_results.json"
    ]


@pytest.mark.parametrize("target", ["another tree", "nothing"])
@pytest.mark.parametrize("level", sorted(LEVELS))
def test_the_file_check_refuses_a_path_through_a_linked_directory(
    scan, level, target
) -> None:
    from automated_security_helper.cli.mcp_tools import (
        _results_file_outside_its_directory,
    )

    _link(
        scan,
        level,
        scan["other"] / LEVELS[level] if target == "another tree" else scan["other"],
    )
    if target == "nothing":
        (scan["ours"] / LEVELS[level]).unlink()
        (scan["ours"] / LEVELS[level]).symlink_to(
            scan["other"] / "gone", target_is_directory=True
        )

    refusal = _results_file_outside_its_directory(
        scan["ours"] / SCANNER_RESULTS, "get_scan_progress", scan["ours"]
    )

    assert refusal is not None
    assert refusal["error"] == (
        f"The results file '{SCANNER_RESULTS.as_posix()}' in '{scan['ours']}' does "
        "not resolve to a file in that directory, so it was not read."
    )
    assert MARKER not in json.dumps(refusal, default=str)
    assert str(scan["other"]) not in refusal["error"]


def test_control_real_directories_are_read(scan) -> None:
    from automated_security_helper.cli.mcp_tools import _result_files_in

    (scan["ours"] / SCANNER_RESULTS).write_text(
        _scanner_document("ours"), encoding="utf-8"
    )

    assert _result_files_in(scan["ours"])[1:] == [scan["ours"] / SCANNER_RESULTS]
    response = _progress(scan)
    assert response.get("success") is not False, response
    assert "bandit" in json.dumps(response, default=str), response


def test_control_the_file_check_passes_a_file_in_a_real_directory(scan) -> None:
    from automated_security_helper.cli.mcp_tools import (
        _results_file_outside_its_directory,
    )

    (scan["ours"] / SCANNER_RESULTS).write_text(
        _scanner_document("ours"), encoding="utf-8"
    )

    assert (
        _results_file_outside_its_directory(
            scan["ours"] / SCANNER_RESULTS, "get_scan_progress", scan["ours"]
        )
        is None
    )


def test_control_a_results_file_not_written_yet_is_not_refused(scan) -> None:
    from automated_security_helper.cli.mcp_tools import (
        _results_file_outside_its_directory,
    )

    shutil.rmtree(scan["ours"] / "scanners")

    assert (
        _results_file_outside_its_directory(
            scan["ours"] / SCANNER_RESULTS, "get_scan_progress", scan["ours"]
        )
        is None
    )
