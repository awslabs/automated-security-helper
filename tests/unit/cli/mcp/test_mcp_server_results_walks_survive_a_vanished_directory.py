# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The results walks of get_scan_progress and get_scan_result_paths survive a race.

Both tools walk a scan's output tree while the scan thread, or a new scan's
set-up, may move or rewrite it. Each directory was listed with a bare iterdir
after a check that it was there, and each results file was stat'ed after an
exists() check, so a directory or file that went away between the check and
the read failed the whole call as an unexpected error. A directory that cannot
be listed is now read as empty, a file that cannot be stat'ed as not there, and
a poll of a scan that is still pending reads nothing from an output directory
whose files are the previous scan's.
"""

from __future__ import annotations

import asyncio
import errno
import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp.server.mcpserver import Context

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    clear_profile_registry,
    clear_session_state,
)
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.core.resource_management.scan_registry import (
    get_scan_registry,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_session_state(None)
    yield
    clear_profile_registry()
    clear_session_state(None)


def _ctx() -> MagicMock:
    """The local client's stand-in: no headers at all."""
    ctx = MagicMock(spec=Context)
    ctx.headers = {}
    for name in ("info", "debug", "warning", "error", "report_progress"):
        setattr(ctx, name, AsyncMock())
    return ctx


def _write(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _vanish_on_listing(monkeypatch, gone: Path) -> None:
    """Make listing ``gone`` fail as a directory removed under the walk does.

    The directory stays on disk, so the check that it resolves inside the
    output directory passes, and only its listing meets the race.
    """
    original = Path.iterdir

    def listing(self: Path):
        if self == gone:
            raise FileNotFoundError(errno.ENOENT, "removed under the walk", str(self))
        return original(self)

    monkeypatch.setattr(Path, "iterdir", listing)


def _scan(tmp_path: Path) -> tuple[str, Path]:
    output = tmp_path / "project" / ".ash" / "ash_output"
    output.mkdir(parents=True)
    scan_id = get_scan_registry().register_scan(
        str(tmp_path / "project"), str(output), session_id=DEFAULT_SESSION_ID
    )
    _write(
        output / "scanners" / "bandit" / "source" / "ASH.ScanResults.json",
        {"severity_counts": {"high": 1}, "status": "PASSED"},
    )
    return scan_id, output


def _progress(tmp_path: Path, monkeypatch, status: str) -> Dict[str, Any]:
    scan_id, output = _scan(tmp_path)
    monkeypatch.setattr(
        mcp_server,
        "mcp_get_scan_progress",
        AsyncMock(
            return_value={
                "scan_id": scan_id,
                "status": status,
                "is_complete": False,
                "scanners": {},
            }
        ),
    )
    return {"scan_id": scan_id, "output": output}


def test_a_scanners_directory_removed_under_the_walk_does_not_fail_the_poll(
    tmp_path: Path, monkeypatch
) -> None:
    scan = _progress(tmp_path, monkeypatch, "running")
    monkeypatch.setattr(
        mcp_server,
        "summarize_scanner_statuses",
        lambda output_dir, environment_values=(): {
            "scanner_statuses": {},
            "skipped_scanners": [],
        },
    )
    _vanish_on_listing(monkeypatch, scan["output"] / "scanners")

    result = asyncio.run(mcp_server.get_scan_progress(_ctx(), scan["scan_id"]))

    # Red before the fix: the poll came back as "Error getting scan progress".
    assert "error" not in result, result
    assert result["scanners"] == {}, result


def test_a_pending_scan_reads_nothing_from_its_output_directory(
    tmp_path: Path, monkeypatch
) -> None:
    """The files there are the previous scan's until the scan's set-up moves them."""
    scan = _progress(tmp_path, monkeypatch, "pending")
    summaries: List[Path] = []

    def recording(output_dir: Path, environment_values: Any = ()) -> Dict[str, Any]:
        summaries.append(output_dir)
        return {"scanner_statuses": {}, "skipped_scanners": []}

    monkeypatch.setattr(mcp_server, "summarize_scanner_statuses", recording)

    result = asyncio.run(mcp_server.get_scan_progress(_ctx(), scan["scan_id"]))

    assert "error" not in result, result
    # Red before the fix: the previous scan's bandit file was read as this scan's.
    assert "bandit" not in result["scanners"], result["scanners"]
    assert result["severity_counts"]["high"] == 0, result["severity_counts"]
    assert summaries == [], "the aggregated results of the previous scan were read"


def _result_paths(tmp_path: Path, monkeypatch) -> Dict[str, Any]:
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    output = tmp_path / "out"
    reports = output / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.sarif").write_text("{}", encoding="utf-8")
    _write(
        output / "scanners" / "bandit" / "source" / "ASH.ScanResults.json",
        {"status": "PASSED"},
    )
    _vanish_on_listing(monkeypatch, output / "scanners")
    return asyncio.run(mcp_server.get_scan_result_paths(_ctx(), output_dir=str(output)))


def test_a_scanners_directory_removed_under_the_listing_lists_no_scanner(
    tmp_path: Path, monkeypatch
) -> None:
    result = _result_paths(tmp_path, monkeypatch)

    # Red before the fix: the whole call failed as an unexpected error.
    assert result["success"] is True, result
    assert result["files"]["sarif"]["exists"] is True
    assert result["scanner_results"] == {}, result


class _Vanishing(type(Path())):
    """A results file the listing saw that is gone by the time it is stat'ed."""

    def exists(self, *args: Any, **kwargs: Any) -> bool:
        return True

    def stat(self, *args: Any, **kwargs: Any):
        raise FileNotFoundError(errno.ENOENT, "set aside by a new scan", str(self))


class _Unreadable(type(Path())):
    """A results file whose stat fails for a reason that is not its absence."""

    def exists(self, *args: Any, **kwargs: Any) -> bool:
        return True

    def stat(self, *args: Any, **kwargs: Any):
        raise PermissionError(errno.EACCES, "not permitted", str(self))


def test_a_results_file_that_vanishes_before_its_stat_is_listed_as_absent(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(
        mcp_server, "_results_file_outside_its_directory", lambda *a, **k: None
    )
    output = tmp_path / "out"
    gone = _Vanishing(output / "reports" / "ash.sarif")

    # Red before the fix: FileNotFoundError escaped from the stat.
    entry = mcp_server._result_path_entry(gone, output)

    assert entry == {"path": str(gone), "exists": False, "size_bytes": 0}, entry


def test_another_stat_error_is_still_raised(tmp_path: Path, monkeypatch) -> None:
    """Control: only the shapes exists() reads as absent are listed as absent."""
    monkeypatch.setattr(
        mcp_server, "_results_file_outside_its_directory", lambda *a, **k: None
    )
    output = tmp_path / "out"

    with pytest.raises(PermissionError):
        mcp_server._result_path_entry(
            _Unreadable(output / "reports" / "ash.sarif"), output
        )
