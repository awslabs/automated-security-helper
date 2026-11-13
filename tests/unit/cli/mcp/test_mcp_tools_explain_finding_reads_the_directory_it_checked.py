# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``explain_finding`` reads the results directory it checked, derived once.

The tool derives the output directory from ``results_path`` (the path itself
when it is a directory, else its parent) and checks that directory against the
roots, the restored marker and a link out of it. The loader then derived the
directory a second time from the same string, with a second ``is_dir`` call, so
a path whose answer changed between the two reads (a directory removed, a file
made in its place) read a directory the checks never saw. The derivation is now
made once and handed to the loader.

The race is replayed by a ``Path`` whose ``is_dir`` answers False only when the
loader asks: at the base bytes the loader then reads the parent directory, which
holds no results, and the lookup fails; with one derivation the loader never asks.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

pytestmark = pytest.mark.unit

SCANNER = "bandit"
FINDING = f"{SCANNER}-finding-one"


def _write_results(output_dir: Path) -> None:
    document: Dict[str, Any] = {
        "metadata": {
            "scan_id": "test-scan",
            "scan_timestamp": "2026-01-01T00:00:00+00:00",
            "summary_stats": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
                "info": 0,
                "suppressed": 0,
            },
        },
        "sarif": {"version": "2.1.0", "runs": []},
        "additional_reports": {
            SCANNER: [
                {
                    "id": "finding-one",
                    "title": "Use of assert detected",
                    "description": "Use of assert statement detected",
                    "severity": "MEDIUM",
                    "type": "SAST",
                    "rule_id": "B101",
                    "file_path": "src/app.py",
                    "line_start": 42,
                    "line_end": 42,
                }
            ]
        },
        "scanner_results": {},
    }
    (output_dir / "ash_aggregated_results.json").write_text(
        json.dumps(document), encoding="utf-8"
    )


def test_the_loader_reads_the_directory_the_checks_saw(tmp_path, monkeypatch) -> None:
    from automated_security_helper.cli import mcp_tools

    output_dir = tmp_path / "ash_output"
    output_dir.mkdir()
    _write_results(output_dir)
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)

    class PathWhoseAnswerChanges(type(Path())):
        """``is_dir`` answers False to the loader's own second derivation only."""

        def is_dir(self, *args: Any, **kwargs: Any) -> bool:
            caller = sys._getframe(1).f_code.co_name
            if caller == "_load_flat_vulns_for_explain":
                return False
            return super().is_dir(*args, **kwargs)

    monkeypatch.setattr(mcp_tools, "Path", PathWhoseAnswerChanges)

    response = mcp_tools.mcp_explain_finding(FINDING, results_path=str(output_dir))

    assert response["success"] is True, response
    assert response["finding"]["title"] == "Use of assert detected", response


def test_the_loader_still_derives_the_directory_when_given_none(tmp_path) -> None:
    """Callers that hand no directory keep the file-or-directory derivation."""
    from automated_security_helper.cli.mcp_tools import _load_flat_vulns_for_explain

    output_dir = tmp_path / "ash_output"
    output_dir.mkdir()
    _write_results(output_dir)

    by_dir = _load_flat_vulns_for_explain(str(output_dir))
    by_file = _load_flat_vulns_for_explain(
        str(output_dir / "ash_aggregated_results.json")
    )
    by_handed = _load_flat_vulns_for_explain("ignored", results_dir=output_dir)

    assert [v.id for v in by_dir] == [v.id for v in by_file] == [FINDING]
    assert [v.id for v in by_handed] == [FINDING]
