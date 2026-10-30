# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""explain_finding, diff_scan_results and suggest_suppression read results as UTF-8.

ASH writes ``ash_aggregated_results.json`` as UTF-8. The three tools read it
with ``Path.read_text()`` and no encoding, which is the locale's default: cp1252
on Windows, which cannot decode every UTF-8 byte sequence, so a results file
holding a finding title with a character outside cp1252 failed every one of
them there. The reads now name the encoding. The locale default is a stand-in
here, so these run on every platform.
"""

from __future__ import annotations

import json
import pathlib
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from automated_security_helper.cli.mcp_tools import (
    mcp_diff_scan_results,
    mcp_explain_finding,
    mcp_suggest_suppression,
)

pytestmark = pytest.mark.unit

FINDING_ID = "bandit-B101-snowman"
#: A title whose UTF-8 bytes cp1252 cannot decode. cp1252 leaves only five
#: bytes undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D), so the character has to carry
#: one of them: the right double quotation mark, U+201D, is E2 80 9D. The snowman
#: this file first used (U+2603, E2 98 83) is three cp1252-defined bytes, so a
#: cp1252 read of it did not raise; it returned the mojibake "â˜ƒ" and the three
#: tool tests passed under a bare read_text() too.
TITLE = "Use of assert detected ”"


def _aggregated() -> Dict[str, Any]:
    return {
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
            "bandit": [
                {
                    "id": "B101-snowman",
                    "title": TITLE,
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


@pytest.fixture
def results_file(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "ash_aggregated_results.json"
    path.write_bytes(json.dumps(_aggregated(), ensure_ascii=False).encode("utf-8"))

    def as_on_windows(self, encoding: Optional[str] = None, errors=None) -> str:
        # The locale default on Windows: a read that names no encoding decodes
        # the file as cp1252, as the real default would there.
        return self.read_bytes().decode(encoding or "cp1252", errors or "strict")

    monkeypatch.setattr(pathlib.Path, "read_text", as_on_windows)
    return path


def test_the_stand_in_locale_cannot_decode_the_file_by_default(results_file) -> None:
    with pytest.raises(UnicodeDecodeError):
        results_file.read_text()


def test_explain_finding_reads_the_file_as_utf8(results_file) -> None:
    result = mcp_explain_finding(FINDING_ID, results_path=str(results_file))

    assert result.get("success") is True, result
    # The title comes back as written, not as a decode that happened to succeed
    # would render it: a read under the wrong codec that raised nothing still
    # fails here.
    assert result["finding"]["title"] == TITLE, result["finding"]


def test_suggest_suppression_reads_the_file_as_utf8(results_file) -> None:
    result = mcp_suggest_suppression(FINDING_ID, results_path=str(results_file))

    assert result.get("success") is True, result
    assert result["json"]["rule_id"] == "B101"


def test_diff_scan_results_reads_both_files_as_utf8(results_file, tmp_path) -> None:
    after = tmp_path / "after.json"
    after.write_bytes(results_file.read_bytes())

    result = mcp_diff_scan_results(str(results_file), str(after))

    # A diff carries no success flag: its answer is the three lists, and a
    # refused or unreadable file is answered as {"success": False, "error": ...}
    # instead. Two reads of the same bytes leave every list empty.
    assert "error" not in result, result
    assert result == {"new": [], "resolved": [], "severity_changed": []}, result
