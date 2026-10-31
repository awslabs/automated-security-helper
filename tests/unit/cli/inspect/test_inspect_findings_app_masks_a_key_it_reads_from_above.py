# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""`ash inspect findings` masks a key block whose BEGIN line is above its window.

The detail view reads the lines around a finding from its file, from five lines
above the finding. A key block is found from its BEGIN line, so a finding deep in
a key body, with the BEGIN line reported by another finding well above the
window, showed body lines of the key: the text the masker was given held no BEGIN
line. The view now asks the masker where to start reading, masks from there, and
cuts the lines above the window off after the masking.

The key body here is derived at import time; none of it is a key.
"""

from __future__ import annotations

import hashlib
import string
from unittest.mock import MagicMock

import pytest

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.secret_masking import (
    MASKED_LINE,
    source_snippet_masker,
)

pytestmark = pytest.mark.unit


def _derived(label, length):
    alphabet = string.ascii_lowercase + string.digits
    digest = hashlib.sha256(label.encode()).digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)[:length]


#: A file of 45 lines: a block from line 11 (BEGIN) through line 38 (END), 26 body
#: lines between, and plain lines around it.
FILE_LINES = (
    [f"v{number} = {number}" for number in range(1, 11)]
    + ["-----BEGIN RSA PRIVATE " + "KEY-----"]
    + [_derived(f"body-{number}", 40) for number in range(12, 38)]
    + ["-----END RSA PRIVATE " + "KEY-----"]
    + [f"w{number} = {number}" for number in range(39, 46)]
)


def _results(reported_line):
    """One finding of a rule that is not a private-key rule, on one line, with no
    snippet: nothing shows the key block it may begin."""
    model = AshAggregatedResults()
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test"}},
                    "results": [
                        {
                            "ruleId": "CUSTOM-1",
                            "level": "warning",
                            "message": {"text": "Custom finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "keys.py"},
                                        "region": {
                                            "startLine": reported_line,
                                            "endLine": reported_line,
                                        },
                                    }
                                }
                            ],
                            "properties": {
                                "scanner_name": "detect-secrets",
                                "tags": ["secret"],
                            },
                        }
                    ],
                }
            ],
        }
    )
    return model


def _snippet_shown_for(tmp_path, reported_line, viewed_line):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "keys.py").write_text("\n".join(FILE_LINES) + "\n", encoding="utf-8")
    finding = {
        "rule_id": "R1",
        "severity": "low",
        "scanner": "probe",
        "message": "m",
        "suppressed": False,
        "file": "keys.py",
        "line": viewed_line,
    }
    app = FindingsExplorerApp(
        [finding],
        mask_source=source_snippet_masker(_results(reported_line)),
        scan_root=root,
    )
    app.filtered_findings = [finding]
    table = MagicMock()
    table.row_count = 1
    table.cursor_row = 0
    app.query_one = MagicMock(return_value=table)
    app.push_screen = MagicMock()

    app.action_view_selected()

    return finding["code_snippet"]


def test_a_finding_deep_in_a_key_body_shows_no_line_of_the_key(tmp_path):
    """The BEGIN line is reported on line 11 and the viewed finding is on line
    30, so the window is lines 25 to 35, all inside the block: every one is
    replaced, and no line above the window is shown."""
    shown = _snippet_shown_for(tmp_path, reported_line=11, viewed_line=30)

    lines = shown.splitlines()
    assert len(lines) == 11
    assert all(line.strip() == MASKED_LINE for line in lines)
    assert not any(body in shown for body in FILE_LINES[11:37])


def test_a_window_that_shows_no_reported_line_is_shown_as_read(tmp_path):
    """Control: the only reported line is below the window and the block's BEGIN
    line is not reported, so nothing above the window is asked for and the lines
    are shown as the file holds them, numbered from line 25."""
    shown = _snippet_shown_for(tmp_path, reported_line=40, viewed_line=30)

    expected = "".join(
        f"{'→ ' if number == 30 else '  '}{number:>2}: {FILE_LINES[number - 1]}\n"
        for number in range(25, 36)
    )
    assert shown == expected
