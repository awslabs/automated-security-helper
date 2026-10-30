# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the ferret-scan plugin makes of the SARIF ferret-scan wrote.

Three readings that went wrong before:

- ferret-scan 2.5.x writes each file's path as a relative ``uri`` under
  ``%SRCROOT%``, as a path and not as a URI reference, so resolving it against the
  declared base with ``urljoin`` as written lost a name's tail at ``#`` or ``?``,
  read a ``%`` as an escape, and read a first segment ending in ``:`` as a scheme.
  The path is percent-encoded first.
- ``scan()`` replaces ``runs[0].invocations`` with ASH's own record, which dropped
  ferret-scan's ``toolExecutionNotifications``: the validator panics and
  incomplete-file notices the not-evaluated gate reads, and the plugin's own exit-3
  message tells the reader to look for. They are carried onto ASH's invocation.
- A results file that failed SARIF validation was returned as the raw dict, which
  the executor stored in ``additional_reports`` outside the masking that keeps
  matched values (``show_match``) out of the reports, and graded on its zero
  findings. It now raises, and the error names only the validation error count.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScannerConfig,
    FerretScannerConfigOptions,
    FerretScanScanner,
    _resolve_sarif_uri_base_ids,
)

pytestmark = pytest.mark.unit

BASE = "file:///work/src/"


def _located(uri: str) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ferret-scan"}},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": BASE}},
                "results": [
                    {
                        "ruleId": "SSN",
                        "message": {"text": "x"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": uri,
                                        "uriBaseId": "%SRCROOT%",
                                    }
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def _resolved(document: dict) -> str:
    return document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]


@pytest.mark.parametrize(
    "uri, expected",
    [
        ("src/a#b.py", BASE + "src/a%23b.py"),
        ("src/a?b.py", BASE + "src/a%3Fb.py"),
        ("src/100%.txt", BASE + "src/100%25.txt"),
        ("x:y/notes.txt", BASE + "x%3Ay/notes.txt"),
        ("src/plain.py", BASE + "src/plain.py"),
    ],
    ids=["hash", "question-mark", "percent", "colon-segment", "plain"],
)
def test_a_relative_uri_is_resolved_as_a_path_not_a_uri_reference(uri, expected):
    document = _located(uri)

    _resolve_sarif_uri_base_ids(document)

    assert _resolved(document) == expected
    assert "originalUriBaseIds" not in document["runs"][0]


def _scanner(context, **options) -> FerretScanScanner:
    scanner = FerretScanScanner(
        context=context,
        config=FerretScannerConfig(options=FerretScannerConfigOptions(**options)),
    )
    scanner.dependencies_satisfied = True
    return scanner


def _scan_with_results(scanner, target: Path, document: dict):
    """Run scan() with a ferret-scan double that writes ``document`` as its SARIF."""

    def _run(command, results_dir, **kwargs):
        Path(results_dir, "ferret-scan.sarif").write_text(
            json.dumps(document), encoding="utf-8"
        )
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_run),
        patch.object(scanner, "_plugin_log"),
    ):
        return scanner.scan(target=target, target_type="source")


def test_ferret_scans_own_notifications_ride_on_the_recorded_invocation(
    mock_plugin_context,
):
    root = mock_plugin_context.source_dir
    (root / "a.txt").write_text("hello\n", encoding="utf-8")
    notification = {
        "level": "error",
        "message": {"text": "validator SSN panicked on a.txt"},
    }
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ferret-scan", "version": "2.5.3"}},
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [notification],
                    }
                ],
            }
        ],
    }

    report = _scan_with_results(_scanner(mock_plugin_context), root, document)

    assert hasattr(report, "runs"), type(report)
    (invocation,) = report.runs[0].invocations
    # ASH's own record is still the invocation: the command line it ran.
    assert invocation.commandLine
    (kept,) = invocation.toolExecutionNotifications
    assert kept.message.root.text == notification["message"]["text"]
    assert getattr(kept.level, "value", kept.level) == "error"


def test_a_results_file_that_is_not_sarif_raises_instead_of_returning_the_document(
    mock_plugin_context,
):
    root = mock_plugin_context.source_dir
    (root / "a.txt").write_text("hello\n", encoding="utf-8")
    # A planted value that no detector pattern matches: the plugin's own validation
    # scans this test, and a card-shaped number here would be a finding of its own.
    matched = "planted-results-value-not-sarif"
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "ferret-scan"}}, "results": matched}],
    }

    with pytest.raises(ScannerError) as raised:
        _scan_with_results(_scanner(mock_plugin_context), root, document)

    message = str(raised.value)
    assert "not SARIF ASH can read" in message
    assert "validation error" in message
    # The validation error's own text quotes the input; none of it is repeated.
    assert matched not in message
