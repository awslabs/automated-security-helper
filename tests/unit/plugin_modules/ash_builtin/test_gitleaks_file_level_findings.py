# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A gitleaks finding about a whole file does not cost the report its findings.

gitleaks has rules that match a file by its path alone: ``pkcs12-file`` reports
every ``.p12`` and ``.pfx``. Such a finding has no line, and gitleaks 8.30.1
writes its region as ``startLine: 0`` (and the columns and end line 0 too). SARIF
2.1.0 requires a ``startLine`` of 1 or more, so ASH refused the whole report and
the scanner ended in ERROR: one certificate anywhere in the tree hid every secret
gitleaks found in it. The scanner now drops a region whose lines are 0 before the
report is validated, so the finding names its file and nothing else.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    LEAKS_EXIT_CODE,
    drop_regions_without_a_line,
)
from tests.unit.plugin_modules.ash_builtin.test_gitleaks_scanner import (
    _report,
    _result,
    _scanner,
)

pytestmark = pytest.mark.unit


def _file_level_result(uri: str) -> dict:
    """A result as gitleaks 8.30.1 writes one for ``pkcs12-file`` (captured)."""
    return {
        "ruleId": "pkcs12-file",
        "message": {"text": "pkcs12-file has detected secret for file " + uri + "."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": 0,
                        "startColumn": 0,
                        "endLine": 0,
                        "endColumn": 0,
                        "snippet": {"text": "REDACTED"},
                    },
                }
            }
        ],
        "partialFingerprints": {
            "commitSha": "",
            "email": "",
            "author": "",
            "date": "",
            "commitMessage": "",
        },
    }


def _scan(tmp_path: Path, monkeypatch, report: dict):
    """Scan a tree with gitleaks standing in as a writer of ``report``."""
    from automated_security_helper.utils import subprocess_utils

    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir
    (source / "config.py").write_text("x")
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)

    def launch(command, **kwargs):
        path = next(
            a.split("=", 1)[1] for a in command if a.startswith("--report-path=")
        )
        Path(path).write_text(json.dumps(report))
        return {"returncode": LEAKS_EXIT_CODE}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", launch)
    return scanner.scan(target=source, target_type="source")


def _located(result) -> tuple:
    physical = result.locations[0].physicalLocation.root
    region = physical.region
    return (
        physical.artifactLocation.uri,
        None if region is None else region.startLine,
    )


def test_a_certificate_in_the_tree_keeps_the_other_findings(tmp_path, monkeypatch):
    report = _scan(
        tmp_path,
        monkeypatch,
        _report(
            _file_level_result("certs/test.pfx"),
            _result("config.py", "generic-api-key", 1, column=1),
        ),
    )

    results = report.runs[0].results
    assert [r.ruleId for r in results] == ["pkcs12-file", "generic-api-key"]
    assert [_located(r) for r in results] == [
        ("certs/test.pfx", None),
        ("config.py", 1),
    ]


def test_a_report_of_file_level_findings_only_is_read(tmp_path, monkeypatch):
    report = _scan(tmp_path, monkeypatch, _report(_file_level_result("a.p12")))

    assert [_located(r) for r in report.runs[0].results] == [("a.p12", None)]


def test_only_a_region_whose_start_line_is_below_one_is_dropped():
    zero = _file_level_result("a.pfx")
    line = _result("b.py", "github-pat", 3, column=7)
    no_line = _result("c.py", "github-pat", 1)
    del no_line["locations"][0]["physicalLocation"]["region"]["startLine"]
    raw = _report(zero, line, no_line)

    drop_regions_without_a_line(raw)

    regions = [
        r["locations"][0]["physicalLocation"].get("region")
        for r in raw["runs"][0]["results"]
    ]
    assert regions[0] is None
    assert regions[1] == {
        "startLine": 3,
        "startColumn": 7,
        "endLine": 3,
        "endColumn": 46,
        "snippet": {"text": "REDACTED"},
    }
    # A region without a startLine is valid SARIF; it is left as it is.
    assert regions[2] == {"snippet": {"text": "REDACTED"}}


@pytest.mark.parametrize(
    "raw",
    [
        [],
        "not a report",
        {},
        {"runs": None},
        {"runs": 5},
        {"runs": [{"results": 5}]},
        {"runs": [{"results": [{"locations": 5}]}]},
        {"runs": [{"results": None}]},
        {"runs": [{"results": [{"locations": None}]}]},
        {"runs": [{"results": [{"locations": [{"physicalLocation": None}]}]}]},
        {"runs": [{"results": [{"locations": [{"physicalLocation": {"region": 7}}]}]}]},
        {
            "runs": [
                {
                    "results": [
                        {
                            "locations": [
                                {"physicalLocation": {"region": {"startLine": "0"}}}
                            ]
                        }
                    ]
                }
            ]
        },
    ],
)
def test_a_report_of_another_shape_is_left_to_the_validation(raw):
    """Only the shape gitleaks writes is changed; anything else reaches the SARIF
    validation as it is, and is refused there if it is not SARIF."""
    before = json.dumps(raw, sort_keys=True)

    drop_regions_without_a_line(raw)

    assert json.dumps(raw, sort_keys=True) == before
