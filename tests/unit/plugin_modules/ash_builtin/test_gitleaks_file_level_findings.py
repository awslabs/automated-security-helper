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

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    gitleaks_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    LEAKS_EXIT_CODE,
    drop_regions_without_a_line,
)
from automated_security_helper.schemas.scanner_output_ingest import IngestRecord
from tests.unit.plugin_modules.ash_builtin.test_gitleaks_scanner import (
    _report,
    _result,
    _scanner,
)

pytestmark = pytest.mark.unit


def _file_level_result(uri: str, rule: str = "pkcs12-file") -> dict:
    """A result as gitleaks 8.30.1 writes one for ``pkcs12-file`` (captured). *rule*
    names another file rule where a test needs two results told apart."""
    return {
        "ruleId": rule,
        "message": {"text": rule + " has detected secret for file " + uri + "."},
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


# --------------------------------------------------------------------------- #
# What the drop costs, counted
#
# The drop is deliberate, and the file keeps its finding. It used to leave no
# trace, though, so a report whose file-level findings lost their regions read
# the same as one that had none. Each dropped region is now noted on the scan's
# record, with its place in gitleaks' document and its rule.
# --------------------------------------------------------------------------- #

_SHARED_SENTENCE = (
    "ASH repaired {n} {parts} of gitleaks' report that SARIF does not allow "
    "(a region with no readable line)."
)


def _region_of(result_index: int) -> str:
    return f"runs/0/results/{result_index}/locations/0/physicalLocation/region"


def _scan_keeping_the_scanner(tmp_path: Path, monkeypatch, report: dict):
    """``_scan``, with the scanner returned beside the report it produced."""
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
    return scanner, scanner.scan(target=source, target_type="source")


def _warnings(report) -> list:
    return [
        note.message.root.text
        for invocation in report.runs[0].invocations
        for note in invocation.toolExecutionNotifications or []
        if getattr(note.level, "value", note.level) == "warning"
    ]


def test_each_dropped_region_is_noted_with_its_place_and_its_rule():
    raw = _report(
        _file_level_result("a.p12"),
        _result("b.py", "github-pat", 3, column=7),
        _file_level_result("c.pfx", "keystore-file"),
    )
    record = IngestRecord()

    drop_regions_without_a_line(raw, record)

    summary = record.summary()
    assert summary["repaired"] == 2 and summary["left_out"] == 0
    # Two different rules, so a note paired with the wrong result would show.
    assert [
        (e["action"], e["code"], e["pointer"], e["rule_id"])
        for e in summary["elements"]
    ] == [
        ("dropped", "region_line_unreadable", _region_of(0), "pkcs12-file"),
        ("dropped", "region_line_unreadable", _region_of(2), "keystore-file"),
    ]


def test_the_note_names_no_file_and_no_value_of_the_report():
    raw = _report(_file_level_result("certs/secret-name.pfx"))
    record = IngestRecord()

    drop_regions_without_a_line(raw, record)

    assert "secret-name" not in json.dumps(record.summary())
    assert "secret-name" not in record.sentence("gitleaks")


@pytest.mark.parametrize(
    "raw",
    [
        _report(_result("b.py", "github-pat", 3, column=7)),
        [],
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
    ids=[
        "a region with a line",
        "not a report",
        "a region that is no object",
        "a text",
    ],
)
def test_nothing_is_noted_where_nothing_is_dropped(raw):
    record = IngestRecord()

    drop_regions_without_a_line(raw, record)

    assert record.is_empty


def test_a_certificate_in_the_tree_is_counted_and_costs_no_finding(
    tmp_path, monkeypatch
):
    scanner, report = _scan_keeping_the_scanner(
        tmp_path,
        monkeypatch,
        _report(
            _file_level_result("certs/test.pfx"),
            _result("config.py", "generic-api-key", 1, column=1),
        ),
    )

    assert [r.ruleId for r in report.runs[0].results] == [
        "pkcs12-file",
        "generic-api-key",
    ]
    summary = scanner.output_ingest_record
    assert summary["repaired"] == 1 and summary["results_read"] == 2
    assert [(e["code"], e["pointer"], e["rule_id"]) for e in summary["elements"]] == [
        ("region_line_unreadable", _region_of(0), "pkcs12-file")
    ]
    assert _warnings(report) == [_SHARED_SENTENCE.format(n=1, parts="part")]


def test_two_certificates_are_two_counted_repairs(tmp_path, monkeypatch):
    scanner, report = _scan_keeping_the_scanner(
        tmp_path,
        monkeypatch,
        _report(
            _file_level_result("a.p12"),
            _result("config.py", "generic-api-key", 1, column=1),
            _file_level_result("b.pfx"),
        ),
    )

    assert len(report.runs[0].results) == 3
    assert scanner.output_ingest_record["repaired"] == 2
    assert _warnings(report) == [_SHARED_SENTENCE.format(n=2, parts="parts")]


def test_a_region_with_a_line_and_an_end_column_of_zero_keeps_its_finding(
    tmp_path, monkeypatch
):
    """The shared step repairs what the gitleaks drop does not name, and counts it."""
    odd = _result("config.py", "generic-api-key", 3, column=1)
    odd["locations"][0]["physicalLocation"]["region"]["endColumn"] = 0

    scanner, report = _scan_keeping_the_scanner(
        tmp_path, monkeypatch, _report(odd, _file_level_result("a.p12"))
    )

    assert [r.ruleId for r in report.runs[0].results] == [
        "generic-api-key",
        "pkcs12-file",
    ]
    kept = report.runs[0].results[0].locations[0].physicalLocation.root.region
    assert kept.startLine == 3 and kept.endColumn is None
    summary = scanner.output_ingest_record
    assert summary["repaired"] == 2
    assert sorted((e["code"], e["pointer"]) for e in summary["elements"]) == [
        ("region_field_unreadable", _region_of(0) + "/endColumn"),
        ("region_line_unreadable", _region_of(1)),
    ]


def test_a_clean_report_is_not_counted(tmp_path, monkeypatch):
    scanner, report = _scan_keeping_the_scanner(
        tmp_path,
        monkeypatch,
        _report(_result("config.py", "generic-api-key", 1, column=1)),
    )

    assert scanner.output_ingest_record is None
    assert _warnings(report) == []


def test_control_a_drop_that_is_not_given_the_record_is_silent(tmp_path, monkeypatch):
    """The same scan with the drop called as it was before: the finding keeps its
    file and loses its region, and nothing says so."""
    original = gitleaks_scanner.drop_regions_without_a_line
    monkeypatch.setattr(
        gitleaks_scanner,
        "drop_regions_without_a_line",
        lambda raw, record=None: original(raw),
    )

    scanner, report = _scan_keeping_the_scanner(
        tmp_path, monkeypatch, _report(_file_level_result("a.p12"))
    )

    assert [r.ruleId for r in report.runs[0].results] == ["pkcs12-file"]
    assert scanner.output_ingest_record is None
    assert _warnings(report) == []
