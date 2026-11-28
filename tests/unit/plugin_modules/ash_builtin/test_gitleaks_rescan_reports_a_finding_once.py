"""A finding both gitleaks runs report is added back to the report once.

When the scanned tree's ``.gitleaksignore`` names a file, ASH re-scans that file and
adds what the first run lacks. A result is the same finding when its file, rule and
region are the same, and the first run's findings are not added twice
(``_rescan_key``).

A part of a result that is empty, of any type (a region written ``[]`` or ``""`` or
``0`` or ``false``, a ``locations`` written ``""``), is read as absent, so the same
finding in both runs has the same key whatever the reading step later does with that
part. It was given no key, so the re-scan's copy was added beside the first run's, and
one finding was reported twice.

A part that cannot be read as anything (a non-empty list where an object is
written) still has no key. Such a result is added as it is, and the reading step
reads it as it reads any other result.
"""

from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    _rescan_key,
)
from automated_security_helper.schemas.scanner_output_ingest import (
    IngestRecord,
    ingest_sarif,
)
from tests.unit.plugin_modules.ash_builtin.test_gitleaks_scanner import (
    _report,
    _result,
    _scanner,
    _write,
)

pytestmark = pytest.mark.unit

#: Whether the reading step of this branch can leave out one result it cannot read.
_CAN_ISOLATE = "isolate" in inspect.signature(ingest_sarif).parameters

#: The empty values a part of a result can hold, and what each part is called in a
#: result: ``(part, value)``, the part's place named by ``_with_the_part``.
_EMPTY_PARTS = [
    pytest.param(("region", []), id="region_a_list"),
    pytest.param(("region", ""), id="region_a_string"),
    pytest.param(("region", 0), id="region_zero"),
    pytest.param(("region", False), id="region_false"),
    pytest.param(("artifactLocation", []), id="artifact_location_a_list"),
    pytest.param(("artifactLocation", ""), id="artifact_location_a_string"),
    pytest.param(("artifactLocation", 0), id="artifact_location_zero"),
    pytest.param(("artifactLocation", False), id="artifact_location_false"),
    pytest.param(("locations", ""), id="locations_a_string"),
    pytest.param(("locations", 0), id="locations_zero"),
    pytest.param(("locations", False), id="locations_false"),
    pytest.param(("locations", {}), id="locations_an_object"),
]


def _with_the_part(result: dict, part: str, value: Any) -> dict:
    """*result* with *part* set to *value*, as a copy."""
    result = copy.deepcopy(result)
    if part == "locations":
        result["locations"] = value
    else:
        result["locations"][0]["physicalLocation"][part] = value
    return result


def _without_the_part(result: dict, part: str) -> dict:
    """*result* with *part* absent, as a copy."""
    result = copy.deepcopy(result)
    if part == "locations":
        del result["locations"]
    else:
        del result["locations"][0]["physicalLocation"][part]
    return result


FINDING = _result("app/x.py", "aws-access-token", 5)
HIDDEN = _result("app/x.py", "github-pat", 4)


@pytest.mark.parametrize("empty", _EMPTY_PARTS)
def test_an_empty_part_is_keyed_as_an_absent_one(empty):
    part, value = empty

    empty_key = _rescan_key(_with_the_part(FINDING, part, value))
    absent_key = _rescan_key(_without_the_part(FINDING, part))

    assert absent_key is not None
    assert empty_key == absent_key


@pytest.mark.parametrize(
    "unreadable",
    [
        pytest.param(("region", [1]), id="region_a_list_with_items"),
        pytest.param(("region", "x"), id="region_a_string_with_text"),
        pytest.param(("artifactLocation", ["a"]), id="artifact_location_a_list"),
        pytest.param(("locations", "app/x.py"), id="locations_a_string_with_text"),
        pytest.param(("locations", 5), id="locations_a_number"),
        pytest.param(("locations", [5]), id="locations_a_list_of_a_number"),
    ],
)
def test_control_a_part_that_cannot_be_read_has_no_key(unreadable):
    part, value = unreadable

    assert _rescan_key(_with_the_part(FINDING, part, value)) is None


def _rescan_reporting(tmp_path, monkeypatch, found: list):
    """A scanner over a tree whose ``.gitleaksignore`` names ``app/x.py``, whose
    re-scan reports *found*, as gitleaks would write the document."""
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:4\n")

    def writing(command, results_dir=None, timeout=None, cwd=None, **kwargs):
        report = next(
            a.split("=", 1)[1] for a in command if a.startswith("--report-path=")
        )
        Path(report).write_text(json.dumps(_report(*found)))
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_run_subprocess", writing)
    return scanner, source


def _add_back(scanner, source: Path, raw: dict, tmp_path: Path) -> list[str]:
    """Run the add-back for *raw*; the rule of each result of the document after it."""
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir(exist_ok=True)
    scanner._add_back_gitleaksignore_drops(
        raw, source, scanner._build_arguments(source, results_file), results_file
    )
    return sorted(r["ruleId"] for r in raw["runs"][0]["results"])


@pytest.mark.parametrize("empty", _EMPTY_PARTS)
def test_a_finding_both_runs_report_is_in_the_document_once(
    tmp_path, monkeypatch, empty
):
    """The first run reports the finding with an empty part, and so does the re-scan,
    beside the finding the ignore file hid. The hidden one is added, the other is
    the one the first run reported."""
    part, value = empty
    finding = _with_the_part(FINDING, part, value)
    scanner, source = _rescan_reporting(
        tmp_path, monkeypatch, [copy.deepcopy(finding), copy.deepcopy(HIDDEN)]
    )

    rules = _add_back(scanner, source, _report(copy.deepcopy(finding)), tmp_path)

    assert rules == ["aws-access-token", "github-pat"]


def test_control_a_finding_only_the_re_scan_reports_is_added(tmp_path, monkeypatch):
    scanner, source = _rescan_reporting(
        tmp_path, monkeypatch, [copy.deepcopy(FINDING), copy.deepcopy(HIDDEN)]
    )

    rules = _add_back(scanner, source, _report(), tmp_path)

    assert rules == ["aws-access-token", "github-pat"]


@pytest.mark.parametrize(
    "empty",
    [
        pytest.param(("region", []), id="region_a_list"),
        pytest.param(("region", ""), id="region_a_string"),
        pytest.param(("region", 0), id="region_zero"),
        pytest.param(("region", False), id="region_false"),
    ],
)
def test_a_finding_with_an_empty_region_is_reported_once(tmp_path, monkeypatch, empty):
    """The whole path: the reading step drops a region that is not an object and
    keeps the finding, so the finding both runs report is one result of the report."""
    part, value = empty
    finding = _with_the_part(FINDING, part, value)
    scanner, source = _rescan_reporting(
        tmp_path, monkeypatch, [copy.deepcopy(finding), copy.deepcopy(HIDDEN)]
    )
    raw = _report(copy.deepcopy(finding))
    _add_back(scanner, source, raw, tmp_path)

    record = IngestRecord()
    report = ingest_sarif(raw, record)

    assert sorted(r.ruleId for r in report.runs[0].results) == [
        "aws-access-token",
        "github-pat",
    ]
    assert record.left_out == 0


@pytest.mark.skipif(
    not _CAN_ISOLATE, reason="the reading step has no isolation on this branch"
)
@pytest.mark.parametrize(
    "empty",
    [
        pytest.param(("locations", ""), id="locations_a_string"),
        pytest.param(("locations", 0), id="locations_zero"),
    ],
)
def test_a_finding_the_reading_step_cannot_read_is_left_out_once(
    tmp_path, monkeypatch, empty
):
    """Reported once or left out once, never twice: with the reading step that
    isolates a result it cannot read, the one result of the finding is left out and
    counted once."""
    part, value = empty
    finding = _with_the_part(FINDING, part, value)
    scanner, source = _rescan_reporting(
        tmp_path, monkeypatch, [copy.deepcopy(finding), copy.deepcopy(HIDDEN)]
    )
    raw = _report(copy.deepcopy(finding))
    _add_back(scanner, source, raw, tmp_path)

    record = IngestRecord()
    report = ingest_sarif(raw, record, isolate=True)

    assert sorted(r.ruleId for r in report.runs[0].results) == ["github-pat"]
    assert record.left_out == 1
