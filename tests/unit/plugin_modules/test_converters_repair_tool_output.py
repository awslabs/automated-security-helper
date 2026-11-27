"""A scanner that builds its SARIF from the tool's own JSON keeps a finding whose field it cannot convert.

npm audit, GuardDog, detect-secrets, actionlint, checkov and cdk-nag turn the tool's
JSON into SARIF themselves, so the one field the SARIF model refuses (an advisory
title that is null, a link that is "N/A", a line that is 0, a file name that is not
Unicode) used to cost the scanner every finding of the run: the conversion raised, and
the scan ended in ERROR for a reason that was one field of one finding.

Each converter now repairs that field where it converts it, keeps the finding, and
notes the repair on the scanner's record with a pointer into the tool's JSON, never a
value from it. The repairs, in the order of the cases below:

* npm audit: a title that is not text is the advisory's id, a link that is not
  absolute is left out, in the npm and the yarn and pnpm shapes, in every lockfile.
* GuardDog: a file name that is not Unicode is fingerprinted as it is, a message,
  description or code that is not text is written as text or left out, a file path that
  is not text is left out, and a field of the wrong kind in the list of risks does not
  stop the findings.
* detect-secrets: a line below 1 builds no region.
* actionlint: the digits of a line written as text are that line, a negative line
  builds no region.
* checkov: a side report whose ``results`` is not an object is left as it is and the
  SARIF is kept, and a part of the SARIF that is not an object is left for the
  validation to refuse in its own words.
* cdk-nag: a rule name or description that is a number is written as its text, a
  description of any other kind is one fixed sentence, and the record crosses from the
  worker's process to the scanner's.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import create_autospec

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
    build_sarif,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
    CdkNagScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    rewrite_checkov_paths,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    convert_guarddog_scan_result,
)
from automated_security_helper.schemas.sarif_schema_model import Result, SarifReport
from automated_security_helper.schemas.scanner_output_ingest import (
    IngestRecord,
    ingest_sarif,
)
from automated_security_helper.utils import cdk_nag_wrapper, cdk_nag_worker
from automated_security_helper.utils.cdk_nag_wrapper import (
    CdkNagWrapperResponse,
    _violations_from_validation_report,
)

pytestmark = pytest.mark.unit

_DATA = Path(__file__).resolve().parents[2] / "test_data" / "scanners"


def _ingest_of(report: SarifReport) -> dict[str, Any] | None:
    """What a report says its scanner repaired: the summary on the invocation's
    notification, as it is written to the results file, or None."""
    dumped = json.loads(report.model_dump_json(exclude_none=True))
    for run in dumped["runs"]:
        for invocation in run.get("invocations") or []:
            for note in invocation.get("toolExecutionNotifications") or []:
                summary = (note.get("properties") or {}).get("ash_output_ingest")
                if summary is not None:
                    return summary
    return None


def _changes(record: IngestRecord) -> dict[tuple[str, str], int]:
    summary = record.summary()
    assert summary is not None, "nothing was noted"
    return {(c["action"], c["code"]): c["count"] for c in summary["changes"]}


def _pointers(record: IngestRecord) -> list[str]:
    summary = record.summary()
    assert summary is not None, "nothing was noted"
    return [element["pointer"] for element in summary["elements"]]


# --------------------------------------------------------------------------- #
# npm audit
# --------------------------------------------------------------------------- #

_NPM = json.loads((_DATA / "npmaudit" / "npm.json").read_text(encoding="utf-8"))
#: The package whose one advisory the cases below damage, and that advisory's id and
#: title.
_PACKAGE = "bootstrap"
_ADVISORY_ID = "GHSA-vc8w-jr9v-vj7f"
_ADVISORY_TITLE = "Bootstrap Cross-Site Scripting (XSS) vulnerability"


def _npm_scanner(tmp_path: Path) -> NpmAuditScanner:
    """A default-configured scanner, as ``NpmAuditScanner.convert_results`` makes one."""
    AshConfig.model_rebuild()
    scanner = NpmAuditScanner(
        context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "ash-output",
            work_dir=tmp_path / "ash-work",
            config=get_default_config(),
        ),
        config=NpmAuditScannerConfig(),
    )
    scanner.exit_code = 0
    return scanner


def _npm_with(**changes: Any) -> dict[str, Any]:
    """The committed capture with fields of one advisory replaced."""
    report = copy.deepcopy(_NPM)
    via = report["vulnerabilities"][_PACKAGE]["via"][0]
    assert via["url"].endswith(_ADVISORY_ID), "the capture changed under this test"
    via.update(changes)
    return report


def _rule(report: SarifReport, rule_id: str) -> Any:
    (rule,) = [r for r in report.runs[0].tool.driver.rules or [] if r.id == rule_id]
    return rule


_NOT_TEXT = [
    pytest.param(None, id="null"),
    pytest.param(5, id="int"),
    pytest.param(["a", "list"], id="list"),
]


@pytest.mark.parametrize("title", _NOT_TEXT)
def test_npm_an_advisory_whose_title_is_not_text_keeps_every_advisory(tmp_path, title):
    baseline = NpmAuditScanner.convert_results(_NPM, tmp_path)

    report = NpmAuditScanner.convert_results(_npm_with(title=title), tmp_path)

    assert len(report.runs[0].results) == len(baseline.runs[0].results)
    # The advisory's own id stands where its title was: the rule's text and the
    # result's message, so the finding still says what it is.
    assert _rule(report, _ADVISORY_ID).shortDescription.text == _ADVISORY_ID
    texts = [r.message.root.text for r in report.runs[0].results]
    assert any(text.startswith(f"{_ADVISORY_ID} in {_PACKAGE}") for text in texts)
    assert _ingest_of(report) is not None
    summary = _ingest_of(report)
    assert summary["repaired"] == 1 and summary["left_out"] == 0
    assert summary["changes"] == [
        {"action": "rewritten", "code": "title_not_text", "count": 1}
    ]
    assert [e["pointer"] for e in summary["elements"]] == [
        "vulnerabilities/*/via/0/title"
    ]
    assert summary["elements"][0]["rule_id"] == _ADVISORY_ID
    assert _PACKAGE not in json.dumps(summary), "a package name reached the record"


@pytest.mark.parametrize(
    "url", ["N/A", "/advisories/GHSA-vc8w", 5, ["https://a.example"]]
)
def test_npm_an_advisory_whose_url_is_not_a_link_keeps_the_advisory_without_it(
    tmp_path, url
):
    baseline = NpmAuditScanner.convert_results(_NPM, tmp_path)

    report = NpmAuditScanner.convert_results(_npm_with(url=url), tmp_path)

    assert len(report.runs[0].results) == len(baseline.runs[0].results)
    # The rule id is the url's last segment, and a url that is not a link is not one
    # the id can be trusted from, so the advisory is found by its title.
    (kept,) = [
        r
        for r in report.runs[0].tool.driver.rules or []
        if r.shortDescription is not None and r.shortDescription.text == _ADVISORY_TITLE
    ]
    assert kept.helpUri is None
    summary = _ingest_of(report)
    assert summary is not None
    assert summary["changes"] == [
        {"action": "dropped", "code": "url_not_absolute", "count": 1}
    ]
    assert [e["pointer"] for e in summary["elements"]] == [
        "vulnerabilities/*/via/0/url"
    ]


def test_npm_a_report_that_needs_no_repair_says_nothing(tmp_path):
    report = NpmAuditScanner.convert_results(_NPM, tmp_path)

    assert _ingest_of(report) is None
    assert not report.runs[0].invocations[0].toolExecutionNotifications


def test_npm_the_yarn_and_pnpm_records_are_repaired_the_same_way(tmp_path):
    """yarn 1 and pnpm write npm's v1 ``advisories``; a title that is a number and a
    link that is "N/A" cost them every lockfile's findings as well."""
    report = {
        "advisories": {
            "1": {
                "id": 1,
                "module_name": "lodash",
                "title": 5,
                "url": "N/A",
                "severity": "high",
                "vulnerable_versions": "<4.17.21",
                "patched_versions": ">=4.17.21",
                "cwe": "CWE-79",
                "findings": [{"version": "4.17.20", "paths": [".>lodash"]}],
            },
            "2": {
                "id": 2,
                "module_name": "minimist",
                "title": "Prototype pollution in minimist",
                "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h",
                "severity": "low",
                "vulnerable_versions": "<1.2.6",
                "patched_versions": ">=1.2.6",
                "cwe": "CWE-1321",
                "findings": [{"version": "1.2.5", "paths": [".>minimist"]}],
            },
        },
        "metadata": {"vulnerabilities": {"low": 1, "high": 1}},
    }

    converted = NpmAuditScanner.convert_results(report, tmp_path)

    assert len(converted.runs[0].results) == 2
    summary = _ingest_of(converted)
    assert summary is not None
    assert {(c["code"], c["count"]) for c in summary["changes"]} == {
        ("title_not_text", 1),
        ("url_not_absolute", 1),
    }
    assert sorted(e["pointer"] for e in summary["elements"]) == [
        "advisories/*/title",
        "advisories/*/url",
    ]


def test_npm_every_lockfile_is_kept_and_a_place_is_named_by_its_lockfile_number(
    tmp_path,
):
    scanner = _npm_scanner(tmp_path)
    first, second = _NPM, _npm_with(title=None, url="N/A")
    locks = [tmp_path / "a" / "yarn.lock", tmp_path / "b" / "yarn.lock"]
    baseline = _npm_scanner(tmp_path)._convert_per_lockfile(
        list(zip(locks, [first, first])), first, tmp_path
    )

    report = scanner._convert_per_lockfile(
        list(zip(locks, [first, second])), first, tmp_path
    )

    assert len(report.runs[0].results) == len(baseline.runs[0].results)
    assert len(report.runs[0].results) > 0
    assert _pointers(scanner._ingest_record) == [
        "lockfile 2: vulnerabilities/*/via/0/title",
        "lockfile 2: vulnerabilities/*/via/0/url",
    ]
    summary = _ingest_of(report)
    assert summary is not None and summary["repaired"] == 2


# --------------------------------------------------------------------------- #
# GuardDog
# --------------------------------------------------------------------------- #

_GUARDDOG = json.loads(
    (_DATA / "guarddog" / "captured" / "scan_pypi_pypi_suspicious.json").read_text(
        encoding="utf-8"
    )
)
_LONE_SURROGATE = chr(0xDCE9)


def _guarddog(
    document: dict[str, Any], record: IngestRecord | None = None
) -> list[Result]:
    return convert_guarddog_scan_result(
        document,
        uri_prefix="pkg",
        ecosystem="pypi",
        include_capabilities=True,
        record=record,
    ).results


def _places(results: list[Result]) -> Counter:
    return Counter(
        (r.ruleId, r.locations[0].physicalLocation.root.artifactLocation.uri)
        for r in results
    )


def _guarddog_with(change) -> dict[str, Any]:
    document = copy.deepcopy(_GUARDDOG)
    change(document)
    return document


def test_guarddog_the_capture_converts_without_a_repair():
    record = IngestRecord()

    results = _guarddog(_GUARDDOG, record)

    assert len(results) > 0
    assert record.is_empty


@pytest.mark.parametrize(
    "threat_code",
    [["exec", "base64"], {"a": 1}, 1.5, True],
    ids=["list", "object", "float", "bool"],
)
def test_guarddog_a_code_that_is_not_text_is_left_out_and_the_finding_kept(threat_code):
    baseline = _guarddog(_GUARDDOG)
    record = IngestRecord()

    results = _guarddog(
        _guarddog_with(lambda d: d["risks"][0].update(threat_code=threat_code)), record
    )

    # Nothing of the baseline is lost; a match the risk no longer accounts for may
    # be reported once more as the match it is.
    assert not (_places(baseline) - _places(results))
    assert _changes(record) == {("rewritten", "field_not_text"): 1}
    assert _pointers(record) == ["risks/0/threat_code"]


def test_guarddog_an_integer_code_is_written_as_text():
    record = IngestRecord()

    results = _guarddog(
        _guarddog_with(lambda d: d["risks"][0].update(threat_code=7)), record
    )

    assert not (_places(_guarddog(_GUARDDOG)) - _places(results))
    assert _changes(record) == {("rewritten", "number_as_text"): 1}
    assert _pointers(record) == ["risks/0/threat_code"]


@pytest.mark.parametrize(
    "description",
    [["a"], {"a": 1}, False, 2.5],
    ids=["list", "object", "false", "float"],
)
def test_guarddog_a_description_that_is_not_text_is_the_rule_id(description):
    results_before = _guarddog(_GUARDDOG)
    record = IngestRecord()
    document = _guarddog_with(
        lambda d: d["risks"][0].update(threat_description=description)
    )

    converted = convert_guarddog_scan_result(
        document,
        uri_prefix="pkg",
        ecosystem="pypi",
        include_capabilities=True,
        record=record,
    )

    assert len(converted.results) == len(results_before)
    rule_id = _GUARDDOG["risks"][0]["threat_rule"]
    assert converted.rules[rule_id].shortDescription.text == f"GuardDog rule {rule_id}"
    if description is False:
        # False is an empty value, which is absent and needs no repair.
        assert record.is_empty
    else:
        assert _changes(record) == {("rewritten", "field_not_text"): 1}
        assert _pointers(record) == ["risks/0/threat_description"]


@pytest.mark.parametrize(
    "file_path", [5, ["setup.py"], {"a": 1}], ids=["int", "list", "object"]
)
def test_guarddog_a_file_path_that_is_not_text_is_left_out(file_path):
    record = IngestRecord()

    def damage(document):
        document["risks"][0].update(threat_location=None, file_path=file_path)

    results = _guarddog(_guarddog_with(damage), record)

    # The risk has no place now, so the match it used to account for is reported as
    # the match it is: nothing is lost, and one finding may be added.
    assert len(results) >= len(_guarddog(_GUARDDOG))
    assert _changes(record) == {("rewritten", "field_not_text"): 1}
    assert _pointers(record) == ["risks/0/file_path"]
    # No place to point at: the finding is on the package.
    first = results[0].locations[0].physicalLocation.root
    assert first.artifactLocation.uri == "pkg" and first.region is None


def test_guarddog_a_file_name_that_is_not_unicode_is_kept_and_fingerprinted():
    record = IngestRecord()
    name = f"setup{_LONE_SURROGATE}.py:17"

    results = _guarddog(
        _guarddog_with(lambda d: d["risks"][0].update(threat_location=name)), record
    )

    assert len(results) >= len(_guarddog(_GUARDDOG))
    assert _changes(record) == {("rewritten", "text_not_unicode"): 1}
    assert _pointers(record) == ["risks/0"]
    assert results[0].partialFingerprints is not None
    results[0].model_dump_json()


def test_guarddog_two_names_that_differ_only_in_the_bad_byte_are_two_findings():
    first = f"setup{chr(0xDCE9)}.py:17"
    second = f"setup{chr(0xDCEA)}.py:17"

    one = _guarddog(
        _guarddog_with(lambda d: d["risks"][0].update(threat_location=first))
    )
    two = _guarddog(
        _guarddog_with(lambda d: d["risks"][0].update(threat_location=second))
    )

    assert one[0].partialFingerprints != two[0].partialFingerprints


def test_guarddog_a_hit_whose_message_is_not_text_is_the_rule_id():
    record = IngestRecord()

    def damage(document):
        document["results"]["capability-network-lolbas"][0]["message"] = {"x": 1}

    results = _guarddog(_guarddog_with(damage), record)

    assert len(results) == len(_guarddog(_GUARDDOG))
    assert _changes(record) == {("rewritten", "field_not_text"): 1}
    assert _pointers(record) == ["results/*/0/message"]
    assert any(
        r.message.root.text.startswith("capability-network-lolbas") for r in results
    )


def test_guarddog_a_hit_whose_code_is_a_list_is_kept_without_it():
    record = IngestRecord()

    def damage(document):
        document["results"]["capability-network-lolbas"][0]["code"] = ["a"]

    results = _guarddog(_guarddog_with(damage), record)

    assert len(results) >= len(_guarddog(_GUARDDOG))
    assert _pointers(record) == ["results/*/0/code"]


def test_guarddog_a_location_that_is_a_list_does_not_stop_the_other_findings():
    """The set of matches a risk accounted for held the raw location and code, and a
    list in either was not hashable."""
    record = IngestRecord()

    def damage(document):
        document["risks"][0]["threat_location"] = ["setup.py", 17]

    results = _guarddog(_guarddog_with(damage), record)

    assert len(results) >= len(_guarddog(_GUARDDOG))
    # The path is read from the risk's file_path, which is text: nothing to repair.
    assert record.is_empty


@pytest.mark.parametrize(
    "tactics", [5, "execution", {"a": 1}], ids=["int", "text", "object"]
)
def test_guarddog_tactics_that_are_not_a_list_are_left_out(tactics):
    record = IngestRecord()

    results = _guarddog(
        _guarddog_with(lambda d: d["risks"][0].update(mitre_tactics=tactics)), record
    )

    assert len(results) == len(_guarddog(_GUARDDOG))
    assert _changes(record) == {("dropped", "mitre_tactics_unreadable"): 1}
    assert _pointers(record) == ["risks/0/mitre_tactics"]


@pytest.mark.parametrize("risks", [5, "text", {"a": 1}], ids=["int", "text", "object"])
def test_guarddog_risks_that_are_not_a_list_leave_the_matches(risks):
    record = IngestRecord()

    results = _guarddog(_guarddog_with(lambda d: d.update(risks=risks)), record)

    assert len(results) > 0
    assert _changes(record) == {("dropped", "risks_unreadable"): 1}
    assert _pointers(record) == ["risks"]


# --------------------------------------------------------------------------- #
# detect-secrets
# --------------------------------------------------------------------------- #


def _secret(line_number: Any, record: IngestRecord | None = None) -> Result:
    return DetectSecretsScanner.build_secret_result(
        finding_type="AWS Access Key",
        uri="src/app.py",
        line_number=line_number,
        start_column=3,
        record=record,
        pointer=("line_number",),
    )


def _physical(result: Result) -> Any:
    return result.locations[0].physicalLocation.root


@pytest.mark.parametrize("line", [0, -4], ids=["zero", "negative"])
def test_detect_secrets_a_line_below_one_builds_no_region(line):
    record = IngestRecord()

    result = _secret(line, record)

    assert _physical(result).region is None
    assert _physical(result).artifactLocation.uri == "src/app.py"
    assert result.message.root.text == (
        "Secret of type 'AWS Access Key' detected in file 'src/app.py'"
    )
    assert result.ruleId == "SECRET-AWS-ACCESS-KEY"
    assert _changes(record) == {("dropped", "region_line_unreadable"): 1}
    assert _pointers(record) == ["line_number"]


def test_detect_secrets_a_line_that_is_a_line_is_as_it_was():
    record = IngestRecord()

    result = _secret(7, record)

    region = _physical(result).region
    assert (region.startLine, region.endLine, region.startColumn) == (7, 7, 3)
    assert result.message.root.text == (
        "Secret of type 'AWS Access Key' detected in file 'src/app.py' at line 7"
    )
    assert record.is_empty


def test_detect_secrets_a_result_made_without_a_record_still_repairs():
    assert _physical(_secret(0)).region is None


# --------------------------------------------------------------------------- #
# actionlint
# --------------------------------------------------------------------------- #


def test_actionlint_a_line_written_as_text_and_a_negative_line_keep_their_findings():
    payload = {
        "version": "1.7.12",
        "errors": [
            {
                "kind": "syntax-check",
                "message": "a",
                "filepath": ".github/workflows/a.yml",
                "line": "3",
                "column": 1,
            },
            {
                "kind": "expression",
                "message": "b",
                "filepath": ".github/workflows/b.yml",
                "line": -1,
                "column": 1,
            },
            {
                "kind": "syntax-check",
                "message": "c",
                "filepath": ".github/workflows/c.yml",
                "line": 9,
                "column": 1,
            },
        ],
    }
    record = IngestRecord()

    report = SarifReport.model_validate(build_sarif(payload, 1, record=record))

    results = report.runs[0].results
    assert [r.message.root.text for r in results] == ["a", "b", "c"]
    regions = [_physical(r).region for r in results]
    assert regions[0].startLine == 3
    assert regions[1] is None
    assert regions[2].startLine == 9
    assert _changes(record) == {
        ("rewritten", "text_as_number"): 1,
        ("dropped", "region_line_unreadable"): 1,
    }
    assert _pointers(record) == ["errors/0/line", "errors/1/line"]


# --------------------------------------------------------------------------- #
# checkov
# --------------------------------------------------------------------------- #


def _rewrite(document: Any, tmp_path: Path, record: IngestRecord | None = None) -> None:
    rewrite_checkov_paths(
        document,
        ran_in="/",
        source_dir=str(tmp_path),
        scanned_dirs=[str(tmp_path)],
        record=record,
    )


@pytest.mark.parametrize(
    "results", [["failed"], "oops", 5], ids=["list", "text", "int"]
)
def test_checkov_a_side_report_whose_results_is_not_an_object_is_left_as_it_is(
    tmp_path, results
):
    document = {"check_type": "terraform", "results": results}
    before = copy.deepcopy(document)
    record = IngestRecord()

    _rewrite(document, tmp_path, record)

    assert document == before
    assert _changes(record) == {("dropped", "side_report_unreadable"): 1}
    assert _pointers(record) == ["results"]


def test_checkov_the_other_reports_of_a_side_report_are_still_rewritten(tmp_path):
    written = str(tmp_path / "main.tf")
    document = [
        {"check_type": "terraform", "results": ["failed"]},
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {"file_abs_path": written, "repo_file_path": "/WRONG"}
                ]
            },
        },
    ]
    record = IngestRecord()

    _rewrite(document, tmp_path, record)

    rewritten = document[1]["results"]["failed_checks"][0]["repo_file_path"]
    assert rewritten != "/WRONG" and rewritten.endswith("main.tf")
    assert _pointers(record) == ["0/results"]


def test_checkov_a_report_with_no_results_needs_no_repair(tmp_path):
    record = IngestRecord()

    _rewrite({"check_type": "terraform", "results": {}}, tmp_path, record)
    _rewrite({"check_type": "terraform", "results": None}, tmp_path, record)
    _rewrite([{"check_type": "terraform"}, "not a report"], tmp_path, record)

    assert record.is_empty


def test_checkov_a_sarif_part_that_is_not_an_object_is_left_for_the_validation(
    tmp_path,
):
    sarif = {
        "runs": [
            {
                "results": [
                    5,
                    "text",
                    None,
                    {
                        "locations": [
                            5,
                            {"physicalLocation": 5},
                            {"physicalLocation": {"artifactLocation": {"uri": "a.tf"}}},
                        ],
                        "relatedLocations": "x",
                    },
                ],
                "artifacts": [7, {"location": 3}],
            },
            7,
            {"results": 5},
        ]
    }

    _rewrite(sarif, tmp_path)

    # The parts it could not read are as they were, and the one it could is a text.
    assert sarif["runs"][0]["results"][:3] == [5, "text", None]
    assert isinstance(
        sarif["runs"][0]["results"][3]["locations"][2]["physicalLocation"][
            "artifactLocation"
        ]["uri"],
        str,
    )
    # The validation then refuses it in its own words, not as an attribute error.
    with pytest.raises(ValidationError):
        ingest_sarif(sarif, IngestRecord())


def test_checkov_a_runs_entry_that_is_not_a_list_does_not_stop_the_rewrite(tmp_path):
    for runs in (5, "x", {"a": 1}):
        _rewrite({"runs": runs}, tmp_path)


# --------------------------------------------------------------------------- #
# cdk-nag
# --------------------------------------------------------------------------- #


def _violation(rule_name: Any, description: Any, suffix: str) -> dict[str, Any]:
    return {
        "ruleName": rule_name,
        "description": description,
        "severity": "error",
        "violatingConstructs": [
            {"constructPath": f"Stack/Template/{suffix}", "constructFqn": "x"}
        ],
    }


def _validation_report(tmp_path: Path, violations: list[dict[str, Any]]) -> Path:
    path = tmp_path / "validation-report.json"
    path.write_text(
        json.dumps(
            {
                "version": "54.0.0",
                "title": "Validation Report",
                "pluginReports": [
                    {
                        "pluginName": "AwsSolutions",
                        "conclusion": "failure",
                        "violations": violations,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_cdk_nag_a_rule_name_or_description_that_is_not_text_keeps_the_finding(
    tmp_path,
):
    path = _validation_report(
        tmp_path,
        [
            _violation(5, "a numeric rule name", "A"),
            _violation("AwsSolutions-S1", 7, "B"),
            _violation("AwsSolutions-S2", ["a", "list"], "C"),
            _violation("AwsSolutions-S3", {"a": 1}, "D"),
            _violation({"a": 1}, "an object rule name", "E"),
            _violation("AwsSolutions-S4", "fine", "F"),
        ],
    )
    record = IngestRecord()

    per_pack, failure = _violations_from_validation_report(path, record=record)

    assert failure is None
    findings = per_pack["AwsSolutions"]
    assert [f.rule_id for f in findings] == [
        "5",
        "AwsSolutions-S1",
        "AwsSolutions-S2",
        "AwsSolutions-S3",
        "",
        "AwsSolutions-S4",
    ]
    unreadable = cdk_nag_wrapper._UNREADABLE_DESCRIPTION
    assert [f.rule_info for f in findings] == [
        "a numeric rule name",
        "7",
        unreadable,
        unreadable,
        "an object rule name",
        "fine",
    ]
    assert {f.compliance for f in findings} == {"Non-Compliant"}
    assert _changes(record) == {
        ("rewritten", "number_as_text"): 2,
        ("rewritten", "field_not_text"): 3,
    }
    assert _pointers(record) == [
        "pluginReports/0/violations/0/ruleName",
        "pluginReports/0/violations/1/description",
        "pluginReports/0/violations/2/description",
        "pluginReports/0/violations/3/description",
        "pluginReports/0/violations/4/ruleName",
    ]
    summary = record.summary()
    assert summary is not None and summary["results_read"] == 6


def test_cdk_nag_a_report_that_needs_no_repair_makes_no_note(tmp_path):
    path = _validation_report(tmp_path, [_violation("AwsSolutions-S1", "fine", "A")])
    record = IngestRecord()

    _violations_from_validation_report(path, record=record)

    assert record.is_empty


def test_cdk_nag_the_reader_repairs_when_no_record_is_given(tmp_path):
    path = _validation_report(tmp_path, [_violation(5, ["a"], "A")])

    per_pack, failure = _violations_from_validation_report(path)

    assert failure is None
    assert [f.rule_id for f in per_pack["AwsSolutions"]] == ["5"]


def test_cdk_nag_the_record_crosses_from_the_worker_to_the_scanner(tmp_path):
    record = IngestRecord()
    record.note(
        "rewritten", "number_as_text", ("pluginReports", 0, "violations", 1, "ruleName")
    )
    response = CdkNagWrapperResponse(results={}, failure=None, ingest=record)

    wire = json.loads(json.dumps(cdk_nag_worker._answer_for_response(response)))
    read_back = cdk_nag_worker._response_from(wire)

    assert read_back.ingest is not None
    assert read_back.ingest.summary() == record.summary()
    # An answer with no record (a worker of another build, a clean run) has none.
    assert (
        cdk_nag_worker._response_from(
            json.loads(
                json.dumps(
                    cdk_nag_worker._answer_for_response(
                        CdkNagWrapperResponse(results={}, failure=None)
                    )
                )
            )
        ).ingest
        is None
    )


@pytest.fixture
def cdk(tmp_path, monkeypatch):
    """A cdk-nag scanner over an empty work directory, its CDK dependencies shown as
    present and its wrapper replaced by a double the test gives an answer to."""
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    node = tmp_path / "bin" / "node"
    node.parent.mkdir(parents=True)
    node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", lambda name: str(node))
    double = create_autospec(
        cdk_nag_wrapper.run_cdk_nag_against_cfn_template, spec_set=True
    )
    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", double)
    return SimpleNamespace(
        scanner=CdkNagScanner(context=context, config=CdkNagScannerConfig()),
        wrapper=double,
        work=context.work_dir,
    )


_TEMPLATE = """Resources:
  MyDataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: placeholder-bucket
"""


def test_cdk_nag_the_scanner_adds_each_templates_record_to_its_own(cdk):
    (cdk.work / "bucket.yaml").write_text(_TEMPLATE, encoding="utf-8")
    (cdk.work / "queue.yaml").write_text(_TEMPLATE, encoding="utf-8")
    record = IngestRecord()
    record.results_read = 3
    record.note("rewritten", "number_as_text", ("pluginReports", 0, "violations", 1))
    cdk.wrapper.return_value = CdkNagWrapperResponse(
        results={}, failure=None, ingest=record
    )

    report = cdk.scanner.scan(target=cdk.work, target_type="converted")

    summary = _ingest_of(report)
    assert summary is not None
    assert (summary["repaired"], summary["results_read"]) == (2, 6)
    assert sorted(e["pointer"] for e in summary["elements"]) == [
        "template 1: pluginReports/0/violations/1",
        "template 2: pluginReports/0/violations/1",
    ]
    assert cdk.scanner.output_ingest_record == summary


def test_cdk_nag_a_second_scan_does_not_carry_the_first_ones_record(cdk):
    (cdk.work / "bucket.yaml").write_text(_TEMPLATE, encoding="utf-8")
    record = IngestRecord()
    record.note("rewritten", "number_as_text", ("pluginReports", 0, "violations", 1))
    cdk.wrapper.return_value = CdkNagWrapperResponse(
        results={}, failure=None, ingest=record
    )
    first = cdk.scanner.scan(target=cdk.work, target_type="converted")
    assert _ingest_of(first) is not None

    cdk.wrapper.return_value = CdkNagWrapperResponse(results={}, failure=None)
    second = cdk.scanner.scan(target=cdk.work, target_type="converted")

    assert _ingest_of(second) is None
    assert cdk.scanner.output_ingest_record is None


def test_cdk_nag_a_response_that_names_no_record_adds_nothing(cdk):
    (cdk.work / "bucket.yaml").write_text(_TEMPLATE, encoding="utf-8")
    cdk.wrapper.return_value = SimpleNamespace(failure=None, results={})

    report = cdk.scanner.scan(target=cdk.work, target_type="converted")

    assert _ingest_of(report) is None
