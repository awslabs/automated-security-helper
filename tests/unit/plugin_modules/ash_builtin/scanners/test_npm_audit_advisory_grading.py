# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How one advisory becomes one SARIF result, and what grade it carries.

The SARIF conversion graded a result from its level when its rule carried no
CVSS score, and ``utils/severity_ladder.result_severity`` reads ``error`` as
CRITICAL and ``note`` as LOW. So an unscored ``high`` advisory counted as
CRITICAL and an ``info`` one as LOW. npm 7+ results also took the package
entry's severity and range, not the advisory's own, so an unscored low or
moderate advisory on a package with a critical one was graded critical; a
``via`` entry with ``"cvss": null`` raised; npm's ``{"score": 0, "vectorString":
null}`` reached the rule as security-severity 0, which GHAS forwards as "0";
and an entry with no ``nodes`` (npm) or no ``versions`` (yarn, pnpm) produced a
rule and no result while the report's metadata counted the advisory.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.utils.sarif_utils import (
    normalize_sarif_result_severities,
)
from automated_security_helper.utils.severity_ladder import result_severity

pytestmark = pytest.mark.unit


#: No ``cvss`` key at all on a via entry (the default), as against ``None``,
#: which writes a null object: the two are different inputs to the reader.
_ABSENT = object()


def _via(name, severity, *, cvss=_ABSENT, score=None, vector=None, rng="<1.0.0"):
    entry = {
        "source": 1,
        "name": name,
        "title": f"{severity} advisory in {name}",
        "url": f"https://github.com/advisories/GHSA-{name}-{severity}",
        "severity": severity,
        "cwe": [],
        "range": rng,
    }
    if cvss is not _ABSENT:
        entry["cvss"] = cvss
    elif score is not None or vector is not None:
        entry["cvss"] = {"score": score, "vectorString": vector}
    return entry


def _report(**packages):
    """An npm 7+ report; each package maps to ``(severity, via list, nodes)``."""
    vulnerabilities = {}
    for name, (severity, via, nodes) in packages.items():
        vulnerabilities[name] = {
            "name": name,
            "severity": severity,
            "isDirect": True,
            "via": via,
            "effects": [],
            "range": "*",
            "nodes": nodes,
            "fixAvailable": True,
        }
    return {
        "auditReportVersion": 2,
        "vulnerabilities": vulnerabilities,
        "metadata": {"vulnerabilities": {"total": len(vulnerabilities)}},
    }


@pytest.fixture
def scanner(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for d in (context.source_dir, context.output_dir, context.work_dir):
        d.mkdir(parents=True)
    return NpmAuditScanner(context=context, config=NpmAuditScannerConfig())


def _graded(scanner, document):
    """The report as the pipeline grades it: converted, then the normalizer
    copies rule scores onto the results, then the ladder reads each result."""
    report = normalize_sarif_result_severities(
        scanner._convert_npm_audit_to_sarif(document, scanner.context.source_dir)
    )
    grades = {
        (r.ruleId, r.properties.model_extra.get("installed_version")): result_severity(
            r
        )
        for r in report.runs[0].results
    }
    # Two results of one advisory at two nodes carry the same installed
    # version (or none) and would share a key, one overwriting the other, so a
    # duplicate result went unnoticed by every check on the grades. Such a
    # document needs the results read as a list.
    assert len(grades) == len(report.runs[0].results), (
        "two results share a (rule, installed_version) key; read the results list"
    )
    return report, grades


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("critical", "CRITICAL"),
        ("high", "HIGH"),
        ("moderate", "MEDIUM"),
        ("low", "LOW"),
        ("info", "INFO"),
    ],
)
def test_an_unscored_advisory_is_graded_by_its_severity_word(
    scanner, severity, expected
):
    """No CVSS score: the grade is the advisory's own word, not the level's
    reading (error = CRITICAL, note = LOW)."""
    document = _report(
        pkg=(
            severity,
            [_via("pkg", severity, score=0, vector=None)],
            ["node_modules/pkg"],
        )
    )

    _, grades = _graded(scanner, document)

    assert list(grades.values()) == [expected], grades


def test_a_scored_advisory_is_graded_by_its_cvss_score(scanner):
    """Control: with a usable score the rule carries it and the normalizer
    grades from it, as before. 9.8 on a 'high' word reads CRITICAL."""
    document = _report(
        pkg=(
            "high",
            [_via("pkg", "high", score=9.8, vector="CVSS:3.1/AV:N")],
            ["node_modules/pkg"],
        )
    )

    # The converted report, before the normalizer: the scanner declares no
    # word-based grade beside a usable score. After normalization the result
    # carries the score's band (the normalizer's documented copy), which is
    # what the ladder then reads.
    converted = scanner._convert_npm_audit_to_sarif(
        document, scanner.context.source_dir
    )
    assert "issue_severity" not in converted.runs[0].results[0].properties.model_extra

    report, grades = _graded(scanner, document)

    assert list(grades.values()) == ["CRITICAL"], grades
    rule = report.runs[0].tool.driver.rules[0]
    assert rule.properties.model_extra["security_severity"] == 9.8
    assert report.runs[0].results[0].properties.model_extra["issue_severity"] == (
        "CRITICAL"
    )


def test_npm_s_zero_score_without_a_vector_is_no_score(scanner):
    """npm writes score 0 and a null vector for an advisory with no CVSS. The
    rule must not carry security-severity 0 (GHAS forwards it as "0", below its
    Low bucket); the result grades from the word instead."""
    document = _report(
        pkg=("high", [_via("pkg", "high", score=0, vector=None)], ["node_modules/pkg"])
    )

    report, grades = _graded(scanner, document)

    rule = report.runs[0].tool.driver.rules[0]
    assert "security_severity" not in (rule.properties.model_extra or {})
    assert list(grades.values()) == ["HIGH"], grades


def test_a_zero_score_with_a_vector_is_still_no_score(scanner):
    """The boundary from the other side: any 0 reads as "no score", a vector
    beside it or not. npm's 0 means the registry gave no CVSS, 0.0 is below
    every bucket GHAS has, and the normalizer skips it as no score too; so the
    rule carries no security-severity and the word grades the result."""
    document = _report(
        pkg=(
            "high",
            [_via("pkg", "high", score=0, vector="CVSS:3.1/AV:N")],
            ["node_modules/pkg"],
        )
    )

    report, grades = _graded(scanner, document)

    rule = report.runs[0].tool.driver.rules[0]
    assert "security_severity" not in (rule.properties.model_extra or {})
    assert list(grades.values()) == ["HIGH"], grades


def test_a_score_with_a_null_vector_is_a_score(scanner):
    """The vector is not consulted: a positive score grades the result. The
    score sits in another band than the word (9.8 on a "high" advisory), so
    the grade says which one set it; 7.5 on "high" read HIGH either way and
    could not tell a score-graded result from a word-graded one."""
    document = _report(
        pkg=(
            "high",
            [_via("pkg", "high", score=9.8, vector=None)],
            ["node_modules/pkg"],
        )
    )

    converted = scanner._convert_npm_audit_to_sarif(
        document, scanner.context.source_dir
    )
    (converted_result,) = converted.runs[0].results
    # A scored advisory declares no word grade of its own; the normalizer's
    # copy of the rule's score is what grades it.
    assert "issue_severity" not in converted_result.properties.model_extra

    report, grades = _graded(scanner, document)

    rule = report.runs[0].tool.driver.rules[0]
    assert rule.properties.model_extra["security_severity"] == 9.8
    assert list(grades.values()) == ["CRITICAL"], grades


def test_a_via_entry_without_a_cvss_key_is_graded_by_its_word(scanner):
    """Most advisories from a registry without CVSS carry no cvss key at all:
    no failure, no score, the word grades the result."""
    document = _report(
        pkg=("moderate", [_via("pkg", "moderate")], ["node_modules/pkg"])
    )

    report, grades = _graded(scanner, document)

    rule = report.runs[0].tool.driver.rules[0]
    assert "security_severity" not in (rule.properties.model_extra or {})
    assert list(grades.values()) == ["MEDIUM"], grades
    assert report.runs[0].results[0].properties.model_extra["cvss"] == {}


def test_a_null_cvss_object_does_not_fail_the_conversion(scanner):
    document = _report(
        pkg=("moderate", [_via("pkg", "moderate", cvss=None)], ["node_modules/pkg"])
    )
    assert document["vulnerabilities"]["pkg"]["via"][0]["cvss"] is None

    report, grades = _graded(scanner, document)

    assert list(grades.values()) == ["MEDIUM"], grades
    assert report.runs[0].results[0].properties.model_extra["cvss"] == {}


def test_each_advisory_of_a_package_keeps_its_own_severity_and_range(scanner):
    """The package entry carries the highest of its advisories' severities and
    the union of their ranges. Each result takes its own advisory's. With no
    lockfile the installed version is unknown, and the result carries no
    installed_version (the package's range stood in for it once; a range is not
    a version), so the grades are keyed on None here."""
    document = _report(
        pkg=(
            "critical",
            [
                _via(
                    "pkg", "critical", score=9.8, vector="CVSS:3.1/AV:N", rng="<1.0.0"
                ),
                _via("pkg", "low", score=0, vector=None, rng=">=2.0.0 <2.0.3"),
            ],
            ["node_modules/pkg"],
        )
    )
    document["vulnerabilities"]["pkg"]["range"] = "<1.0.0 || >=2.0.0 <2.0.3"

    report, grades = _graded(scanner, document)

    by_rule = {r.ruleId: r for r in report.runs[0].results}
    low = by_rule["GHSA-pkg-low"]
    assert low.level == "note"
    assert low.properties.model_extra["severity"] == "low"
    assert low.properties.model_extra["vulnerable_versions"] == ">=2.0.0 <2.0.3"
    assert ">=2.0.0 <2.0.3" in low.message.root.text
    assert "installed_version" not in low.properties.model_extra
    assert grades[("GHSA-pkg-low", None)] == "LOW"
    critical = by_rule["GHSA-pkg-critical"]
    assert critical.level == "error"
    assert critical.properties.model_extra["vulnerable_versions"] == "<1.0.0"
    assert grades[("GHSA-pkg-critical", None)] == "CRITICAL"
    rules = {r.id: r for r in report.runs[0].tool.driver.rules}
    assert "low" in rules["GHSA-pkg-low"].properties.tags
    assert "critical" in rules["GHSA-pkg-critical"].properties.tags


def test_an_advisory_without_a_version_range_keeps_the_package_s(scanner):
    """Control: a via entry that names no range reads the package's, as before."""
    via = _via("pkg", "high", score=0, vector=None)
    del via["range"]
    document = _report(pkg=("high", [via], ["node_modules/pkg"]))
    document["vulnerabilities"]["pkg"]["range"] = "<3.0.0"

    report, _ = _graded(scanner, document)

    (result,) = report.runs[0].results
    assert result.properties.model_extra["vulnerable_versions"] == "<3.0.0"


def test_an_npm_entry_with_no_nodes_still_produces_a_result(scanner):
    """npm counted the advisory in the report's metadata; a rule with no result
    dropped it. One result for the package by name: its URI is the hoisted
    location a copy of that name would have, and it carries no package_path or
    package_version, since npm named no installed copy."""
    document = _report(pkg=("high", [_via("pkg", "high", score=0, vector=None)], []))

    report, grades = _graded(scanner, document)

    (result,) = report.runs[0].results
    location = result.locations[0].model_dump(by_alias=True, exclude_none=True)
    assert (
        location["physicalLocation"]["artifactLocation"]["uri"]
        == "node_modules/pkg/package.json"
    )
    props = result.properties.model_extra
    assert props["package_name"] == "pkg"
    assert "package_path" not in props
    assert "package_version" not in props
    assert list(grades.values()) == ["HIGH"], grades


def test_a_transitive_entry_with_no_nodes_still_produces_a_result(scanner):
    document = _report(
        root=(
            "high",
            [_via("root", "high", score=0, vector=None)],
            ["node_modules/root"],
        ),
        child=("high", ["root"], []),
    )

    report, grades = _graded(scanner, document)

    transitive = [
        r for r in report.runs[0].results if r.ruleId == "npm-audit-transitive-child"
    ]
    assert len(transitive) == 1, [r.ruleId for r in report.runs[0].results]
    # No node and no lockfile: the installed version is unknown, so the result
    # carries no installed_version and the grade is keyed on None.
    assert grades[("npm-audit-transitive-child", None)] == "HIGH"


def _two_lockfiles(scanner, first, second):
    """Two npm lockfiles, outside the scanned tree so neither is indexed,
    converted and merged as the scan merges them, then graded."""
    locks = scanner.context.output_dir / "elsewhere"
    return normalize_sarif_result_severities(
        scanner._convert_per_lockfile(
            [
                (locks / "a" / "package-lock.json", first),
                (locks / "b" / "package-lock.json", second),
            ],
            {"metadata": {"vulnerabilities": {}}},
            scanner.context.source_dir,
        )
    )


@pytest.mark.parametrize("scored_first", [False, True])
def test_the_one_rule_two_lockfiles_share_carries_the_score_either_one_brings(
    scanner, scored_first
):
    """Two lockfiles hit one advisory; the merge keeps the first rule per id.
    One lockfile's record is unscored (as a yarn 4 one always is) and declares
    its word grade, HIGH; the other's has a usable score, 9.8, declares no
    grade and relies on the rule's score. With the kept rule carrying no score
    the scored result fell to the SARIF level, CRITICAL for a high advisory by
    accident rather than by its score. Whichever lockfile comes first, the kept
    rule carries the one score, the word-graded result keeps HIGH, and the
    scored result reads the score's band, CRITICAL; the two bands differ so the
    grades say which path graded which result (7.5 on "high" could not)."""
    unscored = _report(
        pkg=("high", [_via("pkg", "high", score=0, vector=None)], ["node_modules/pkg"])
    )
    scored = _report(
        pkg=(
            "high",
            [_via("pkg", "high", score=9.8, vector="CVSS:3.1/AV:N")],
            ["node_modules/pkg"],
        )
    )
    first, second = (scored, unscored) if scored_first else (unscored, scored)

    report = _two_lockfiles(scanner, first, second)

    (rule,) = report.runs[0].tool.driver.rules
    assert rule.properties.model_extra["security_severity"] == 9.8
    assert sorted(result_severity(r) for r in report.runs[0].results) == [
        "CRITICAL",
        "HIGH",
    ]


@pytest.mark.parametrize("higher_first", [False, True])
def test_two_lockfiles_with_two_scores_keep_the_higher_whichever_comes_first(
    scanner, higher_first
):
    """Both records carry a score and they differ (5.0 and 7.5). The merged
    rule keeps the higher, whichever lockfile is walked first: both results
    rely on the rule, so both read the 7.5 band, HIGH. Keeping the first
    lockfile's score let the walk order lower an advisory's grade (5.0 first
    read MEDIUM for both, 7.5 first read HIGH for both), and a gate then saw a
    grade below what one lockfile's own report scored it."""
    low = _report(
        pkg=(
            "high",
            [_via("pkg", "high", score=5.0, vector="CVSS:3.1/AV:N")],
            ["node_modules/pkg"],
        )
    )
    high = _report(
        pkg=(
            "high",
            [_via("pkg", "high", score=7.5, vector="CVSS:3.1/AV:N")],
            ["node_modules/pkg"],
        )
    )
    first, second = (high, low) if higher_first else (low, high)

    report = _two_lockfiles(scanner, first, second)

    (rule,) = report.runs[0].tool.driver.rules
    assert rule.properties.model_extra["security_severity"] == 7.5
    assert [result_severity(r) for r in report.runs[0].results] == ["HIGH", "HIGH"]


def test_a_root_with_no_nodes_still_gives_the_transitive_result_a_ref(scanner):
    """The transitive result's root_advisories names every root result, placed
    as that result is, so a suppression on the advisory reaches it. A root npm
    listed no node for has one result by name and got no ref: suppressing
    another root's advisory then suppressed the transitive result while this
    root's advisory was live."""
    document = _report(
        root=("high", [_via("root", "high", score=0, vector=None)], []),
        child=("high", ["root"], ["node_modules/child"]),
    )

    report, _ = _graded(scanner, document)

    by_rule = {r.ruleId: r for r in report.runs[0].results}
    root_result = by_rule["GHSA-root-high"]
    root_location = root_result.locations[0].model_dump(
        by_alias=True, exclude_none=True
    )
    root_uri = root_location["physicalLocation"]["artifactLocation"]["uri"]
    refs = by_rule["npm-audit-transitive-child"].properties.model_extra[
        "root_advisories"
    ]
    assert refs == [{"rule_id": "GHSA-root-high", "uri": root_uri}], refs
    assert root_uri == "node_modules/root/package.json"


def test_a_null_nodes_list_on_a_root_does_not_fail_the_conversion(scanner):
    document = _report(
        root=("high", [_via("root", "high", score=0, vector=None)], []),
        child=("high", ["root"], ["node_modules/child"]),
    )
    document["vulnerabilities"]["root"]["nodes"] = None

    report, _ = _graded(scanner, document)

    by_rule = {r.ruleId: r for r in report.runs[0].results}
    refs = by_rule["npm-audit-transitive-child"].properties.model_extra[
        "root_advisories"
    ]
    assert [ref["rule_id"] for ref in refs] == ["GHSA-root-high"], refs


def test_a_yarn_or_pnpm_record_with_no_versions_still_produces_a_result(scanner):
    """The v1 and berry readers list each installed version under the record's
    versions map; a record with an empty map is still the tool's finding, one
    result for the package by name with no installed_version (the vulnerable
    range stood in for the version once; a range is not a version)."""
    record = {
        "package": "lodash",
        "id": 1065,
        "title": "Prototype Pollution",
        "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
        "severity": "high",
        "cvss": {},
        "cwe": ["CWE-1321"],
        "vulnerable_versions": ">=3.7.0 <4.17.19",
        "patched_versions": ">=4.17.19",
        "versions": {},
        "paths_key": "dependency_paths",
    }
    document = {
        "yarn_advisories": [record],
        "metadata": {"vulnerabilities": {"high": 1}},
    }

    report, grades = _graded(scanner, document)

    (result,) = report.runs[0].results
    props = result.properties.model_extra
    assert props["package_name"] == "lodash"
    assert "installed_version" not in props, props
    assert props["vulnerable_versions"] == ">=3.7.0 <4.17.19"
    assert "dependency_paths" not in props
    assert grades[("GHSA-p6mc-m468-83gw", None)] == "HIGH"


_EMPTY_FINDINGS_ADVISORY = {
    "module_name": "lodash",
    "id": 1065,
    "title": "Prototype Pollution",
    "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
    "severity": "high",
    "cwe": ["CWE-1321"],
    "vulnerable_versions": ">=3.7.0 <4.17.19",
    "patched_versions": ">=4.17.19",
    "findings": [],
}


def _yarn_1_stream(advisory) -> str:
    events = [
        {
            "type": "auditAdvisory",
            "data": {
                "resolution": {"id": 1065, "path": "lodash"},
                "advisory": advisory,
            },
        },
        {"type": "auditSummary", "data": {"vulnerabilities": {"high": 1}}},
    ]
    return "".join(json.dumps(event) + "\n" for event in events)


@pytest.mark.parametrize(
    ("yarn_major", "stdout"),
    [
        pytest.param(1, _yarn_1_stream(_EMPTY_FINDINGS_ADVISORY), id="yarn-1"),
        pytest.param(
            4,
            json.dumps(
                {
                    "value": "lodash",
                    "children": {
                        "ID": 1065,
                        "Issue": "Prototype Pollution",
                        "URL": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
                        "Severity": "high",
                        "Vulnerable Versions": ">=3.7.0 <4.17.19",
                        "Tree Versions": [],
                        "Dependents": [],
                    },
                }
            )
            + "\n",
            id="yarn-4",
        ),
    ],
)
def test_an_advisory_the_reader_lists_no_version_for_still_reaches_a_result(
    scanner, yarn_major, stdout
):
    """The test above hands the conversion a record built by hand. This one
    runs the tool's own document through the reader first: a yarn 1 advisory
    with an empty ``findings`` list and a yarn 4 line with no ``Tree Versions``
    each come out of ``_parse_yarn_audit`` as a record with an empty versions
    map, and that record converts to one result by name. A reader that dropped
    such an advisory would lose it from start to finish while the hand-built
    record still passed."""
    report, reason = NpmAuditScanner._parse_yarn_audit(
        yarn_major, {"stdout": stdout, "stderr": "", "returncode": 1}
    )

    assert reason is None, reason
    (record,) = report["yarn_advisories"]
    assert record["versions"] == {}
    graded, grades = _graded(scanner, report)
    (result,) = graded.runs[0].results
    assert result.properties.model_extra["package_name"] == "lodash"
    assert "installed_version" not in result.properties.model_extra
    assert grades[("GHSA-p6mc-m468-83gw", None)] == "HIGH"


def test_a_yarn_record_with_a_score_grades_from_it(scanner):
    """Control for the yarn path: a usable score on the record reaches the rule
    and decides the grade; no word-based grade is declared beside it."""
    record = {
        "package": "minimist",
        "id": 1179,
        "title": "Prototype Pollution",
        "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h",
        "severity": "critical",
        "cvss": {"score": 9.8, "vectorString": "CVSS:3.1/AV:N"},
        "cwe": ["CWE-1321"],
        "vulnerable_versions": "<0.2.4",
        "patched_versions": ">=0.2.4",
        "versions": {"0.0.8": ["mkdirp>minimist"]},
        "paths_key": "dependency_paths",
    }
    document = {"yarn_advisories": [record], "metadata": {}}

    # Before the normalizer no word-based grade is declared beside the score.
    converted = scanner._convert_npm_audit_to_sarif(
        document, scanner.context.source_dir
    )
    (converted_result,) = converted.runs[0].results
    assert "issue_severity" not in converted_result.properties.model_extra

    report, grades = _graded(scanner, document)

    (result,) = report.runs[0].results
    # After it the result carries the score's band, the normalizer's copy.
    assert result.properties.model_extra["issue_severity"] == "CRITICAL"
    rule = report.runs[0].tool.driver.rules[0]
    assert rule.properties.model_extra["security_severity"] == 9.8
    assert grades[("GHSA-xvch-5gv4-984h", "0.0.8")] == "CRITICAL"


def test_the_result_keeps_its_historical_uri_shape_and_recommendation(scanner):
    """The identity, recommendation and CVSS object a scored npm result carried
    before the per-advisory grading are still there, and so is the URI's
    historical shape: every ``node_modules/`` in the node path is dropped, so a
    nested copy at node_modules/a/node_modules/pkg is reported at
    node_modules/a/pkg/package.json, a path that does not exist on disk. That
    shape is kept on purpose, because the path-based suppressions users wrote
    against it match it; the real install path is ``package_path`` (when the
    lockfile gives one). A change of the URI is a change of the suppression
    contract, not a fix this test stands in the way of."""
    document = _report(
        pkg=(
            "high",
            [_via("pkg", "high", score=7.5, vector="CVSS:3.1/AV:N")],
            ["node_modules/a/node_modules/pkg"],
        )
    )

    report, _ = _graded(scanner, document)

    (result,) = report.runs[0].results
    location = result.locations[0].model_dump(by_alias=True, exclude_none=True)
    assert (
        location["physicalLocation"]["artifactLocation"]["uri"]
        == "node_modules/a/pkg/package.json"
    )
    props = result.properties.model_extra
    assert props["recommendation"] == "Update pkg to a non-vulnerable version"
    assert props["fix_available"] is True
    assert props["cvss"] == {"score": 7.5, "vectorString": "CVSS:3.1/AV:N"}
