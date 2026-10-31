# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An npm 7+ advisory is reported against the copies its range covers.

npm audit lists an entry's installed copies (nodes) under each of the entry's
advisories: a copy is listed when one of them covers its version, and each
copy then carries every advisory of the entry. The conversion paired every
node with every advisory, so a copy another advisory covers carried this one
too, and one GHSA split into several ranges (minimist's ``<0.2.4`` and
``>=1.0.0 <1.2.6``) was reported once per range on every copy. When the
lockfile gives a copy's installed version and the advisory's own range
excludes it, no result is made; when the answer is uncertain (no version, an
unparsable range, a prerelease) the result is kept, once per advisory and copy.
A listed copy that NO range covers is not npm's shape: npm's reading of the
install and this reading of the lockfile disagree on it, so it keeps a result
for every advisory and the disagreement is logged, where the per-copy
exclusion dropped it silently.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
    _version_in_range,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.package_identity import identity_properties

pytestmark = pytest.mark.unit

GHSA = "https://github.com/advisories/GHSA-xvch-5gv4-984h"


def _via(rng, source=1179):
    """One advisory entry. npm's bulk advisory data gives each range of a
    multi-range GHSA its own advisory id, so ``_report`` hands each range a
    different ``source`` with the one URL: the merge keys on the URL."""
    return {
        "source": source,
        "name": "minimist",
        "title": "Prototype Pollution in minimist",
        "url": GHSA,
        "severity": "critical",
        "cwe": ["CWE-1321"],
        "cvss": {"score": 9.8, "vectorString": "CVSS:3.1/AV:N"},
        "range": rng,
    }


def _report(nodes, ranges=("<0.2.4", ">=1.0.0 <1.2.6")):
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "minimist": {
                "name": "minimist",
                "severity": "critical",
                "isDirect": False,
                "via": [_via(r, source=1179 + i) for i, r in enumerate(ranges)],
                "effects": ["mkdirp"],
                "range": " || ".join(ranges),
                "nodes": list(nodes),
                "fixAvailable": True,
            }
        },
        "metadata": {"vulnerabilities": {"critical": 1}},
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


def _versions(monkeypatch, by_node):
    """Stand in for the lockfile index: each node's installed version."""

    def identity(pkg_name, node_path, lock_rel, lock_index):
        return identity_properties(pkg_name, by_node.get(node_path), node_path)

    monkeypatch.setattr(NpmAuditScanner, "_node_identity", staticmethod(identity))


def _rows(report):
    return sorted(
        (
            r.properties.model_extra.get("package_path"),
            r.properties.model_extra["vulnerable_versions"],
        )
        for r in report.runs[0].results
    )


def test_each_copy_takes_the_range_that_covers_it(scanner, monkeypatch):
    old, new = "node_modules/mkdirp/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {old: "0.0.8", new: "1.2.5"})

    report = scanner._convert_npm_audit_to_sarif(
        _report([old, new]), scanner.context.source_dir
    )

    # One row per copy, each on the range that covers its version; _rows sorts
    # by path, and "node_modules/minimist" sorts before "node_modules/mkdirp/".
    assert _rows(report) == sorted([(old, "<0.2.4"), (new, ">=1.0.0 <1.2.6")])
    assert len(report.runs[0].tool.driver.rules) == 1


def test_a_copy_one_range_covers_carries_no_advisory_meant_for_another(
    scanner, monkeypatch
):
    """npm's real shape for a project with one vulnerable copy and one fixed
    copy: only the vulnerable copy is listed (npm lists a copy when an
    advisory covers it). That copy takes the one range that covers it, not
    both."""
    old = "node_modules/a/node_modules/minimist"
    _versions(monkeypatch, {old: "0.0.8", "node_modules/minimist": "1.2.8"})

    report = scanner._convert_npm_audit_to_sarif(
        _report([old]), scanner.context.source_dir
    )

    assert _rows(report) == [(old, "<0.2.4")]


class _Messages(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.texts: list[str] = []

    def emit(self, record):
        self.texts.append(record.getMessage())


def _debug_messages(monkeypatch):
    """ASH's logger at DEBUG for the test, with a handler of our own: the
    logger does not propagate, so caplog does not see it. ``setLevel`` is used
    on both sides, never a write to ``.level``: ``Logger.isEnabledFor`` keeps
    a per-level cache that only ``setLevel`` clears, so a direct write left a
    stale False (the record never arrived, order-dependent) or a stale True
    (DEBUG records leaked into later tests)."""
    messages = _Messages()
    saved = ASH_LOGGER.level
    ASH_LOGGER.addHandler(messages)
    ASH_LOGGER.setLevel(logging.DEBUG)

    def restore():
        ASH_LOGGER.removeHandler(messages)
        ASH_LOGGER.setLevel(saved)

    return messages, restore


def _named_copies(message: str) -> list:
    """The copies a disagreement log names: the list in its parentheses."""
    named = message.split("while npm listed them (", 1)[1].split(")", 1)[0]
    return named.split(", ")


def test_an_entry_whose_every_copy_is_excluded_keeps_its_results(scanner, monkeypatch):
    """Both copies at versions outside both ranges: npm listed the advisory for
    them and counted it in the metadata, so this reading of the lockfile and
    npm's disagree (a stale lockfile, a wrong index lookup). The exclusion is
    then not applied, the entry keeps one result per copy naming both ranges,
    and the disagreement is logged once naming both copies; dropping every
    copy silently left a counted advisory with no result."""
    old, fixed = "node_modules/a/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {old: "1.2.8", fixed: "1.3.0"})
    messages, restore = _debug_messages(monkeypatch)
    try:
        report = scanner._convert_npm_audit_to_sarif(
            _report([old, fixed]), scanner.context.source_dir
        )
    finally:
        restore()

    both = "<0.2.4 || >=1.0.0 <1.2.6"
    assert _rows(report) == sorted([(old, both), (fixed, both)])
    logged = [m for m in messages.texts if "fall outside every range" in m]
    assert len(logged) == 1, messages.texts
    assert "2 of 2 listed copy(ies) of minimist" in logged[0], logged[0]
    # The hoisted path is also the tail of the nested one, so a substring check
    # passes a log that names only the nested copy; compare the named list.
    assert _named_copies(logged[0]) == sorted([old, fixed]), logged[0]


def test_a_listed_copy_no_range_covers_is_kept_as_a_disagreement(scanner, monkeypatch):
    """One copy a range covers beside one that none does. npm lists a copy only
    when an advisory covers it, so the second is a copy npm and this reading
    of the lockfile disagree on (the index resolved a nested copy to the
    hoisted entry's version, say), not a fixed copy carried along. It was
    dropped per copy with no log, while the all-copies case next to it was
    kept and logged. The covered copy takes its one range; the other keeps a
    result naming both, and the disagreement is logged once naming it."""
    old, odd = "node_modules/a/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {old: "0.0.8", odd: "1.2.8"})
    messages, restore = _debug_messages(monkeypatch)
    try:
        report = scanner._convert_npm_audit_to_sarif(
            _report([old, odd]), scanner.context.source_dir
        )
    finally:
        restore()

    assert _rows(report) == sorted([(old, "<0.2.4"), (odd, "<0.2.4 || >=1.0.0 <1.2.6")])
    logged = [m for m in messages.texts if "fall outside every range" in m]
    assert len(logged) == 1, messages.texts
    assert "1 of 2 listed copy(ies) of minimist" in logged[0], logged[0]
    assert _named_copies(logged[0]) == [odd], logged[0]


def _mixed_report(nodes, own_range="<2.0.0", dependency="mkdirp"):
    """An entry vulnerable twice over: through its own advisory (``own_range``)
    and through a dependency (a package name in ``via``)."""
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "minimist": {
                "name": "minimist",
                "severity": "critical",
                "isDirect": False,
                "via": [_via(own_range), dependency],
                "effects": [],
                "range": own_range,
                "nodes": list(nodes),
                "fixAvailable": True,
            }
        },
        "metadata": {"vulnerabilities": {"critical": 1}},
    }


def _by_rule(report):
    return sorted(
        (r.ruleId, r.properties.model_extra.get("package_path"))
        for r in report.runs[0].results
    )


def test_a_copy_listed_only_for_its_dependency_is_not_blamed_for_the_own_advisory(
    scanner, monkeypatch
):
    """``minimist`` has its own advisory (``<2.0.0``) and a vulnerable
    dependency. The copy at 1.5.0 is covered by the advisory; the copy at 2.3.0
    is listed because of the dependency, and the own advisory does not cover it.
    That copy fell outside every range, was read as a disagreement, and kept the
    own advisory's rule, severity and fix text: a false positive that tripped a
    gate and let a suppression of the advisory hide the dependency's problem.
    It gets a transitive result instead, and the advisory's result stays on the
    copy it covers."""
    covered, outside = "node_modules/a/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {covered: "1.5.0", outside: "2.3.0"})
    messages, restore = _debug_messages(monkeypatch)
    try:
        report = scanner._convert_npm_audit_to_sarif(
            _mixed_report([covered, outside]), scanner.context.source_dir
        )
    finally:
        restore()

    assert _by_rule(report) == sorted(
        [
            ("GHSA-xvch-5gv4-984h", covered),
            ("npm-audit-transitive-minimist", outside),
        ]
    )
    assert not [m for m in messages.texts if "fall outside every range" in m], (
        messages.texts
    )


def test_every_copy_outside_the_own_range_of_a_mixed_entry_is_transitive(
    scanner, monkeypatch
):
    """Control: when no copy is in the own advisory's range, none carries it;
    every listed copy is the dependency's finding."""
    one, two = "node_modules/a/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {one: "2.1.0", two: "3.0.0"})

    report = scanner._convert_npm_audit_to_sarif(
        _mixed_report([one, two]), scanner.context.source_dir
    )

    assert _by_rule(report) == sorted(
        [("npm-audit-transitive-minimist", one), ("npm-audit-transitive-minimist", two)]
    )


def test_a_copy_of_a_mixed_entry_with_no_known_version_keeps_the_own_advisory(
    scanner, monkeypatch
):
    """Control: with no installed version the answer is uncertain, so the copy
    keeps the advisory and gets no transitive result."""
    node = "node_modules/minimist"
    _versions(monkeypatch, {})

    report = scanner._convert_npm_audit_to_sarif(
        _mixed_report([node]), scanner.context.source_dir
    )

    assert _by_rule(report) == [("GHSA-xvch-5gv4-984h", node)]


@pytest.mark.parametrize(
    "nodes",
    [
        [{"path": "node_modules/minimist"}, "node_modules/minimist"],
        [["node_modules/minimist"]],
        [{"path": "node_modules/minimist"}],
    ],
    ids=["dict-beside-a-path", "a-list", "only-a-dict"],
)
def test_a_node_that_is_not_a_path_does_not_fail_the_conversion(scanner, nodes):
    """The range exclusion keeps copies in a set, and an item of ``nodes`` that
    is a dict or a list cannot be hashed: ``node_path not in disagreeing`` raised
    ``TypeError`` and the whole conversion failed as a scanner error, where the
    neighbouring code skips a malformed ``via``. Such an item is left out, and
    the entry is still reported: against its path when it lists one, else by
    package name."""
    report = scanner._convert_npm_audit_to_sarif(
        _report(nodes, ranges=("<2.0.0",)), scanner.context.source_dir
    )

    assert [r.ruleId for r in report.runs[0].results] == ["GHSA-xvch-5gv4-984h"]


def _uri(result) -> str:
    location = result.locations[0].model_dump(by_alias=True, exclude_none=True)
    return location["physicalLocation"]["artifactLocation"]["uri"]


def _with_dependent(document, nodes, name="mkdirp"):
    """Add a package vulnerable only through ``minimist`` (``mkdirp`` unless
    ``name`` says another)."""
    document["vulnerabilities"][name] = {
        "name": name,
        "severity": "critical",
        "isDirect": False,
        "via": ["minimist"],
        "effects": [],
        "range": "*",
        "nodes": list(nodes),
        "fixAvailable": True,
    }
    return document


_NOT_A_PATH = [
    pytest.param({"path": "node_modules/mkdirp"}, id="a-dict"),
    pytest.param(["node_modules/mkdirp"], id="a-list"),
]


@pytest.mark.parametrize("item", _NOT_A_PATH)
def test_a_transitive_entry_leaves_out_a_node_that_is_not_a_path(scanner, item):
    """The advisory loop left such an item out, but the arm for an entry
    vulnerable only through a dependency read the raw ``nodes``: the item was
    turned into text and became the result URI, with no warning
    (``node_modules/{'path': 'mkdirp'}/package.json``). With the item left out
    and no path left, the entry is reported by package name, as one that lists
    no node is."""
    document = _with_dependent(
        _report(["node_modules/minimist"], ranges=("<2.0.0",)), [item]
    )

    report = scanner._convert_npm_audit_to_sarif(document, scanner.context.source_dir)

    (transitive,) = [
        r for r in report.runs[0].results if r.ruleId == "npm-audit-transitive-mkdirp"
    ]
    assert _uri(transitive) == "node_modules/mkdirp/package.json"


def test_a_transitive_entry_keeps_the_path_listed_beside_one_that_is_not(scanner):
    document = _with_dependent(
        _report(["node_modules/minimist"], ranges=("<2.0.0",)),
        [{"path": "node_modules/mkdirp"}, "node_modules/mkdirp"],
    )

    report = scanner._convert_npm_audit_to_sarif(document, scanner.context.source_dir)

    assert [
        _uri(r)
        for r in report.runs[0].results
        if r.ruleId == "npm-audit-transitive-mkdirp"
    ] == ["node_modules/mkdirp/package.json"]


@pytest.mark.parametrize(
    "item",
    [
        pytest.param({"path": "node_modules/minimist"}, id="a-dict"),
        pytest.param(["node_modules/minimist"], id="a-list"),
    ],
)
def test_a_root_reference_names_no_node_that_is_not_a_path(scanner, item):
    """The references a dependent carries to its root's results are placed as
    those results are. The root's own results leave an item that is not a path
    out, so a reference to one pointed at a result that never existed (and its
    URI was the item's text)."""
    document = _with_dependent(
        _report([item, "node_modules/minimist"], ranges=("<2.0.0",)),
        ["node_modules/mkdirp"],
    )

    report = scanner._convert_npm_audit_to_sarif(document, scanner.context.source_dir)

    (transitive,) = [
        r for r in report.runs[0].results if r.ruleId == "npm-audit-transitive-mkdirp"
    ]
    refs = transitive.properties.model_extra["root_advisories"]
    assert [ref["uri"] for ref in refs] == ["node_modules/minimist/package.json"], refs


def _refs_of(report, package):
    """The root references of ``package``'s transitive result, and those among
    them that no result of the report answers to (same rule id and path)."""
    results = report.runs[0].results
    have = {(r.ruleId, r.properties.model_extra.get("package_path")) for r in results}
    (transitive,) = [
        r for r in results if r.ruleId == f"npm-audit-transitive-{package}"
    ]
    refs = transitive.properties.model_extra["root_advisories"]
    dangling = [
        ref for ref in refs if (ref["rule_id"], ref.get("package_path")) not in have
    ]
    return refs, dangling


def test_a_dependent_of_a_mixed_root_points_only_at_results_that_exist(
    scanner, monkeypatch
):
    """``minimist`` has its own advisory (``<2.0.0``) and a dependency; the copy
    at 2.3.0 is listed for the dependency and has no result under the
    advisory. A dependent listed every copy under the advisory, so one of its
    references answered to no result, and the suppression pass leaves a
    dependent visible when a reference matches nothing: suppressing the
    advisory could not suppress it. The references name the copy the advisory
    covers, for the dependent and for the root's own transitive result."""
    covered, outside = "node_modules/a/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {covered: "1.5.0", outside: "2.3.0"})
    document = _with_dependent(
        _mixed_report([covered, outside], dependency="y"),
        ["node_modules/d"],
        name="d",
    )

    report = scanner._convert_npm_audit_to_sarif(document, scanner.context.source_dir)

    for package in ("d", "minimist"):
        refs, dangling = _refs_of(report, package)
        assert dangling == [], (package, dangling)
        assert [(ref["rule_id"], ref["package_path"]) for ref in refs] == [
            ("GHSA-xvch-5gv4-984h", covered)
        ], (package, refs)


def test_a_dependent_of_a_two_advisory_root_points_each_advisory_at_its_own_copy(
    scanner, monkeypatch
):
    """Two advisories of one root, each covering one of its two copies: the
    root has a result for each advisory on its own copy only, so a reference to
    either advisory on the other copy answers to nothing."""
    lo, hi = "node_modules/a/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {lo: "0.5.0", hi: "2.5.0"})

    def advisory(rng, ghsa, title, source):
        entry = _via(rng, source=source)
        entry["url"] = f"https://github.com/advisories/{ghsa}"
        entry["title"] = title
        return entry

    document = _with_dependent(
        {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "minimist": {
                    "name": "minimist",
                    "severity": "critical",
                    "isDirect": False,
                    "via": [
                        advisory("<1.0.0", "GHSA-aaaa-aaaa-aaaa", "One", 1),
                        advisory(">=2.0.0 <3.0.0", "GHSA-bbbb-bbbb-bbbb", "Two", 2),
                    ],
                    "effects": [],
                    "range": "<1.0.0 || >=2.0.0 <3.0.0",
                    "nodes": [lo, hi],
                    "fixAvailable": True,
                }
            },
            "metadata": {"vulnerabilities": {"critical": 1}},
        },
        ["node_modules/d"],
        name="d",
    )

    report = scanner._convert_npm_audit_to_sarif(document, scanner.context.source_dir)

    refs, dangling = _refs_of(report, "d")
    assert dangling == [], dangling
    assert sorted((ref["rule_id"], ref["package_path"]) for ref in refs) == [
        ("GHSA-aaaa-aaaa-aaaa", lo),
        ("GHSA-bbbb-bbbb-bbbb", hi),
    ], refs


def _mixed_report_with_dependencies(dependencies):
    """A mixed entry (a critical advisory of its own, ``<2.0.0``) whose ``via``
    also names the packages in ``dependencies``, a ``{name: severity}`` map;
    each gets an entry of that severity with an advisory of its own."""
    document = _mixed_report(["node_modules/minimist"], dependency=None)
    document["vulnerabilities"]["minimist"]["via"] = [_via("<2.0.0"), *dependencies]
    for source, (name, severity) in enumerate(dependencies.items(), start=2000):
        advisory = _via("<1.0.0", source=source)
        advisory.update(
            name=name,
            severity=severity,
            url=f"https://github.com/advisories/GHSA-{name}-{name}-{name}",
            title=f"{name} advisory",
            cvss={},
        )
        document["vulnerabilities"][name] = {
            "name": name,
            "severity": severity,
            "isDirect": False,
            "via": [advisory],
            "effects": ["minimist"],
            "range": "<1.0.0",
            "nodes": [f"node_modules/{name}"],
            "fixAvailable": True,
        }
    return document


@pytest.mark.parametrize(
    ("dependencies", "graded"),
    [
        ({"mkdirp": "low"}, "low"),
        ({"mkdirp": "low", "rimraf": "high"}, "high"),
    ],
    ids=["one-dependency", "the-highest-of-two"],
)
def test_a_copy_listed_for_its_dependency_is_graded_by_the_dependency(
    scanner, monkeypatch, dependencies, graded
):
    """An entry's severity is the highest over everything in its ``via``, its
    own critical advisory included, so the copy at 2.3.0 (listed only for the
    dependency, outside the advisory's range) was graded critical: the
    over-grading the transitive result exists to end, and enough to trip a
    severity gate. It takes the highest severity of the entries it depends on."""
    covered, outside = "node_modules/a/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {covered: "1.5.0", outside: "2.3.0"})
    document = _mixed_report_with_dependencies(dependencies)
    document["vulnerabilities"]["minimist"]["nodes"] = [covered, outside]

    report = scanner._convert_npm_audit_to_sarif(document, scanner.context.source_dir)

    (transitive,) = [
        r for r in report.runs[0].results if r.ruleId == "npm-audit-transitive-minimist"
    ]
    extra = transitive.properties.model_extra
    assert extra["severity"] == graded, extra
    assert extra["issue_severity"] == graded.upper(), extra
    level = getattr(transitive.level, "value", transitive.level)
    assert level == {"low": "note", "high": "error"}[graded], level
    (own,) = [r for r in report.runs[0].results if r.ruleId.startswith("GHSA-xvch")]
    assert own.properties.model_extra["severity"] == "critical"


def test_a_copy_listed_for_a_dependency_with_no_entry_keeps_the_entrys_severity(
    scanner, monkeypatch
):
    """Control: the report gives no entry for the named dependency, so there is
    nothing to grade the copy by and it keeps the entry's severity."""
    covered, outside = "node_modules/a/node_modules/minimist", "node_modules/minimist"
    _versions(monkeypatch, {covered: "1.5.0", outside: "2.3.0"})

    report = scanner._convert_npm_audit_to_sarif(
        _mixed_report([covered, outside]), scanner.context.source_dir
    )

    (transitive,) = [
        r for r in report.runs[0].results if r.ruleId == "npm-audit-transitive-minimist"
    ]
    assert transitive.properties.model_extra["severity"] == "critical"


def test_an_entry_vulnerable_only_through_dependencies_keeps_its_severity(scanner):
    """Control: with no advisory of its own the entry's severity is the
    dependencies' already, and the result is graded by it as before."""
    document = _with_dependent(
        _report(["node_modules/minimist"], ranges=("<2.0.0",)),
        ["node_modules/mkdirp"],
    )
    document["vulnerabilities"]["mkdirp"]["severity"] = "high"

    report = scanner._convert_npm_audit_to_sarif(document, scanner.context.source_dir)

    (transitive,) = [
        r for r in report.runs[0].results if r.ruleId == "npm-audit-transitive-mkdirp"
    ]
    assert transitive.properties.model_extra["severity"] == "high"


def test_an_unknown_version_keeps_the_advisory_once_per_copy(scanner, monkeypatch):
    """Control: with no installed version the answer is uncertain, so the
    advisory is still reported on the copy. Once: the two via entries are one
    GHSA split into two ranges, and one advisory on one copy is one result,
    where it used to be one result per range. That result names BOTH ranges:
    the first alone understated the advisory for a copy that is in fact at a
    version the second range covers."""
    node = "node_modules/minimist"
    _versions(monkeypatch, {})

    report = scanner._convert_npm_audit_to_sarif(
        _report([node]), scanner.context.source_dir
    )

    assert _rows(report) == [(node, "<0.2.4 || >=1.0.0 <1.2.6")]
    assert len(report.runs[0].tool.driver.rules) == 1
    (result,) = report.runs[0].results
    assert "<0.2.4 || >=1.0.0 <1.2.6" in result.message.root.text


def test_an_unparsable_range_keeps_the_result(scanner, monkeypatch):
    node = "node_modules/minimist"
    _versions(monkeypatch, {node: "1.2.8"})

    report = scanner._convert_npm_audit_to_sarif(
        _report([node], ranges=("^1.0.0",)), scanner.context.source_dir
    )

    assert _rows(report) == [(node, "^1.0.0")]


def test_a_prerelease_copy_keeps_the_result(scanner, monkeypatch):
    node = "node_modules/minimist"
    _versions(monkeypatch, {node: "1.3.0-beta.1"})

    report = scanner._convert_npm_audit_to_sarif(
        _report([node], ranges=("<1.2.6",)), scanner.context.source_dir
    )

    assert _rows(report) == [(node, "<1.2.6")]


@pytest.mark.parametrize(
    ("version", "vulnerable_range", "expected"),
    [
        ("0.0.8", "<0.2.4", True),
        ("1.2.5", "<0.2.4", False),
        ("1.2.5", "<0.2.4 || >=1.0.0 <1.2.6", True),
        ("1.2.6", "<0.2.4 || >=1.0.0 <1.2.6", False),
        ("4.17.21", ">=4.0.0 <=4.17.23", True),
        ("4.17.24", ">=4.0.0 <=4.17.23", False),
        ("3.0.0", "=3.0.0", True),
        ("3.0.1", "3.0.0", False),
        ("v1.0.0", "<2.0.0", True),
        # Numeric order, not string order: a string compare reads "4.17.9" as
        # above "4.17.21" and "1.10.0" as below "1.9.0", and each wrong answer
        # here drops a vulnerable copy or keeps a fixed one.
        ("4.17.9", "<4.17.21", True),
        ("1.10.0", "<1.9.0", False),
        # The copy exactly on an inclusive bound, each side; and ">", the one
        # operator the rows above never used.
        ("1.0.0", ">=1.0.0 <1.2.6", True),
        ("4.17.23", "<=4.17.23", True),
        ("1.0.0", ">1.0.0", False),
        ("1.0.1", ">1.0.0", True),
        ("1.0.0", "*", True),
        ("1.0.0", "", True),
        ("1.0.0", "^1.0.0", None),
        ("1.0.0", "1.0.0 - 2.0.0", None),
        ("1.0.0-rc.1", "<2.0.0", None),
        # Numeric suffixes: semver prereleases that packaging reads as
        # post-releases ABOVE the release, so a False here dropped a result
        # npm's semver counts as vulnerable. The answer is uncertain: None.
        ("1.2.5-1", ">=1.0.0 <1.2.5", None),
        ("2.0.0-0", "<2.0.0", None),
        ("1.0.0-20240101", "<1.0.0", None),
        ("1.0.0-r1", "<1.0.0", None),
        ("1.0.0-post1", "<1.0.0", None),
        ("1.0.0+build.7", "<2.0.0", None),
        ("2.0.0", ">=2.0.0-0", None),
        # Shapes the comparator grammar does not read, each answered None (keep),
        # never False (drop): a partial version, which node's semver pads to a
        # range of its own ("<=1.2" is "<1.3.0-0"), a bare partial version, a
        # space between the operator and its version, and a union whose only
        # branch that could cover the copy is the one that does not parse.
        ("1.2.5", "<=1.2", None),
        ("1.2.5", "1.2", None),
        ("4.1.0", ">= 4.0.0 < 4.17.21", None),
        ("1.5.0", "<0.2.4 || ^1.0.0", None),
        # A union whose readable branch covers the copy is settled by it, True,
        # whatever the other branch reads (True or unknown is True); an answer
        # of None here was less than the grammar knew.
        ("0.1.0", "<0.2.4 || ^1.0.0", True),
        ("not a version", "<2.0.0", None),
        (None, "<2.0.0", None),
        ("1.0.0", None, None),
    ],
)
def test_version_in_range(version, vulnerable_range, expected):
    assert _version_in_range(version, vulnerable_range) is expected
