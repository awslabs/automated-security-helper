# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A finding read from a SARIF result carries its CVE and its CWE.

``FlatVulnerability`` has a ``cve_id`` and a ``cwe_id``, and the CSV, flat JSON,
HTML, Markdown and text reports and the MCP ``explain_finding`` tool show them.
``from_sarif_result`` set neither, so both were empty for every scanner finding:
a trivy finding whose rule id is ``CVE-2019-20477`` had no CVE, and a bandit
finding whose rule is tagged ``external/cwe/cwe-78`` had no CWE.

The CVE is read from the head of the rule id, as the OCSF reporter reads it. The
CWE is read from the tags of the result and of the rule the result names in its
run, in the two spellings the bundled scanners write.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit


def _result(rule_id: str | None, **properties) -> Result:
    return Result(
        ruleId=rule_id,
        level=Level.warning,
        message=Message.model_validate({"text": "finding text"}),
        properties=PropertyBag(**properties) if properties else None,
    )


def _rule(rule_id: str, *tags: str) -> ReportingDescriptor:
    return ReportingDescriptor(
        id=rule_id, properties=PropertyBag(tags=list(tags)) if tags else None
    )


def _run(*extensions: ToolComponent, results: list[Result]) -> Run:
    return Run(
        tool=Tool(driver=ToolComponent(name="ASH"), extensions=list(extensions)),
        results=results,
    )


def _flat(result: Result, run: Run | None = None) -> FlatVulnerability:
    return FlatVulnerability.from_sarif_result(result, "ASH", "SAST", run=run)


class TestTheCveIsReadFromTheRuleId:
    @pytest.mark.parametrize(
        "rule_id, expected",
        [
            ("CVE-2019-20477", "CVE-2019-20477"),
            # grype names a rule by the CVE and the package
            ("CVE-2022-40897-setuptools", "CVE-2022-40897"),
            ("cve-2024-35195", "CVE-2024-35195"),
            ("CVE-2026-132276", "CVE-2026-132276"),
        ],
    )
    def test_a_rule_id_that_starts_with_a_cve_names_it(self, rule_id, expected):
        assert _flat(_result(rule_id)).cve_id == expected

    @pytest.mark.parametrize(
        "rule_id",
        [
            "B602",
            "CKV_AWS_24",
            "GHSA-8q59-q68h-6hv4-pyyaml",
            # a CVE further in is part of another id, not the rule's own
            "vendor.CVE-2019-20477",
            # not the shape of a CVE id
            "CVE-2019",
            "CVE-2019-204779x",
            None,
        ],
    )
    def test_any_other_rule_id_names_no_cve(self, rule_id):
        assert _flat(_result(rule_id)).cve_id is None


class TestTheCweIsReadFromTheTags:
    def test_a_code_scanning_tag_on_the_rule(self):
        result = _result("B602", scanner_name="bandit")
        run = _run(
            ToolComponent(
                name="bandit", rules=[_rule("B602", "security", "external/cwe/cwe-78")]
            ),
            results=[result],
        )

        assert _flat(result, run).cwe_id == "CWE-78"

    def test_a_tag_that_starts_with_the_cwe_and_its_name(self):
        result = _result("rules.hardcoded", scanner_name="opengrep")
        run = _run(
            ToolComponent(
                name="opengrep",
                rules=[
                    _rule(
                        "rules.hardcoded",
                        "CWE-798: Use of Hard-coded Credentials",
                        "OWASP-A07:2021 - Identification and Authentication Failures",
                    )
                ],
            ),
            results=[result],
        )

        assert _flat(result, run).cwe_id == "CWE-798"

    def test_several_cwes_are_each_listed_once_in_the_order_written(self):
        result = _result("R1", scanner_name="opengrep")
        run = _run(
            ToolComponent(
                name="opengrep",
                rules=[
                    _rule(
                        "R1",
                        "CWE-1357: Reliance on Insufficiently Trustworthy Component",
                        "CWE-353: Missing Support for Integrity Check",
                        "external/cwe/cwe-1357",
                    )
                ],
            ),
            results=[result],
        )

        assert _flat(result, run).cwe_id == "CWE-1357, CWE-353"

    def test_a_tag_on_the_result_is_read_without_a_run(self):
        result = _result("R1", tags=["security", "external/cwe/cwe-502"])

        assert _flat(result).cwe_id == "CWE-502"

    def test_the_results_own_cwe_comes_before_its_rules(self):
        result = _result("R1", scanner_name="bandit", tags=["CWE-20"])
        run = _run(
            ToolComponent(name="bandit", rules=[_rule("R1", "external/cwe/cwe-78")]),
            results=[result],
        )

        assert _flat(result, run).cwe_id == "CWE-20, CWE-78"

    @pytest.mark.parametrize(
        "tag",
        [
            "security",
            "CRITICAL",
            # a CWE further in is a mention, not the tag's subject
            "see CWE-78",
            "owasp/cwe-78",
            "CWE-",
            "CWE-78x",
        ],
    )
    def test_a_tag_that_is_not_a_cwe_names_none(self, tag):
        result = _result("R1", scanner_name="bandit")
        run = _run(
            ToolComponent(name="bandit", rules=[_rule("R1", tag)]), results=[result]
        )

        assert _flat(result, run).cwe_id is None

    def test_a_rule_without_tags_names_none(self):
        result = _result("CKV_AWS_24", scanner_name="checkov")
        run = _run(
            ToolComponent(name="checkov", rules=[_rule("CKV_AWS_24")]),
            results=[result],
        )

        assert _flat(result, run).cwe_id is None

    def test_a_result_whose_rule_no_component_declares_names_none(self):
        result = _result("R1", scanner_name="bandit")
        run = _run(ToolComponent(name="bandit"), results=[result])

        assert _flat(result, run).cwe_id is None


class TestTheCweIsReadFromTheResultsOwnScanner:
    def test_two_scanners_that_share_a_rule_id_keep_their_own_cwe(self):
        first = _result("R1", scanner_name="semgrep")
        second = _result("R1", scanner_name="opengrep")
        run = _run(
            ToolComponent(name="semgrep", rules=[_rule("R1", "CWE-79: XSS")]),
            ToolComponent(name="opengrep", rules=[_rule("R1", "CWE-89: SQLi")]),
            results=[first, second],
        )

        assert _flat(first, run).cwe_id == "CWE-79"
        assert _flat(second, run).cwe_id == "CWE-89"


class TestALookupThatRaisesCostsOnlyTheCwe:
    def test_the_finding_is_still_built(self, monkeypatch):
        from automated_security_helper.utils import sarif_rule_descriptors

        def refuse(result, tool):
            raise RuntimeError("the rules could not be read")

        monkeypatch.setattr(sarif_rule_descriptors, "rule_of_result", refuse)
        result = _result("CVE-2019-20477", scanner_name="trivy")
        run = _run(ToolComponent(name="trivy"), results=[result])

        flat = _flat(result, run)

        assert flat.cwe_id is None
        assert flat.cve_id == "CVE-2019-20477"


class TestTheFlatViewOfAScanCarriesBoth:
    def test_each_finding_is_read_against_its_run(self):
        model = AshAggregatedResults()
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                _run(
                    ToolComponent(
                        name="bandit", rules=[_rule("B602", "external/cwe/cwe-78")]
                    ),
                    ToolComponent(name="trivy", rules=[_rule("CVE-2019-20477")]),
                    results=[
                        _result("B602", scanner_name="bandit"),
                        _result("CVE-2019-20477", scanner_name="trivy"),
                    ],
                )
            ],
        )

        found = {
            flat.rule_id: (flat.cve_id, flat.cwe_id)
            for flat in model.to_flat_vulnerabilities()
        }

        assert found == {
            "B602": (None, "CWE-78"),
            "CVE-2019-20477": ("CVE-2019-20477", None),
        }
