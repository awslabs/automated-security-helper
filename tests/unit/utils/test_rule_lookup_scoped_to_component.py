# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A rule looked up by id is found in the result's own tool component first.

Two scanners can share a rule id: grype and trivy both name a CVE. The merge that
aggregates their runs keeps each scanner's rules in its own extension and drops
the result's component reference, so every merged result names its rule by id
alone. Read first-wins across every component, one scanner's copy of the id
graded another scanner's result: a level-less copy gave a result "warning" where
its own rule said "error", and a copy with a lower security-severity gave it a
lower severity. The lookup now reads the component the reference names, then the
component whose name is the result's scanner, and only then every component.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message,
    Message1,
    PropertyBag,
    ReportingConfiguration,
    ReportingDescriptor,
    ReportingDescriptorReference,
    ReportingDescriptorReference1,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
    ToolComponentReference,
)
from automated_security_helper.utils.sarif_utils import (
    normalize_sarif_result_severities,
)
from automated_security_helper.utils.severity_ladder import (
    component_labels,
    resolve_missing_levels,
    result_scanner_labels,
)

pytestmark = pytest.mark.unit

CVE = "CVE-2024-0001"


def _rule(
    identifier: str, level: Level | None, score: str | None
) -> ReportingDescriptor:
    fields: dict = {"id": identifier}
    if level is not None:
        fields["defaultConfiguration"] = ReportingConfiguration(level=level)
    if score is not None:
        fields["properties"] = PropertyBag(**{"security-severity": score})
    return ReportingDescriptor(**fields)


def _result(scanner: str | None, **overrides) -> Result:
    fields: dict = {"ruleId": CVE, "message": Message(root=Message1(text="found"))}
    if scanner is not None:
        fields["properties"] = PropertyBag(scanner_name=scanner)
    fields.update(overrides)
    return Result(**fields)


def _merged_report(*results: Result) -> SarifReport:
    """The merged shape: a rule-less driver, grype's copy of the CVE rule with no
    level and a medium score, trivy's copy with ``error`` and a critical score."""
    grype = ToolComponent(name="Grype", rules=[_rule(CVE, None, "5.0")])
    trivy = ToolComponent(
        name="Trivy",
        rules=[_rule("OTHER", Level.note, None), _rule(CVE, Level.error, "9.5")],
    )
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH"), extensions=[grype, trivy]),
                results=list(results),
            )
        ],
    )


def _level(result: Result) -> str:
    level = result.level
    return str(getattr(level, "value", level))


class TestTheLabels:
    def test_component_labels_are_name_and_full_name_lower_cased(self):
        component = ToolComponent(name="Trivy", fullName="Trivy Vulnerability Scanner")
        assert component_labels(component) == frozenset(
            {"trivy", "trivy vulnerability scanner"}
        )
        assert (
            component_labels(SimpleNamespace(name="  ", fullName=None)) == frozenset()
        )

    def test_result_scanner_labels_read_the_name_and_the_tool_name(self):
        by_name = _result("Trivy")
        assert result_scanner_labels(by_name) == frozenset({"trivy"})
        by_details = _result(
            None, properties=PropertyBag(scanner_details={"tool_name": "Grype"})
        )
        assert result_scanner_labels(by_details) == frozenset({"grype"})
        assert result_scanner_labels(_result(None)) == frozenset()

        class Raising:
            @property
            def properties(self):
                raise RuntimeError("a stand-in's field raised")

        assert result_scanner_labels(Raising()) == frozenset()


class TestTheLevelResolution:
    def test_a_result_is_graded_by_its_own_scanners_copy_of_the_rule(self):
        trivy_result = _result("trivy")
        grype_result = _result("grype")
        report = _merged_report(trivy_result, grype_result)
        resolve_missing_levels(report)
        # trivy's rule says error; read first-wins, grype's level-less copy said
        # "warning" for it.
        assert _level(trivy_result) == "error"
        # grype's own copy states no level, so SARIF's missing level applies.
        assert _level(grype_result) == "warning"

    def test_a_reference_naming_a_component_is_resolved_inside_that_component(self):
        """The reference names trivy (extension 1) with an index that points at
        another rule; the stated id is then looked up in trivy's rules, not in
        every component first-wins."""
        referenced = _result(
            None,
            rule=ReportingDescriptorReference(
                root=ReportingDescriptorReference1(
                    id=CVE, index=0, toolComponent=ToolComponentReference(index=1)
                )
            ),
        )
        report = _merged_report(referenced)
        resolve_missing_levels(report)
        assert _level(referenced) == "error"

    def test_without_a_scanner_or_a_reference_the_first_copy_still_wins(self):
        """SARIF's reading of a bare ruleId: the first component that holds it.
        The global fallback is unchanged; only the scoping before it is new."""
        bare = _result(None)
        report = _merged_report(bare)
        resolve_missing_levels(report)
        assert _level(bare) == "warning"

    def test_a_result_that_states_its_level_keeps_it(self):
        stated = _result("trivy", level=Level.note)
        report = _merged_report(stated)
        resolve_missing_levels(report)
        assert _level(stated) == "note"


class TestTheSeverityNormalization:
    def test_the_security_severity_comes_from_the_result_scanners_rule(self):
        trivy_result = _result("trivy")
        grype_result = _result("grype")
        report = _merged_report(trivy_result, grype_result)
        normalize_sarif_result_severities(report)
        assert getattr(trivy_result.properties, "issue_severity", None) == "CRITICAL"
        assert getattr(grype_result.properties, "issue_severity", None) == "MEDIUM"

    def test_a_reference_naming_a_component_scores_from_that_component(self):
        referenced = _result(
            None,
            rule=ReportingDescriptorReference(
                root=ReportingDescriptorReference1(
                    id=CVE, index=0, toolComponent=ToolComponentReference(index=1)
                )
            ),
        )
        report = _merged_report(referenced)
        normalize_sarif_result_severities(report)
        assert getattr(referenced.properties, "issue_severity", None) == "CRITICAL"
