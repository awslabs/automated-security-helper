# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A hierarchical rule id is looked up in the result's own scope before anywhere else.

A rule id is looked up in the component the reference names, then in the
component of the result's scanner, then across every component. A hierarchical id
(``CA1001/sub``) falls back to each shorter prefix, and each prefix went through
all three steps before the next was tried, so another scanner's exact
``CA1001/sub`` won over the result's own scanner's ``CA1001``: the cross-scanner
bleed the scope exists to prevent.
"""

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message,
    PropertyBag,
    ReportingConfiguration,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.severity_ladder import resolve_missing_levels

pytestmark = pytest.mark.unit


def _rule(identifier: str, level: Level) -> ReportingDescriptor:
    return ReportingDescriptor(
        id=identifier, defaultConfiguration=ReportingConfiguration(level=level)
    )


def _graded(rule_id: str, scanner: str | None) -> str:
    """The level a result of *scanner* naming *rule_id* is given, with Grype's
    extension holding ``CA1001`` (note) and Trivy's holding ``CA1001/sub`` (error)."""
    fields: dict = {"ruleId": rule_id, "message": Message(text="x")}
    if scanner is not None:
        fields["properties"] = PropertyBag(scanner_name=scanner)
    report = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(name="ASH"),
                    extensions=[
                        ToolComponent(
                            name="Grype", rules=[_rule("CA1001", Level.note)]
                        ),
                        ToolComponent(
                            name="Trivy", rules=[_rule("CA1001/sub", Level.error)]
                        ),
                    ],
                ),
                results=[Result(**fields)],
            )
        ],
    )

    resolve_missing_levels(report)

    level = report.runs[0].results[0].level
    return str(getattr(level, "value", level))


def test_the_own_scanners_prefix_wins_over_another_scanners_exact_id():
    # Trivy's exact CA1001/sub (error) is not Grype's to read: Grype's own CA1001
    # (note) is. It read "error" before.
    assert _graded("CA1001/sub", "Grype") == "note"


def test_the_own_scanners_exact_id_still_wins():
    assert _graded("CA1001/sub", "Trivy") == "error"


def test_a_result_with_no_scanner_still_reads_the_longest_id_across_components():
    """The control: with no scope to read, the longest prefix any component holds."""
    assert _graded("CA1001/sub", None) == "error"
    assert _graded("CA1001/other", None) == "note"


def test_a_prefix_no_scanner_holds_is_found_globally():
    assert _graded("CA1001/sub/deeper", "Grype") == "note"
    # Nothing in Trivy's scope matches: the global fallback reads the shorter id.
    assert _graded("CA1001/other", "Trivy") == "note"
