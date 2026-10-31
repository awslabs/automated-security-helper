# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``resolve_missing_levels`` finds a result's rule every way SARIF lets a result
name one.

It read ``ruleId`` and ``rule.id`` alone, so a result that names its rule by
``ruleIndex``, or through ``rule.index`` into an extension, took the missing
level ("warning", MEDIUM) in place of the rule's own default, and a hierarchical
rule id (``CA1001/sub``) matched nothing.
"""

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Message,
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


def _rule(rule_id: str, level: str) -> ReportingDescriptor:
    return ReportingDescriptor(
        id=rule_id, defaultConfiguration=ReportingConfiguration(level=level)
    )


def _report(result: Result, driver_rules, extension_rules=None) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(name="ash", rules=driver_rules),
                    extensions=[ToolComponent(name="ext", rules=extension_rules)]
                    if extension_rules is not None
                    else None,
                ),
                results=[result],
            )
        ],
    )


def _level(report: SarifReport) -> str:
    level = report.runs[0].results[0].level
    return str(getattr(level, "value", level))


def test_a_rule_named_by_index_alone_gives_its_default_level():
    result = Result(ruleIndex=1, message=Message(text="x"))
    report = _report(result, [_rule("A", "error"), _rule("B", "note")])

    resolve_missing_levels(report)

    # Read as the missing level, "warning", before.
    assert _level(report) == "note"


def test_a_rule_in_an_extension_is_found_through_the_rule_reference():
    result = Result(
        rule={"index": 0, "toolComponent": {"index": 0}}, message=Message(text="x")
    )
    report = _report(result, [_rule("DRIVER", "warning")], [_rule("EXT", "error")])

    resolve_missing_levels(report)

    assert _level(report) == "error"


def test_an_indexed_rule_whose_id_disagrees_yields_to_the_stated_id():
    result = Result(ruleId="B", ruleIndex=0, message=Message(text="x"))
    report = _report(result, [_rule("A", "error"), _rule("B", "note")])

    resolve_missing_levels(report)

    assert _level(report) == "note"


def test_a_hierarchical_rule_id_falls_back_to_its_prefix():
    result = Result(ruleId="CA1001/sub/case", message=Message(text="x"))
    report = _report(result, [_rule("CA1001", "note")])

    resolve_missing_levels(report)

    assert _level(report) == "note"


def test_a_result_naming_no_known_rule_still_takes_the_missing_level():
    result = Result(ruleId="UNKNOWN", message=Message(text="x"))
    report = _report(result, [_rule("A", "error")])

    resolve_missing_levels(report)

    assert _level(report) == "warning"
