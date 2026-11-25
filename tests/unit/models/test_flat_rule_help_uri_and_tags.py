# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A flat row carries the help link and tags its SARIF rule declares.

A scanner states a rule's ``helpUri`` and ``properties.tags`` once, on the rule
in ``tool.driver.rules``, not on every result. ``from_sarif_result`` read the
flat ``references`` only from a result's ``relatedLocations`` and the flat
``tags`` only from the result's properties, so the rule-level values were
discarded for every scanner that writes them there.

The read is the same for every scanner, whatever its tier or its name: it
follows the SARIF rule, so core, alpha and SDK-shipped scanners are treated
alike. The result's own values keep precedence.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

_HELP = "https://example.com/rules/R1"


def _rule(**kwargs) -> ReportingDescriptor:
    return ReportingDescriptor(id="R1", **kwargs)


def _result(**kwargs) -> Result:
    return Result(
        ruleId="R1",
        level=Level.warning,
        message=Message.model_validate({"text": "finding text"}),
        **kwargs,
    )


def _run(tool_name: str, rule: ReportingDescriptor, result: Result) -> Run:
    return Run(
        tool=Tool(driver=ToolComponent(name=tool_name, rules=[rule])),
        results=[result],
    )


def _flat(tool_name: str, rule: ReportingDescriptor, result: Result):
    run = _run(tool_name, rule, result)
    return FlatVulnerability.from_sarif_result(result, tool_name, "SAST", run=run)


@pytest.mark.parametrize("tool_name", ["trivy", "semgrep", "some-sdk-plugin"])
def test_rule_help_uri_and_tags_reach_the_flat_row(tool_name):
    flat = _flat(
        tool_name,
        _rule(helpUri=_HELP, properties=PropertyBag(tags=["security", "HIGH"])),
        _result(),
    )
    assert json.loads(flat.references) == [_HELP]
    assert json.loads(flat.tags) == ["security", "HIGH"]


def test_result_level_values_keep_precedence():
    related = Location(
        physicalLocation=PhysicalLocation.model_validate(
            {"artifactLocation": {"uri": "https://example.com/own"}}
        )
    )
    flat = _flat(
        "trivy",
        _rule(helpUri=_HELP, properties=PropertyBag(tags=["rule-tag"])),
        _result(
            relatedLocations=[related],
            properties=PropertyBag(tags=["result-tag"]),
        ),
    )
    assert json.loads(flat.references) == ["https://example.com/own"]
    assert json.loads(flat.tags) == ["result-tag"]


def test_a_rule_without_either_leaves_the_columns_empty():
    flat = _flat("trivy", _rule(), _result())
    assert flat.references is None
    assert flat.tags is None


def test_without_a_run_nothing_is_read_from_the_rule():
    flat = FlatVulnerability.from_sarif_result(_result(), "trivy", "SAST")
    assert flat.references is None
    assert flat.tags is None
