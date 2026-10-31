# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The rule a result's message is resolved against is found where it is declared.

ASH writes one run whose tool components are the scanners, and two scanners can
declare one rule id. The descriptor of a result is looked up in its own run, and
within the run in the component the result names, else the component its scanner
name names, else the driver and then the extensions in order.
"""

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Message,
    MultiformatMessageString,
    PropertyBag,
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
from automated_security_helper.utils.sarif_rule_descriptors import (
    rule_descriptors_by_result,
)

pytestmark = pytest.mark.unit


def _text(value: str) -> MultiformatMessageString:
    return MultiformatMessageString(text=value)


def _rule(rule_id: str, text: str) -> ReportingDescriptor:
    return ReportingDescriptor(id=rule_id, messageStrings={"default": _text(text)})


def _component(name: str, *rules: ReportingDescriptor, **fields) -> ToolComponent:
    return ToolComponent(name=name, rules=list(rules) or None, **fields)


def _result(rule_id: str | None = "R1", **fields) -> Result:
    return Result(
        ruleId=rule_id,
        level=Level.warning,
        message=Message.model_validate({"id": "default"}),
        **fields,
    )


def _sarif(*runs: Run) -> SarifReport:
    return SarifReport(version="2.1.0", runs=list(runs))


def _default_text(descriptor) -> str:
    return descriptor.messageStrings["default"].text


class TestTheComponentIsChosenPerResult:
    def test_a_result_is_read_against_the_extension_its_scanner_names(self):
        run = Run(
            tool=Tool(
                driver=_component("ASH"),
                extensions=[
                    _component("trivy", _rule("R1", "trivy text")),
                    _component("grype", _rule("R1", "grype text")),
                ],
            ),
            results=[
                _result(properties=PropertyBag(scanner_name="grype")),
                _result(properties=PropertyBag(scanner_name="trivy")),
            ],
        )

        found = rule_descriptors_by_result(_sarif(run))

        assert [_default_text(d) for d in found] == ["grype text", "trivy text"]

    def test_a_scanner_that_does_not_declare_the_rule_borrows_no_other_string(self):
        run = Run(
            tool=Tool(
                driver=_component("ASH"),
                extensions=[
                    _component("trivy", _rule("R1", "trivy text")),
                    _component("grype"),
                ],
            ),
            results=[_result(properties=PropertyBag(scanner_name="grype"))],
        )

        assert rule_descriptors_by_result(_sarif(run)) == [None]

    def test_a_result_with_no_scanner_is_read_driver_first_then_extensions(self):
        run = Run(
            tool=Tool(
                driver=_component("ASH", _rule("R1", "driver text")),
                extensions=[_component("trivy", _rule("R1", "trivy text"))],
            ),
            results=[_result()],
        )

        (found,) = rule_descriptors_by_result(_sarif(run))

        assert _default_text(found) == "driver text"

    def test_a_rule_reference_names_its_extension_by_index(self):
        reference = ReportingDescriptorReference(
            root=ReportingDescriptorReference1(
                id="R1", index=0, toolComponent=ToolComponentReference(index=1)
            )
        )
        run = Run(
            tool=Tool(
                driver=_component("ASH"),
                extensions=[
                    _component("trivy", _rule("R1", "trivy text")),
                    _component("grype", _rule("R1", "grype text")),
                ],
            ),
            results=[
                _result(rule=reference, properties=PropertyBag(scanner_name="trivy"))
            ],
        )

        (found,) = rule_descriptors_by_result(_sarif(run))

        assert _default_text(found) == "grype text"

    def test_the_rule_at_the_results_index_wins_among_rules_of_one_id(self):
        run = Run(
            tool=Tool(
                driver=_component(
                    "ASH", _rule("R1", "first text"), _rule("R1", "second text")
                )
            ),
            results=[_result(ruleIndex=1), _result()],
        )

        found = rule_descriptors_by_result(_sarif(run))

        assert [_default_text(d) for d in found] == ["second text", "first text"]


class TestTheStringsOfTheComponent:
    def test_the_components_strings_sit_under_the_rules_own(self):
        run = Run(
            tool=Tool(
                driver=_component(
                    "ASH",
                    ReportingDescriptor(
                        id="R1", messageStrings={"default": _text("rule text")}
                    ),
                    globalMessageStrings={
                        "default": _text("component text"),
                        "other": _text("other component text"),
                    },
                )
            ),
            results=[_result()],
        )

        (found,) = rule_descriptors_by_result(_sarif(run))

        assert found.messageStrings["default"].text == "rule text"
        assert found.messageStrings["other"].text == "other component text"


class TestTheAnswerIsOnePerResult:
    def test_the_list_follows_the_order_of_every_result_in_every_run(self):
        runs = [
            Run(
                tool=Tool(driver=_component("one", _rule("R1", "text one"))),
                results=[_result("R1"), _result("MISSING")],
            ),
            Run(
                tool=Tool(driver=_component("two", _rule("R1", "text two"))),
                results=[_result(None), _result("R1")],
            ),
        ]
        report = _sarif(*runs)

        found = rule_descriptors_by_result(report)

        assert len(found) == len(report.get_all_results()) == 4
        assert [None if d is None else _default_text(d) for d in found] == [
            "text one",
            None,
            None,
            "text two",
        ]
