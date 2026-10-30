# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The JUnit report states each result as the SARIF records it.

* A message that holds only the id of a message string, and a result that names
  its rule through a rule reference, were named after nothing.
* A test name does not carry an empty ``[...]`` when one of its two parts is
  missing.
* ``below_threshold`` is a flag. The string ``"false"`` is truthy to Python, and
  negating it marked an actionable finding as below the threshold.
* ``issue_severity`` with surrounding blanks was not recognized.
* The ``type`` of an ``<error>`` follows the level, so a ``note`` finding is not
  typed ``error`` because its kind is the default ``fail``.
* A result of kind ``pass`` or ``informational`` is graded by its level like any
  other, so the report agrees with the exit code: below the threshold it is a
  skip, and an actionable one with no ``error`` or ``warning`` level is a passing
  test.
"""

import xml.etree.ElementTree as ET  # nosec B405

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Message1,
    Message2,
    PropertyBag,
    ReportingDescriptorReference,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit


def _result(
    *,
    rule_id: str | None = "R1",
    message: Message | None = None,
    level: str = "error",
    extra: dict | None = None,
    **fields,
) -> Result:
    props = PropertyBag(tags=["tool_name::scanner1"])
    props.__pydantic_extra__ = {"scanner_name": "scanner1", **(extra or {})}
    return Result(
        ruleId=rule_id,
        level=level,
        message=message or Message(root=Message1(text="Test finding")),
        properties=props,
        **fields,
    )


def _render(tmp_path, result: Result, threshold: str | None = None) -> ET.Element:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin.reporters.junitxml_reporter import (
        JunitXmlReporter,
    )

    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.metadata.generated_at = "2025-01-15T10:30:00+00:00"
    model.sarif = SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scanner1")),
                results=[result],
            )
        ]
    )
    if threshold:
        model.ash_config.global_settings.severity_threshold = threshold
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    root = ET.fromstring(JunitXmlReporter(context=context).report(model))  # nosec B314
    return root.find(".//testcase")


class TestTheCaseIsNamedFromWhatTheResultHolds:
    def test_a_message_holding_only_an_id_names_the_case(self, tmp_path):
        case = _render(tmp_path, _result(message=Message(root=Message2(id="msg.1"))))
        assert case.get("name") == "msg.1 [R1]"

    def test_a_rule_reference_names_the_rule(self, tmp_path):
        reference = ReportingDescriptorReference.model_validate(
            {"id": "R9", "index": 0}
        )
        case = _render(tmp_path, _result(rule_id=None, rule=reference))
        assert case.get("classname") == "R9"
        assert case.get("name") == "Test finding [R9]"

    def test_a_blank_message_does_not_leave_an_empty_prefix(self, tmp_path):
        case = _render(tmp_path, _result(message=Message(root=Message1(text="  "))))
        assert case.get("name") == "R1"

    def test_a_result_with_no_rule_is_named_by_its_message(self, tmp_path):
        case = _render(tmp_path, _result(rule_id=None))
        assert case.get("name") == "Test finding"


class TestBelowThresholdIsAFlag:
    def test_the_string_false_does_not_set_the_finding_aside(self, tmp_path):
        case = _render(tmp_path, _result(extra={"below_threshold": "false"}))
        assert case.find("error") is not None
        assert case.find("skipped") is None

    def test_the_string_true_sets_it_aside(self, tmp_path):
        case = _render(tmp_path, _result(extra={"below_threshold": "true"}))
        assert case.find("skipped") is not None
        assert case.find("error") is None

    def test_a_value_that_states_neither_decides_nothing(self, tmp_path):
        # The control: the same result without the property is an error, so the
        # gate decided here.
        case = _render(tmp_path, _result(extra={"below_threshold": "maybe"}))
        assert case.find("error") is not None


class TestIssueSeverityIsStripped:
    def test_blanks_around_a_severity_do_not_hide_it(self, tmp_path):
        """HIGH meets the MEDIUM gate whatever the level; the blanks hid it."""
        case = _render(
            tmp_path, _result(level="note", extra={"issue_severity": " HIGH "})
        )
        assert case.find("error") is not None
        assert case.find("skipped") is None


class TestTheTypeFollowsTheLevel:
    @pytest.mark.parametrize(
        "level, expected",
        [("error", "error"), ("warning", "warning"), ("note", "note")],
    )
    def test_a_default_kind_finding_is_typed_by_its_level(
        self, tmp_path, level, expected
    ):
        case = _render(tmp_path, _result(level=level), threshold="ALL")
        assert case.find("error").get("type") == expected

    def test_a_finding_with_no_level_takes_the_lowest_label(self, tmp_path):
        case = _render(tmp_path, _result(level="none"), threshold="ALL")
        assert case.find("error").get("type") == "note"


class TestAResultThatIsNotAFindingIsGradedByItsLevel:
    """The exit code reads the level against the threshold and ignores the kind,
    so the report does the same."""

    @pytest.mark.parametrize("kind", ["pass", "informational"])
    def test_one_below_the_threshold_is_a_skip(self, tmp_path, kind):
        result = _result(level="note")
        result.kind = kind
        case = _render(tmp_path, result)
        skipped = case.find("skipped")
        assert skipped is not None
        assert skipped.get("type") == "threshold"
        assert case.find("error") is None

    @pytest.mark.parametrize("kind", ["pass", "informational"])
    def test_one_that_is_actionable_without_an_error_level_is_a_passing_test(
        self, tmp_path, kind
    ):
        result = _result(level="none")
        result.kind = kind
        case = _render(tmp_path, result, threshold="ALL")
        assert case.find("skipped") is None
        assert case.find("error") is None

    def test_a_finding_below_the_threshold_is_a_skip_too(self, tmp_path):
        # The control: the kind makes no difference to the skip.
        case = _render(tmp_path, _result(level="note"))
        assert case.find("skipped") is not None
