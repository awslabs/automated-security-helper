# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every JUnit document the reporter writes is well-formed XML, whatever the text.

XML 1.0 forbids a C0 control character (other than tab, line feed and carriage
return) in text and attributes. A scanner's message, a suppression's
justification, a rule id and every property value reach the document as the
scanner wrote them, and a file name in a scanned repository can hold such a
character, so one finding made the whole ``ash.junit.xml`` unreadable to every
JUnit consumer. The reporter now writes each forbidden character as its escape
(``\\x01``), the same way the human reports show control characters.

A result with no ``properties`` at all raised AttributeError when the reporter
read ``properties.__pydantic_extra__`` for the scanner's name, which lost the
whole artefact; it now gets its test case under the default suite.
"""

import xml.etree.ElementTree as ET  # nosec B405

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Message1,
    Result,
    Suppression,
)

from tests.unit.plugin_modules.ash_builtin.reporters.test_junitxml_reporter import (
    _get_reporter,
    _make_model,
    _make_result,
    _make_run,
)

pytestmark = pytest.mark.unit

#: The C0 control a file name or a tool's output can carry, plus the escape it
#: is written as.
CONTROL = "\x01"
SHOWN = "\\x01"


def _render(tmp_path, results):
    return _get_reporter(tmp_path).report(
        _make_model(runs=[_make_run(results=results)])
    )


class TestForbiddenCharactersAreWrittenAsEscapes:
    def test_a_control_in_the_message_parses_and_is_shown(self, tmp_path):
        result = _make_result(message_text=f"bad{CONTROL}name", level="error")

        output = _render(tmp_path, [result])

        root = ET.fromstring(output)  # nosec B314
        case = root.find(".//testcase")
        assert CONTROL not in output
        assert SHOWN in case.get("name")
        assert SHOWN in case.find("error").get("message")

    def test_a_control_in_a_suppression_justification_parses(self, tmp_path):
        result = _make_result(
            level="error",
            suppressions=[Suppression(kind="inSource", justification=f"why{CONTROL}")],
        )

        output = _render(tmp_path, [result])

        root = ET.fromstring(output)  # nosec B314
        assert CONTROL not in output
        assert SHOWN in root.find(".//skipped").get("message")

    def test_a_control_in_a_property_value_and_the_rule_id_parses(self, tmp_path):
        result = _make_result(rule_id=f"R{CONTROL}1", level="error")
        result.properties.__pydantic_extra__["note"] = f"p{CONTROL}v"

        output = _render(tmp_path, [result])

        root = ET.fromstring(output)  # nosec B314
        case = root.find(".//testcase")
        assert CONTROL not in output
        assert case.get("classname") == f"R{SHOWN}1"
        assert SHOWN in case.find("system-out").text

    def test_layout_characters_are_kept(self, tmp_path):
        """Tab and line feed are legal XML and system-out is joined by them."""
        result = _make_result(level="error")
        result.properties.__pydantic_extra__["note"] = "a\tb"

        output = _render(tmp_path, [result])

        system_out = ET.fromstring(output).find(".//system-out").text  # nosec B314
        assert "a\tb" in system_out
        assert "\n" in system_out


class TestAResultWithoutPropertiesKeepsItsCase:
    def test_the_result_lands_under_the_default_suite(self, tmp_path):
        result = Result(
            ruleId="NOPROPS",
            level="error",
            message=Message(root=Message1(text="no properties")),
            properties=None,
        )

        output = _render(tmp_path, [result])

        root = ET.fromstring(output)  # nosec B314
        suites = {suite.get("name"): suite for suite in root.iter("testsuite")}
        assert "ash" in suites
        assert suites["ash"].find("testcase").get("classname") == "NOPROPS"


class TestAScannerNameThatIsNotTextKeepsItsCase:
    @pytest.mark.parametrize(
        "name", [["bandit", "semgrep"], {"tool": "bandit"}, 7, None], ids=repr
    )
    def test_the_result_lands_under_the_default_suite(self, tmp_path, name):
        """An imported SARIF can write anything as ``properties.scanner_name``.

        The name is the key the reporter memoizes the scanner's threshold under
        and the suite the case is filed in, so a list or a mapping there raised
        TypeError (unhashable) and lost the whole artefact, the same loss the
        properties-less case above guards against.
        """
        result = _make_result(rule_id="ODDNAME", level="error")
        result.properties.__pydantic_extra__["scanner_name"] = name
        result.properties.tags = []

        output = _render(tmp_path, [result])

        root = ET.fromstring(output)  # nosec B314
        suites = {suite.get("name"): suite for suite in root.iter("testsuite")}
        assert "ash" in suites
        assert suites["ash"].find("testcase").get("classname") == "ODDNAME"
