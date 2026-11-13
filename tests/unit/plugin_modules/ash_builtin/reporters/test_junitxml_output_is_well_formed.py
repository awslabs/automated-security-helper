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

import re
import xml.etree.ElementTree as ET  # nosec B405

import pytest

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
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
        # The value itself, not just a control's escape: the rule id is in
        # the same element and would satisfy a bare check for the escape.
        assert f"p{SHOWN}v" in case.find("system-out").text

    def test_layout_characters_are_kept(self, tmp_path):
        """Tab and line feed are legal XML and system-out is joined by them."""
        result = _make_result(level="error")
        result.properties.__pydantic_extra__["note"] = "a\tb"

        output = _render(tmp_path, [result])

        system_out = ET.fromstring(output).find(".//system-out").text  # nosec B314
        assert "a\tb" in system_out
        assert "\n" in system_out

    @pytest.mark.parametrize(
        "character, shown",
        [
            (chr(0x00), "\\x00"),
            (chr(0x08), "\\x08"),
            (chr(0x0B), "\\x0b"),
            (chr(0x0C), "\\x0c"),
            (chr(0x0E), "\\x0e"),
            (chr(0x1F), "\\x1f"),
            (chr(0xD800), "\\" + "ud800"),
            (chr(0xDCFF), "\\" + "udcff"),
            (chr(0xDFFF), "\\" + "udfff"),
            (chr(0xFFFE), "\\" + "ufffe"),
            (chr(0xFFFF), "\\" + "uffff"),
        ],
        ids=lambda value: f"U+{ord(value):04X}" if len(value) == 1 else None,
    )
    def test_every_forbidden_character_is_written_as_its_escape(
        self, tmp_path, character, shown
    ):
        """XML 1.0 forbids the C0 controls but tab, line feed and carriage
        return, the surrogates (a file name that is not UTF-8 reaches Python as
        a lone one) and U+FFFE and U+FFFF. One character covers none of the
        range: an escape that stopped at U+0008, or one that took the vertical
        tab and the form feed for whitespace, would pass the single control
        above."""
        result = _make_result(level="error")
        # Set past the model's validation: a lone surrogate is not text the
        # model accepts, and the reporter reads whatever the attribute holds.
        result.message.root.__dict__["text"] = f"bad{character}name"

        output = _render(tmp_path, [result])

        root = ET.fromstring(output)  # nosec B314
        case = root.find(".//testcase")
        assert character not in output
        assert f"bad{shown}name" in case.get("name")

    @pytest.mark.parametrize("character", ["\t", "\n", "\r"])
    def test_every_layout_character_is_left_unescaped(self, tmp_path, character):
        """The allowed set: none of the three is written as an escape, and the
        document still parses with it in the text."""
        result = _make_result(level="error")
        result.properties.__pydantic_extra__["note"] = f"a{character}b"

        output = _render(tmp_path, [result])

        root = ET.fromstring(output)  # nosec B314
        assert f"\\x{ord(character):02x}" not in output
        # The note reached the output: without this the two checks above pass
        # for a reporter that drops the note, whatever it does with a character.
        system_out = root.find(".//system-out").text
        assert re.search(r"a[\t\n\r]b", system_out), system_out

    @pytest.mark.parametrize(
        "character",
        [
            chr(0x20),
            chr(0xD7FF),
            chr(0xE000),
            chr(0xFFFD),
            chr(0x10000),
            chr(0x1F600),
        ],
        ids=lambda value: f"U+{ord(value):04X}",
    )
    def test_the_characters_beside_the_forbidden_ranges_are_kept(
        self, tmp_path, character
    ):
        """The neighbours of the forbidden ranges are legal XML text: the space
        below the controls, the last character before the surrogates, the first
        after them, the replacement character beside U+FFFE and U+FFFF, and an
        astral character. A range written one character too wide would escape
        one of them, and the single-character cases above would not notice."""
        result = _make_result(level="error")
        result.message.root.__dict__["text"] = f"ok{character}name"

        output = _render(tmp_path, [result])

        root = ET.fromstring(output)  # nosec B314
        case = root.find(".//testcase")
        assert f"ok{character}name" in case.get("name")
        assert f"\\u{ord(character):04x}" not in output


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

    @pytest.mark.parametrize(
        "project", [["svc", "lib"], {"name": "svc"}, 7, ""], ids=repr
    )
    def test_a_workspace_project_that_is_not_text_keeps_the_case(
        self, tmp_path, project
    ):
        """An imported SARIF can write anything as ``properties.workspace_project``.

        The reporter looks the project up in the per-report ``{project: gate}``
        table, a dict lookup that hashes its key, so a list or a mapping there
        would raise TypeError and lose the whole artefact as a non-text scanner
        name did. ``extract_workspace_project`` reads only a non-empty str and
        answers None for anything else, so the lookup never sees such a value;
        this pins that reading at the document.
        """
        result = _make_result(rule_id="ODDPROJECT", level="error")
        result.properties.__pydantic_extra__["workspace_project"] = project
        result.properties.tags = []
        # A workspace with a project, so the ``{project: gate}`` table the lookup
        # reads is not empty: a reporter that skips the lookup for an empty
        # table would never hash the value, and this test would guard nothing.
        model = _make_model(runs=[_make_run(results=[result])])
        model.workspace = WorkspaceResults(
            workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            exit_code=0,
            projects=[
                WorkspaceProjectResult(
                    project="svc",
                    relative_path="svc",
                    display_label="svc",
                    status=ProjectRunStatus.COMPLETED,
                    severity_threshold="MEDIUM",
                    output_path="projects/svc",
                )
            ],
        )

        output = _get_reporter(tmp_path).report(model)

        root = ET.fromstring(output)  # nosec B314
        cases = [case.get("classname") for case in root.iter("testcase")]
        assert "ODDPROJECT" in cases, output
        # Filed under the default suite, not under the value read as text: a
        # case under "7/test-scanner" or "['svc', 'lib']/test-scanner" would
        # still be present above.
        shown = str(project)
        names = [suite.get("name") for suite in root.iter("testsuite")]
        if shown:
            assert not any(shown in name for name in names), names
