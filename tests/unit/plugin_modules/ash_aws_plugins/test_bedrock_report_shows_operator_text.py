# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The Bedrock summary report shows repository text instead of obeying it.

The report file this reporter writes renders the scanned repository's own
text: the project name, rule ids, file paths, finding messages and code
snippets. A repository can commit any of those, so each one is shown through
the terminal_text helpers (controls become visible escapes, line-start
commands are broken) before it lands in the markdown document.

Every cell drives the public ``report()`` path with a stubbed boto3 session,
so no request leaves the process.
"""

import json
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from markdown_it import MarkdownIt

import automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter as bsr_module
from automated_security_helper.config.ash_config import AshConfig
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    make_reporter,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

RLO = chr(0x202E)
NEL = chr(0x85)
MARKER = "ZX9MARK"

#: Raw control characters that must never appear in the rendered document.
RAW_CONTROLS = ("\x1b", "\x07", "\r", NEL, RLO)


def _probe(tag: str) -> str:
    """Repository-controlled text carrying one of each control class."""
    return f"{tag}-\x1b[31m-\x07-\r-{NEL}-{RLO}-\n::add-mask::{tag}{MARKER}"


#: A model answer in each HTML shape a Markdown viewer renders live: a script,
#: an image with an error handler, an inline javascript: link, an open details
#: element, and an unclosed comment, which hides everything after it.
HOSTILE_HTML_ANSWER = (
    "Summary of the scan.\n\n"
    "<script>alert(1)</script>\n\n"
    '<img src=x onerror="alert(2)">\n\n'
    'See <a href="javascript:alert(3)">the fix</a> for details.\n\n'
    "<details open><summary>more</summary>hidden text</details>\n\n"
    "<!-- the rest of the report is hidden"
)
#: What an HTML token made from that answer would hold.
HOSTILE_MARKERS = ("<script", "onerror", "javascript:", "<details open", "<!--")

#: Code in an answer, in each form CommonMark keeps as written: inline spans, a
#: fenced block, an indented block, and a four-backtick fence holding a
#: three-backtick line, which does not close it. Its text outside code holds an
#: entity written out and a bare "<", which make no HTML, so only the escape
#: outside code keeps them reading as written.
CODE_ANSWER = (
    "Use &lt;T> as `List<String>` and `a && b` here.\n\n"
    "```sh\ncmd 2>&1 | tee <log>\n```\n\n"
    "Then:\n\n"
    "    if a < b && c:\n        run()\n\n"
    "````\nshown ```\nx < y & z\n````\n\n"
    "Write &lt; for a literal <, then Done."
)
#: What a viewer shows as code from that answer: each span, then each block.
CODE_AS_WRITTEN = (
    ("code_inline", "List<String>"),
    ("code_inline", "a && b"),
    ("fence", "cmd 2>&1 | tee <log>\n"),
    ("code_block", "if a < b && c:\n    run()\n"),
    ("fence", "shown ```\nx < y & z\n"),
)

#: Backtick strings that pair with nothing (two, one, three), and backticks a
#: backslash makes literal: no code span forms, so the HTML in it is text.
UNPAIRED_BACKTICKS_ANSWER = (
    "Odd ``<img src=x onerror=alert(1)>` and <script>alert(2)</script>``` marks.\n\n"
    "Also \\`<b onclick=alert(3)>\\` here."
)
UNPAIRED_MARKERS = ("onerror", "<script", "onclick")

#: The same two shapes, each in its own paragraph with an entity written out
#: beside it and no HTML anywhere: no code span forms, so each entity reads as
#: written. (In one paragraph the lone backtick would close on the one after a
#: backslash, as CommonMark reads no escape inside a span.)
UNPAIRED_ENTITY_ANSWER = (
    "Odd ` mark: write &lt; as written.\n\nAlso \\`x &lt; y\\` here."
)
UNPAIRED_ENTITY_READS = ("Odd ` mark: write &lt; as written.", "Also `x &lt; y` here.")

#: An ordinary answer holding text HTML would read: a generic type, an
#: ampersand, and an entity the model wrote out as text.
PLAIN_TEXT_ANSWER = (
    "Use List<String> for the names, check a & b, and write &lt; in HTML."
)


#: A "##name[" form a runner reads anywhere in a line.
HASH_COMMAND = re.compile(r"##[A-Za-z]*\[")


def _markdown_tokens(document: str) -> list:
    """The document as a CommonMark viewer parses it, inline tokens included."""
    tokens = []
    for token in MarkdownIt("commonmark").parse(document):
        tokens.append(token)
        tokens.extend(token.children or [])
    return tokens


def _live_answer_html(document: str) -> list:
    """The HTML tokens the hostile answer would make, if any render."""
    return [
        token.content
        for token in _markdown_tokens(document)
        if token.type in ("html_block", "html_inline")
        and any(marker in token.content for marker in HOSTILE_MARKERS)
    ]


def _finding_headings(document: str) -> list:
    """The Evidence section's finding headings a viewer renders."""
    tokens = MarkdownIt("commonmark").parse(document)
    return [
        tokens[index + 1].content
        for index, token in enumerate(tokens)
        if token.type == "heading_open"
        and token.tag == "h4"
        and re.match(r"Finding \d+: ", tokens[index + 1].content)
    ]


def _rendered_text(document: str) -> str:
    """The text a viewer shows, one rendered line per inline run."""
    return "\n".join(
        "".join(child.content for child in token.children or [] if child.type == "text")
        for token in MarkdownIt("commonmark").parse(document)
        if token.type == "inline"
    )


def _code_tokens(document: str) -> list:
    """(type, content) of each piece of code a CommonMark viewer renders."""
    return [
        (token.type, token.content)
        for token in _markdown_tokens(document)
        if token.type in ("code_inline", "fence", "code_block")
    ]


def _headings(document: str) -> list:
    """The text of every heading a CommonMark viewer renders."""
    tokens = MarkdownIt("commonmark").parse(document)
    return [
        tokens[index + 1].content
        for index, token in enumerate(tokens)
        if token.type == "heading_open"
    ]


def _executive_answer_only(answer: str):
    """The model's answers by section: *answer* for the executive summary, and a
    plain sentence for every other section, so no later answer closes what the
    executive summary's answer leaves open."""

    def answer_for(system: str) -> str:
        return answer if "executive summary" in system else "Plain analysis."

    return answer_for


@pytest.fixture
def mock_context(temp_project_dir, temp_output_dir):
    from automated_security_helper.base.plugin_context import PluginContext

    return PluginContext(output_dir=temp_output_dir, source_dir=temp_project_dir)


def _make_reporter(mock_context, monkeypatch, model_text):
    """A reporter whose boto3 session only ever yields a stubbed client.

    *model_text* is the answer to every call, or a function of a call's system
    prompt that gives that call's answer.
    """
    answer_for = model_text if callable(model_text) else (lambda system: model_text)

    def converse(**request):
        system = " ".join(part.get("text", "") for part in request.get("system", []))
        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": answer_for(system)}],
                }
            }
        }

    runtime = MagicMock()
    runtime.converse.side_effect = converse
    session = MagicMock()
    session.client.return_value = runtime
    monkeypatch.setattr(bsr_module.boto3, "Session", MagicMock(return_value=session))
    return make_reporter(
        mock_context, output_markdown=False, include_code_snippets=True
    )


@pytest.fixture
def reporter(mock_context, monkeypatch):
    """A reporter whose stubbed model answers with plain text."""
    return _make_reporter(mock_context, monkeypatch, "Generated summary from Bedrock.")


@pytest.fixture
def reporter_with_hostile_model_text(mock_context, monkeypatch):
    """A reporter whose stubbed model answer carries the control set.

    A model response can echo the scanned repository's text verbatim, so the
    generated-analysis sections are repository text one hop removed.
    """
    return _make_reporter(mock_context, monkeypatch, _probe("model"))


@pytest.fixture
def reporter_with_html_answer(mock_context, monkeypatch):
    """A reporter whose stubbed model answers in HTML a viewer would run."""
    return _make_reporter(mock_context, monkeypatch, HOSTILE_HTML_ANSWER)


@pytest.fixture
def reporter_with_plain_text_answer(mock_context, monkeypatch):
    """A reporter whose stubbed model answers with ordinary text."""
    return _make_reporter(mock_context, monkeypatch, PLAIN_TEXT_ANSWER)


def _model_without_findings(project_name: str):
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import (
        SarifReport,
        Run,
        Tool,
        ToolComponent,
    )

    AshAggregatedResults.model_rebuild()
    run = Run(
        tool=Tool(driver=ToolComponent(name="ASH", version="1.0.0")),
        results=[],
    )
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])
    model.scanner_results = {}
    model.metadata.project_name = project_name
    return model


def _model_with_hostile_finding(
    project_name: str, count: int = 1, message: "str | None" = None
):
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import (
        SarifReport,
        Run,
        Tool,
        ToolComponent,
        Result,
        Message,
        Location,
        PhysicalLocation,
        ArtifactLocation,
        Region,
        ArtifactContent,
        PropertyBag,
    )

    AshAggregatedResults.model_rebuild()
    finding = Result(
        ruleId=_probe("rule"),
        level="error",
        message=Message(text=_probe("msg") if message is None else message),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=_probe("file")),
                    region=Region(
                        startLine=10,
                        endLine=12,
                        snippet=ArtifactContent(text=_probe("snip")),
                    ),
                )
            )
        ],
        # The type the product reads (utils/scanner_tool_types.result_tool_types):
        # a tool_type:: tag or the engine's scanner_name. A finding of unknown
        # type has its snippet dropped before rendering (fail closed).
        properties=PropertyBag(scanner_type="SAST", tags=["tool_type::SAST"]),
    )
    run = Run(
        tool=Tool(driver=ToolComponent(name="ASH", version="1.0.0")),
        results=[finding] * count,
    )
    model = AshAggregatedResults()
    model.sarif = SarifReport(version="2.1.0", runs=[run])
    model.scanner_results = {}
    model.metadata.project_name = project_name
    return model


def _assert_document_is_shown(document: str) -> None:
    """No raw control reaches the document, and no line starts a command."""
    for control in RAW_CONTROLS:
        assert control not in document, (
            "a raw control character reached the rendered report: " + ascii(control)
        )
    for line in document.splitlines():
        assert not line.startswith("::"), (
            "a line of the rendered report starts a workflow command: "
            + ascii(line[:40])
        )


class TestBedrockReportShowsOperatorText:
    def test_project_line_shows_the_project_name_without_findings(self, reporter):
        """The no-findings outcome prints the project name as one shown line."""
        model = _model_without_findings(_probe("proj"))

        document = reporter.report(model)

        _assert_document_is_shown(document)
        places = re.findall(r"Project: ([^\n]*)", document)
        assert places, "the outcome section lost its Project line"
        assert any("proj" in place and MARKER in place for place in places), (
            "the project name's probe did not survive onto the Project line"
        )

    def test_project_line_shows_the_project_name_with_findings(self, reporter):
        """The full structured report prints the project name as one shown line."""
        model = _model_with_hostile_finding(_probe("proj"))

        document = reporter.report(model)

        _assert_document_is_shown(document)
        places = re.findall(r"Project: ([^\n]*)", document)
        assert places, "the outcome section lost its Project line"
        assert any("proj" in place and MARKER in place for place in places), (
            "the project name's probe did not survive onto the Project line"
        )

    def test_finding_index_row_shows_each_field_on_its_row(self, reporter):
        """The finding-index table keeps rule id, file and message in their row."""
        model = _model_with_hostile_finding("sample-project")

        document = reporter.report(model)

        _assert_document_is_shown(document)
        rows = [
            line
            for line in document.splitlines()
            if line.startswith("| ") and "rule" in line
        ]
        assert rows, "the finding-index table lost its finding row"
        row = rows[0]
        assert MARKER in row, "the rule id's probe did not survive into its row"
        assert "file" in row, "the file path did not survive into its row"
        assert "msg" in row, "the message did not survive into its row"

    def test_evidence_heading_and_location_are_one_shown_line(self, reporter):
        """The Evidence heading and Location line each stay one shown line."""
        model = _model_with_hostile_finding("sample-project")

        document = reporter.report(model)

        _assert_document_is_shown(document)
        headings = re.findall(r"#### Finding 1: ([^\n]*)", document)
        assert headings, "the Evidence section lost its finding heading"
        assert any("rule" in heading and MARKER in heading for heading in headings), (
            "the rule id's probe did not survive onto the finding heading"
        )

        summaries = re.findall(r"<summary>([^\n]*)</summary>", document)
        assert any("rule" in summary and MARKER in summary for summary in summaries), (
            "the rule id's probe did not survive onto the details summary"
        )

        locations = re.findall(r"Location: ([^\n]*)", document)
        assert locations, "the Evidence section lost its Location line"
        assert any(
            "file" in location and MARKER in location for location in locations
        ), "the file path's probe did not survive onto the Location line"

    def test_generated_analysis_sections_show_the_model_text(
        self, reporter_with_hostile_model_text
    ):
        """The structured report shows the model's answer without obeying it."""
        model = _model_with_hostile_finding("sample-project")

        document = reporter_with_hostile_model_text.report(model)

        _assert_document_is_shown(document)
        assert "model" + MARKER in document, (
            "the model answer's probe did not survive into the report"
        )

    def test_simple_report_shows_the_model_text(self, reporter_with_hostile_model_text):
        """The simple (no section headers) report shows the model's answer."""
        reporter_with_hostile_model_text.config.options.add_section_headers = False
        model = _model_with_hostile_finding("sample-project")

        document = reporter_with_hostile_model_text.report(model)

        _assert_document_is_shown(document)
        assert "model" + MARKER in document, (
            "the model answer's probe did not survive into the report"
        )

    def test_flat_findings_section_shows_the_model_text(
        self, reporter_with_hostile_model_text
    ):
        """Findings not grouped by severity show the model's answer."""
        reporter_with_hostile_model_text.config.options.group_by_severity = False
        model = _model_with_hostile_finding("sample-project")

        document = reporter_with_hostile_model_text.report(model)

        _assert_document_is_shown(document)
        assert "model" + MARKER in document, (
            "the model answer's probe did not survive into the report"
        )

    def test_batch_synthesis_shows_the_model_text(
        self, reporter_with_hostile_model_text
    ):
        """The answer synthesized from batch summaries is shown, not obeyed."""
        options = reporter_with_hostile_model_text.config.options
        options.group_by_severity = False
        options.batch_processing = True
        options.max_findings_to_analyze = 1
        # Only the batch path writes model text into this run's report.
        options.include_sections = ["technical_analysis"]
        model = _model_with_hostile_finding("sample-project", count=2)

        document = reporter_with_hostile_model_text.report(model)

        _assert_document_is_shown(document)
        assert "model" + MARKER in document, (
            "the synthesized answer's probe did not survive into the report"
        )

    @pytest.mark.parametrize(
        "section, option",
        [
            ("executive_summary", "output_executive_file"),
            ("technical_analysis", "output_technical_file"),
        ],
    )
    def test_each_written_section_file_shows_the_model_text(
        self, reporter_with_hostile_model_text, section, option
    ):
        """The executive and technical files the reporter writes show the
        model's answer, as the report does."""
        options = reporter_with_hostile_model_text.config.options
        options.output_markdown = True
        options.include_sections = [section]
        model = _model_with_hostile_finding("sample-project")

        reporter_with_hostile_model_text.report(model)

        written = (
            Path(reporter_with_hostile_model_text.context.output_dir)
            / "reports"
            / getattr(options, option)
        ).read_text(encoding="utf-8")
        _assert_document_is_shown(written)
        assert "model" + MARKER in written, (
            "the model answer's probe did not survive into the written file"
        )

    def test_model_html_renders_inert_and_hides_no_finding(
        self, reporter_with_html_answer
    ):
        """HTML in the model's answer renders as text, and an unclosed comment
        in it hides none of the Evidence section's findings."""
        model = _model_with_hostile_finding("sample-project")

        document = reporter_with_html_answer.report(model)

        # The control: the answer's own words are in the report.
        assert "the fix" in _rendered_text(document)
        assert _live_answer_html(document) == []
        assert len(_finding_headings(document)) == 1, _finding_headings(document)

    def test_model_html_renders_inert_in_the_simple_report(
        self, reporter_with_html_answer
    ):
        """The simple report renders the model's HTML as text too."""
        reporter_with_html_answer.config.options.add_section_headers = False
        model = _model_with_hostile_finding("sample-project")

        document = reporter_with_html_answer.report(model)

        assert "the fix" in _rendered_text(document)
        assert _live_answer_html(document) == []

    @pytest.mark.parametrize(
        "section, option",
        [
            ("executive_summary", "output_executive_file"),
            ("technical_analysis", "output_technical_file"),
        ],
    )
    def test_model_html_renders_inert_in_each_written_section_file(
        self, reporter_with_html_answer, section, option
    ):
        """The section files the reporter writes render the model's HTML as
        text, as the report does."""
        options = reporter_with_html_answer.config.options
        options.output_markdown = True
        options.include_sections = [section]
        model = _model_with_hostile_finding("sample-project")

        reporter_with_html_answer.report(model)

        written = (
            Path(reporter_with_html_answer.context.output_dir)
            / "reports"
            / getattr(options, option)
        ).read_text(encoding="utf-8")
        assert "the fix" in _rendered_text(written)
        assert _live_answer_html(written) == []

    @pytest.mark.parametrize("surface", ["report", "executive file"])
    def test_code_in_a_model_answer_reads_as_written(
        self, mock_context, monkeypatch, surface
    ):
        """Inside an answer's code spans and code blocks a viewer shows the code
        as the model wrote it: CommonMark decodes no entity in code, and HTML in
        code is already text."""
        reporter = _make_reporter(mock_context, monkeypatch, CODE_ANSWER)
        reporter.config.options.output_markdown = surface == "executive file"
        model = _model_with_hostile_finding("sample-project")

        document = reporter.report(model)

        if surface == "executive file":
            document = (
                Path(reporter.context.output_dir)
                / "reports"
                / reporter.config.options.output_executive_file
            ).read_text(encoding="utf-8")
        code = _code_tokens(document)
        for piece in CODE_AS_WRITTEN:
            assert piece in code, (piece, code)
        # The text around the code reads as written, its entities included.
        rendered = _rendered_text(document)
        assert "Use &lt;T> as" in rendered, rendered
        assert "Write &lt; for a literal <, then Done." in rendered, rendered

    @pytest.mark.parametrize("fence", ["```", "````", "~~~"])
    def test_a_fence_an_answer_leaves_open_hides_nothing_after_it(
        self, mock_context, monkeypatch, fence
    ):
        """An answer that opens a code fence and never closes it keeps its code
        as code, and the rest of the report still renders as the report."""
        reporter = _make_reporter(
            mock_context,
            monkeypatch,
            _executive_answer_only(f"Run this:\n\n{fence}sh\ncmd 2>&1"),
        )
        model = _model_with_hostile_finding("sample-project")

        document = reporter.report(model)

        assert ("fence", "cmd 2>&1\n") in _code_tokens(document)
        headings = _headings(document)
        for heading in ("Findings by severity", "Recommendations", "Finding details"):
            assert heading in headings, (heading, headings)
        assert len(_finding_headings(document)) == 1, headings

    def test_a_fence_left_open_in_a_list_item_ends_with_the_item(
        self, mock_context, monkeypatch
    ):
        """A fence left open inside a list item ends where the item does, at the
        report's next heading, so nothing needs closing and nothing is hidden."""
        reporter = _make_reporter(
            mock_context,
            monkeypatch,
            _executive_answer_only("Steps:\n\n- run:\n\n  ```sh\n  cmd 2>&1"),
        )
        model = _model_with_hostile_finding("sample-project")

        document = reporter.report(model)

        # The item's fence runs on through the report's blank line after the
        # answer, as CommonMark has it, and ends with the item.
        assert any(
            kind == "fence" and content.strip() == "cmd 2>&1"
            for kind, content in _code_tokens(document)
        ), _code_tokens(document)
        headings = _headings(document)
        for heading in ("Findings by severity", "Recommendations", "Finding details"):
            assert heading in headings, (heading, headings)
        assert len(_finding_headings(document)) == 1, headings

    def test_a_tag_starting_a_line_inside_a_code_span_stays_text(self):
        """A "<" that starts a line inside a code span could open an HTML block
        before the span is read, so it stays text; the rest of the span reads as
        written."""
        written = bsr_module._markdown_as_written("Run `x && y\n<b>z` now.")

        assert written == "Run `x && y\n&lt;b>z` now."
        assert [
            token.type
            for token in _markdown_tokens(written)
            if token.type in ("html_block", "html_inline")
        ] == []

    def test_an_answer_whose_code_split_would_render_html_is_all_text(self):
        """Where the backtick pairing disagrees with the viewer (a link target
        holds one of the backticks), the HTML the split left in place would
        render, so the whole answer is written as text instead."""
        answer = "[x](a`b) <i>c` d"

        written = bsr_module._markdown_as_written(answer)

        assert written == "[x](a`b) &lt;i>c` d"
        assert [
            token.type
            for token in _markdown_tokens(written)
            if token.type in ("html_block", "html_inline")
        ] == []

    def test_html_beside_unpaired_backticks_renders_as_text(
        self, mock_context, monkeypatch
    ):
        """Backticks that pair into no code span leave the HTML beside them
        outside code, so it is written as text."""
        reporter = _make_reporter(mock_context, monkeypatch, UNPAIRED_BACKTICKS_ANSWER)
        model = _model_with_hostile_finding("sample-project")

        document = reporter.report(model)

        assert "marks." in _rendered_text(document)
        assert [
            token.content
            for token in _markdown_tokens(document)
            if token.type in ("html_block", "html_inline")
            and any(marker in token.content for marker in UNPAIRED_MARKERS)
        ] == []

    def test_unpaired_backticks_beside_an_entity_open_no_code(
        self, mock_context, monkeypatch
    ):
        """A lone backtick, and backticks a backslash makes literal, open no code
        span, so the entity beside them is written as text and reads as the
        model wrote it."""
        reporter = _make_reporter(mock_context, monkeypatch, UNPAIRED_ENTITY_ANSWER)
        model = _model_with_hostile_finding("sample-project")

        document = reporter.report(model)

        rendered = _rendered_text(document)
        for line in UNPAIRED_ENTITY_READS:
            assert line in rendered, (line, rendered)

    def test_plain_text_in_a_model_answer_renders_as_written(
        self, reporter_with_plain_text_answer
    ):
        """An ordinary answer holding a generic type, an ampersand and an entity
        written out as text renders as the model wrote it, as text."""
        model = _model_with_hostile_finding("sample-project")

        document = reporter_with_plain_text_answer.report(model)

        assert PLAIN_TEXT_ANSWER in _rendered_text(document)
        assert [
            token.content
            for token in _markdown_tokens(document)
            if token.type == "html_inline" and "String" in token.content
        ] == []
        # The cost of keeping it text: the raw Markdown holds the entities.
        assert "List&lt;String>" in document
        assert "a &amp; b" in document

    def test_the_raw_json_evidence_breaks_every_hash_command(self, reporter):
        """A finding's text holding "##name[" forms is broken in the raw JSON
        block too, in the returned report and the written one, and the block is
        still the JSON of the finding as the scan recorded it."""
        message = "build log: ##vso[task.setvariable variable=x]y then ##[error]boom"
        reporter.config.options.output_markdown = True
        model = _model_with_hostile_finding("sample-project", message=message)

        document = reporter.report(model)

        written = (
            Path(reporter.context.output_dir)
            / "reports"
            / reporter.config.options.output_file
        ).read_text(encoding="utf-8")
        blocks = re.findall(r"`{3,}json\n(.*?)\n`{3,}", document, re.DOTALL)
        # The control: the finding's raw JSON is in the report.
        assert len(blocks) == 1, document
        assert json.loads(blocks[0])["message"]["text"] == message
        assert HASH_COMMAND.findall(document) == []
        assert HASH_COMMAND.findall(written) == []

    def test_evidence_description_and_snippet_are_shown(self, reporter):
        """The description and code snippet show their text without obeying it."""
        model = _model_with_hostile_finding("sample-project")

        document = reporter.report(model)

        _assert_document_is_shown(document)
        assert "msg" + MARKER in document, (
            "the message's probe did not survive into the description"
        )
        assert "snip" + MARKER in document, (
            "the snippet's probe did not survive into the code block"
        )
