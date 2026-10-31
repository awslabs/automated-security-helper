# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report`` writes the report, and only the report, to stdout.

Why this exists
---------------
``ash report --format sarif > ash.sarif`` is how a CI job re-renders a report
from saved results, so stdout has to carry a file a SARIF consumer can read:

* ASH's log lines go to stderr, never to stdout ahead of the document.
* The report does not go through rich, which would re-indent and highlight JSON
  and keep its escape codes under ``--no-color`` and with stdout redirected, and
  would wrap other formats at 80 columns, so the CSV would parse to the wrong
  number of rows and the JUnit XML would not be well formed.
* With no results file the command fails with a clear error, and creates no
  ``.ash/ash_output`` in the working directory.

When stdout is not an interactive terminal (or
with ``--no-color``) the report on stdout is the reporter's output, not
re-indented, highlighted or wrapped. (It is not byte for byte the file the scan
wrote: rendered again from the saved results, SARIF carries defaulted fields and
CSV, HTML and Markdown carry a new timestamp.) On a terminal, ``--no-color``
included (``docker run -t``), control characters are still shown escaped; the
reporter's exact output needs stdout off a terminal. An unknown ``--format`` is
refused before the results are read, and a missing or unreadable results file is
a clear error with exit 1; a failed command creates nothing.

Known limitations
-----------------
* On an interactive terminal with color on, JSON is still pretty-printed and
  Markdown rendered for reading; that path is checked through the helper, since a
  CliRunner stdout is never a terminal.
"""

import csv
import io
import json
import re
from pathlib import Path
from unittest.mock import patch

import pytest
from defusedxml import ElementTree as ET
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.report import (
    JSON_STDOUT_FORMATS,
    MARKDOWN_STDOUT_FORMATS,
)
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.utils.helpers import importing_this_checkout
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

#: Longer than any console, with rich markup and non-ASCII text: three things rich
#: changed on the way to stdout (wrapping, markup, encoding).
TRICKY = (
    "first line [red]not markup[/red] " + "x" * 300 + " end\n"
    "second line with ünïcode and a [bold]tag[/bold]\n"
)


def _model() -> AshAggregatedResults:
    results = []
    for index in range(3):
        props = PropertyBag(tags=["tool_name::bandit"])
        props.__pydantic_extra__ = {"scanner_name": "bandit", "issue_severity": "LOW"}
        results.append(
            Result(
                ruleId=f"B10{index}",
                level="note",
                message=Message(
                    root=Message1(text="a message, long enough to wrap " * 4)
                ),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            root=PhysicalLocation2(
                                artifactLocation=ArtifactLocation(
                                    uri=f"src/f{index}.py"
                                ),
                                region=Region(startLine=1, endLine=1),
                            )
                        )
                    )
                ],
                properties=props,
            )
        )
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.sarif = SarifReport(
        runs=[Run(tool=Tool(driver=ToolComponent(name="bandit")), results=results)]
    )
    return model


@pytest.fixture
def results_dir(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "ash_aggregated_results.json").write_text(
        _model().model_dump_json(by_alias=True), encoding="utf-8"
    )
    return output


def _report(output_dir: Path, fmt: str, *extra: str):
    return CliRunner().invoke(
        app, ["report", "--format", fmt, "--output-dir", str(output_dir), *extra]
    )


class TestStdoutIsTheReport:
    @pytest.mark.parametrize(
        "fmt, reporter, content",
        [
            # A JSON format's report is read as JSON before it is written (a
            # reporter returns its error text in place of a document it could
            # not produce), so the tricky text rides inside a document there.
            (
                "sarif",
                "SarifReporter",
                json.dumps({"text": TRICKY}, ensure_ascii=False),
            ),
            ("markdown", "MarkdownReporter", TRICKY),
            ("csv", "CsvReporter", TRICKY),
        ],
        ids=["json-route", "markdown-route", "plain-route"],
    )
    @pytest.mark.unit
    def test_the_report_is_written_byte_for_byte(
        self, results_dir, fmt, reporter, content
    ):
        target = (
            "automated_security_helper.plugin_modules.ash_builtin.reporters."
            f"{reporter}.report"
        )
        with patch(target, return_value=content):
            result = _report(results_dir, fmt)

        assert result.exit_code == 0, result.output
        assert result.stdout == content

    @pytest.mark.unit
    def test_the_log_goes_to_stderr(self, results_dir):
        result = _report(results_dir, "sarif", "--log-level", "INFO")

        assert result.exit_code == 0, result.output
        json.loads(result.stdout)
        assert "Found reporter plugin" in result.stderr
        assert "Found reporter plugin" not in result.stdout

    @pytest.mark.unit
    @pytest.mark.parametrize("extra", [[], ["--no-color"]], ids=["default", "no-color"])
    @pytest.mark.parametrize(
        "fmt", ["sarif", "flat-json", "csv", "junitxml", "markdown", "text", "html"]
    )
    def test_no_escape_codes_reach_stdout(self, results_dir, fmt, extra):
        result = _report(results_dir, fmt, *extra)

        assert result.exit_code == 0, result.output
        assert "\x1b" not in result.stdout

    @pytest.mark.unit
    def test_the_csv_has_one_row_per_finding(self, results_dir):
        result = _report(results_dir, "csv")

        rows = list(csv.reader(io.StringIO(result.stdout)))
        assert len(rows) == 1 + 3, rows[:5]

    @pytest.mark.unit
    def test_the_junit_xml_is_well_formed(self, results_dir):
        result = _report(results_dir, "junitxml")

        ET.fromstring(result.stdout)

    @pytest.mark.unit
    def test_stdout_is_the_reporters_output_for_the_saved_results(self, results_dir):
        """What SarifReporter.report returns for the reloaded results, unchanged."""
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
            SarifReporter,
        )

        model = AshAggregatedResults.model_validate_json(
            (results_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
        )
        written = SarifReporter(
            context=PluginContext(source_dir=results_dir, output_dir=results_dir)
        ).report(model)

        assert _report(results_dir, "sarif").stdout == written


class TestPrettyOnlyOnATerminal:
    @pytest.mark.unit
    def test_json_is_indented_on_a_terminal(self):
        from automated_security_helper.cli.report import _write_report

        stream = _Terminal()
        _write_report('{"a": [1, 2]}', "sarif", pretty=True, stream=stream)

        # Highlighted as well when color is on; the text under it is indented JSON.
        printed = re.sub(r"\x1b\[[0-9;]*m", "", stream.getvalue())
        assert printed != '{"a": [1, 2]}'
        assert json.loads(printed) == {"a": [1, 2]}

    @pytest.mark.unit
    @pytest.mark.parametrize("pretty", [True, False], ids=["color", "no-color"])
    @pytest.mark.parametrize(
        "fmt, content",
        [("sarif", '{"a": [1, 2]}'), ("markdown", TRICKY)],
        ids=["sarif", "markdown"],
    )
    def test_nothing_is_changed_off_a_terminal(self, fmt, content, pretty):
        """Color asks for pretty output; the stream it goes to decides.

        Whether to pretty-print was decided from sys.stdout and whether to escape
        from the stream written to, so a caller passing a stream that is not a
        terminal with color on got re-indented JSON there.
        """
        from automated_security_helper.cli.report import _write_report

        stream = io.StringIO()
        _write_report(content, fmt, pretty=pretty, stream=stream)

        assert stream.getvalue() == content


#: OSC 52 (write the clipboard), an OSC 8 hyperlink, BEL, backspaces, a bare
#: carriage return with CSI 2K (erase the line), a C1 CSI and DEL: what a scanned
#: repository can put in a finding's message or its project name.
HOSTILE = (
    "a\x1b]52;c;cGF5bG9hZA==\x07b \x1b]8;;https://example.invalid\x07link"
    "\x1b]8;;\x07 c\x08\x08 d\r\x1b[2Ke \x9b31m f\x7f g\tend\r\n"
)
UNSAFE = ["\x1b]", "\x07", "\x08", "\x1b[2K", "\x9b", "\x7f"]


class _Terminal(io.StringIO):
    def isatty(self):
        return True


class TestNothingFromTheReportControlsTheTerminal:
    """On a terminal, control characters in a report are shown, not obeyed.

    On a terminal, the control characters a finding's message or a project_name
    holds (OSC 52, OSC 8, BEL, cursor movement) are shown as escapes, so none of
    them acts on the terminal.
    """

    @staticmethod
    def _content(fmt):
        if fmt == "sarif":
            return json.dumps({"message": HOSTILE}, ensure_ascii=False)
        return HOSTILE

    @pytest.mark.unit
    @pytest.mark.parametrize("pretty", [True, False], ids=["pretty", "plain"])
    @pytest.mark.parametrize("fmt", ["csv", "text", "markdown", "sarif"])
    def test_no_control_sequence_reaches_a_terminal(self, fmt, pretty):
        from automated_security_helper.cli.report import _write_report

        stream = _Terminal()
        _write_report(self._content(fmt), fmt, pretty=pretty, stream=stream)

        written = stream.getvalue()
        assert [u for u in UNSAFE if u in written] == []
        assert "\r\x1b" not in written
        # A carriage return is kept only before a newline: alone it returns to
        # the start of the line, and what follows overwrites it.
        assert re.search(r"\r(?!\n)", written) is None
        if fmt == "sarif":
            # Still JSON, and the same document; the highlighting's SGR aside.
            shown = re.sub(r"\x1b\[[0-9;]*m", "", written)
            assert json.loads(shown) == json.loads(self._content(fmt))
        # Shown instead, and the ordinary whitespace is kept.
        assert "52;c;cGF5bG9hZA==" in written
        # (JSON writes a tab as \t, and Markdown rendering may reflow it.)
        assert "\t" in written or fmt in ("markdown", "sarif")
        if fmt in ("csv", "text"):
            # Every line break too: escaped, the report would be one line.
            assert written.count("\n") == HOSTILE.count("\n")
            # Text formats show a control as \xNN, not in JSON's \u00NN form.
            assert "\\x9b31m" in written

    @pytest.mark.unit
    @pytest.mark.parametrize("fmt", sorted(MARKDOWN_STDOUT_FORMATS))
    def test_rendered_markdown_plants_no_hyperlink(self, fmt, monkeypatch):
        """A link in a finding's text is shown with its target, not made live.

        A link or autolink in rendered Markdown is shown as text with its target
        and never becomes an OSC 8 hyperlink, so the scanned repository chooses
        neither what a reader clicks nor where it goes. This is the default
        ``ash report``.
        """
        from automated_security_helper.cli.report import _write_report

        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TTY_COMPATIBLE", raising=False)
        content = (
            "Fix it as [the docs](https://example.invalid/planted) say, "
            "or see <https://example.invalid/auto>.\n"
        )
        stream = _Terminal()
        _write_report(content, fmt, pretty=True, stream=stream)

        written = stream.getvalue()
        # Rendered with styles, so a link would have been written as one.
        assert "\x1b[" in written
        assert "\x1b]8;" not in written
        # What the reader sees, the styling taken out: each link's text with its
        # target after it, so where a link goes stays visible.
        visible = " ".join(_SGR.sub("", written).split())
        assert "the docs (https://example.invalid/planted)" in visible
        assert "https://example.invalid/auto" in visible

    @pytest.mark.unit
    @pytest.mark.parametrize("fmt", sorted(MARKDOWN_STDOUT_FORMATS))
    def test_markdown_holding_an_escape_is_shown_unrendered(self, fmt, monkeypatch):
        """An ESC and the text of its escape never print alike, by default either.

        rich's Markdown shows "\\\\" as "\\", so the doubled backslash that keeps
        the text "\\x1b" apart from an escaped ESC was undone when the report was
        rendered, and the two printed the same in the default ``ash report``. A
        report that holds a control character or an escape's text is printed as
        the escaped text instead; one that holds neither is still rendered.
        """
        from automated_security_helper.cli.report import _write_report

        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TTY_COMPATIBLE", raising=False)
        shown = []
        for text in ("\x1b", "\\x1b", "plain"):
            stream = _Terminal()
            _write_report(
                f"# Findings\n\nThe message is {text}.\n",
                fmt,
                pretty=True,
                stream=stream,
            )
            shown.append(stream.getvalue())

        escape, lookalike, plain = shown
        assert escape == "# Findings\n\nThe message is \\x1b.\n"
        assert lookalike == "# Findings\n\nThe message is \\\\x1b.\n"
        # Rendered: the heading's markup is gone and rich styled it.
        assert "#" not in _SGR.sub("", plain) and "\x1b[" in plain

    @pytest.mark.unit
    @pytest.mark.parametrize("fmt", sorted(JSON_STDOUT_FORMATS))
    def test_plain_json_on_a_terminal_is_still_the_same_document(self, fmt):
        """``--no-color`` on a terminal (``docker run -t``) still gives valid JSON.

        The same document, not the same bytes: controls are escaped there. A
        serializer escapes C0 controls in a string but leaves DEL and C1 as they
        are, and they were written as ``\\xNN``, which is not a JSON escape: the
        SARIF on the terminal stopped parsing ("Invalid \\escape").
        """
        from automated_security_helper.cli.report import _write_report

        content = self._content("sarif")
        stream = _Terminal()
        _write_report(content, fmt, pretty=False, stream=stream)

        written = stream.getvalue()
        assert [u for u in UNSAFE if u in written] == []
        assert json.loads(written) == json.loads(content)

    #: A SARIF-shaped document: hostile text in a message, in a list and as a
    #: key, and keys that differ only by a control character or the text of its
    #: escape.
    HOSTILE_DOC = {
        "runs": [
            {
                "results": [{"ruleId": "R1", "message": {"text": HOSTILE}}],
                "tags": ["plain", HOSTILE],
                HOSTILE: "a hostile key",
                "k\x1b": "ESC",
                "k\\x1b": "the text of an escape",
                "k\x9b": "C1",
                "k\\u009b": "the text of a JSON escape",
                "k\x7f": "DEL",
            }
        ]
    }

    @pytest.mark.unit
    @pytest.mark.parametrize("pretty", [True, False], ids=["pretty", "plain"])
    @pytest.mark.parametrize("fmt", sorted(JSON_STDOUT_FORMATS))
    def test_json_on_a_terminal_is_the_same_document(self, fmt, pretty):
        """Pretty or plain, a JSON report on a terminal parses to the report.

        Pretty JSON was rebuilt from the parsed document with every string
        escaped, so it showed strings the report did not hold, and two keys
        could come out as one.
        """
        from automated_security_helper.cli.report import _write_report

        content = json.dumps(self.HOSTILE_DOC, ensure_ascii=False, indent=2)
        stream = _Terminal()
        _write_report(content, fmt, pretty=pretty, stream=stream)

        written = stream.getvalue()
        # The highlighting's SGR sequences are the only escape sequences.
        text = re.sub(r"\x1b\[[0-9;]*m", "", written)
        assert "\x1b" not in text
        assert [u for u in UNSAFE if u in written] == []
        assert re.search(r"\r(?!\n)", written) is None
        assert json.loads(text) == json.loads(content)
        if not pretty:
            assert written.count("\n") == content.count("\n")

    #: Unicode's bidirectional controls (embeddings, overrides and isolates):
    #: text holding them displays in an order other than the one it holds.
    BIDI = "".join(chr(c) for c in [*range(0x202A, 0x202F), *range(0x2066, 0x206A)])

    @pytest.mark.unit
    @pytest.mark.parametrize("pretty", [True, False], ids=["pretty", "plain"])
    @pytest.mark.parametrize("fmt", ["csv", "text", "markdown", "sarif"])
    def test_bidi_controls_are_shown_on_a_terminal(self, fmt, pretty):
        """A finding's text cannot reorder what the terminal shows."""
        from automated_security_helper.cli.report import _write_report

        content = f"access = 'user{self.BIDI}' # admin\n"
        if fmt == "sarif":
            content = json.dumps({"message": content}, ensure_ascii=False)
        stream = _Terminal()
        _write_report(content, fmt, pretty=pretty, stream=stream)

        written = stream.getvalue()
        assert [hex(ord(c)) for c in self.BIDI if c in written] == []
        assert "\\u202e" in written
        if fmt == "sarif":
            shown = re.sub(r"\x1b\[[0-9;]*m", "", written)
            assert json.loads(shown) == json.loads(content)

    @pytest.mark.unit
    @pytest.mark.parametrize("fmt", ["text", "sarif"])
    def test_bidi_controls_off_a_terminal_are_left_alone(self, fmt):
        from automated_security_helper.cli.report import _write_report

        content = f"user{self.BIDI}\n"
        if fmt == "sarif":
            content = json.dumps({"message": content}, ensure_ascii=False)
        stream = io.StringIO()
        _write_report(content, fmt, pretty=True, stream=stream)

        assert stream.getvalue() == content

    #: Each reads differently once shown: an ESC, the text of its escape, a
    #: backslash before an ESC, two backslashes before the text, upper-case hex,
    #: and the same three for a right-to-left override (written with chr, so
    #: this file holds no bidirectional control itself).
    RLO = chr(0x202E)
    LOOKALIKES = [
        "\x1b",
        "\\x1b",
        "\\\x1b",
        "\\\\x1b",
        "\\x1B",
        "x1b",
        RLO,
        "\\" + "u202e",
        "\\" + RLO,
        # The JSON form of an ESC's escape, as text in a non-JSON report.
        "\\" + "u001b",
    ]

    @pytest.mark.unit
    @pytest.mark.parametrize("fmt", ["csv", "text"])
    def test_an_escape_never_reads_as_text_the_report_holds(self, fmt):
        """Text that looks like an escape is shown so that it does not read as one.

        An ESC is shown so that it never reads the same as the four characters
        ``\\x1b`` in a finding's message, and the reverse, so a repository can
        neither show a reader an escape that is not there nor hide one that is.
        """
        from automated_security_helper.cli.report import _write_report

        shown = []
        for text in self.LOOKALIKES:
            stream = _Terminal()
            _write_report(f"<{text}>\n", fmt, pretty=False, stream=stream)
            shown.append(stream.getvalue())

        assert len(set(shown)) == len(self.LOOKALIKES), shown
        assert "\x1b" not in "".join(shown)
        assert self.RLO not in "".join(shown)

    @pytest.mark.unit
    def test_pretty_json_tells_an_escape_from_the_same_text(self):
        from automated_security_helper.cli.report import _write_report

        stream = _Terminal()
        content = json.dumps({str(i): t for i, t in enumerate(self.LOOKALIKES)})
        _write_report(content, "sarif", pretty=True, stream=stream)

        printed = json.loads(re.sub(r"\x1b\[[0-9;]*m", "", stream.getvalue()))
        assert len(set(printed.values())) == len(self.LOOKALIKES), printed

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "path",
        [
            "C:\\Users\\xavier\\src\\\\server\\x7y.py\n",
            # \x64 and \x41 are not escapes the terminal output can hold.
            "C:\\build\\x64\\Release\\x41.dll\n",
            "C:\\src\\u2070\\uabcd.txt\n",
        ],
        ids=["plain", "x-hex", "u-hex"],
    )
    def test_backslashes_that_look_like_no_escape_are_left_alone(self, path):
        """A Windows path is shown as it is.

        A segment that started with x and two hex digits had its backslash
        doubled, though no such escape could come from the report:
        ``C:\\build\\x64\\Release`` showed as ``C:\\build\\\\x64\\Release``.
        """
        from automated_security_helper.cli.report import _write_report

        stream = _Terminal()
        _write_report(path, "text", pretty=False, stream=stream)

        assert stream.getvalue() == path

    @pytest.mark.integration
    def test_a_long_run_of_backslashes_is_shown_in_linear_time(self):
        """200,000 backslashes in a finding are shown in seconds.

        The lookalike pattern took the rest of a backslash run at every position
        in it and backtracked, so the time grew with the square of the run: one
        finding holding 40,000 made ``ash report`` on a terminal take 164 s. Run
        in a child process so that the quadratic version fails on the timeout
        rather than holding the worker for minutes.
        """
        import subprocess  # nosec B404 -- this interpreter, a fixed program
        import sys

        program = (
            "from automated_security_helper.cli.report import _shown_not_obeyed\n"
            "text = chr(92) * 200_000 + 'y'\n"
            "assert _shown_not_obeyed(text) == text\n"
        )
        subprocess.run(  # nosec B603 -- this interpreter, a fixed program
            [sys.executable, "-c", importing_this_checkout(program)],
            check=True,
            timeout=60,
        )

    @pytest.mark.unit
    @pytest.mark.parametrize("pretty", [True, False], ids=["pretty", "plain"])
    @pytest.mark.parametrize("fmt", ["csv", "text", "sarif"])
    def test_a_bidirectional_control_is_shown_on_a_terminal(self, fmt, pretty):
        """A right-to-left override reorders what the reader sees after it (a
        finding's path or message can be made to read as something else), so it
        is shown as an escape, as the console log shows it."""
        from automated_security_helper.cli.report import _write_report

        text = "file\N{RIGHT-TO-LEFT OVERRIDE}txt.exe and \N{LEFT-TO-RIGHT MARK}x"
        content = (
            json.dumps({"message": text}, ensure_ascii=False)
            if fmt == "sarif"
            else text
        )
        stream = _Terminal()
        _write_report(content, fmt, pretty=pretty, stream=stream)

        written = stream.getvalue()
        assert "\N{RIGHT-TO-LEFT OVERRIDE}" not in written, repr(written)
        assert "\N{LEFT-TO-RIGHT MARK}" not in written, repr(written)
        assert "\\u202e" in written and "\\u200e" in written, repr(written)

    @pytest.mark.unit
    @pytest.mark.parametrize("pretty", [True, False], ids=["pretty", "plain"])
    @pytest.mark.parametrize("fmt", ["csv", "text", "sarif"])
    def test_a_separator_or_a_format_character_is_shown_on_a_terminal(
        self, fmt, pretty
    ):
        """The console's set holds U+200B and the line and paragraph
        separators, which end a line in some terminals and viewers. A tag
        character, outside the BMP, is shown too; in JSON as the surrogate pair
        JSON reads, so the document still parses to the same string."""
        from automated_security_helper.cli.report import _write_report

        text = "a\N{ZERO WIDTH SPACE}b\N{LINE SEPARATOR}c\N{PARAGRAPH SEPARATOR}d\U000e0041e"
        content = (
            json.dumps({"message": text}, ensure_ascii=False)
            if fmt == "sarif"
            else text
        )
        stream = _Terminal()
        _write_report(content, fmt, pretty=pretty, stream=stream)

        written = stream.getvalue()
        for character in ("\N{ZERO WIDTH SPACE}", "\N{LINE SEPARATOR}", "\U000e0041"):
            assert character not in written, repr(written)
        assert "\N{PARAGRAPH SEPARATOR}" not in written, repr(written)
        assert "\\u200bb\\u2028c\\u2029d" in written, repr(written)
        if fmt == "sarif":
            # Pretty JSON is colored; the document is what is left without them.
            document = re.sub(r"\x1b\[[0-9;]*m", "", written)
            assert json.loads(document)["message"] == text, repr(written)
        else:
            assert "\\U000e0041" in written, repr(written)

    @pytest.mark.unit
    def test_the_report_shows_the_controls_the_console_shows(self):
        """One set: ash report's terminal escape is built on utils/terminal_text.py's
        set, so a character added there reaches the report too. report.py keeps
        no copy of its own, so the bidirectional and format controls in the
        shared set are escaped in a report shown on a terminal."""
        from automated_security_helper.cli import report
        from automated_security_helper.utils import terminal_text

        sample = list(range(0x3000)) + [0xE000, 0xFDD0, 0xFEFF, 0xFFFE, 0xE0041]
        changed = [
            code for code in sample if report._shown_not_obeyed(chr(code)) != chr(code)
        ]
        # Tab and newline lay a report out; alone, a carriage return is shown.
        controls = [
            code
            for code in sample
            if terminal_text.is_shown_as_escape(chr(code)) and chr(code) not in "\t\n"
        ]
        assert changed == controls
        # The controls change, and a backslash run that reads as one of their
        # escapes is doubled, so "\x1b" a finding wrote stays text and is never
        # taken for an escaped ESC. Nothing else: no command broken, CRLF and tab
        # kept, the other backslash left alone.
        kept = "C:\\x1b\\out ::error::x ##[add-mask]y\r\n\tz"
        assert report._shown_not_obeyed(kept) == (
            "C:\\\\x1b\\out ::error::x ##[add-mask]y\r\n\tz"
        )

    @pytest.mark.unit
    @pytest.mark.parametrize("fmt", ["csv", "markdown", "sarif"])
    def test_off_a_terminal_the_bytes_are_unchanged(self, fmt):
        from automated_security_helper.cli.report import _write_report

        stream = io.StringIO()
        _write_report(self._content(fmt), fmt, pretty=False, stream=stream)

        assert stream.getvalue() == self._content(fmt)


#: SGR sequences: rich's own styling, the only escape sequences stderr may hold.
_SGR = re.compile(r"\x1b\[[0-9;]*m")


class TestErrorsShowWhatTheyQuoteAsText:
    """An error message shows the values it quotes; it does not run them.

    _print_error prints exception text, paths and the --format value as text: no
    markup is read, no hyperlink is made, and on a terminal their control
    characters are shown as escapes.
    """

    @pytest.fixture
    def terminal_stderr(self, monkeypatch, tmp_path):
        """report.py's stderr, as an interactive terminal.

        Its consoles are pointed at the terminal rather than sys.stderr being
        replaced: pytest's live logging puts sys.stderr back whenever a record
        passes through it, part way through the command.
        """
        from automated_security_helper.cli import report

        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("TTY_COMPATIBLE", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.chdir(tmp_path)
        terminal = _Terminal()
        # report.py builds each console through utils/console.py's factory.
        real_console = report.ash_console

        def console(*args, **kwargs):
            if kwargs.pop("stderr", False):
                kwargs["file"] = terminal
            return real_console(*args, **kwargs)

        monkeypatch.setattr(report, "ash_console", console)
        return terminal

    @staticmethod
    def _run(**kwargs):
        import typer

        from automated_security_helper.cli.report import report_command

        with pytest.raises(typer.Exit) as exit_info:
            report_command(**kwargs)
        return exit_info.value.exit_code

    @pytest.mark.unit
    def test_markup_in_the_format_is_shown(self, terminal_stderr, tmp_path):
        planted = "x[/y] [link=https://example.invalid/planted]pdf[/link]"

        code = self._run(report_format=planted, output_dir=str(tmp_path))

        written = terminal_stderr.getvalue()
        # An unknown --format; its code is not pinned here (the usage-error
        # code once the cli cluster's exit-code change is stacked).
        assert code != 0
        assert "\x1b]8;" not in written
        assert planted in _SGR.sub("", written)

    @pytest.mark.unit
    def test_controls_in_the_format_are_shown(self, terminal_stderr, tmp_path):
        planted = "pdf\x1b]52;c;cGF5bG9hZA==\x07\x9b31m" + chr(0x202E)

        code = self._run(report_format=planted, output_dir=str(tmp_path))

        shown = _SGR.sub("", terminal_stderr.getvalue())
        assert code != 0
        assert [c for c in ("\x1b", "\x07", "\x9b", chr(0x202E)) if c in shown] == []
        assert "52;c;cGF5bG9hZA==" in shown

    @pytest.mark.unit
    def test_an_exception_and_its_traceback_are_shown(
        self, terminal_stderr, results_dir
    ):
        planted = (
            "boom [/x] \x1b]52;c;cGF5bG9hZA==\x07 [link=https://example.invalid/t]t"
        )
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.reporters."
            "TextReporter.report",
            side_effect=RuntimeError(planted),
        ):
            code = self._run(
                report_format="text", output_dir=str(results_dir), debug=True
            )

        written = terminal_stderr.getvalue()
        shown = _SGR.sub("", written)
        assert code == 1
        assert "\x1b]8;" not in written
        assert [c for c in ("\x1b", "\x07") if c in shown] == []
        assert "Error generating report: boom [/x]" in shown
        assert "Traceback" in shown and "RuntimeError" in shown


class TestMissingResults:
    @pytest.mark.parametrize("name", ["nowhere", "d" * 90], ids=["short", "long"])
    @pytest.mark.unit
    def test_a_missing_results_file_is_a_clear_error(self, tmp_path, monkeypatch, name):
        """The message names every path whole, however long.

        Errors went through rich's print, folded at 80 columns off a terminal,
        so a long path came out split across lines.
        """
        monkeypatch.chdir(tmp_path)

        result = _report(tmp_path / name, "sarif")

        assert result.exit_code == 1
        assert "NoneType" not in result.output
        assert "No scan results found" in result.stderr
        assert "ash_aggregated_results.json" in result.stderr
        output = (tmp_path / name).as_posix()
        for searched in (
            f"{output}/.ash/ash_output/ash_aggregated_results.json",
            f"{output}/ash_output/ash_aggregated_results.json",
            f"{output}/ash_aggregated_results.json",
        ):
            assert searched in result.stderr, result.stderr
        assert result.stdout == ""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "planted",
        [None, (".ash", "ash_output"), ("ash_output",)],
        ids=["none", "doubled-dot-ash", "doubled-ash-output"],
    )
    def test_a_defaulted_output_dir_searches_and_names_its_own_file(
        self, tmp_path, monkeypatch, planted
    ):
        """With no --output-dir and no ASH_OUTPUT_DIR the directory is
        .ash/ash_output, where a scan writes, and only its own results file is
        read: one at .ash/ash_output/.ash/ash_output/ or .ash/ash_output/ash_output/
        is not, and the message names the one path."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_OUTPUT_DIR", raising=False)
        default = tmp_path / ".ash" / "ash_output"
        if planted is not None:
            elsewhere = default.joinpath(*planted)
            elsewhere.mkdir(parents=True)
            (elsewhere / "ash_aggregated_results.json").write_text(
                _model().model_dump_json(by_alias=True), encoding="utf-8"
            )

        result = CliRunner().invoke(app, ["report", "--format", "sarif"])

        assert result.exit_code == 1, result.output
        expected = (default / "ash_aggregated_results.json").as_posix()
        assert f"No scan results found: {expected} does not exist." in result.stderr, (
            result.stderr
        )
        assert "ash_output/.ash/ash_output" not in result.stderr, result.stderr
        assert "ash_output/ash_output" not in result.stderr, result.stderr
        assert result.stdout == ""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "where",
        [(".ash", "ash_output"), ("ash_output",), ()],
        ids=["dot-ash", "ash-output", "itself"],
    )
    def test_control_a_given_output_dir_reads_each_of_its_three(self, tmp_path, where):
        output = tmp_path / "out"
        found = output.joinpath(*where)
        found.mkdir(parents=True)
        (found / "ash_aggregated_results.json").write_text(
            _model().model_dump_json(by_alias=True), encoding="utf-8"
        )

        result = _report(output, "sarif")

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["version"] == "2.1.0"

    @pytest.mark.unit
    def test_a_failed_command_creates_nothing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("ASH_OUTPUT_DIR", raising=False)

        _report(tmp_path / "nowhere", "sarif")
        CliRunner().invoke(app, ["report", "--format", "sarif"])

        assert list(tmp_path.iterdir()) == []

    @pytest.mark.unit
    def test_an_unreadable_results_file_is_a_clear_error(self, tmp_path):
        output = tmp_path / "out"
        output.mkdir()
        (output / "ash_aggregated_results.json").write_text(
            "{not json", encoding="utf-8"
        )

        result = _report(output, "sarif")

        assert result.exit_code == 1
        assert "Could not read the scan results" in result.stderr
        assert result.stdout == ""
        assert sorted(p.name for p in output.iterdir()) == [
            "ash_aggregated_results.json"
        ]

    @pytest.mark.unit
    def test_a_results_file_it_cannot_open_is_named_once(self, tmp_path, monkeypatch):
        """The refusal names the file; an OSError's own text names it again,
        quoted, with a Windows path's backslashes doubled. Only the error's
        reason is shown."""
        output = tmp_path / "out"
        output.mkdir()
        (output / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")

        def denied(path, *args, **kwargs):
            raise PermissionError(13, "Permission denied", r"C:\scan\elsewhere.json")

        monkeypatch.setattr(
            "automated_security_helper.cli.report.open", denied, raising=False
        )
        result = _report(output, "sarif")

        refusal = " ".join(result.stderr.split())
        assert result.exit_code == 1, result.output
        assert "Could not read the scan results in" in refusal, refusal
        assert refusal.endswith(": Permission denied"), refusal
        assert "elsewhere" not in refusal, refusal

    @pytest.mark.unit
    def test_an_unknown_format_is_an_error_on_stderr(self, results_dir):
        result = _report(results_dir, "no-such-reporter")

        # A --format no reporter answers to is a usage error (exit 5).
        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "not found" in result.stderr
        assert result.stdout == ""

    @pytest.mark.unit
    @pytest.mark.parametrize("results", ["missing", "unreadable"])
    def test_an_unknown_format_is_refused_before_the_results_are_read(
        self, tmp_path, monkeypatch, results
    ):
        """Configuration first, then the reporter, then the results."""
        monkeypatch.chdir(tmp_path)
        output = tmp_path / "out"
        output.mkdir()
        if results == "unreadable":
            (output / "ash_aggregated_results.json").write_text(
                "{not json", encoding="utf-8"
            )

        with patch(
            "automated_security_helper.cli.report.AshAggregatedResults.model_validate_json",
            side_effect=AssertionError("the results were read"),
        ):
            result = _report(output, "no-such-reporter")

        assert result.exit_code == ASH_EXIT_USAGE_ERROR
        assert "not found" in result.stderr
        assert "No scan results found" not in result.stderr
        assert "Could not read the scan results" not in result.stderr
        assert "the results were read" not in result.output
