# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The human reports show the results file's metadata, not obey it.

A results file carries its metadata as free text: the project name and the tool
version are plain strings, and the metadata model allows extra fields, which a
report's metadata section prints as they come. ``ash report`` with no
``--output-dir`` renders a results file under ``.ash/ash_output`` of the
directory it runs in, and a repository can commit that file, so each of those
values can be the repository's text. The text, Markdown and HTML reports print
them in their headers (the HTML report's title is the project, and its
report-context line under the title holds the version) and their scan-metadata
sections. Each place shows the value on one line, as ``shown_on_one_line`` writes
it: a control character is a visible escape, and a CI command form is broken.

One cell per place, one cell per report and field for the whole document, and
one that renders a committed results file through ``ash report`` to a pipe.
"""

import html
import os
import re
import sys
import threading

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)

#: The marker each probe value ends with, after its line feed.
MARKER = "probe-mark"

#: The right-to-left override (a format character), named by code point.
RLO = chr(0x202E)
#: ESC, BEL, a lone carriage return, NEL (a C1 control) and the right-to-left
#: override: each is acted on, not shown, when written raw.
CONTROLS = ("\x1b", "\x07", "\r", "\x85", RLO)

#: The metadata fields a report prints, with the tag each probe starts with.
#: ``report_id`` is validated against a pattern on load, so the hostile value
#: reaches a report through the model's extra fields instead, which the HTML
#: metadata section prints like any field; ``extra`` pins that path.
TAGS = {
    "project_name": "PROJECT",
    "tool_version": "VERSION",
    "extra": "EXTRA",
}


def _probe(tag):
    """Metadata text with each control, a line feed and a CI command form."""
    return f"{tag}-\x1b[31m-\x07-\r-\x85-{RLO}-\n::add-mask::{MARKER}"


def _model(field):
    model = AshAggregatedResults(ash_config=get_default_config())
    if field == "extra":
        # An extra metadata field, as a loaded results file can carry one:
        # the metadata model allows extras.
        model.metadata.scanner_note = _probe(TAGS[field])
    else:
        setattr(model.metadata, field, _probe(TAGS[field]))
    model._flat_cache = None
    return model


REPORTERS = {
    "text": TextReporter,
    "markdown": MarkdownReporter,
    "html": HtmlReporter,
}


def _no_raw_controls(text):
    found = [control for control in CONTROLS if control in text]
    assert found == [], (found, repr(text))


def _lines(document):
    """Lines split on line feeds only, so a raw CR or NEL stays inside its line."""
    return document.split("\n")


def _line_at(document, prefix):
    """The first line that starts (after spaces) with *prefix*, and the next."""
    lines = _lines(document)
    for index, line in enumerate(lines):
        if line.lstrip(" ").startswith(prefix):
            return line, lines[index + 1] if index + 1 < len(lines) else ""
    raise AssertionError(f"no line starts with {prefix!r}:\n{document}")


def _element_texts(document, pattern):
    """The texts *pattern* captures, HTML entities decoded; at least one."""
    found = re.findall(pattern, document, re.DOTALL)
    assert found, pattern
    return [html.unescape(text) for text in found]


# (report, field, how the place is found). A text or Markdown place is found by
# the prefix of its line; an HTML place by a pattern capturing its text. Every
# place holds the whole value on one line.
SITES = [
    # Text: the metadata section's Project and ASH version lines.
    ("text", "project_name", "Project: PROJECT-"),
    ("text", "tool_version", "ASH version: VERSION-"),
    # Markdown: the header line, and the scan-metadata Project and version lines.
    ("markdown", "project_name", "Project: PROJECT-"),
    ("markdown", "project_name", "- Project: PROJECT-"),
    ("markdown", "tool_version", "- ASH version: VERSION-"),
    # HTML: the project in the title, the version on the report-context line
    # under it, and the metadata section's rows (the dumped field, and an extra
    # field).
    # The capture stops at the line's end, so an unguarded value's raw line
    # feed cuts it before the marker and the cell fails on the marker.
    ("html", "project_name", r"<strong>project_name:</strong> (PROJECT-[^\n<]*)"),
    ("html", "tool_version", r"<strong>tool_version:</strong> (VERSION-[^\n<]*)"),
    ("html", "extra", r"<strong>scanner_note:</strong> (EXTRA-[^\n<]*)"),
    # HTML: the page header's title and its version line.
    ("html", "project_name", r'<h1 id="report-title">(PROJECT-[^\n<]*)'),
    ("html", "tool_version", r"</span> ASH (VERSION-[^\n<]*)"),
]


def _site_id(site):
    report, field, place = site
    return f"{report}-{field}-{place[:24]}"


@pytest.mark.parametrize("site", SITES, ids=[_site_id(site) for site in SITES])
def test_each_place_shows_the_metadata(site, test_plugin_context):
    report, field, place = site
    document = REPORTERS[report](context=test_plugin_context).report(_model(field))
    tag = TAGS[field]

    if report == "html":
        for text in _element_texts(document, place):
            assert text.startswith(tag), repr(text)
            _no_raw_controls(text)
            # Shown, not dropped: the escapes are written out.
            assert "x1b" in text and "u202e" in text, repr(text)
            assert MARKER in text and "\n" not in text, repr(text)
        return

    line, after = _line_at(document, place)
    assert tag in line, repr(line)
    _no_raw_controls(line)
    assert "x1b" in line and "u202e" in line, repr(line)
    assert MARKER in line, repr(line)
    # No line the value spills onto starts a CI command.
    assert not after.lstrip().startswith("::"), repr(after)


@pytest.mark.parametrize("field", sorted(TAGS))
@pytest.mark.parametrize("report", sorted(REPORTERS))
def test_no_place_in_the_report_obeys_the_metadata(report, field, test_plugin_context):
    """The whole document, so a place the list above does not name is caught:
    the HTML title and report-context line among them."""
    if field == "extra" and report != "html":
        pytest.skip("only the HTML report prints extra metadata fields")
    document = REPORTERS[report](context=test_plugin_context).report(_model(field))

    # The control: the value is printed.
    assert TAGS[field] in document, document[:1500]
    _no_raw_controls(document)
    assert [
        line
        for line in _lines(document)
        if line.lstrip().startswith("::") and MARKER in line
    ] == []


def test_an_extra_field_s_own_name_is_shown(test_plugin_context):
    """A loaded results file chooses its extra fields' NAMES too: a hostile
    name is shown in the HTML metadata section, never written raw."""
    from automated_security_helper.models.asharp_model import ReportMetadata

    hostile_key = _probe("KEY")
    model = AshAggregatedResults(ash_config=get_default_config())
    model.metadata = ReportMetadata.model_validate(
        {**model.metadata.model_dump(by_alias=True), hostile_key: "noted"}
    )
    model._flat_cache = None

    document = HtmlReporter(context=test_plugin_context).report(model)

    texts = _element_texts(document, r"<strong>(KEY-[^\n<]*):</strong>")
    for text in texts:
        _no_raw_controls(text)
        assert "x1b" in text and MARKER in text, repr(text)
    _no_raw_controls(document)


def _through_a_pipe(args, monkeypatch):
    from automated_security_helper.cli.main import app

    read_end, write_end = os.pipe()
    chunks: list = []
    with open(read_end, "rb") as reader:
        drain = threading.Thread(target=lambda: chunks.append(reader.read()))
        drain.start()
        with open(write_end, "w", encoding="utf-8") as stdout:
            with monkeypatch.context() as patched:
                patched.setattr(sys, "stdout", stdout)
                exit_code = app(args, standalone_mode=False)
        drain.join(timeout=60)
    assert exit_code in (None, 0)
    return b"".join(chunks).decode("utf-8")


@pytest.mark.parametrize("fmt", ["text", "markdown", "html"])
def test_a_committed_results_file_reports_its_metadata_shown(
    fmt, tmp_path, monkeypatch
):
    """The hostile project name and version pass the model's validation, so a
    committed results file can carry them; ``ash report`` shows them."""
    model = AshAggregatedResults(ash_config=get_default_config())
    model.metadata.project_name = _probe("PROJECT")
    model.metadata.tool_version = _probe("VERSION")
    output = tmp_path / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    printed = _through_a_pipe(["report", "--format", fmt], monkeypatch)

    # The control: the committed file is the one rendered.
    assert "PROJECT-" in printed and "VERSION-" in printed, printed[:800]
    _no_raw_controls(printed)
    assert [
        line
        for line in _lines(printed)
        if line.lstrip().startswith("::") and MARKER in line
    ] == []
