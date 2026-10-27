# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The human reports show a finding's scanner text, not obey it.

A finding's rule ID (which is also its title), its message, its code snippet,
its file path, its package name and version, and its suppression reason come
from the tools a scan ran and from the scanned repository. The text, Markdown
and HTML reports print them in their findings sections, tables and hotspot
lists. Each is shown, not obeyed: a control character is written as a visible
escape, and a CI command form at a line start is broken. A one-line value (a
rule ID, a path, a package) stays on its line, as ``shown_on_one_line`` writes
it; a message, a snippet and a suppression reason keep their lines, as
``shown_not_obeyed`` writes them.

One cell per place a report prints the value, so dropping the one guard there
turns its own cell red, and one cell per report checks the whole document.
"""

import html
import re

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
    MarkdownReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
    TextReporterConfig,
    TextReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import Result

#: The marker each probe text ends with, after its line feed.
MARKER = "probe-mark"

#: The tag each field's probe text starts with.
TAGS = {
    "rule_id": "RULEID",
    "message": "MSG",
    "snippet": "SNIP",
    "file_path": "PATH",
    "package_name": "PKG",
    "package_version": "VER",
    "suppression": "SUPP",
    "workspace_project": "PROJECT",
    "cve_id": "CVE",
    "cwe_id": "CWE",
}

#: ESC, BEL, a lone carriage return and NEL (a C1 control): each is acted on.
CONTROLS = ("\x1b", "\x07", "\r", "\x85")


def _probe(tag):
    """Scanner text with each control, a line feed and a CI command form."""
    return f"{tag}-\x1b[31m-\x07-\r-\x85-\n::warning::{MARKER}"


def _model(field):
    """One finding whose *field* is the probe text, and nothing else hostile.

    A CVE and a CWE are carried by a scanner's own report entry, so for those a
    second finding is added from one, with the probe text in that field.
    """
    model = AshAggregatedResults(ash_config=get_default_config())
    probe = _probe(TAGS[field])
    properties = {
        "scanner_name": "bandit",
        "package_name": probe if field == "package_name" else "left-pad",
        "package_version": probe if field == "package_version" else "1.0.0",
    }
    if field == "workspace_project":
        properties["workspace_project"] = probe
    result = {
        "ruleId": probe if field == "rule_id" else "R1",
        "level": "error",
        "message": {"text": probe if field == "message" else "fixture"},
        "properties": properties,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": probe if field == "file_path" else "src/app.py"
                    },
                    "region": {
                        "startLine": 3,
                        "snippet": {"text": probe if field == "snippet" else "x = 1"},
                    },
                }
            }
        ],
    }
    if field == "suppression":
        result["suppressions"] = [{"kind": "inSource", "justification": probe}]
    model.sarif.runs[0].results = [Result.model_validate(result)]
    model.additional_reports["bandit"] = {
        "source": {"scanner_name": "bandit", "status": "PASSED", "duration": 1.0}
    }
    if field in ("cve_id", "cwe_id"):
        model.additional_reports["custom"] = [
            {
                "title": "T1",
                "description": "fixture",
                "severity": "CRITICAL",
                "rule_id": "T1",
                "file_path": "src/lib.py",
                "line_start": 4,
                field: probe,
            }
        ]
    model._flat_cache = None
    return model


def _text_reporter(context, sections=False):
    if not sections:
        return TextReporter(context=context)
    options = TextReporterConfigOptions(
        include_findings_table=True, include_detailed_findings=True
    )
    return TextReporter(context=context, config=TextReporterConfig(options=options))


def _markdown_reporter(context, sections=False):
    if not sections:
        return MarkdownReporter(context=context)
    options = MarkdownReporterConfigOptions(include_findings_table=True)
    return MarkdownReporter(
        context=context, config=MarkdownReporterConfig(options=options)
    )


def _html_reporter(context, sections=False):
    return HtmlReporter(context=context)


REPORTERS = {
    "text": _text_reporter,
    "markdown": _markdown_reporter,
    "html": _html_reporter,
}


def _no_raw_controls(text):
    found = [control for control in CONTROLS if control in text]
    assert found == [], (found, repr(text))


def _line_at(document, prefix):
    """The first line that starts (after spaces) with *prefix*, and the next.

    Split on line feeds only, so a raw CR or NEL stays inside its line."""
    lines = document.split("\n")
    for index, line in enumerate(lines):
        if line.lstrip(" ").startswith(prefix):
            return line, lines[index + 1] if index + 1 < len(lines) else ""
    raise AssertionError(f"no line starts with {prefix!r}:\n{document}")


def _element_text(document, pattern):
    """The text of the one element *pattern* captures, HTML entities decoded."""
    found = re.findall(pattern, document, re.DOTALL)
    assert len(found) == 1, (pattern, found)
    return html.unescape(found[0])


# (reporter, its optional sections on, field, how the place is found, layout)
#
# A place is found by the prefix of its line or, in HTML, by a pattern that
# captures its element's text. "one line" places hold the whole value on their
# line; "cut" ones are one-line table columns that cut the value to their width;
# "lines kept" ones show it with its own line breaks.
SITES = [
    # Markdown: the rule ID, which is also the finding's title.
    ("markdown", False, "rule_id", "<summary>1.", "one line"),
    ("markdown", False, "rule_id", "### Finding 1:", "one line"),
    ("markdown", False, "rule_id", "- Rule ID:", "one line"),
    ("markdown", True, "rule_id", "| CRITICAL | bandit |", "one line"),
    # Markdown: the message and the snippet.
    ("markdown", False, "message", "MSG-", "lines kept"),
    ("markdown", False, "snippet", "SNIP-", "lines kept"),
    # Markdown: the file path.
    ("markdown", False, "file_path", "| 1 |", "one line"),
    ("markdown", False, "file_path", "<summary>1.", "one line"),
    ("markdown", False, "file_path", "- Location:", "one line"),
    ("markdown", True, "file_path", "| CRITICAL | bandit | R1 | R1 |", "one line"),
    # HTML: the title and the rule ID on the finding's card.
    ("html", False, "rule_id", r'<h3 id="finding-1">(.*?)</h3>', "one line"),
    (
        "html",
        False,
        "rule_id",
        r'<p class="finding-meta"><code>(.*?)</code>',
        "one line",
    ),
    # HTML: the message on the finding's card.
    (
        "html",
        False,
        "message",
        r'<p class="finding-description">(.*?)</p>',
        "lines kept",
    ),
    # HTML: the file path in the hotspots table.
    (
        "html",
        False,
        "file_path",
        r'aria-label="Top hotspots".*?<td>\d+</td>\s*<td>(.*?)</td>',
        "one line",
    ),
    # HTML: the package, its version and the suppression reason on the card.
    (
        "html",
        False,
        "package_name",
        r"<p><strong>Package:</strong> (.*?)</p>",
        "one line",
    ),
    (
        "html",
        False,
        "package_version",
        r"<p><strong>Version:</strong> (.*?)</p>",
        "one line",
    ),
    (
        "html",
        False,
        "suppression",
        r'<p class="suppression-reason"><strong>Suppression reason:</strong> (.*?)</p>',
        "lines kept",
    ),
    # HTML: the project, CVE and CWE in the card's context list.
    (
        "html",
        False,
        "workspace_project",
        r"<p><strong>Project:</strong> (.*?)</p>",
        "one line",
    ),
    ("html", False, "cve_id", r"<p><strong>CVE:</strong> (.*?)</p>", "one line"),
    ("html", False, "cwe_id", r"<p><strong>CWE:</strong> (.*?)</p>", "one line"),
    # Markdown: the CVE and CWE labels of the detailed findings.
    ("markdown", False, "cve_id", "- CVE:", "one line"),
    ("markdown", False, "cwe_id", "- CWE:", "one line"),
    # Text: the CVE and CWE lines of the detailed findings.
    ("text", True, "cve_id", "CVE:", "one line"),
    ("text", True, "cwe_id", "CWE:", "one line"),
    # Text: the file path in the hotspots, the findings table and the details.
    ("text", False, "file_path", "1 PATH-", "one line"),
    ("text", True, "file_path", "CRITICAL   bandit", "cut"),
    ("text", True, "file_path", "Location:", "one line"),
    # Text: the rule ID (the title too) in the findings table and the details,
    # and the message in the details.
    ("text", True, "rule_id", "CRITICAL   bandit", "cut"),
    ("text", True, "rule_id", "Finding 1:", "one line"),
    ("text", True, "rule_id", "Rule ID:", "one line"),
    ("text", True, "message", "MSG-", "lines kept"),
]


def _site_id(site):
    reporter, sections, field, place, layout = site
    return f"{reporter}{'+sections' if sections else ''}-{field}-{place[:24]}"


@pytest.mark.parametrize("site", SITES, ids=[_site_id(site) for site in SITES])
def test_each_place_shows_the_finding_s_scanner_text(site, test_plugin_context):
    reporter, sections, field, place, layout = site
    document = REPORTERS[reporter](test_plugin_context, sections).report(_model(field))
    tag = TAGS[field]

    if reporter == "html":
        text = _element_text(document, place)
        assert text.startswith(tag), repr(text)
        _no_raw_controls(text)
        # Shown, not dropped: the escapes are written out.
        assert "x1b" in text and "x85" in text, repr(text)
        assert MARKER in text, repr(text)
        if layout == "one line":
            assert "\n" not in text, repr(text)
        else:
            assert "\n" in text, repr(text)
            assert not any(
                line.lstrip().startswith("::") for line in text.split("\n")
            ), repr(text)
        return

    line, after = _line_at(document, place)
    assert tag in line, repr(line)
    _no_raw_controls(line)
    assert "x1b" in line, repr(line)
    if layout != "cut":
        assert "x85" in line, repr(line)
    # No line the value spills onto starts a CI command.
    assert not after.lstrip().startswith("::"), repr(after)
    if layout == "one line":
        assert MARKER in line, repr(line)
    elif layout == "lines kept":
        _no_raw_controls(after)
        assert MARKER in after, repr(after)


# The reports, and the fields each one prints, that the places above cover.
DOCUMENTS = [
    ("markdown", False, "rule_id"),
    ("markdown", True, "rule_id"),
    ("markdown", False, "message"),
    ("markdown", False, "snippet"),
    ("markdown", False, "file_path"),
    ("markdown", True, "file_path"),
    ("html", False, "rule_id"),
    ("html", False, "message"),
    ("html", False, "file_path"),
    ("html", False, "package_name"),
    ("html", False, "package_version"),
    ("html", False, "suppression"),
    ("html", False, "workspace_project"),
    ("html", False, "cve_id"),
    ("html", False, "cwe_id"),
    ("markdown", False, "cve_id"),
    ("markdown", False, "cwe_id"),
    ("text", False, "file_path"),
    ("text", True, "file_path"),
    ("text", True, "rule_id"),
    ("text", True, "message"),
    ("text", True, "cve_id"),
    ("text", True, "cwe_id"),
]


@pytest.mark.parametrize(
    "reporter, sections, field",
    DOCUMENTS,
    ids=[
        f"{reporter}{'+sections' if sections else ''}-{field}"
        for reporter, sections, field in DOCUMENTS
    ],
)
def test_no_place_in_the_report_obeys_the_finding_s_scanner_text(
    reporter, sections, field, test_plugin_context
):
    """The whole document, so a place the list above does not name is caught."""
    document = REPORTERS[reporter](test_plugin_context, sections).report(_model(field))

    # The control: the value is printed.
    assert TAGS[field] in document, document
    _no_raw_controls(document)
    assert [
        line
        for line in document.split("\n")
        if line.lstrip().startswith("::") and MARKER in line
    ] == []


def test_a_one_line_value_is_written_as_its_escapes(test_plugin_context):
    """The exact form, once: the Markdown rule ID line, with Markdown's own
    backslash escapes over the shown text."""
    document = MarkdownReporter(context=test_plugin_context).report(_model("rule_id"))

    line, _ = _line_at(document, "- Rule ID:")

    assert line == (
        "- Rule ID: RULEID-\\\\x1b\\[31m-\\\\x07-\\\\x0d-\\\\x85-\\\\x0a::warning::probe-mark"
    ), repr(line)
