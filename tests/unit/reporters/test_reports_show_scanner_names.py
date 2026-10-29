# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The human reports show a scanner's name, not obey it.

A scan's own results name each scanner from its plugin. ``ash report`` with no
``--output-dir`` renders the results file under ``.ash/ash_output`` of the
directory it runs in, and a repository can commit that file, so every scanner
name a report prints can be the repository's text. The text, Markdown and HTML
reports print it in the scanner results table, the needing-attention and
incomplete-coverage notices, the stale-database notice, the findings table, a
finding's details, and the HTML report's scanner filter and finding cards.
Each place shows the name on one line, as ``shown_on_one_line`` writes it: a
control character is a visible escape, and a CI command form is broken. The
stale-database notice also names the content database from the same file, so
its name is probed the same way.

One cell per place, so dropping the one guard there turns its own cell red, one
cell per report and model for the whole document, and three cells that render a
committed results file through ``ash report`` to a pipe.
"""

import html
import os
import re
import sys
import threading
from datetime import datetime, timedelta, timezone

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
from automated_security_helper.utils import content_db_staleness as staleness
from automated_security_helper.utils.content_databases import STALENESS_WARN

pytestmark = pytest.mark.unit

#: The marker each probe name ends with, after its line feed.
MARKER = "probe-mark"

#: ESC, BEL, a lone carriage return and NEL (a C1 control): each is acted on.
CONTROLS = ("\x1b", "\x07", "\r", "\x85")


def _probe(tag):
    """A scanner name with each control, a line feed and a CI command form."""
    return f"{tag}-\x1b[31m-\x07-\r-\x85-\n::warning::{MARKER}"


def _base(scanner="bandit"):
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": "R1",
                "level": "error",
                "message": {"text": "fixture"},
                "properties": {"scanner_name": scanner},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/app.py"},
                            "region": {"startLine": 3},
                        }
                    }
                ],
            }
        )
    ]
    model.additional_reports["bandit"] = {
        "source": {"scanner_name": "bandit", "status": "PASSED", "duration": 1.0}
    }
    return model


def _named():
    """The name on a finding, so in the scanner tables, the notice and the card."""
    model = _base(_probe("SCAN"))
    model._flat_cache = None
    return model


def _shortfall():
    """A scanner of that name that could not evaluate two of its three targets."""
    model = _base()
    name = _probe("SHORT")
    model.additional_reports[name] = {
        "source": {
            "scanner_name": name,
            "status": "PASSED",
            "duration": 1.0,
            "targets_attempted": 3,
            "targets_failed": 2,
        }
    }
    model._flat_cache = None
    return model


def _stale(name="grype-db", scanner=None):
    """A stale content database whose record names the scanner."""
    model = _base()
    now = datetime.now(timezone.utc)
    record = staleness.ContentDbAgeRecord(
        name=name,
        scanner=_probe("STALE") if scanner is None else scanner,
        built=now - timedelta(days=30),
        measured_by="the cell",
        max_age=timedelta(days=1),
        measured_at=now,
        policy=STALENESS_WARN,
        bound_source="the cell",
        bound_is_tool_default=False,
        refresh="refresh it",
    )
    staleness.attach_records(model.sarif, [record])
    model._flat_cache = None
    return model


def _stale_name():
    """A stale content database whose own name is the repository's text: the
    record comes from a results file, so its name can be any string."""
    return _stale(name=_probe("DBNAME"), scanner="grype")


MODELS = {
    "named": (_named, "SCAN"),
    "shortfall": (_shortfall, "SHORT"),
    "stale": (_stale, "STALE"),
    "stale-name": (_stale_name, "DBNAME"),
}


def _text(context):
    options = TextReporterConfigOptions(
        include_findings_table=True, include_detailed_findings=True
    )
    return TextReporter(context=context, config=TextReporterConfig(options=options))


def _markdown(context):
    options = MarkdownReporterConfigOptions(include_findings_table=True)
    return MarkdownReporter(
        context=context, config=MarkdownReporterConfig(options=options)
    )


def _html(context):
    return HtmlReporter(context=context)


REPORTERS = {"text": _text, "markdown": _markdown, "html": _html}


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


def _element_text(document, pattern):
    """The text of the one element *pattern* captures, HTML entities decoded."""
    found = re.findall(pattern, document, re.DOTALL)
    assert len(found) == 1, (pattern, found)
    return html.unescape(found[0])


# (report, model, how the place is found, layout). A text or Markdown place is
# found by the prefix of its line; an HTML place by a pattern capturing its
# text. "one line" places hold the whole name on their line; "cut" ones are
# table columns that cut it to their width.
SITES = [
    # Text.
    ("text", "named", "Scanners needing attention:", "one line"),
    ("text", "named", "SCAN-", "one line"),
    ("text", "named", "CRITICAL   SCAN-", "cut"),
    ("text", "named", "Scanner: SCAN-", "one line"),
    ("text", "shortfall", "- SHORT-", "one line"),
    ("text", "stale", "- [WARNING] Content database", "one line"),
    ("text", "stale-name", "- [WARNING] Content database DBNAME-", "one line"),
    # Markdown.
    ("markdown", "named", "| SCAN-", "one line"),
    ("markdown", "named", "**Scanners needing attention:**", "one line"),
    ("markdown", "shortfall", "- **SHORT-", "one line"),
    ("markdown", "stale", "- **grype-db** (", "one line"),
    ("markdown", "stale-name", "- **DBNAME-", "one line"),
    # HTML.
    (
        "html",
        "named",
        r"<h3>Scanners needing attention</h3><p>(.*?)\. Check",
        "one line",
    ),
    ("html", "named", r'<option value="(SCAN-[^"]*)"', "one line"),
    ("html", "named", r'<option value="SCAN-[^"]*">(.*?)</option>', "one line"),
    ("html", "named", r'data-scanner="(SCAN-[^"]*)"', "one line"),
    ("html", "named", r'<span class="finding-scanner">(.*?)</span>', "one line"),
    ("html", "named", r"<td>(SCAN-.*?)</td>", "one line"),
    ("html", "shortfall", r"<li><strong>(SHORT-.*?)</strong>: evaluated", "one line"),
    ("html", "stale", r"<li><strong>grype-db</strong> \((STALE-.*?)\): ", "one line"),
    ("html", "stale", r"\): (Content database grype-db .*?)</li>", "one line"),
    (
        "html",
        "stale-name",
        r"<li><strong>(DBNAME-.*?)</strong> \(grype\): ",
        "one line",
    ),
    (
        "html",
        "stale-name",
        r"</strong> \(grype\): (Content database DBNAME-.*?)</li>",
        "one line",
    ),
]


def _site_id(site):
    report, model, place, layout = site
    return f"{report}-{model}-{place[:26]}"


@pytest.mark.parametrize("site", SITES, ids=[_site_id(site) for site in SITES])
def test_each_place_shows_the_scanner_s_name(site, test_plugin_context):
    report, model_name, place, layout = site
    build, tag = MODELS[model_name]
    document = REPORTERS[report](test_plugin_context).report(build())

    if report == "html":
        text = _element_text(document, place)
        assert tag in text, repr(text)
        _no_raw_controls(text)
        # Shown, not dropped: the escape is written out.
        assert "x1b" in text and "x85" in text, repr(text)
        assert MARKER in text and "\n" not in text, repr(text)
        return

    line, after = _line_at(document, place)
    assert tag in line, repr(line)
    _no_raw_controls(line)
    assert "x1b" in line, repr(line)
    # No line the name spills onto starts a CI command.
    assert not after.lstrip().startswith("::"), repr(after)
    if layout == "one line":
        assert MARKER in line, repr(line)


@pytest.mark.parametrize("model_name", sorted(MODELS))
@pytest.mark.parametrize("report", sorted(REPORTERS))
def test_no_place_in_the_report_obeys_a_scanner_s_name(
    report, model_name, test_plugin_context
):
    """The whole document, so a place the list above does not name is caught."""
    build, tag = MODELS[model_name]
    document = REPORTERS[report](test_plugin_context).report(build())

    # The control: the name is printed.
    assert tag in document, document
    _no_raw_controls(document)
    assert [
        line
        for line in _lines(document)
        if line.lstrip().startswith("::") and MARKER in line
    ] == []


# ---------------------------------------------------------------------------
# A committed results file rendered by `ash report` to a pipe
# ---------------------------------------------------------------------------


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
def test_a_committed_results_file_reports_its_scanner_names_shown(
    fmt, tmp_path, monkeypatch
):
    """``ash report`` with no ``--output-dir`` reads ``.ash/ash_output`` of the
    directory it runs in, as a checkout of a repository that committed it."""
    output = tmp_path / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / "ash_aggregated_results.json").write_text(
        _named().model_dump_json(by_alias=True), encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    printed = _through_a_pipe(["report", "--format", fmt], monkeypatch)

    # The control: the committed file is the one rendered.
    assert "SCAN-" in printed, printed[:400]
    _no_raw_controls(printed)
    assert [
        line
        for line in _lines(printed)
        if line.lstrip().startswith("::") and MARKER in line
    ] == []
