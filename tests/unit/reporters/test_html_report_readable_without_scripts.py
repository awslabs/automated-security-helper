# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HTML report is readable with no network and with its script unavailable.

Why these tests exist
---------------------
The report is one self-contained file. html_reporter.py inlines its stylesheet,
its script and its font, and writes every finding as plain HTML that the script
only filters and searches. The documentation site now loads a library from
cdnjs.cloudflare.com, and the report must not follow it there: a report is
opened from a CI artifact, an email attachment or a host with no internet
access, where no CDN answers.

These tests render a report, take its scripts out, and require every finding to
be present as a card that is not hidden, holding its rule and its message, the
no-JavaScript note to be there, and no element or stylesheet rule to load
anything over the network. They pass on the tree before the site's change too:
they hold a property the report already has, so the change cannot take it away.
The browser checks in docs/ui-tests/specs/reports.spec.cjs open the same kind of
document in a real browser: one records every request it makes, and another
opens it with JavaScript off.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters import html_reporter
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.schemas.sarif_schema_model import Result

pytestmark = pytest.mark.unit

ASSETS = Path(html_reporter.__file__).parent / "assets"
FINDINGS = (
    ("STATIC-RULE-ONE", "error", "bandit", "First finding read without scripts"),
    ("STATIC-RULE-TWO", "warning", "semgrep", "Second finding read without scripts"),
)
VOID_ELEMENTS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "source",
        "track",
        "wbr",
    }
)
#: Elements that fetch what their attribute names when the page loads.
LOADING_ATTRIBUTES = {
    "script": "src",
    "img": "src",
    "source": "src",
    "iframe": "src",
    "audio": "src",
    "video": "src",
    "embed": "src",
    "track": "src",
    "input": "src",
    "link": "href",
    "object": "data",
}
NETWORK_URL = re.compile(r"^\s*(?:https?:)?//", re.IGNORECASE)
#: A stylesheet rule that fetches: url(...) or @import with a network URL. The
#: report's own font is a data: URL, which loads nothing.
STYLE_FETCH = re.compile(
    r"url\(\s*['\"]?\s*(?:https?:)?//|@import\s+['\"]\s*(?:https?:)?//",
    re.IGNORECASE,
)
SCRIPT_ELEMENT = re.compile(
    r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL
)


class _ReportReader(HTMLParser):
    """Finding cards, the no-JavaScript note, and what the document would fetch."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.cards: list[dict] = []
        self.noscript: list[str] = []
        self.loads: list[str] = []
        self.styles: list[str] = []
        self._depth = 0
        self._noscript = 0
        self._style = False

    def handle_starttag(self, tag, attrs):
        attributes = {name: value or "" for name, value in attrs}
        url = attributes.get(LOADING_ATTRIBUTES.get(tag, ""), "")
        if url and NETWORK_URL.match(url):
            self.loads.append(f"<{tag}> {url}")
        if attributes.get("style"):
            self.styles.append(attributes["style"])
        if tag == "noscript":
            self._noscript += 1
        if tag == "style":
            self._style = True
        if tag in VOID_ELEMENTS:
            return
        if self._depth:
            self._depth += 1
        elif tag == "article" and "finding-card" in attributes.get("class", "").split():
            self._depth = 1
            self.cards.append({"attributes": attributes, "text": []})

    def handle_endtag(self, tag):
        if tag == "noscript" and self._noscript:
            self._noscript -= 1
        if tag == "style":
            self._style = False
        if tag in VOID_ELEMENTS:
            return
        if self._depth:
            self._depth -= 1

    def handle_data(self, data):
        if self._depth:
            self.cards[-1]["text"].append(data)
        if self._noscript:
            self.noscript.append(data)
        if self._style:
            self.styles.append(data)


def _read(document: str) -> _ReportReader:
    reader = _ReportReader()
    reader.feed(document)
    reader.close()
    return reader


def _render(test_plugin_context) -> str:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": rule,
                "level": level,
                "message": {"text": message},
                "properties": {"scanner_name": scanner},
            }
        )
        for rule, level, scanner, message in FINDINGS
    ]
    model._flat_cache = None
    return HtmlReporter(context=test_plugin_context).report(model)


def test_every_finding_is_a_visible_card_with_the_scripts_taken_out(
    test_plugin_context,
):
    document = _render(test_plugin_context)
    assert SCRIPT_ELEMENT.search(document), (
        "the rendered report has no script to remove"
    )
    without_scripts = SCRIPT_ELEMENT.sub("", document)
    assert "<script" not in without_scripts.lower()

    reader = _read(without_scripts)

    assert len(reader.cards) == len(FINDINGS), [
        card["attributes"] for card in reader.cards
    ]
    texts = [" ".join(" ".join(card["text"]).split()) for card in reader.cards]
    for rule, _level, _scanner, message in FINDINGS:
        holding = [text for text in texts if rule in text and message in text]
        assert holding, f"no card holds {rule} and its message; cards: {texts}"
    for card in reader.cards:
        assert "hidden" not in card["attributes"], card["attributes"]
        assert "js-only" not in card["attributes"].get("class", "").split()


def test_the_no_javascript_note_is_in_the_report(test_plugin_context):
    reader = _read(_render(test_plugin_context))
    note = " ".join(" ".join(reader.noscript).split())
    assert "All findings are visible" in note, note


def test_the_report_loads_nothing_over_the_network(test_plugin_context):
    document = _render(test_plugin_context)
    reader = _read(document)
    assert reader.styles, "no stylesheet read: the report's inlined CSS went missing"
    fetching_rules = [
        match.group(0) for css in reader.styles for match in STYLE_FETCH.finditer(css)
    ]
    assert reader.loads == [], reader.loads
    assert fetching_rules == [], fetching_rules
    assert "cdnjs.cloudflare.com" not in document


def test_the_report_template_names_no_network_resource():
    template = (ASSETS / "ash-report.html").read_text(encoding="utf-8")
    reader = _read(template)
    assert reader.loads == [], reader.loads
    assert "cdnjs.cloudflare.com" not in template


def test_the_reader_flags_planted_network_loads_and_passes_local_ones():
    """The checks above can fail: each planted fetch is found, each local one is not."""
    planted = (
        "<html><head>"
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/x/1.0.0/x.js"></script>'
        '<link rel="stylesheet" href="//example.com/x.css">'
        "<style>@font-face { src: url('https://example.com/f.woff2'); }"
        ' @font-face { src: url("data:font/woff2;base64,AAAA"); }</style>'
        "</head><body>"
        '<img src="https://example.com/pixel.png" alt="">'
        '<a href="https://github.com/awslabs/automated-security-helper">docs</a>'
        '<article class="finding-card"><h3>R1</h3><p>message one<br>more</p></article>'
        "<noscript><p>All findings are visible.</p></noscript>"
        "</body></html>"
    )
    reader = _read(planted)

    assert reader.loads == [
        "<script> https://cdnjs.cloudflare.com/ajax/libs/x/1.0.0/x.js",
        "<link> //example.com/x.css",
        "<img> https://example.com/pixel.png",
    ]
    fetching_rules = [
        match.group(0) for css in reader.styles for match in STYLE_FETCH.finditer(css)
    ]
    assert len(fetching_rules) == 1, fetching_rules
    assert [" ".join(card["text"]) for card in reader.cards] == ["R1 message one more"]
    assert " ".join(reader.noscript) == "All findings are visible."
