# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The HTML report's filter, search, theme and masthead.

The page's script runs in a browser and has no runner here, so the script is
checked as text for the shapes the fixes rely on, and the rendered document is
checked for the markup the script reads.

* The "All scanners" entry has the empty value, and no scanner has it: a scanner
  named "all" used to select every finding.
* The search reads the finding's own text, not the buttons and labels around it,
  so searching "copy" does not match every card.
* A stored theme other than light or dark falls back to the system preference
  instead of setting a theme the stylesheet has no rules for.
* The masthead counts scanners that did not run as skipped, not as disabled: a
  scanner with nothing to scan is not disabled.
"""

import re
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


def _script() -> str:
    return (ASSETS / "ash-report.js").read_text(encoding="utf-8")


def _render(test_plugin_context, scanner_name: str) -> str:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif.runs[0].results = [
        Result.model_validate(
            {
                "ruleId": "R1",
                "level": "error",
                "message": {"text": "fixture"},
                "properties": {"scanner_name": scanner_name},
            }
        )
    ]
    model._flat_cache = None
    return HtmlReporter(context=test_plugin_context).report(model)


class TestTheAllScannersEntryHasTheEmptyValue:
    def test_the_rendered_filter(self, test_plugin_context):
        document = _render(test_plugin_context, "all")

        values = re.findall(r'<option value="([^"]*)">', document)
        # A scanner named "all" is listed under its own name, and the empty
        # value belongs to the "All scanners" entry alone.
        assert '<option value="">All scanners</option>' in document
        assert values.count("") == 1, values
        assert '<option value="all">all</option>' in document

    def test_the_script_treats_only_the_empty_value_as_every_scanner(self):
        script = _script()
        assert 'scanner.value === ""' in script
        assert 'scanner.value === "all"' not in script
        assert 'scanner.value = ""' in script


class TestTheSearchReadsTheFindingsOwnText:
    def test_the_script_does_not_search_the_whole_card(self):
        script = _script()
        assert "card.textContent" not in script
        assert "cloneNode(true)" in script
        for selector in ("button", "summary", "strong", ".finding-status"):
            assert selector in script

    def test_the_selected_parts_exist_in_a_rendered_card(self, test_plugin_context):
        document = _render(test_plugin_context, "bandit")

        for marker in (
            "<h3 ",
            'class="finding-scanner"',
            'class="finding-meta"',
            'class="finding-body"',
        ):
            assert marker in document, marker


class TestAStoredThemeIsOneTheStylesheetKnows:
    def test_only_light_and_dark_are_taken_from_storage(self):
        script = _script()
        assert 'stored === "light" || stored === "dark"' in script
        assert 'setTheme(localStorage.getItem("ash-report-theme") ||' not in script


class TestTheMastheadCountsSkippedScanners:
    def test_the_template_and_the_rendered_page(self, test_plugin_context):
        template = (ASSETS / "ash-report.html").read_text(encoding="utf-8")
        assert "$skipped skipped" in template
        assert "$skipped disabled" not in template

        document = _render(test_plugin_context, "bandit")
        assert re.search(r"\d+ skipped · \d+ unavailable", document)


class TestTheSeverityChipsAreEscapedWhereTheyBecomeMarkup:
    def test_a_bucket_name_is_escaped_in_the_class_and_in_the_text(self):
        """The buckets are an open set: a row rated outside the five levels
        counts under its own name, which reaches a class attribute and the text.

        RED at the base: the name was written as it came.
        """
        chips = HtmlReporter._format_severity_counts({"high": 2, "r&d": 1})

        assert '<span class="severity-high"><strong>2</strong> High</span>' in chips
        assert (
            '<span class="severity-r&amp;d"><strong>1</strong> R&amp;D</span>' in chips
        )
        assert "r&d" not in chips
