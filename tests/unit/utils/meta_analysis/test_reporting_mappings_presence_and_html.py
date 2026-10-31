# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporter mappings, field presence and the HTML report in ``reporting``.

``get_reporter_mappings`` returned an empty dict on ImportError although its
comment said the static mappings were kept, and derived "flatjson" from the
reporter's class name beside the static "flat-json". ``check_field_presence_in_reports``
looked reporter mappings up with indexed paths while the keys use ``[]``, walked a
mapped field such as ``vulnerabilities[].desc`` as literal dict keys, raised
TypeError on a scalar on the way, read a text report as showing a field whenever the
path's last segment occurred in it, and listed types and scanners in set order.
``generate_html_report`` declared no charset, split a string ``type`` into its
characters, hard-coded ``.ash/ash_output`` in its JQ examples, recognized only
``ash-aggregated`` as the aggregate, labeled field counts as findings, filtered on
a whole table entry and sorted with a comparator that never returned 0.
"""

from __future__ import annotations

import html as html_module
import sys

import pytest

from automated_security_helper.utils.meta_analysis.reporting import (
    AGGREGATE_SCANNER_NAMES,
    check_field_presence_in_reports,
    generate_html_report,
    get_reporter_mappings,
)

pytestmark = pytest.mark.unit


class TestGetReporterMappings:
    def test_the_static_mappings_stand_when_the_reporters_cannot_be_imported(
        self, monkeypatch
    ):
        # A module set to None in sys.modules makes its import raise ImportError.
        monkeypatch.setitem(
            sys.modules,
            "automated_security_helper.plugin_modules.ash_builtin.reporters",
            None,
        )

        mappings = get_reporter_mappings()

        # Returned {} before, against the comment beside the except.
        assert "ocsf" in mappings
        assert "flat-json" in mappings
        assert "runs[].results[].ruleId" in mappings["asff"]

    def test_a_reporters_own_mappings_land_under_the_static_key(self, monkeypatch):
        from automated_security_helper.plugin_modules.ash_builtin.reporters import (
            FlatJsonReporter,
        )

        monkeypatch.setattr(
            FlatJsonReporter,
            "sarif_field_mappings",
            staticmethod(lambda: {"runs[].results[].guid": "id"}),
        )

        mappings = get_reporter_mappings()

        # "flatjson" was a second column beside "flat-json".
        assert "flatjson" not in mappings
        assert mappings["flat-json"]["runs[].results[].guid"] == "id"
        assert mappings["flat-json"]["runs[].results[].ruleId"] == "rule_id"


class TestCheckFieldPresenceInReports:
    FIELD = "runs[0].results[0].message.text"

    def _presence(self, flat_reports):
        return check_field_presence_in_reports(
            {self.FIELD: {"type": {"str"}, "scanners": {"bandit"}}},
            {"runs": [{"results": [{"message": {"text": "m"}}]}]},
            flat_reports,
        )

    def test_an_indexed_path_finds_the_reporter_mapping(self):
        presence = self._presence({"ocsf": {"vulnerabilities": [{"desc": "m"}]}})

        # The mapping keys use []; an indexed path never matched one.
        assert presence[self.FIELD]["reporter_mappings"]["ocsf"] == (
            "vulnerabilities[].desc"
        )
        assert presence[self.FIELD]["in_flat"]["ocsf"] is True

    def test_a_mapped_field_through_an_array_is_found_in_a_dict_report(self):
        presence = self._presence(
            {"asff": {"Findings": [{"Types": []}, {"Description": "m"}]}}
        )

        # "Findings[]" was looked up as a literal key, so this read absent.
        assert presence[self.FIELD]["in_flat"]["asff"] is True

    def test_a_scalar_on_the_mapped_path_is_absent_not_an_error(self):
        # "testcase" is a string here; "name" in it was a substring test, and a
        # number raised TypeError.
        presence = self._presence({"junitxml": {"testcase": "classname"}})
        assert presence[self.FIELD]["in_flat"]["junitxml"] is False

        presence = self._presence({"junitxml": {"testcase": 7}})
        assert presence[self.FIELD]["in_flat"]["junitxml"] is False

    def test_a_text_report_without_a_mapping_shows_no_field(self):
        presence = self._presence({"plain": "the text of the report says text"})

        # The path's last segment "text" occurred in the report, so it was True.
        assert presence[self.FIELD]["in_flat"]["plain"] is False

    def test_a_text_report_with_a_mapping_shows_the_mapped_name(self):
        # The header is whatever the csv reporter maps the field to: the static
        # table's when the reporters cannot be imported, the reporter's own when
        # they can.
        header = get_reporter_mappings()["csv"]["runs[].results[].message.text"]
        presence = self._presence({"csv": f"rule,{header},level\n"})

        assert presence[self.FIELD]["in_flat"]["csv"] is True

    def test_types_and_scanners_are_listed_in_sorted_order(self):
        presence = check_field_presence_in_reports(
            {"version": {"type": {"str", "int"}, "scanners": {"b", "a", "c"}}},
            {"version": "2.1.0"},
        )

        assert presence["version"]["type"] == ["int", "str"]
        assert presence["version"]["scanners"] == ["a", "b", "c"]


def _results(summary_extra=None):
    return {
        "missing_fields": {},
        "match_statistics": {},
        "summary": {
            "total_findings": 2,
            "matched_findings": 1,
            "critical_missing_fields": 0,
            "important_missing_fields": 0,
            "informational_missing_fields": 0,
            **(summary_extra or {}),
        },
    }


class TestGenerateHtmlReport:
    def test_the_page_declares_its_utf8_charset(self, tmp_path):
        report = tmp_path / "report.html"

        generate_html_report(_results(), str(report), {})

        text = report.read_text(encoding="utf-8")
        assert '<meta charset="utf-8">' in text
        assert text.index("<meta charset") < text.index("<title>")

    def test_a_string_type_is_one_type_not_its_characters(self, tmp_path):
        report = tmp_path / "report.html"

        generate_html_report(
            _results(),
            str(report),
            {"runs[].results[].x": {"type": "str", "scanners": "bandit"}},
        )

        text = report.read_text(encoding="utf-8")
        # "str" went into set() and rendered as "r, s, t".
        assert "<td>str</td>" in text
        assert "<td>r, s, t</td>" not in text

    def test_the_jq_examples_name_the_analyzed_directory(self, tmp_path):
        report = tmp_path / "report.html"

        generate_html_report(
            _results(),
            str(report),
            {
                "runs[].results[].x": {
                    "type": ["str"],
                    "scanners": ["bandit"],
                    "in_aggregate": True,
                }
            },
            sarif_dir="/data/run 7/ash_output",
        )

        page = html_module.unescape(report.read_text(encoding="utf-8"))
        assert "'/data/run 7/ash_output'/scanners/bandit/**/*.sarif" in page
        assert ".ash/ash_output" not in page

    @pytest.mark.parametrize("aggregate", AGGREGATE_SCANNER_NAMES)
    def test_a_field_only_the_aggregate_carries_points_at_the_aggregate(
        self, tmp_path, aggregate
    ):
        report = tmp_path / "report.html"

        generate_html_report(
            _results(),
            str(report),
            {
                "runs[].results[].x": {
                    "type": ["str"],
                    "scanners": [aggregate],
                    "in_aggregate": True,
                }
            },
        )

        page = html_module.unescape(report.read_text(encoding="utf-8"))
        # The aggregate is named "ash" by the field analysis; only "ash-aggregated"
        # was special-cased, so "ash" pointed at scanners/ash/**/*.sarif.
        assert ".ash/ash_output/reports/ash.sarif" in page
        assert "scanners/ash" not in page

    def test_field_counts_are_labeled_as_fields_when_the_caller_says_so(self, tmp_path):
        report = tmp_path / "report.html"

        generate_html_report(_results({"unit": "fields"}), str(report), {})

        text = report.read_text(encoding="utf-8")
        assert "Total Fields: 2" in text
        assert "Fields in Aggregate: 1 (50.00%)" in text
        assert "Total Findings" not in text

    def test_the_match_rate_comes_from_match_rate_when_given(self, tmp_path):
        results = _results()
        results["match_statistics"] = {
            "bandit": {
                "matched_results": 1,
                "total_results": 2,
                "match_rate": 0.5,
                "field_preservation_rate": 0.9,
            }
        }
        results["missing_fields"] = {
            "bandit": {"critical": [], "important": [], "informational": []}
        }
        report = tmp_path / "report.html"

        generate_html_report(results, str(report), {})

        text = report.read_text(encoding="utf-8")
        assert "Match Rate: 1/2 (50.00%)" in text

    def test_the_table_filters_read_the_field_name_and_combine(self, tmp_path):
        report = tmp_path / "report.html"

        generate_html_report(
            _results(),
            str(report),
            {"runs[].results[].x": {"type": ["str"], "scanners": ["bandit"]}},
        )

        text = report.read_text(encoding="utf-8")
        # The field name has its own element, the filters read it, every
        # filter applies in one pass, and the sort comparator returns 0 for
        # equal entries.
        assert "<span class='field-name'>runs[].results[].x</span>" in text
        assert "entry.querySelector('.field-name')" in text
        assert "function applyFilters()" in text
        assert "onkeyup='applyFilters()'" in text
        assert "input.addEventListener('keyup', applyFilters)" in text
        assert "aColText.localeCompare(bColText) * dirModifier" in text
        assert "aColText > bColText ?" not in text
