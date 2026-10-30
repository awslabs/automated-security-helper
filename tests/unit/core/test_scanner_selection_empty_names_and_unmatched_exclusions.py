# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Empty names and unmatched exclusions in ``core.scanner_selection``.

* A trailing comma ("--scanners bandit,") leaves an empty name. It survived the
  subtraction, so "--scanners bandit, --exclude-scanners bandit" came back as
  ``[""]`` instead of being refused as a selection that cancels itself, and the
  later spelling refusal named an empty scanner.
* An exclusion that matches no registered scanner was invisible, so a misspelled
  one left the scanner the operator meant to leave out running.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.scanner_selection import (
    exclusions_matching_no_scanner,
    refuse_selection_matching_no_scanner,
    selection_after_exclusions,
)

pytestmark = pytest.mark.unit


class TestAStrayCommaInTheAllowlist:
    def test_it_does_not_defeat_the_cancelled_selection_refusal(self):
        # Red at the base: returned [""].
        with pytest.raises(ScannerSelectionError, match="cancels itself"):
            selection_after_exclusions(["bandit", ""], ["bandit"])

    def test_the_refusal_does_not_list_the_empty_name(self):
        with pytest.raises(ScannerSelectionError) as raised:
            selection_after_exclusions(["bandit", " "], ["bandit"])

        assert "selected bandit;" in str(raised.value)

    def test_it_is_dropped_from_the_selection(self):
        assert selection_after_exclusions(["bandit", ""], []) == ["bandit"]
        assert selection_after_exclusions(["bandit", "", "semgrep"], ["semgrep"]) == [
            "bandit"
        ]

    def test_an_empty_exclusion_name_excludes_nothing(self):
        assert selection_after_exclusions(["bandit"], [""]) == ["bandit"]

    def test_an_allowlist_of_only_empty_names_is_left_for_the_spelling_check(self):
        remaining = selection_after_exclusions([""], ["bandit"])

        assert remaining == [""]
        with pytest.raises(ScannerSelectionError) as raised:
            refuse_selection_matching_no_scanner(remaining, ["bandit", "semgrep"])
        assert "(an empty name)" in str(raised.value)

    def test_the_controls_a_plain_cancelled_selection_and_a_plain_one(self):
        with pytest.raises(ScannerSelectionError, match="cancels itself"):
            selection_after_exclusions(["bandit"], ["Bandit "])
        assert selection_after_exclusions(["bandit", "semgrep"], ["bandit"]) == [
            "semgrep"
        ]


class TestTheSpellingRefusalNamesRealNames:
    def test_an_empty_name_is_left_out_of_the_list(self):
        with pytest.raises(ScannerSelectionError) as raised:
            refuse_selection_matching_no_scanner(
                ["detect_secrets", ""], ["detect-secrets"]
            )

        assert "None of the requested scanners exist: detect_secrets. " in str(
            raised.value
        )


class TestExclusionsMatchingNoScanner:
    REGISTERED = ["bandit", "detect-secrets", "Semgrep"]

    def test_a_misspelled_name_is_reported_in_its_own_spelling(self):
        # Red at the base: nothing reported it.
        assert exclusions_matching_no_scanner(
            ["detect_secrets", "bandit"], self.REGISTERED
        ) == ["detect_secrets"]

    def test_matching_ignores_case_and_surrounding_blanks(self):
        assert (
            exclusions_matching_no_scanner([" BANDIT ", "semgrep"], self.REGISTERED)
            == []
        )

    def test_a_repeated_name_is_reported_once(self):
        assert exclusions_matching_no_scanner(
            ["nope", "NOPE ", "nope"], self.REGISTERED
        ) == ["nope"]

    def test_empty_names_are_not_reported(self):
        assert exclusions_matching_no_scanner(["", "  "], self.REGISTERED) == []

    def test_with_nothing_registered_there_is_nothing_to_compare(self):
        assert exclusions_matching_no_scanner(["anything"], []) == []

    def test_no_exclusions_report_nothing(self):
        assert exclusions_matching_no_scanner([], self.REGISTERED) == []
