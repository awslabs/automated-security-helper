# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/validate_ferret_plugin.py: an expired suppression covers nothing.

The validator parsed each suppression's ``expiration`` and never read it, so it
kept treating a suppression as active after ASH had stopped applying it (ASH's
rule: a YYYY-MM-DD date, expired from the start of that day; an unreadable date
is refused, so it never applies either).
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def validator(script_loader):
    return script_loader("validate_ferret_plugin")


def _entry(**fields):
    entry = {"rule_id": "SECRET-SECRET-KEYWORD", "path": "docs/*.md"}
    entry.update(fields)
    return entry


class TestParser:
    """At the base a hand-written line scanner read the suppressions list."""

    def test_an_inline_comment_is_not_part_of_the_value(self, validator):
        text = (
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: 'docs/a.md'  # the README\n"
            "      rule_id: SECRET-SECRET-KEYWORD\n"
            "      line_start: 12  # first hit\n"
            "      line_end: 14\n"
        )
        [entry] = validator.parse_suppressions(text)
        assert entry["path"] == "docs/a.md"
        assert entry["line_start"] == 12
        assert entry["line_end"] == 14
        assert validator.suppression_covers(
            entry, "docs/a.md", 13, "SECRET-SECRET-KEYWORD"
        )

    def test_a_folded_reason_does_not_start_a_new_entry(self, validator):
        text = (
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: docs/a.md\n"
            "      rule_id: SECRET-SECRET-KEYWORD\n"
            "      reason: >-\n"
            "        documented keyword:\n"
            "        - the example assignment\n"
            "      line_start: 3\n"
            "      line_end: 3\n"
        )
        entries = validator.parse_suppressions(text)
        assert len(entries) == 1
        assert entries[0]["line_start"] == 3

    def test_a_top_level_key_after_the_list_ends_it_without_losing_entries(
        self, validator
    ):
        text = (
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: docs/a.md\n"
            "      rule_id: SECRET-SECRET-KEYWORD\n"
            "    - path: docs/b.md\n"
            "      rule_id: SECRET-SECRET-KEYWORD\n"
            "  severity_threshold: MEDIUM\n"
            "scanners:\n"
            "  bandit:\n"
            "    enabled: true\n"
        )
        assert [e["path"] for e in validator.parse_suppressions(text)] == [
            "docs/a.md",
            "docs/b.md",
        ]

    def test_narrowing_keys_are_kept_and_such_an_entry_covers_no_text_hit(
        self, validator
    ):
        text = (
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: docs/a.md\n"
            "      rule_id: SECRET-SECRET-KEYWORD\n"
            "      symbol: load_settings\n"
        )
        [entry] = validator.parse_suppressions(text)
        assert entry["symbol"] == "load_settings"
        assert not validator.suppression_covers(
            entry, "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_a_line_number_ash_cannot_read_covers_nothing(self, validator):
        text = (
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: docs/a.md\n"
            "      rule_id: SECRET-SECRET-KEYWORD\n"
            "      line_start: twelve\n"
        )
        [entry] = validator.parse_suppressions(text)
        # At the base this comparison raised TypeError and aborted the script.
        assert not validator.suppression_covers(
            entry, "docs/a.md", 13, "SECRET-SECRET-KEYWORD"
        )

    def test_both_config_files_are_read(self, validator, tmp_path):
        community = tmp_path / "community.yaml"
        community.write_text(
            "global_settings:\n  suppressions:\n    - path: a.md\n      rule_id: X\n",
            encoding="utf-8",
        )
        ash = tmp_path / "ash.yaml"
        ash.write_text(
            "global_settings:\n  suppressions:\n    - path: b.md\n      rule_id: Y\n",
            encoding="utf-8",
        )
        entries = validator.load_community_suppressions([community, ash])
        assert [(e["path"], e["source"]) for e in entries] == [
            ("a.md", "community.yaml"),
            ("b.md", "ash.yaml"),
        ]


class TestMatchingFollowsAsh:
    def test_rule_id_is_a_case_insensitive_glob(self, validator):
        assert validator.suppression_covers(
            _entry(rule_id="secret-secret-keyword"),
            "docs/a.md",
            3,
            "SECRET-SECRET-KEYWORD",
        )
        assert validator.suppression_covers(
            _entry(rule_id="SECRET-*"), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_an_entry_without_rule_id_covers_any_rule(self, validator):
        entry = {"path": "docs/*.md"}
        assert validator.suppression_covers(
            entry, "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_a_recursive_glob_matches_zero_directories(self, validator):
        """At the base fnmatch required at least one directory for `**/`."""
        assert validator.suppression_covers(
            _entry(path="docs/**/*.md"), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )
        assert validator.suppression_covers(
            _entry(path="docs/**/*.md"), "docs/x/y/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_a_line_end_alone_bounds_the_entry(self, validator):
        """At the base line_end was read only when line_start was present."""
        assert validator.suppression_covers(
            _entry(line_end=10), "docs/a.md", 5, "SECRET-SECRET-KEYWORD"
        )
        assert not validator.suppression_covers(
            _entry(line_end=10), "docs/a.md", 11, "SECRET-SECRET-KEYWORD"
        )

    def test_a_line_start_alone_is_open_ended(self, validator):
        assert validator.suppression_covers(
            _entry(line_start=10), "docs/a.md", 500, "SECRET-SECRET-KEYWORD"
        )
        assert not validator.suppression_covers(
            _entry(line_start=10), "docs/a.md", 9, "SECRET-SECRET-KEYWORD"
        )


class TestKeywordPattern:
    def test_quoted_and_dotted_keywords_are_matched(self, validator):
        """At the base a quote or a dot before the keyword never matched."""
        assert validator.SECRET_KEYWORD_PATTERN.search('"api_key": "value"')
        assert validator.SECRET_KEYWORD_PATTERN.search("self.api_key = value")
        assert validator.SECRET_KEYWORD_PATTERN.search("password = value")

    def test_an_allowlist_token_in_a_trailing_comment_does_not_exempt_code(
        self, validator
    ):
        """At the base any line mentioning the rule name was exempt."""
        line = 'password = "x"  # SECRET-SECRET-KEYWORD'
        assert validator.SECRET_KEYWORD_PATTERN.search(
            validator._code_part(line, ".py")
        )
        assert not validator.keyword_hit_is_exempt(line, ".py")

    def test_prose_naming_the_rule_is_exempt(self, validator):
        line = "The SECRET-SECRET-KEYWORD rule flags `password =` in docs."
        assert validator.keyword_hit_is_exempt(line, ".md")

    def test_an_example_comment_is_exempt(self, validator):
        assert validator.keyword_hit_is_exempt("# e.g. password = ...", ".py")


class TestExcludeGlobSyntax:
    def _config(self, scanner: str, body: str) -> list[str]:
        return (
            "# exclude_patterns are documented here, which must not arm the check\n"
            "scanners:\n"
            f"  {scanner}:\n"
            "    enabled: true\n"
            "    options:\n"
            f"{body}"
        ).splitlines()

    def test_a_ferret_glob_pattern_is_a_hit(self, validator):
        lines = self._config(
            "ferret-scan", "      exclude_patterns:\n        - '**/node_modules'\n"
        )
        assert validator.exclude_glob_hits(lines) == [(7, "**/node_modules")]

    def test_another_scanners_glob_is_not_ferrets_business(self, validator):
        """At the base every exclude_patterns key in the file was read."""
        lines = self._config(
            "semgrep", "      exclude_patterns:\n        - '**/node_modules'\n"
        )
        assert validator.exclude_glob_hits(lines) == []

    def test_a_comment_naming_the_key_does_not_arm_the_check(self, validator):
        lines = self._config(
            "ferret-scan",
            "      # exclude_patterns go below\n      other:\n        - '**/x'\n",
        )
        assert validator.exclude_glob_hits(lines) == []

    def test_a_flow_style_list_on_the_key_line_is_inspected(self, validator):
        """At the base the key's own line was skipped, so a flow list was never read."""
        lines = self._config(
            "ferret-scan", "      exclude_patterns: ['**/build', 'dist']\n"
        )
        assert validator.exclude_glob_hits(lines) == [(6, "**/build")]


class TestTestCount:
    def test_only_definitions_are_counted(self, validator):
        source = (
            "# def test_in_a_comment\n"
            'DOC = "def test_in_a_string"\n'
            "def test_one():\n    pass\n"
            "class TestX:\n    def test_two(self):\n        pass\n"
            "    async def test_three(self):\n        pass\n"
            "def helper():\n    pass\n"
        )
        assert validator.count_test_functions(source) == 3


class TestWindowsPaths:
    def test_str_of_a_path_in_a_tool_argument_anywhere_is_a_hit(self, validator):
        """At the base only three identifiers inside two methods were read."""
        lines = [
            "    def _process_config_options(self):",
            '        args.append(ToolExtraArg(key="--config", value=str(config_file_path)))',
            "    def other(self):",
            "        value = str(self._empty_config_file())",
            '        args += ["--config", str(self._empty_config_file())]',
            '        args += ["--config", config_file_path.as_posix()]',
        ]
        assert [i for i, _ in validator.windows_path_hits(lines)] == [2, 5]


class TestMultipleExcludeArgs:
    def test_a_wrapped_append_is_a_hit(self, validator):
        """At the base both tokens had to be on one physical line."""
        lines = [
            "    def _process_config_options(self):",
            "        for pattern in exclude_patterns:",
            "            args.append(",
            '                f"--exclude={pattern}"',
            "            )",
        ]
        assert validator.multiple_exclude_hits(lines) == [2]


class TestFerretInAshYaml:
    def test_a_comment_naming_the_key_does_not_arm_the_check(self, validator):
        """At the base `ash_plugin_modules` anywhere on a line entered list mode."""
        lines = [
            "# ash_plugin_modules: are listed below",
            "other_list:",
            "  - automated_security_helper.plugin_modules.ash_ferret_plugins",
        ]
        assert validator.ferret_in_ash_yaml_hits(lines) == []

    def test_the_key_itself_arms_the_check(self, validator):
        lines = [
            "ash_plugin_modules:",
            "  - automated_security_helper.plugin_modules.ash_ferret_plugins",
        ]
        assert validator.ferret_in_ash_yaml_hits(lines) == [2]


class TestExpiration:
    def test_an_entry_without_expiration_covers(self, validator):
        assert validator.suppression_covers(
            _entry(), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_a_future_expiration_still_covers(self, validator):
        # Far from today, so neither the runner's timezone nor the time of day
        # moves it across the boundary; the boundary itself is pinned below.
        far_off = (date.today() + timedelta(days=30)).isoformat()
        assert validator.suppression_covers(
            _entry(expiration=far_off), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_a_past_expiration_covers_nothing(self, validator):
        assert not validator.suppression_covers(
            _entry(expiration="2000-01-01"), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )

    def test_the_expiration_date_itself_has_already_expired(self, validator):
        """Pinned to a fixed clock: local date.today() flipped this test west of
        UTC in the evening and east of UTC in the morning."""
        today = date(2026, 6, 15)
        assert validator.suppression_has_expired("2026-06-15", today=today)
        assert validator.suppression_has_expired(date(2026, 6, 15), today=today)
        assert not validator.suppression_has_expired("2026-06-16", today=today)
        assert validator.suppression_has_expired("2026-06-14", today=today)

    def test_the_default_clock_is_utc(self, validator):
        from datetime import datetime, timezone

        assert validator._today_utc() == datetime.now(timezone.utc).date()

    def test_an_unreadable_date_counts_as_expired(self, validator):
        assert validator.suppression_has_expired("next week")
        assert not validator.suppression_covers(
            _entry(expiration="31/12/2099"), "docs/a.md", 3, "SECRET-SECRET-KEYWORD"
        )
