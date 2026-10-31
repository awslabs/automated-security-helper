# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Small corrections to ``ash config lint`` and its two fixers.

Each test names what the code did before. They are grouped by the function
they pin, and each builds the smallest input that reaches it: most call the
function directly, because the lint of a whole file takes the path through
ConfigValidator and the environment record, which these tests are not about.
"""

from __future__ import annotations

import errno
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.config import config_linter
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintIssue,
    LintResult,
    LintSeverity,
    UnusedSuppressionsNotEditable,
)
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.config.environment_record import EnvironmentReference

pytestmark = pytest.mark.unit


def _issue(category: LintCategory, fixable: bool = True) -> LintIssue:
    return LintIssue(
        severity=LintSeverity.WARNING,
        category=category,
        message="m",
        path="p",
        fixable=fixable,
        fix_description="fix it" if fixable else "",
    )


class TestValidatorWarningCategory:
    def test_a_warning_in_words_lint_does_not_know_is_not_a_syntax_error(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the fallback category of an unrecognized validator
        warning was SYNTAX_ERROR, the category that says the file did not load.
        The CLI skips the fixers for a file with one, so a warning a scan
        accepts switched ``--fix`` off."""
        config_path = tmp_path / "ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        check = SimpleNamespace(
            chain=[],
            environment_values=[],
            file_references=[],
            references=[],
            environment_paths=frozenset(),
            resolved_data=None,
            shown_resolved=None,
            errors=[],
            warnings=["A scan accepts this, and lint has no words for it"],
            path_patterns=[],
        )
        monkeypatch.setattr(
            ConfigValidator, "check_config_file", staticmethod(lambda *a, **k: check)
        )
        result = LintResult(config_path=config_path)

        ConfigLinter._check_validation_issues(config_path, {}, result)

        assert [i.category for i in result.issues] == [LintCategory.OTHER]
        assert result.issues[0].severity == LintSeverity.WARNING
        assert LintCategory.SYNTAX_ERROR not in {i.category for i in result.issues}

    def test_an_error_in_words_lint_does_not_know_is_not_a_syntax_error_either(
        self,
    ):
        """Red at the base: the fallback of ``_validator_error_to_lint_issue``
        gave an unrecognized ERROR message SYNTAX_ERROR, so the CLI took a file
        that had parsed for one it could not load and skipped both fixers."""
        issue = ConfigLinter._validator_error_to_lint_issue(
            "A refusal in words lint has no pattern for", {}
        )

        assert issue.severity == LintSeverity.ERROR
        assert issue.category == LintCategory.OTHER


class TestFixableMarkReads:
    def test_the_environment_is_read_once_for_every_issue(self, tmp_path, monkeypatch):
        """Red at the base: ``uses_env_references`` opened and parsed the file
        once per fixable issue."""
        config_path = tmp_path / "ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        calls = {"n": 0}
        real = config_linter.uses_env_references

        def counted(path):
            calls["n"] += 1
            return real(path)

        monkeypatch.setattr(config_linter, "uses_env_references", counted)
        result = LintResult(config_path=config_path)
        result.issues = [_issue(LintCategory.SUPPRESSION_EXPIRED) for _ in range(5)]

        ConfigLinter._clear_fixable_a_fixer_refuses(config_path, result)

        assert calls["n"] == 1
        assert [i.fixable for i in result.issues] == [True] * 5

    def test_a_file_that_cannot_be_read_again_keeps_the_marks(
        self, tmp_path, monkeypatch
    ):
        """A read failure here was a traceback out of lint(); the marks stand and
        the fixer reports its own refusal when it runs."""
        config_path = tmp_path / "ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")

        def gone(_path):
            raise OSError("went away")

        monkeypatch.setattr(config_linter, "uses_env_references", gone)
        result = LintResult(config_path=config_path)
        result.issues = [_issue(LintCategory.SUPPRESSION_EXPIRED)]

        ConfigLinter._clear_fixable_a_fixer_refuses(config_path, result)

        assert [i.fixable for i in result.issues] == [True]


class TestFixableMarks:
    @pytest.mark.parametrize("name", ["pyproject.toml", "ash.toml"])
    def test_nothing_in_a_toml_file_is_marked_fixable(self, tmp_path, name):
        """Red at the base: both fixers refuse a TOML file, and the issues said
        to run them."""
        config_path = tmp_path / name
        config_path.write_text("[tool.ash]\n", encoding="utf-8")
        result = LintResult(config_path=config_path)
        result.issues = [
            _issue(LintCategory.SUPPRESSION_UNUSED),
            _issue(LintCategory.SUPPRESSION_EXPIRED),
        ]

        ConfigLinter._clear_fixable_a_fixer_refuses(config_path, result)

        assert [i.fixable for i in result.issues] == [False, False]
        # The description stays: it is the hand remedy once --fix has refused
        # the file (a TOML lint's line_end fix text is read by
        # tests/unit/config/test_checks_name_environment_values_by_place.py).
        assert [i.fix_description for i in result.issues] == ["fix it", "fix it"]

    def test_an_unused_suppression_in_a_json_file_is_not_fixable_but_others_are(
        self, tmp_path
    ):
        """Red at the base: ``--fix-unused`` edits text and refuses JSON, while
        ``--fix`` rewrites JSON as JSON."""
        config_path = tmp_path / "ash.json"
        config_path.write_text("{}", encoding="utf-8")
        result = LintResult(config_path=config_path)
        result.issues = [
            _issue(LintCategory.SUPPRESSION_UNUSED),
            _issue(LintCategory.SUPPRESSION_EXPIRED),
        ]

        ConfigLinter._clear_fixable_a_fixer_refuses(config_path, result)

        assert [i.fixable for i in result.issues] == [False, True]

    def test_a_yaml_file_that_reads_the_environment_keeps_only_unused_fixable(
        self, tmp_path
    ):
        """Red at the base: ``--fix`` refuses a file that reads the environment
        (it would write each reference's value over it); ``--fix-unused`` edits
        text and does not."""
        config_path = tmp_path / "ash.yaml"
        config_path.write_text("project_name: ${ASH_LOW_NAME}\n", encoding="utf-8")
        result = LintResult(config_path=config_path)
        result.issues = [
            _issue(LintCategory.SUPPRESSION_UNUSED),
            _issue(LintCategory.SUPPRESSION_EXPIRED),
        ]

        ConfigLinter._clear_fixable_a_fixer_refuses(config_path, result)

        assert [i.fixable for i in result.issues] == [True, False]
        assert result.issues[1].fix_description == "fix it"

    def test_the_un_marked_issues_are_kept_for_the_refusal(self, tmp_path):
        """Red before the list existed: the marks were cleared and nothing kept
        what was cleared, so ``ash config lint --fix`` on a TOML file holding a
        fix to make read no fixable issue, printed "No fixable issues found" and
        exited 0 where it refuses to rewrite a TOML file (the CLI's refusal fires
        on ``fixable or lint_result.fixes_refused``)."""
        config_path = tmp_path / "ash.toml"
        config_path.write_text("[tool.ash]\n", encoding="utf-8")
        result = LintResult(config_path=config_path)
        expired = _issue(LintCategory.SUPPRESSION_EXPIRED)
        not_fixable = _issue(LintCategory.INTERNAL_FIELD, fixable=False)
        result.issues = [expired, not_fixable]

        ConfigLinter._clear_fixable_a_fixer_refuses(config_path, result)

        assert result.fixes_refused == [expired]
        assert expired.fixable is False
        assert result.fixable_issues == []

    def test_a_plain_yaml_file_keeps_every_mark(self, tmp_path):
        config_path = tmp_path / "ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        result = LintResult(config_path=config_path)
        result.issues = [
            _issue(LintCategory.SUPPRESSION_UNUSED),
            _issue(LintCategory.SUPPRESSION_EXPIRED),
        ]

        ConfigLinter._clear_fixable_a_fixer_refuses(config_path, result)

        assert [i.fixable for i in result.issues] == [True, True]


class TestUnusedReport:
    @pytest.mark.parametrize(
        "config_data, expected",
        [
            pytest.param({}, "reports/ash.unused-suppressions.json", id="default"),
            pytest.param(
                {"reporters": {"unused-suppressions": {"extension": "found.json"}}},
                "reports/ash.found.json",
                id="kebab",
            ),
            pytest.param(
                {"reporters": {"Unused_Suppressions": {"extension": "found.json"}}},
                "reports/ash.found.json",
                id="another-spelling",
            ),
            pytest.param(
                {"reporters": {"unused-suppressions": {"extension": "../up"}}},
                "reports/ash.unused-suppressions.json",
                id="path-like-extension-is-the-reporters-to-refuse",
            ),
            pytest.param(
                {"reporters": {"unused-suppressions": {"extension": ""}}},
                "reports/ash.unused-suppressions.json",
                id="empty-extension",
            ),
            pytest.param(
                {"reporters": {"unused-suppressions": {"extension": 3}}},
                "reports/ash.unused-suppressions.json",
                id="not-a-string",
            ),
            pytest.param(
                {"reporters": "x"},
                "reports/ash.unused-suppressions.json",
                id="reporters-not-a-mapping",
            ),
            pytest.param(
                {"reporters": {"unused-suppressions": None}},
                "reports/ash.unused-suppressions.json",
                id="null-section-enables-the-reporter-with-its-defaults",
            ),
            pytest.param(
                {
                    "reporters": {
                        "unused_suppressions": {"extension": "a.json"},
                        "unused-suppressions": {"extension": "b.json"},
                    }
                },
                "reports/ash.b.json",
                id="two-spellings-the-canonical-one-wins",
            ),
            pytest.param(
                {
                    "reporters": {
                        "unused-suppressions": {"extension": "b.json"},
                        "unused_suppressions": {"extension": "a.json"},
                    }
                },
                "reports/ash.b.json",
                id="two-spellings-whatever-the-order",
            ),
            pytest.param(
                {
                    "reporters": {
                        "unused_suppressions": {"extension": "a.json"},
                        "unused-suppressions": {"enabled": True},
                    }
                },
                "reports/ash.a.json",
                id="two-spellings-the-canonical-one-sets-no-extension",
            ),
        ],
    )
    def test_the_report_name_follows_the_reporters_extension(
        self, config_data, expected
    ):
        """Red at the base: the lookup used the default name only, so a scan
        configured with ``extension`` wrote a report the lint never found."""
        assert ConfigLinter._unused_report_name(config_data) == expected

    def test_the_report_is_found_under_the_configured_name(self, tmp_path):
        out = tmp_path / "out"
        (out / "reports").mkdir(parents=True)
        report = out / "reports" / "ash.found.json"
        report.write_text("{}", encoding="utf-8")
        config_path = tmp_path / "ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        data = {"reporters": {"unused-suppressions": {"extension": "found.json"}}}

        found, stamp = ConfigLinter._find_unused_report(config_path, out, data)

        assert found == report
        assert stamp is not None

    @staticmethod
    def _refuse_stat_of(monkeypatch, refused):
        """Make ``Path.stat`` fail with EACCES for the paths in ``refused``, as
        the system does for a path below a directory the user cannot search."""
        real_stat = Path.stat

        def stat(self, *args, **kwargs):
            if self in refused:
                raise PermissionError(errno.EACCES, "Permission denied", str(self))
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", stat)

    def test_a_report_that_cannot_be_statted_is_no_report(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: ``report_path.exists()`` re-raises every error but
        "not found" before Python 3.14, so ``lint --source-dir`` on a tree whose
        output directory the user cannot search ended in a PermissionError
        traceback where the lint used to carry on without a report."""
        out = tmp_path / "out"
        out.mkdir()
        config_path = tmp_path / "ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        report = out / ConfigLinter.UNUSED_SUPPRESSIONS_REPORT
        self._refuse_stat_of(monkeypatch, {report})

        found, stamp = ConfigLinter.find_unused_report(config_path, out, {})

        assert (found, stamp) == (None, None)

    def test_the_lookup_goes_on_to_the_next_place_after_an_unreadable_one(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the first place beside the config raised, so the
        report in the second was never reached."""
        root = tmp_path.resolve()
        config_path = root / "ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        name = ConfigLinter.UNUSED_SUPPRESSIONS_REPORT
        unreadable = root / ".ash" / "ash_output" / name
        report = root / "ash_output" / name
        report.parent.mkdir(parents=True)
        report.write_text("{}", encoding="utf-8")
        self._refuse_stat_of(monkeypatch, {unreadable})

        found, stamp = ConfigLinter.find_unused_report(config_path, None, {})

        assert found == report
        assert stamp is not None

    @pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="needs a directory this user cannot search",
    )
    def test_a_directory_the_user_cannot_search_holds_no_report(self, tmp_path):
        """Red at the base on Python before 3.14: the same case as above, with
        the system's own refusal in place of the stand-in."""
        out = tmp_path / "out"
        (out / "reports").mkdir(parents=True)
        config_path = tmp_path / "ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        (out / "reports").chmod(0o000)
        try:
            found, stamp = ConfigLinter.find_unused_report(config_path, out, {})
        finally:
            (out / "reports").chmod(0o700)

        assert (found, stamp) == (None, None)


class TestReportAge:
    @pytest.fixture
    def pacific_time(self, monkeypatch):
        if not hasattr(time, "tzset"):
            pytest.skip("no tzset on this platform")
        monkeypatch.setenv("TZ", "America/Los_Angeles")
        time.tzset()
        if datetime(2026, 1, 15, 12).astimezone().utcoffset() != timedelta(hours=-8):
            monkeypatch.undo()
            time.tzset()
            pytest.skip("the time zone database has no America/Los_Angeles")
        yield
        monkeypatch.undo()
        time.tzset()

    def test_the_age_counts_the_hour_a_daylight_saving_change_skips(
        self, pacific_time, monkeypatch
    ):
        """Red at the base: two naive local times subtract as wall-clock
        readings. 01:30 and 03:30 on the morning clocks move forward are one
        hour apart, and the subtraction said two."""

        class SpringForward(datetime):
            @classmethod
            def now(cls, tz=None):
                # One instant, 03:30 PDT on the morning the clocks moved: given
                # as ``tz`` asks, so a reading made with ``now(timezone.utc)``
                # gets the same instant and not a naive value that would make
                # the subtraction raise for the wrong reason.
                instant = datetime(2026, 3, 8, 10, 30, tzinfo=timezone.utc)
                if tz is not None:
                    return instant.astimezone(tz)
                return instant.astimezone().replace(tzinfo=None)

        monkeypatch.setattr(config_linter, "datetime", SpringForward)

        age = ConfigLinter._seconds_since(datetime(2026, 3, 8, 1, 30))

        assert age == 3600.0


class TestWhichSuppressionsTheReportLists:
    def test_an_entry_whose_value_is_another_entrys_written_form_is_not_listed(self):
        """Red at the base: entry V reads ``${OTHER}``, and the environment gives
        that variable the text ``${A}``, so V resolves to the written form of
        entry U. The report lists U by its written form; matching V by its
        resolved id commented V out too."""
        make = ConfigLinter._make_suppression_id
        u_written = {"path": "${A}", "rule_id": "B1"}
        u_resolved = {"path": "src/a.py", "rule_id": "B1"}
        v_written = {"path": "${OTHER}", "rule_id": "B1"}
        v_resolved = {"path": "${A}", "rule_id": "B1"}
        unused_ids = {make(u_written)}
        written_ids = {make(u_written), make(v_written)}

        assert ConfigLinter._is_listed_unused(
            u_resolved, u_written, unused_ids, written_ids
        )
        assert not ConfigLinter._is_listed_unused(
            v_resolved, v_written, unused_ids, written_ids
        )

    def test_an_older_report_lists_an_entry_by_its_resolved_id(self):
        make = ConfigLinter._make_suppression_id
        resolved = {"path": "src/a.py", "rule_id": "B1"}
        written = {"path": "${A}", "rule_id": "B1"}

        assert ConfigLinter._is_listed_unused(
            resolved, written, {make(resolved)}, {make(written)}
        )

    @pytest.mark.parametrize(
        "entry", [{"path": "src/a.py"}, {"path": "src/a.py", "rule_id": None}]
    )
    def test_an_entry_with_no_rule_is_named_with_a_star(self, entry):
        """Red at the base: a report writes a missing rule as ``null``, and the
        message read ``rule_id='None'``."""
        assert ConfigLinter._rule_shown(entry) == "*"

    def test_an_extension_set_in_an_extends_base_names_the_report(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the report's name was taken from the checked file's
        own data, so an ``extension`` an ``extends`` base sets (a scan reads the
        merged configuration and writes ``reports/ash.<extension>``) made lint
        report no report found. Lint names it from the merged data now."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "base.yaml").write_text(
            "reporters:\n  unused-suppressions:\n    extension: from-base.json\n",
            encoding="utf-8",
        )
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "extends: base.yaml\n"
            "project_name: demo\n"
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: src/own.py\n"
            "      rule_id: B1\n"
            "      reason: own\n",
            encoding="utf-8",
        )
        out = tmp_path / "out"
        (out / "reports").mkdir(parents=True)
        (out / "reports" / "ash.from-base.json").write_text(
            json.dumps(
                {
                    "unused_suppressions": [
                        {"path": "src/own.py", "rule_id": "B1", "reason": "own"}
                    ]
                }
            ),
            encoding="utf-8",
        )

        result = ConfigLinter.lint(config_path, output_dir=out, check_unused=True)

        messages = [
            issue.message
            for issue in result.issues
            if issue.category == LintCategory.SUPPRESSION_UNUSED
        ]
        assert not any("No unused suppressions report found" in m for m in messages), (
            messages
        )
        assert any(m.startswith("Unused suppression:") for m in messages), messages

    @pytest.mark.parametrize(
        "merged, found",
        [
            pytest.param(
                {"reporters": {"unused-suppressions": {"extension": "merged.json"}}},
                True,
                id="the-merged-data-names-the-report",
            ),
            pytest.param(None, False, id="no-merged-data-the-file-alone-names-it"),
        ],
    )
    def test_the_unused_check_names_the_report_by_the_merged_data(
        self, tmp_path, merged, found
    ):
        """The check reads ``result.resolved_data`` (the merged chain, as lint
        fills it) for the report's name and the checked file's own data only
        when there is none. Pinned at the check itself: a result carrying merged
        data that sets the extension finds ``reports/ash.merged.json``; the same
        file with no merged data looks under its own (default) name and finds no
        report."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        out = tmp_path / "out"
        (out / "reports").mkdir(parents=True)
        (out / "reports" / "ash.merged.json").write_text(
            json.dumps({"unused_suppressions": []}), encoding="utf-8"
        )
        result = LintResult(config_path=config_path)
        result.resolved_data = merged

        ConfigLinter._check_unused_suppressions(
            config_path, {"project_name": "demo"}, out, result
        )

        messages = [
            issue.message
            for issue in result.issues
            if issue.category == LintCategory.SUPPRESSION_UNUSED
        ]
        not_found = any("No unused suppressions report found" in m for m in messages)
        assert not_found is (not found), messages

    def test_only_the_files_own_entries_are_fixable(self, tmp_path, monkeypatch):
        """An entry an ``extends`` base supplies is reported unused with the
        file's, since a scan reads the merged list, and is not fixable: the
        fixer edits the file's own text, where the base's entry is not. The
        earlier form of this test never handed the other entry to the code, so
        its "not in ids" held whatever the code did."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "base.yaml").write_text(
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: src/base.py\n"
            "      rule_id: B2\n"
            "      reason: base\n",
            encoding="utf-8",
        )
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "extends: base.yaml\n"
            "project_name: demo\n"
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: src/own.py\n"
            "      rule_id: B1\n"
            "      reason: own\n",
            encoding="utf-8",
        )
        out = tmp_path / "out"
        (out / "reports").mkdir(parents=True)
        (out / "reports" / "ash.unused-suppressions.json").write_text(
            json.dumps(
                {
                    "unused_suppressions": [
                        {"path": "src/own.py", "rule_id": "B1", "reason": "own"},
                        {"path": "src/base.py", "rule_id": "B2", "reason": "base"},
                    ]
                }
            ),
            encoding="utf-8",
        )

        result = ConfigLinter.lint(config_path, output_dir=out, check_unused=True)

        # The per-entry lines are INFO (a report's listing, not a defect of the
        # file); the category and the message prefix pick them out.
        unused = {
            issue.message: issue.fixable
            for issue in result.issues
            if issue.category == LintCategory.SUPPRESSION_UNUSED
            and issue.message.startswith("Unused suppression:")
        }
        own = [
            fixable for message, fixable in unused.items() if "src/own.py" in message
        ]
        base = [
            fixable for message, fixable in unused.items() if "src/base.py" in message
        ]
        assert own == [True], unused
        assert base == [False], unused


class TestCommentedOutEntries:
    TEXT = (
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: |\n"
        "        first line\n"
        "          deeper line\n"
        "    - path: src/b.py\n"
        "      rule_id: B102\n"
    )

    def test_taking_the_comment_marker_off_restores_the_entry(self):
        """Red at the base: the marker was put flush to the dash column and the
        line's own indentation was lost, so un-commenting an entry left lines
        that did not parse."""
        fixed, commented = ConfigLinter._comment_out_suppressions(
            self.TEXT, {0}, "2026-01-01"
        )

        assert commented == {0}
        restored = []
        for line in fixed.split("\n"):
            if "[ash-lint" in line:
                continue
            if line.startswith("    # "):
                line = "    " + line[len("    # ") :]
            restored.append(line)
        assert "\n".join(restored) == self.TEXT

    def test_the_continuation_lines_keep_their_indentation_inside_the_comment(self):
        fixed, _ = ConfigLinter._comment_out_suppressions(self.TEXT, {0}, "2026-01-01")

        assert "    # - path: src/a.py\n" in fixed
        assert "    #   rule_id: B101\n" in fixed
        assert "    #     first line\n" in fixed
        assert "    #       deeper line\n" in fixed

    def test_an_anchored_list_is_refused_for_its_anchor(self):
        """An edit of a list another key aliases would change every use of the
        anchor, so the fixer refuses and says why. The composer places an
        anchored node at its anchor token, not at its first ``-``; read as a
        plain list that would have been refused for a dash count of zero, a
        reason the file does not show."""
        text = (
            "global_settings:\n"
            "  suppressions: &shared\n"
            "  - path: src/a.py\n"
            "    rule_id: B101\n"
        )

        with pytest.raises(
            UnusedSuppressionsNotEditable, match=r"anchored \(&shared\)"
        ) as refused:
            ConfigLinter._comment_out_suppressions(text, {0}, "2026-01-01")

        assert "list dashes" not in str(refused.value)

    def test_an_alias_of_a_list_written_elsewhere_is_refused_as_an_alias(self):
        """The anchored list sits under another key; the suppressions key is an
        alias of it, and the refusal names the alias, not the anchor."""
        text = (
            "shared: &shared\n"
            "  - path: src/a.py\n"
            "    rule_id: B101\n"
            "global_settings:\n"
            "  suppressions: *shared\n"
        )

        with pytest.raises(UnusedSuppressionsNotEditable, match="is an alias"):
            ConfigLinter._comment_out_suppressions(text, {0}, "2026-01-01")


class TestPluginSectionSpellings:
    def test_a_section_under_another_spelling_is_the_built_in_one(self):
        """Red at the base: ``--fix`` looked the class up by the exact name, so a
        section a scan reads as ``bandit`` (``Bandit``) was an unknown plugin and
        its internal-only field was kept."""
        config = {"scanners": {"Bandit": {"install_timeout": 300}}}

        assert ConfigLinter.fix_removes(
            ("scanners", "Bandit", "install_timeout"), config
        )

    def test_an_option_the_plugin_declares_is_kept_under_any_spelling(self):
        config = {"scanners": {"Bandit": {"tool_version": "1.2.3"}}}

        reason = ConfigLinter._option_pin_kept_because(
            "scanners", "Bandit", "tool_version", config
        )

        assert reason is not None
        assert "declares this option" in reason

    @pytest.mark.parametrize("spelling", ["checkov", "Checkov", "CHECK_OV"])
    def test_an_expired_entry_is_found_under_every_spelling(self, spelling):
        """Red at the base: the walk read the exact key ``checkov``, so an
        entry a scan applies (and so expires) under ``Checkov`` was not reported."""
        config = {
            "scanners": {
                spelling: {
                    "options": {
                        "skip_path": [
                            {
                                "path": "a",
                                "reason": "r",
                                "expiration": "2020-01-01",
                            }
                        ]
                    }
                }
            }
        }
        result = LintResult()

        ConfigLinter._check_ignore_path_expirations(config, result)

        assert [i.category for i in result.issues] == [LintCategory.IGNORE_PATH_ISSUE]
        assert "Checkov skip path has expired" in result.issues[0].message


class TestKeysReadFromTheEnvironment:
    def test_a_literal_key_is_named_when_its_neighbours_came_from_the_environment(
        self,
    ):
        """Red at the base: two keys read from the environment are both ``<value>``
        in the shown copy, so the copy has fewer keys than the section and every
        key was shown as ``<value>``, the literal ``cdk_nag`` included."""
        config = {
            "scanners": {
                "cdk_nag": {"enabled": True},
                "vendor-one": {"enabled": True},
                "vendor-two": {"enabled": True},
            }
        }
        shown = {"scanners": {"<value>": {"enabled": True}}}
        result = LintResult()
        result.file_references = [
            EnvironmentReference(
                path=("scanners",),
                written="${ASH_LOW_KEY_ONE}",
                resolved="vendor-one",
                value="vendor-one",
                key=True,
            ),
            EnvironmentReference(
                path=("scanners",),
                written="${ASH_LOW_KEY_TWO}",
                resolved="vendor-two",
                value="vendor-two",
                key=True,
            ),
        ]

        ConfigLinter._check_legacy_name_variants(config, result, shown)

        issues = [i for i in result.issues if i.path == "scanners.cdk_nag"]
        assert len(issues) == 1
        assert "'cdk_nag'" in issues[0].message


class TestInternalFieldPath:
    def test_a_plugin_name_with_a_dot_is_removed_whole(self):
        """Red at the base: the path was split on every dot and a name with one
        was not three parts, so the field was never removed."""
        config = {"scanners": {"my.plugin": {"name": "x", "enabled": True}}}
        issue = _issue(LintCategory.INTERNAL_FIELD)
        issue.path = "scanners.my.plugin.name"

        assert ConfigLinter._fix_internal_field(config, issue) is True
        assert config == {"scanners": {"my.plugin": {"enabled": True}}}


class TestSchemaComment:
    def test_a_byte_order_mark_does_not_hide_the_schema_comment(self):
        """Red at the base: the mark is not whitespace to ``strip``, so the first
        line did not read as a comment and the default reference replaced the
        file's own."""
        comment = "# yaml-language-server: $schema=./my-schema.json"
        raw = chr(0xFEFF) + comment + "\nproject_name: demo\n"

        content = ConfigLinter._generate_config_content(
            Path("ash.yaml"), raw, {"project_name": "demo"}
        )

        assert content.startswith(comment + "\n")
        assert "raw.githubusercontent.com" not in content
