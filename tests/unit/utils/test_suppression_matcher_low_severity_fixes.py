# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Small fixes in ``utils/suppression_matcher.py``, each pinned by the input that
broke it.

Why this file exists
--------------------
* The unmatched-directory warning said a suppression path ending in ``/`` matches
  "only that literal path", for ``build/**/`` too. The matcher reads the slash after
  ``**`` as part of it (``build/**``), which matches files, so the warning was wrong
  about that path. The warning also printed a path read from the environment by its
  value, where every other message about a suppression shows the reference.
* ``_has_expired`` warned about an unreadable date on every call, and
  ``should_suppress_finding`` calls it once per entry per finding, so one bad date
  wrote one warning per finding.
* ``_expiring_within`` named an entry kept from a results file with an unknown key as
  expiring, though such an entry is never applied.
* Inline ``ash-ignore`` directives were read from UTF-8 only, so a source file saved
  as UTF-16 or UTF-32 (with its byte order mark) never had one recognized, and the
  directive text inside a string literal counted as a directive.
"""

import codecs
import logging
from datetime import timedelta
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.models.core import AshSuppression, current_date
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.suppression_matcher import (
    check_for_expiring_suppressions,
    find_inline_suppressions,
    should_suppress_finding,
    warn_unmatched_directory_suppressions,
)
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit


@pytest.fixture
def ash_warnings():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    yield records
    ASH_LOGGER.removeHandler(handler)


def _finding(path: str = "src/a.py", rule_id: str = "R1") -> FlatVulnerability:
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="s",
        scanner_type="SAST",
        rule_id=rule_id,
        file_path=path,
    )


class TestUnmatchedDirectoryWarning:
    @pytest.mark.parametrize("path", ["build/**/", "build\\**\\", "**/"])
    def test_a_path_ending_in_doublestar_and_a_slash_is_not_called_literal(
        self, ash_warnings, path
    ):
        """Red at the base: the warning said ``build/**/`` matches only that
        literal path, though it is ``build/**`` and matches the files below."""
        suppression = AshSuppression(path=path, rule_id="R1", reason="r")

        warn_unmatched_directory_suppressions([suppression], used_ids=set())

        assert [record.getMessage() for record in ash_warnings] == []

    def test_a_literal_directory_path_still_draws_the_warning(self, ash_warnings):
        """The control: ``build/`` really matches nothing, and a path whose slash
        follows another component than ``**`` is still named."""
        literal = AshSuppression(path="build/", rule_id="R1", reason="r")
        deeper = AshSuppression(path="build/**/*/", rule_id="R2", reason="r")
        # One slash after ``**`` is part of it; a second is a component no path
        # has, so this one matches nothing.
        doubled = AshSuppression(path="a/b/**//", rule_id="R3", reason="r")

        warn_unmatched_directory_suppressions(
            [literal, deeper, doubled], used_ids=set()
        )

        messages = [record.getMessage() for record in ash_warnings]
        assert len(messages) == 3, messages
        for path in ("build/", "build/**/*/", "a/b/**//"):
            assert any(f"'{path}'" in message for message in messages), (path, messages)

    @pytest.mark.parametrize("path", ["./", ".\\"])
    def test_a_path_that_reduces_to_the_current_directory_raises_nothing(
        self, ash_warnings, path
    ):
        """The path's components are never empty (``str.split`` returns at least
        one, and only a ``**`` pair is dropped), so ``./`` and ``.\\`` reach the
        trailing-slash warning like any literal directory and do not raise
        IndexError in the pass that reads the last component."""
        suppression = AshSuppression(path=path, rule_id="R1", reason="r")

        warn_unmatched_directory_suppressions([suppression], used_ids=set())

        messages = [record.getMessage() for record in ash_warnings]
        assert len(messages) == 1, messages
        assert f"'{path}'" in messages[0], messages

    def test_a_path_read_from_the_environment_is_quoted_by_its_reference(
        self, ash_warnings
    ):
        """Red at the base: ``recorded`` was not a parameter, and the warning
        quoted the resolved path."""
        suppression = AshSuppression(path="resolved-dir/", rule_id="R1", reason="r")
        recorded = {id(suppression): {"path": "${ASH_LOW_FIX_DIR}/"}}

        warn_unmatched_directory_suppressions(
            [suppression], used_ids=set(), recorded=recorded
        )

        messages = [record.getMessage() for record in ash_warnings]
        assert len(messages) == 1, messages
        assert "'${ASH_LOW_FIX_DIR}/'" in messages[0]
        assert "'${ASH_LOW_FIX_DIR}/**/*'" in messages[0]
        assert "resolved-dir" not in messages[0]

    def test_without_a_record_the_path_is_quoted_as_it_is(self, ash_warnings):
        suppression = AshSuppression(path="plain-dir/", rule_id="R1", reason="r")

        warn_unmatched_directory_suppressions([suppression], used_ids=set())

        messages = [record.getMessage() for record in ash_warnings]
        assert len(messages) == 1 and "'plain-dir/'" in messages[0], messages

    def test_a_config_given_builds_the_record_itself(self, ash_warnings, monkeypatch):
        """Red at the base: the function took ``recorded`` only, and the scan's
        caller passed neither, so this one warning quoted a path read from the
        environment by its value. Given the config, the record is built here
        (``recorded_suppressions``) from the config's own suppressions, and the
        path is quoted by its reference."""
        from automated_security_helper.utils import suppression_matcher

        suppression = AshSuppression(path="resolved-dir/", rule_id="R1", reason="r")
        config = object()
        asked_for = []

        def fake_record(given):
            asked_for.append(given)
            return {id(suppression): {"path": "${ASH_LOW_FIX_DIR}/"}}

        monkeypatch.setattr(suppression_matcher, "recorded_suppressions", fake_record)

        warn_unmatched_directory_suppressions(
            [suppression], used_ids=set(), config=config
        )

        assert asked_for == [config]
        messages = [record.getMessage() for record in ash_warnings]
        assert len(messages) == 1, messages
        assert "'${ASH_LOW_FIX_DIR}/'" in messages[0]
        assert "resolved-dir" not in messages[0]


class TestUnreadableExpiration:
    def test_one_bad_date_warns_once_not_once_per_finding(self, ash_warnings):
        """Red at the base: five findings wrote five warnings for one entry."""
        first = AshSuppression.model_construct(
            path="src/a.py", rule_id="R1", reason="r", expiration="not-a-date"
        )
        second = AshSuppression.model_construct(
            path="src/b.py", rule_id="R2", reason="r", expiration="2026/13/45"
        )

        for _ in range(5):
            suppressed, _ = should_suppress_finding(_finding(), [first, second])
            assert suppressed is False

        warned = [
            record.getMessage()
            for record in ash_warnings
            if "Invalid expiration date format" in record.getMessage()
        ]
        assert len(warned) == 2, warned
        assert "global_settings.suppressions[0]" in warned[0]
        assert "global_settings.suppressions[1]" in warned[1]

    def test_an_entry_loaded_again_is_warned_about_again(self, ash_warnings):
        """Once per entry object, so a scan that loads its config anew says it
        again."""
        for _ in range(2):
            entry = AshSuppression.model_construct(
                path="src/a.py", rule_id="R1", reason="r", expiration="not-a-date"
            )
            should_suppress_finding(_finding(), [entry])
            should_suppress_finding(_finding(), [entry])

        warned = [
            record
            for record in ash_warnings
            if "Invalid expiration date format" in record.getMessage()
        ]
        assert len(warned) == 2


class TestExpiringEntries:
    def test_an_entry_with_unknown_keys_is_not_named_as_expiring(self):
        """Red at the base: the entry kept from a results file, which is never
        applied, was named in "will expire within 30 days"."""
        soon = (current_date() + timedelta(days=10)).strftime("%Y-%m-%d")
        kept = AshSuppression.model_validate(
            {
                "path": "a.py",
                "rule_id": "R1",
                "reason": "r",
                "expiration": soon,
                "bogus": 1,
            },
            context={TOLERATE_STORED_CONFIG: []},
        )
        assert kept.has_unknown_keys is True
        plain = AshSuppression(path="b.py", rule_id="R2", reason="r", expiration=soon)

        expiring = check_for_expiring_suppressions([kept, plain])

        assert len(expiring) == 1 and expiring[0] is plain


class TestInlineDirectives:
    @pytest.mark.parametrize(
        "encode",
        [
            pytest.param(lambda text: text.encode("utf-16"), id="utf-16-le-bom"),
            pytest.param(
                lambda text: codecs.BOM_UTF16_BE + text.encode("utf-16-be"),
                id="utf-16-be-bom",
            ),
            pytest.param(lambda text: text.encode("utf-32"), id="utf-32-bom"),
        ],
    )
    def test_a_source_file_with_a_byte_order_mark_is_read_in_its_encoding(
        self, tmp_path, encode
    ):
        """Red at the base: read as UTF-8 the text had a NUL between characters,
        and no directive in it was recognized."""
        source = tmp_path / "app.py"
        source.write_bytes(
            encode("x = 1\ny = 2  # ash-ignore: B101 saved as unicode\n")
        )

        found = find_inline_suppressions(source)

        assert [(s.line_number, s.rule_id, s.reason) for s in found] == [
            (2, "B101", "saved as unicode")
        ]

    def test_a_file_with_no_byte_order_mark_is_still_read_as_utf_8(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("x = 'café'  # ash-ignore: B101 accents\n", "utf-8")

        found = find_inline_suppressions(source)

        assert [(s.line_number, s.rule_id) for s in found] == [(1, "B101")]

    def test_directive_text_inside_a_string_literal_is_not_a_directive(self, tmp_path):
        """Red at the base: all of the first three lines suppressed a finding."""
        source = tmp_path / "app.py"
        source.write_text(
            'a = "# ash-ignore: B101 inside a string"\n'
            "b = '// ash-ignore: B102 inside a string'\n"
            'c = "# ash-ignore-next-line: B106 inside a string"\n'
            'd = "it\'s"  # ash-ignore: B103 a real comment\n'
            'e = 1  # ash-ignore: B104 real, with a "quoted" word after it\n'
            'url = "http://x.test"  // ash-ignore: B105 after a url\n',
            encoding="utf-8",
        )

        found = find_inline_suppressions(source)

        assert [(s.line_number, s.rule_id) for s in found] == [
            (4, "B103"),
            (5, "B104"),
            (6, "B105"),
        ]
        assert found[1].reason == 'real, with a "quoted" word after it'

    def test_an_apostrophe_that_never_closes_hides_nothing(self, tmp_path):
        """A quote with no partner on its line is no string, so a comment after
        it is still a comment."""
        source = tmp_path / "notes.txt"
        source.write_text("don't forget this  # ash-ignore: B101 prose\n", "utf-8")

        found = find_inline_suppressions(Path(source))

        assert [(s.line_number, s.rule_id) for s in found] == [(1, "B101")]
