"""What a report may show as the reason a scanner failed.

One check, in ``utils/short_reason.py``, read by the type that records a reason
(``core/exceptions.py``) and by the reports that show one: a sentence that is
one printable line, not blank, at most 200 characters and with no local path.
"""

import pytest

from automated_security_helper.utils.short_reason import (
    SHORT_REASON_LIMIT,
    is_short_reason,
    names_a_local_path,
)

pytestmark = pytest.mark.unit


class TestWhatIsAShortReason:
    @pytest.mark.parametrize(
        "text",
        [
            "its tool exited with code 2, which this scanner does not accept",
            "it could not be constructed (ValueError)",
            "no rule was evaluated against 3 of its 7 targets",
            "its --exclude patterns left out all 12 files it found",
            "a" * SHORT_REASON_LIMIT,
            "its config_file option names a file that does not exist",
            "the https://example.test/x address is not reachable",
            "a path-like and/or word is not a path",
        ],
    )
    def test_a_plain_sentence_is_one(self, text):
        assert is_short_reason(text)

    @pytest.mark.parametrize(
        "text, why",
        [
            ("", "empty"),
            ("   ", "blank"),
            ("a" * (SHORT_REASON_LIMIT + 1), "over the limit"),
            ("two\nlines", "a line break"),
            ("carriage\rreturn", "a carriage return"),
            ("tab\tseparated", "a tab"),
            ("bell\x07", "a control character"),
            ("escape \x1b[31m", "an escape sequence"),
            ("line\u2028separator", "a Unicode line separator"),
            ("lone \udc80 surrogate", "a lone surrogate"),
            ("could not read /etc/hosts", "a POSIX absolute path"),
            ("/etc/hosts could not be read", "a path at the start"),
            ("could not read ~/scan", "a home-relative path"),
            ("could not read C:\\scan\\out", "a drive path"),
            ("could not read C:/scan/out", "a drive path with slashes"),
            ("could not read \\\\host\\share", "a UNC path"),
            ("config_file='/tmp/x'", "a path after a quote"),
            ("config_file=/tmp/x", "a path after an equals sign"),
        ],
    )
    def test_text_that_is_not_fit_to_show_is_refused(self, text, why):
        assert not is_short_reason(text), why

    @pytest.mark.parametrize("value", [None, 7, b"bytes", ["a"], {"a": "b"}])
    def test_only_a_string_is_one(self, value):
        assert not is_short_reason(value)

    def test_a_sentence_at_the_limit_is_kept_and_one_over_is_not(self):
        assert is_short_reason("y" * SHORT_REASON_LIMIT)
        assert not is_short_reason("y" * (SHORT_REASON_LIMIT + 1))


class TestWhatLooksLikeALocalPath:
    @pytest.mark.parametrize(
        "text",
        [
            "/etc/x",
            "see /etc/x",
            "'/etc/x'",
            '"/etc/x"',
            "dir=/etc/x",
            "~/x",
            "see ~/x",
            "C:\\x",
            "d:/x",
            "\\\\h\\s",
        ],
    )
    def test_a_path_is_found(self, text):
        assert names_a_local_path(text)

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "its tool exited with code 2",
            "and/or",
            "a/b",
            "https://example.test",
            "tilde ~ alone",
            "C: is not a path",
        ],
    )
    def test_a_word_with_a_slash_inside_is_not_a_path(self, text):
        assert not names_a_local_path(text)


def test_the_reporter_uses_the_same_limit_and_check():
    """The first-sentence parse of #1195 reads the limit and path check kept here."""
    from automated_security_helper.plugin_modules.ash_builtin.reporters import (
        report_content_emitter,
    )

    assert report_content_emitter.SHORT_ERROR_REASON_LIMIT == SHORT_REASON_LIMIT
    prefix = "Failed to execute x scanner on source: "
    assert report_content_emitter.short_error_reason(prefix + "read /etc/hosts") is None
    assert report_content_emitter.short_error_reason(prefix + "read nothing") == (
        "read nothing"
    )
