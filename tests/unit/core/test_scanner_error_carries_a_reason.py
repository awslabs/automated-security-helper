"""A ScannerError can carry the reason a scanner failed, as a code and a sentence.

``ScannerError`` was a bare ``Exception`` with a message for the log, which holds
paths and the tool's own words, so a report could only read the reason back by
parsing the first sentence of that message. The error now takes a ``reason=``
keyword: a ``FailureReason`` that is built never to raise, and that holds no path.
"""

import copy
import logging
import pickle

import pytest

from automated_security_helper.core import exceptions
from automated_security_helper.core.exceptions import (
    DEFAULT_SENTENCES,
    FALLBACK_SENTENCE,
    FailureReason,
    ReasonCode,
    ScannerError,
    is_reason_code,
    reason_of,
)
from automated_security_helper.utils.short_reason import is_short_reason

pytestmark = pytest.mark.unit

REASON = FailureReason(ReasonCode.TIMED_OUT, "it timed out after 300 s")


class LocalScannerError(ScannerError):
    """A subclass the way a plugin writes one: its own ``__init__`` and attribute."""

    def __init__(self, message: str, *, exit_code: int = 0) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _roundtrips(error):
    """The error as ``copy.copy``, ``copy.deepcopy`` and ``pickle`` give it back."""
    return {
        "copy": copy.copy(error),
        "deepcopy": copy.deepcopy(error),
        "pickle": pickle.loads(pickle.dumps(error)),
    }


class TestTheErrorKeepsItsMessage:
    def test_a_positional_error_is_unchanged(self):
        error = ScannerError("its tool failed")

        assert str(error) == "its tool failed"
        assert error.args == ("its tool failed",)
        assert error.reason is None

    def test_a_reason_does_not_change_the_message(self):
        error = ScannerError("its tool failed", reason=REASON)

        assert str(error) == "its tool failed"
        assert error.args == ("its tool failed",)
        assert error.reason is REASON

    def test_more_than_one_positional_argument_still_works(self):
        error = ScannerError("a", 2, reason=REASON)

        assert error.args == ("a", 2)
        assert error.reason == REASON

    def test_no_argument_still_works(self):
        assert str(ScannerError()) == ""

    def test_a_reason_is_keyword_only(self):
        """Passed by position it is one more message argument, never the reason."""
        error = ScannerError("a", REASON)

        assert error.args == ("a", REASON)
        assert error.reason is None

    @pytest.mark.parametrize("not_a_reason", ["its tool failed", 7, {"code": "x"}])
    def test_a_reason_that_is_not_one_is_dropped_and_never_raises(self, not_a_reason):
        error = ScannerError("x", reason=not_a_reason)  # type: ignore[arg-type]

        assert error.reason is None
        assert str(error) == "x"


class TestTheReasonSurvivesCopyAndPickle:
    @pytest.mark.parametrize("how", ["copy", "deepcopy", "pickle"])
    def test_the_reason_the_message_and_the_type_are_kept(self, how):
        error = ScannerError("its tool failed", reason=REASON)

        again = _roundtrips(error)[how]

        assert type(again) is ScannerError
        assert again is not error
        assert again.reason == REASON
        assert str(again) == "its tool failed"

    @pytest.mark.parametrize("how", ["copy", "deepcopy", "pickle"])
    def test_an_error_with_no_reason_stays_without_one(self, how):
        again = _roundtrips(ScannerError("its tool failed"))[how]

        assert again.reason is None
        assert str(again) == "its tool failed"

    @pytest.mark.parametrize("how", ["copy", "deepcopy", "pickle"])
    def test_a_subclass_with_its_own_init_keeps_both_its_attributes(self, how):
        error = LocalScannerError("its tool failed", exit_code=3)
        error.reason = REASON

        again = _roundtrips(error)[how]

        assert type(again) is LocalScannerError
        assert again.reason == REASON
        assert again.exit_code == 3
        assert str(again) == "its tool failed"


class TestTheReasonOfAChain:
    def test_no_error_has_no_reason(self):
        assert reason_of(None) is None

    def test_an_error_with_no_reason_and_no_chain_has_none(self):
        assert reason_of(ScannerError("x")) is None
        assert reason_of(ValueError("x")) is None

    def test_the_raised_error_is_read_first(self):
        inner = ScannerError("inner", reason=FailureReason(ReasonCode.NO_RESULT))
        outer = ScannerError("outer", reason=REASON)
        outer.__cause__ = inner

        assert reason_of(outer) is REASON

    def test_a_cause_is_read(self):
        cause = ScannerError("cause", reason=REASON)
        try:
            try:
                raise cause
            except ScannerError as caught:
                raise ValueError("wrapped") from caught
        except ValueError as wrapped:
            assert reason_of(wrapped) is REASON

    def test_a_context_is_read(self):
        """The template raises its wrapper inside its ``except`` block."""
        try:
            try:
                raise ScannerError("inner", reason=REASON)
            except ScannerError:
                raise ScannerError("outer")
        except ScannerError as outer:
            assert outer.reason is None
            assert outer.__cause__ is None
            assert reason_of(outer) is REASON

    def test_a_context_two_levels_down_is_read(self):
        try:
            try:
                try:
                    raise ScannerError("inner", reason=REASON)
                except ScannerError:
                    raise RuntimeError("middle")
            except RuntimeError:
                raise ScannerError("outer")
        except ScannerError as outer:
            assert reason_of(outer) is REASON

    def test_the_cause_is_read_before_the_context(self):
        cause = ScannerError("cause", reason=FailureReason(ReasonCode.NO_RESULT))
        context = ScannerError("context", reason=REASON)
        error = ScannerError("error")
        error.__cause__ = cause
        error.__context__ = context

        assert reason_of(error) == FailureReason(ReasonCode.NO_RESULT)

    def test_a_cause_is_followed_all_the_way_before_the_context(self):
        deep = ScannerError("deep", reason=FailureReason(ReasonCode.NO_RESULT))
        cause = ValueError("cause")
        cause.__context__ = deep
        context = ScannerError("context", reason=REASON)
        error = ScannerError("error")
        error.__cause__ = cause
        error.__context__ = context

        assert reason_of(error) == FailureReason(ReasonCode.NO_RESULT)

    def test_a_cycle_ends(self):
        first = RuntimeError("first")
        second = RuntimeError("second")
        first.__context__ = second
        second.__context__ = first

        assert reason_of(first) is None

    def test_a_cycle_does_not_hide_a_reason_beyond_it(self):
        first = RuntimeError("first")
        second = RuntimeError("second")
        first.__context__ = second
        second.__context__ = first
        second.__cause__ = ScannerError("end", reason=REASON)

        assert reason_of(first) is REASON

    def test_a_context_that_raise_from_none_hid_is_not_followed(self):
        try:
            try:
                raise ScannerError("inner", reason=REASON)
            except ScannerError:
                raise ScannerError("outer") from None
        except ScannerError as outer:
            assert outer.__suppress_context__ is True
            assert reason_of(outer) is None

    def test_a_reason_attribute_that_is_not_a_reason_is_ignored(self):
        """``UnicodeError.reason`` is a string; it is not a ``FailureReason``."""
        error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

        assert isinstance(error.reason, str)
        assert reason_of(error) is None

    def test_a_long_chain_is_read_to_its_end(self):
        error: BaseException = ScannerError("end", reason=REASON)
        for number in range(500):
            wrapper = RuntimeError(f"wrapper {number}")
            wrapper.__context__ = error
            error = wrapper

        assert reason_of(error) is REASON


class TestAFailureReasonNeverRaises:
    def test_the_sentence_is_kept_when_it_is_a_short_one(self):
        reason = FailureReason(ReasonCode.EXIT_CODE_REJECTED, "its tool exited with 2")

        assert reason.code == "exit_code_rejected"
        assert reason.sentence == "its tool exited with 2"

    def test_the_sentence_is_trimmed(self):
        assert FailureReason(ReasonCode.TIMED_OUT, "  it timed out  ").sentence == (
            "it timed out"
        )

    def test_a_reason_with_no_sentence_has_its_codes_default(self):
        reason = FailureReason(ReasonCode.NO_PLUGIN_CONTEXT)

        assert reason.sentence == DEFAULT_SENTENCES[ReasonCode.NO_PLUGIN_CONTEXT]
        assert reason.sentence == "it has no plugin context"

    @pytest.mark.parametrize(
        "sentence",
        [
            "could not read /etc/x",
            "could not read ~/x",
            "could not read C:\\x",
            "could not read \\\\h\\s",
            "two\nlines",
            "y" * 201,
            "",
            "   ",
            "bell\x07",
        ],
    )
    def test_a_sentence_that_is_not_fit_to_show_is_replaced_by_the_default(
        self, sentence
    ):
        reason = FailureReason(ReasonCode.TIMED_OUT, sentence)

        assert reason.sentence == DEFAULT_SENTENCES[ReasonCode.TIMED_OUT]
        assert reason.code == ReasonCode.TIMED_OUT

    def test_a_code_with_no_default_has_the_run_failed_sentence(self):
        reason = FailureReason("some_new_code", "could not read /etc/x")

        assert reason.code == "some_new_code"
        assert reason.sentence == FALLBACK_SENTENCE == "its run failed"

    @pytest.mark.parametrize(
        "code", ["", "Timed Out", "timed-out", "9lives", "a", "x" * 49]
    )
    def test_a_code_that_is_not_written_as_one_is_recorded_as_run_failed(self, code):
        reason = FailureReason(code, "it timed out")

        assert reason.code == ReasonCode.RUN_FAILED
        assert reason.sentence == "it timed out"

    @pytest.mark.parametrize("code", [None, 7, b"timed_out"])
    def test_a_code_that_is_not_a_string_does_not_raise(self, code):
        reason = FailureReason(code)  # type: ignore[arg-type]

        assert reason.code == ReasonCode.RUN_FAILED
        assert reason.sentence == FALLBACK_SENTENCE

    def test_a_sentence_that_is_not_a_string_does_not_raise(self):
        reason = FailureReason(ReasonCode.NO_RESULT, None)  # type: ignore[arg-type]

        assert reason.sentence == DEFAULT_SENTENCES[ReasonCode.NO_RESULT]

    def test_a_reason_is_frozen_and_compares_by_value(self):
        reason = FailureReason(ReasonCode.NO_RESULT)

        with pytest.raises(AttributeError):
            reason.sentence = "changed"  # type: ignore[misc]
        assert reason == FailureReason(ReasonCode.NO_RESULT)
        assert hash(reason) == hash(FailureReason(ReasonCode.NO_RESULT))

    def test_the_debug_line_for_a_replacement_does_not_quote_the_sentence(self):
        records: list[logging.LogRecord] = []

        class Collect(logging.Handler):
            def emit(self, record):
                records.append(record)

        logger = logging.getLogger("ash")
        handler = Collect(level=logging.DEBUG)
        before = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            FailureReason(ReasonCode.TIMED_OUT, "could not read /secret/place")
        finally:
            logger.removeHandler(handler)
            logger.setLevel(before)

        assert records, "a replacement leaves a DEBUG line"
        text = "\n".join(record.getMessage() for record in records)
        assert "secret" not in text
        assert "/secret/place" not in text
        assert {record.levelno for record in records} == {logging.DEBUG}

    def test_a_reason_survives_a_round_trip_through_pickle(self):
        reason = FailureReason(ReasonCode.TIMED_OUT, "it timed out after 300 s")

        assert pickle.loads(pickle.dumps(reason)) == reason
        assert copy.deepcopy(reason) == reason


class TestTheVocabulary:
    def test_every_code_is_written_as_a_code(self):
        codes = {
            value
            for name, value in vars(ReasonCode).items()
            if name.isupper() and isinstance(value, str)
        }

        assert codes
        assert all(is_reason_code(code) for code in codes), codes

    def test_every_code_has_a_default_sentence_fit_to_show(self):
        codes = {
            value
            for name, value in vars(ReasonCode).items()
            if name.isupper() and isinstance(value, str)
        }

        assert set(DEFAULT_SENTENCES) == codes
        for code, sentence in DEFAULT_SENTENCES.items():
            assert is_short_reason(sentence), (code, sentence)

    def test_no_code_is_defined_twice(self):
        values = [
            value
            for name, value in vars(ReasonCode).items()
            if name.isupper() and isinstance(value, str)
        ]

        assert len(values) == len(set(values))

    def test_a_code_is_the_string_itself_and_not_an_enum_member(self):
        assert type(ReasonCode.TIMED_OUT) is str
        assert f"{ReasonCode.TIMED_OUT}" == "timed_out"
        assert str(ReasonCode.TIMED_OUT) == "timed_out"

    @pytest.mark.parametrize(
        "code, expected",
        [
            ("timed_out", True),
            ("ab", True),
            ("a" + "b" * 47, True),
            ("a" + "b" * 48, False),
            ("a", False),
            ("Timed", False),
            ("timed out", False),
            ("1timed", False),
            ("", False),
            (None, False),
        ],
    )
    def test_what_a_code_looks_like(self, code, expected):
        assert is_reason_code(code) is expected


class TestControl:
    """The cases above can fail: a reason that keeps what it is given is caught."""

    def test_a_check_that_keeps_a_path_fails_the_replacement_case(self, monkeypatch):
        def replaced(sentence: str) -> bool:
            return FailureReason(ReasonCode.TIMED_OUT, sentence).sentence != sentence

        assert replaced("could not read /etc/x")

        monkeypatch.setattr(exceptions, "is_short_reason", lambda text: True)

        assert not replaced("could not read /etc/x")
