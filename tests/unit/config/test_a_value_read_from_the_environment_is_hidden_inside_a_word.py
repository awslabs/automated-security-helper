# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value read from the environment is hidden in free text by how long it is.

Free text names no field: a parser's message, a plugin's exception, a debug line
that prints a section whole. ``redact_values`` hides the values the config read
from the environment in it: an eight-character-or-longer value also inside a
longer word (``ASH_<value>_logs``), and a shorter one beside another value's
match. Each value is replaced by its band:

- under four characters, only where the text quotes it whole (``'x'`` or
  ``"x"``), the way a repr-printed input or an override's text shows it;
- four to seven characters, all word characters, as a whole word, which a
  quoted one is too: ``true`` is hidden, and the ``true`` in ``untrue`` is not.
  By default "_" bounds a word like any other non-alphanumeric character, so
  the value in ``ASH_<value>_logs`` IS a whole word and is hidden; only under
  the test-report rule (``_redact_for_test_reports``, the private entry point
  the backstop calls) is
  "_" a word character, so that value stays readable there (a CI host's
  ``USER=runner`` otherwise mangled test paths). The edge of another value's
  match still bounds a word, so two values run together, or one beside a
  hidden longer one, are hidden whole;
- eight characters or more, or four or more holding any other character
  (``/src``), anywhere, inside a longer word too. A piece of a long one, eight
  characters or more, is hidden where it touches "..." or "…", as a message
  that shortens a value prints it, and only as a whole word on its other side.

The bands keep a short value, or a common word inside longer ones, from taking
ASH's own words out of its messages. The replacement of a model error's own
input, which is the file's text and not the environment's, keeps to whole words
(``whole_words``) and leaves a value under four characters, so a message stays
readable.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.config_validator import (
    REDACTED,
    ConfigCheck,
    _redact_for_test_reports,
    redact_values,
)

#: Values read from the environment, eight characters each: replaced anywhere.
VALUE = "qzab1234"
OTHER = "1234cd56"
#: A value read from the environment shorter than MIN_REDACTED_LENGTH.
SHORT = "q7"


@pytest.mark.parametrize(
    "text, values, expected",
    [
        pytest.param(
            f"got 'ASH_{VALUE}_logs' here",
            [VALUE],
            f"got 'ASH_{REDACTED}_logs' here",
            id="inside-a-word",
        ),
        pytest.param(
            f"got '{VALUE}xy' here",
            [VALUE],
            f"got '{REDACTED}xy' here",
            id="before-a-word",
        ),
        pytest.param(
            f"got 'xy{VALUE}' here",
            [VALUE],
            f"got 'xy{REDACTED}' here",
            id="after-a-word",
        ),
        pytest.param(
            "got 'qzab1234cd56' here",
            [VALUE, OTHER],
            f"got '{REDACTED}' here",
            id="overlapping",
        ),
        pytest.param(
            "got 'xqzab1234cd56y' here",
            [VALUE, OTHER],
            f"got 'x{REDACTED}y' here",
            id="overlapping-inside-a-word",
        ),
        pytest.param(
            f"got '{VALUE}{VALUE}' here",
            [VALUE],
            f"got '{REDACTED}' here",
            id="twice",
        ),
        pytest.param(
            "checked /srcdir/app", ["/src"], f"checked {REDACTED}dir/app", id="non-word"
        ),
    ],
)
def test_a_long_value_inside_a_longer_word_is_hidden(text, values, expected):
    """Eight characters or more, or one holding a non-word character: anywhere."""
    redacted = redact_values(text, values)
    assert redacted == expected
    assert not [value for value in values if value in redacted]


@pytest.mark.parametrize(
    "text, expected",
    [
        pytest.param("the flag is true", f"the flag is {REDACTED}", id="whole-word"),
        pytest.param("got 'true'", f"got '{REDACTED}'", id="quoted"),
        pytest.param("this is untrue", "this is untrue", id="inside-a-word"),
    ],
)
def test_a_four_to_seven_character_word_is_hidden_as_a_whole_word(text, expected):
    """``${CI}`` read as "true": the word and its quoted form are hidden, the
    ``true`` inside ``untrue`` is not."""
    assert redact_values(text, ["true"]) == expected


@pytest.mark.parametrize(
    "value, text, hidden",
    [
        pytest.param("q7z", "got q7z here", False, id="3-chars-unquoted"),
        pytest.param("q7z", "got 'q7z' here", True, id="3-chars-quoted"),
        pytest.param("q7zx", "got q7zx here", True, id="4-chars-whole-word"),
        pytest.param("q7zx", "got xq7zxy here", False, id="4-chars-inside-a-word"),
        pytest.param("qzab123", "got qzab123 here", True, id="7-chars-whole-word"),
        pytest.param(
            "qzab123", "got xqzab123y here", False, id="7-chars-inside-a-word"
        ),
        pytest.param(
            "qzab1234", "got xqzab1234y here", True, id="8-chars-inside-a-word"
        ),
    ],
)
def test_the_band_boundaries(value, text, hidden):
    """3 against 4 characters, and 7 against 8."""
    assert (value not in redact_values(text, [value])) is hidden


def test_control_a_marker_already_in_the_text_is_left():
    """The marker's own word is not a value to find again: redacting twice
    changes nothing more."""
    text = f"got '{REDACTED}' and qzvalue1s here"
    assert redact_values(text, ["qzvalue1"]) == f"got '{REDACTED}' and {REDACTED}s here"
    once = redact_values(text, ["qzvalue1"])
    assert redact_values(once, ["qzvalue1"]) == once
    assert redact_values(f"got '{REDACTED}'", ["value"]) == f"got '{REDACTED}'"


def test_a_check_s_free_text_hides_a_value_inside_a_longer_word():
    """ConfigCheck.redact, which a refusal's free text goes through."""
    check = ConfigCheck(environment_values=[VALUE])
    assert VALUE not in check.redact(f"bucket ASH_{VALUE}_logs was not found")


def test_an_error_s_text_hides_a_value_inside_a_longer_word():
    """error_text and traceback_text, which a plugin's exception goes through."""
    from automated_security_helper.utils.error_text import error_text, traceback_text

    error = RuntimeError(f"bucket ASH_{VALUE}_logs was not found")
    assert VALUE not in error_text(error, [VALUE])
    try:
        raise error
    except RuntimeError as raised:
        assert VALUE not in traceback_text(raised, [VALUE])


def test_a_short_value_a_plugin_s_exception_quotes_is_hidden():
    """A two-character value, quoted in a plugin's exception: error_text and
    traceback_text, which the scan's log and results go through."""
    from automated_security_helper.utils.error_text import error_text, traceback_text

    error = RuntimeError(f"bucket '{SHORT}' was not found")
    assert error_text(error, [SHORT]) == f"bucket '{REDACTED}' was not found"
    try:
        raise error
    except RuntimeError as raised:
        assert f"'{SHORT}'" not in traceback_text(raised, [SHORT])


def test_a_short_value_a_parser_s_message_quotes_is_hidden():
    """A two-character value a parser's message quotes in double quotes, in a
    refusal's free text (ConfigCheck.redact)."""
    check = ConfigCheck(environment_values=[SHORT])
    assert check.redact(f'expected a mapping, found "{SHORT}" at line 3') == (
        f'expected a mapping, found "{REDACTED}" at line 3'
    )


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(f"a scan ignores {SHORT} here", id="unquoted"),
        pytest.param(f"got 'x{SHORT}' here", id="quoted-with-more"),
        pytest.param(f"got '{SHORT}\" here", id="mismatched-quotes"),
    ],
)
def test_control_a_short_value_not_quoted_whole_is_left(text):
    """Unquoted, or part of a longer quoted text, a short value is left, so a
    short value does not take ASH's own words out of its messages."""
    assert redact_values(text, [SHORT]) == text


def test_the_band_is_the_form_a_message_prints():
    """``build/`` is printed without its slash (``build/**``), and that form is
    five word characters: a whole word, so "rebuild" keeps its "build". The band
    is chosen from the form matched, not from the value with its slash."""
    text = "the rebuild ran: use 'build/**' or build"
    assert redact_values(text, ["build/"]) == (
        f"the rebuild ran: use '{REDACTED}/**' or {REDACTED}"
    )


@pytest.mark.parametrize(
    "value, text, expected",
    [
        pytest.param(
            VALUE, "got QZAB1234 here", f"got {REDACTED} here", id="long-upper-cased"
        ),
        pytest.param("true", "the flag is TRUE", f"the flag is {REDACTED}", id="word"),
        pytest.param(
            SHORT, "got 'Q7' here", f"got '{REDACTED}' here", id="short-quoted"
        ),
    ],
)
def test_a_case_changed_value_is_hidden(value, text, expected):
    """A message can print a value in another case (a validator upper-cases its
    input): it is the value all the same."""
    assert redact_values(text, [value]) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        pytest.param(f"got `{SHORT}` here", f"got `{REDACTED}` here", id="backticks"),
        pytest.param(
            f'{{"msg": "found \\"{SHORT}\\" here"}}',
            f'{{"msg": "found \\"{REDACTED}\\" here"}}',
            id="json-escaped-quotes",
        ),
        pytest.param(
            f"found \\'{SHORT}\\' here",
            f"found \\'{REDACTED}\\' here",
            id="escaped-single-quotes",
        ),
    ],
)
def test_a_short_value_quoted_another_way_is_hidden(text, expected):
    """Backticks quote a value as the quotes do, and a JSON string escapes its
    quotes: ``\\"q7\\"``."""
    assert redact_values(text, [SHORT]) == expected


#: A long value read from the environment, which a message can cut.
LONG = "qzab1234secretvaluelong5678"


@pytest.mark.parametrize(
    "text, expected",
    [
        pytest.param(
            "input 'qzab1234secr...' refused",
            f"input '{REDACTED}...' refused",
            id="prefix-then-dots",
        ),
        pytest.param(
            "input 'qzab1234secr…' refused",
            f"input '{REDACTED}…' refused",
            id="prefix-then-ellipsis",
        ),
        pytest.param(
            "input 'qzab1234se...uelong5678' refused",
            f"input '{REDACTED}...{REDACTED}' refused",
            id="both-ends",
        ),
    ],
)
def test_a_long_value_a_message_cuts_is_hidden(text, expected):
    """A message that shortens a long value (pydantic keeps its two ends around
    "...") prints a part of it, eight characters or more."""
    redacted = redact_values(text, [LONG])
    assert redacted == expected
    assert "qzab1234" not in redacted
    assert "uelong5678" not in redacted


@pytest.mark.parametrize(
    "text, expected",
    [
        pytest.param(
            "input ASH_qzab1234secr... refused",
            f"input ASH_{REDACTED}... refused",
            id="piece-after-an-underscore",
        ),
        pytest.param(
            "input ...tvaluelong5678_LOGS refused",
            f"input ...{REDACTED}_LOGS refused",
            id="piece-before-an-underscore",
        ),
    ],
)
def test_a_cut_piece_bounded_by_an_underscore_is_hidden(text, expected):
    """ "_" still bounds a long cut piece's far side (``_bounds_strict``):
    eight characters or more of a long value's own print beside a marker is a
    real cut, not a word that happens to match, so the piece glued by "_" is
    hidden on its own. This cell runs the DEFAULT rule, where "_" bounds the
    whole-word band too; the next cell pins the same far-side rule under the
    test-report rule, the one place the band reads "_" as part of a word."""
    assert redact_values(text, [LONG]) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        pytest.param(
            "input ASH_qzab1234secr... refused",
            f"input ASH_{REDACTED}... refused",
            id="piece-after-an-underscore",
        ),
        pytest.param(
            "input ...tvaluelong5678_LOGS refused",
            f"input ...{REDACTED}_LOGS refused",
            id="piece-before-an-underscore",
        ),
    ],
)
def test_a_cut_piece_s_far_side_reads_the_strict_rule_under_the_report_rule(
    text, expected
):
    """The test-report rule loosens whole-word bounding for FULL values, never
    for a long value's cut pieces: eight or more characters of the value's own
    print beside a marker is a real cut whichever rule the text is read under,
    so "_" on the piece's far side still bounds (``_bounds_strict``) and the
    piece hides. Reading the far side with the report rule instead would glue
    the 12-character piece to the word past the "_" and print it."""
    assert _redact_for_test_reports(text, [LONG]) == expected


@pytest.mark.parametrize(
    "text, value",
    [
        pytest.param(
            "allowed in production", "production-eu-west-1", id="last-word-of-a-message"
        ),
        pytest.param(
            "allowed in PRODUCTION", "production-eu-west-1", id="last-word-upper-cased"
        ),
        pytest.param(
            "found a misconfiguration",
            "configuration_path_override",
            id="end-of-a-longer-word",
        ),
        pytest.param(
            "...productions and more", "xx-production", id="start-of-a-word-after-dots"
        ),
        pytest.param(
            "…productions", "xx-production", id="start-of-a-word-after-an-ellipsis"
        ),
        pytest.param(
            "written to /repo/.ash/ash_output",
            "/repo/.ash/ash_output/run1",
            id="a-path-s-parent-at-the-end",
        ),
        pytest.param("ends with qzab1234secr", LONG, id="a-piece-at-the-end"),
    ],
)
def test_control_a_word_a_long_value_starts_or_ends_with_is_left(text, value):
    """A piece of a long value is hidden only where it touches "..." or "…", and
    only as a whole word on its other side. A message that ends in a word, or a
    longer word that holds a piece, is far more common than a value cut with no
    marker, and the marker is what shows a cut."""
    assert redact_values(text, [value]) == text


def test_a_whole_word_touching_dots_that_starts_a_long_value_is_hidden():
    """The known over-hide. A word of eight characters or more that touches
    "..." and that a long value starts with reads exactly as a message that cut
    the value there: "settings..." could be "settings_override_file" shortened.
    Hiding it is the safe way to be wrong."""
    assert redact_values("Loading settings... done", ["settings_override_file"]) == (
        f"Loading {REDACTED}... done"
    )


def test_a_cut_piece_run_into_another_value_is_hidden():
    """A cut piece run into another value's match is hidden with it: either
    alone would be shown, and together each holds the other up, as two whole
    values run together do (the piece's far side takes another match's edge
    for the text's)."""
    long_value = "qzab1234secretvaluelong5678"
    assert redact_values("got qz4bqzab1234secr... here", ["qz4b", long_value]) == (
        f"got {REDACTED}... here"
    )
    assert redact_values("got ...valuelong5678qz4b here", ["qz4b", long_value]) == (
        f"got ...{REDACTED} here"
    )


def test_a_value_holding_dots_is_hidden_whole_beside_a_value_it_starts():
    """The cut piece of one value and the full form of another start at the same
    place: the full form is hidden too, not only the piece."""
    text = "got abcdefgh...zzyy here"
    assert redact_values(text, ["abcdefghXXXXXXXXXXXX", "abcdefgh...zzyy"]) == (
        f"got {REDACTED} here"
    )


#: A second long value read from the environment.
OTHER_LONG = "zyxw9876othersecretvalue4321"


@pytest.mark.parametrize(
    ("text", "values"),
    [
        pytest.param(
            "got ...valuelong5678zyxw9876othe... here",
            [LONG, OTHER_LONG],
            id="two-values-cut-at-both-ends",
        ),
        pytest.param(
            "got ...valuelong5678qzab1234secr... here",
            [LONG],
            id="one-value-end-then-start",
        ),
        pytest.param(
            "got ...cretvaluelong5678zyxw9876other... here",
            [LONG, OTHER_LONG, LONG + OTHER_LONG],
            id="a-composite-cut-at-both-ends",
        ),
    ],
)
def test_two_cut_pieces_run_together_are_hidden(text, values):
    """A message that cuts at both ends can show the end of one value run into
    the start of another, with no full match beside them. Each piece's far side
    is the other piece, so the two hold each other up and are hidden as one run,
    as two whole values run together are."""
    assert redact_values(text, values) == f"got ...{REDACTED}... here"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "got ...1234secretvaluelong5... here",
            f"got ...{REDACTED}... here",
            id="a-middle-window-of-the-value",
        ),
        pytest.param(
            "got ...1234SECRETVALUELONG5… here",
            f"got ...{REDACTED}… here",
            id="a-middle-window-in-another-case",
        ),
    ],
)
def test_a_window_cut_at_both_ends_inside_a_value_is_hidden(text, expected):
    """A message that cuts a long value at both ends prints a part from its
    middle, between two markers. A part of eight characters or more that the
    value holds is hidden, as its cut start and cut end are."""
    assert redact_values(text, [LONG]) == expected


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "got ...somethingelseentirely... here", id="not-a-part-of-the-value"
        ),
        pytest.param("got ...1234sec... here", id="shorter-than-eight"),
    ],
)
def test_control_a_window_no_value_holds_is_left(text):
    """A window between two markers that no value holds, or one shorter than the
    eight characters a cut piece needs, is left as it is."""
    assert redact_values(text, [LONG]) == text


#: Two long values printed back to back and cut at both ends, and a short one.
RUN_A = "aqbwcedrftgyhuji"
RUN_B = "5839201746583920"
RUN_C = "kq7zw"


@pytest.mark.parametrize(
    ("window", "markers"),
    [
        pytest.param(RUN_A[-6:] + RUN_B[:6], ("...", "..."), id="six-and-six"),
        pytest.param(RUN_A[-4:] + RUN_B[:12], ("...", "..."), id="four-and-twelve"),
        pytest.param(RUN_A[-12:] + RUN_B[:4], ("...", "..."), id="twelve-and-four"),
        pytest.param(RUN_A[-4:] + RUN_B[:4], ("...", "..."), id="four-and-four"),
        pytest.param(RUN_A[-7:] + RUN_B[:7], ("…", "…"), id="seven-and-seven"),
        pytest.param(
            RUN_A[-5:] + RUN_C + RUN_B[:5], ("...", "..."), id="five-five-five"
        ),
        pytest.param(RUN_A[-10:] + RUN_B[:10], ("...", "..."), id="ten-and-ten"),
    ],
)
def test_two_values_cut_short_and_run_together_are_hidden(window, markers):
    """A message that cuts two values printed back to back can leave as little
    as four characters of one beside the other. A piece of four to seven
    characters at a value's end, touching a marker, is held up by the match it
    runs into, and a run of such pieces and matches, eight characters or more,
    is hidden whole."""
    opening, closing = markers
    text = f"got {opening}{window}{closing} here"
    assert redact_values(text, [RUN_A, RUN_B, RUN_C]) == (
        f"got {opening}{REDACTED}{closing} here"
    )


@pytest.mark.parametrize(
    ("window", "values"),
    [
        pytest.param(RUN_A[-3:] + RUN_B[:12], [RUN_A, RUN_B], id="three-and-twelve"),
        pytest.param(RUN_A[-12:] + RUN_B[:3], [RUN_A, RUN_B], id="twelve-and-three"),
        pytest.param(RUN_A[-3:] + RUN_B[:3], [RUN_A, RUN_B], id="three-and-three"),
        pytest.param(RUN_A[-4:] + RUN_B[:3], [RUN_A, RUN_B], id="four-and-three"),
        pytest.param(
            RUN_A[-6:] + "x" + RUN_B[:6], [RUN_A, RUN_B], id="a-letter-between"
        ),
        pytest.param(RUN_A[-6:] + RUN_B[:6], [RUN_A], id="only-one-value-listed"),
        pytest.param(RUN_A[-4:], [RUN_A, RUN_B], id="four-characters-alone"),
    ],
)
def test_control_a_short_cut_piece_with_no_run_is_left(window, values):
    """A piece under four characters is never one, so a piece beside it has
    nothing to stand by; a run of seven characters is under the floor; a
    character no value holds breaks the run; text no listed value starts with is
    no piece; and four characters of a value's end alone read as a chance
    match. Each is left as it is."""
    text = f"got ...{window}... here"
    assert redact_values(text, values) == text


#: A value read from the environment far longer than a message prints it: a
#: token, a certificate or a JSON document.
HUGE = "qzab1234" * 250


def test_a_long_value_a_message_cuts_is_hidden_whatever_its_length():
    """The cut pieces of a 2000-character value are found and hidden, past the
    length at which a pattern with one group per character would reach the
    regex parser's recursion limit (about 500 characters)."""
    text = "input '" + HUGE[:12] + "...' refused"
    assert redact_values(text, [HUGE]) == f"input '{REDACTED}...' refused"
    assert redact_values(f"got ...{HUGE[-12:]} here", [HUGE]) == (
        f"got ...{REDACTED} here"
    )


@pytest.mark.parametrize(
    ("text", "values"),
    [
        pytest.param("abcd" * 1600 + "1", ["abcd"], id="one-form-chained"),
        pytest.param("A" * 800 + "1", ["AAAA"], id="one-letter-run"),
    ],
)
def test_a_chain_of_banded_matches_resolves_in_bounded_time(text, values):
    """A run of matches that stand only by one another, ended by a digit, all
    fall, and in time bounded by the matches, not by re-scanning every one for
    each one dropped: each dropped match re-checks its neighbors only."""
    import time

    started = time.monotonic()
    result = redact_values(text, values)
    elapsed = time.monotonic() - started
    assert result == text
    assert elapsed < 1.0, elapsed


def _greatest_fixed_point(
    text, candidates, fixed, short=(), underscore_joins_words=False
):
    """The plain fixed point, for the property cells: drop every candidate that
    an edge rule fails, and every one of *short* (indices into *candidates*)
    whose run of standing and fixed matches is under eight characters; re-check
    them all, and stop when none drops.

    The edge rule is written independently of the fixed point's own witness
    arithmetic, as a regex over a MASKED copy of the text: every character a
    fixed match or a standing candidate covers is replaced by NUL (a non-word
    character), so "covered" and "bounds a word" read as one pattern. Under
    the strict rule (the default) a side is closed when its masked context
    ends (starts) with nothing or any non-alphanumeric character, "_"
    included. Under the test-report rule it is closed on nothing, a non-word
    character, a single "_" whose far side is one of those, or a run of two
    or more "_" whose far side is nothing or a COVERED character only;
    anything else leaves the side open and the candidate drops.

    A "_" a fixed match covers is marker text, so it closes the side like
    any covered character: this oracle reads it so through the mask (a
    covered "_" is NUL), and the product's walk stops at a covered "_" the
    same way (``test_a_covered_underscore_closes_the_side``)."""
    import re

    def word(character):
        if underscore_joins_words:
            return re.match(r"\w", character) is not None
        return character.isalnum()

    def run_length(start, end, spans):
        """The length of the run of overlapping or touching *spans* that holds
        the span from *start* to *end*."""
        grown = True
        while grown:
            grown = False
            for o_start, o_end in spans:
                touches = o_start <= end and o_end >= start
                if touches and (o_start < start or o_end > end):
                    start, end = min(start, o_start), max(end, o_end)
                    grown = True
        return end - start

    if underscore_joins_words:
        _LEFT_CLOSED = re.compile(r"(?:\A|\W|(?:\A|\W)_|(?:\A|\x00)_{2,})\Z", re.DOTALL)
        _RIGHT_CLOSED = re.compile(
            r"\A(?:\Z|\W|_(?:\W|\Z)|_{2,}(?:\x00|\Z))", re.DOTALL
        )
    else:
        _LEFT_CLOSED = re.compile(r"(?:\A|\W|_)\Z", re.DOTALL)
        _RIGHT_CLOSED = re.compile(r"\A(?:\Z|\W|_)", re.DOTALL)

    def closed(masked, start, end, left):
        if left:
            if not word(text[start]):
                return True
            return _LEFT_CLOSED.search(masked[:start]) is not None
        if not word(text[end - 1]):
            return True
        return _RIGHT_CLOSED.match(masked[end:]) is not None

    standing = list(range(len(candidates)))
    changed = True
    while changed:
        changed = False
        kept = []
        others = fixed + [candidates[i] for i in standing]
        spans = [(o_start, o_end) for o_start, o_end, _ in others]
        masked = list(text)
        for o_start, o_end in spans:
            for position in range(o_start, min(o_end, len(masked))):
                masked[position] = "\x00"
        masked = "".join(masked)
        for i in standing:
            start, end, _ = candidates[i]
            long_enough = i not in short or run_length(start, end, spans) >= 8
            if (
                closed(masked, start, end, True)
                and closed(masked, start, end, False)
                and long_enough
            ):
                kept.append(i)
            else:
                changed = True
        standing = kept
    return [candidates[i] for i in standing]


#: The pinned base seed per property test, plus the three seeds that
#: disagreed with the oracle before a covered "_" closed the side under the
#: test-report rule (the standing-cover class) -- committed so that class
#: stays red if it ever reopens.
_PROPERTY_EXTRA_SEEDS = (6, 10, 12)


@pytest.mark.parametrize("seed", [0, *_PROPERTY_EXTRA_SEEDS])
@pytest.mark.parametrize("joined", [False, True], ids=["strict", "test-report"])
def test_the_standing_matches_are_the_greatest_fixed_point(joined, seed):
    """Property: the four- to seven-character matches kept as whole words equal
    the plain fixed point, dropping any unsupported match and re-checking them
    all until none drops, over seeded random texts."""
    import random

    from automated_security_helper.config.config_validator import _whole_word_spans

    brute = _greatest_fixed_point
    rng = random.Random(seed)
    forms = ["qzab", "rk5c", "qz4b_x"]
    alphabet = "qzab rk5c_14x."
    checked = 0
    for case in range(100):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(8, 60)))
        for _ in range(rng.randrange(0, 4)):
            at = rng.randrange(len(text))
            text = text[:at] + rng.choice(forms) + text[at:]
        candidates = [
            (match.start(1), match.end(1), form)
            for form in forms
            for match in __import__("re").finditer(
                f"(?=({__import__('re').escape(form)}))", text
            )
        ]
        fixed = []
        if candidates and rng.random() < 0.3:
            start = rng.randrange(len(text))
            fixed = [(start, min(len(text), start + rng.randrange(1, 9)), "F")]
        checked += len(candidates)
        assert _whole_word_spans(
            text, candidates, fixed, underscore_joins_words=joined
        ) == brute(text, candidates, fixed, underscore_joins_words=joined), (
            text,
            candidates,
            fixed,
        )
    assert checked > 100


@pytest.mark.parametrize("seed", [1, *_PROPERTY_EXTRA_SEEDS])
@pytest.mark.parametrize("joined", [False, True], ids=["strict", "test-report"])
def test_the_standing_matches_with_long_pieces_are_the_greatest_fixed_point(
    joined, seed
):
    """The same property with candidates of eight characters or more beside the
    short ones, as cut pieces are: each ends where a "." begins or starts where
    one ends, so its far side is the only edge that can fail. They overlap,
    nest and run into one another and into the short matches."""
    import random
    import re

    from automated_security_helper.config.config_validator import _whole_word_spans

    rng = random.Random(seed)
    forms = ["qzab", "rk5c", "qz4b_x"]
    alphabet = "qzab rk5c_14x"
    longs_checked = 0
    for case in range(200):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(20, 80)))
        for _ in range(rng.randrange(1, 4)):
            at = rng.randrange(len(text))
            text = text[:at] + "..." + text[at:]
        for _ in range(rng.randrange(0, 4)):
            at = rng.randrange(len(text))
            text = text[:at] + rng.choice(forms) + text[at:]
        candidates = [
            (match.start(1), match.end(1), form)
            for form in forms
            for match in re.finditer(f"(?=({re.escape(form)}))", text)
        ]
        dots = [match.start() for match in re.finditer(r"\.\.\.", text)]
        for dot in dots:
            for _ in range(rng.randrange(1, 6)):
                length = rng.randrange(8, 20)
                if rng.random() < 0.5 and dot - length >= 0:
                    candidates.append((dot - length, dot, "L"))
                elif dot + 3 + length <= len(text):
                    candidates.append((dot + 3, dot + 3 + length, "L"))
        longs_checked += sum(1 for _, _, label in candidates if label == "L")
        fixed = []
        if rng.random() < 0.3:
            start = rng.randrange(len(text))
            fixed = [(start, min(len(text), start + rng.randrange(1, 12)), "F")]
        assert _whole_word_spans(
            text, candidates, fixed, underscore_joins_words=joined
        ) == _greatest_fixed_point(
            text, candidates, fixed, underscore_joins_words=joined
        ), (text, candidates, fixed)
    assert longs_checked > 500


@pytest.mark.parametrize("seed", [2, *_PROPERTY_EXTRA_SEEDS])
@pytest.mark.parametrize("joined", [False, True], ids=["strict", "test-report"])
def test_the_standing_matches_with_short_pieces_are_the_greatest_fixed_point(
    joined, seed
):
    """The same property with cut pieces of four to seven characters beside the
    long ones and the banded matches: a short piece stands only in a run of
    eight characters or more, so one that falls for its run takes down the
    matches that leaned on it, and nothing else."""
    import random
    import re

    from automated_security_helper.config.config_validator import _whole_word_spans

    rng = random.Random(seed)
    forms = ["qzab", "rk5c", "qz4b_x"]
    alphabet = "qzab rk5c_14x"
    shorts_checked = 0
    shorts_standing = 0
    shorts_fallen_for_their_run = 0
    for case in range(300):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(10, 60)))
        for _ in range(rng.randrange(1, 5)):
            at = rng.randrange(len(text))
            text = text[:at] + "..." + text[at:]
        for _ in range(rng.randrange(0, 3)):
            at = rng.randrange(len(text))
            text = text[:at] + rng.choice(forms) + text[at:]
        candidates = [
            (match.start(1), match.end(1), form)
            for form in forms
            for match in re.finditer(f"(?=({re.escape(form)}))", text)
        ]
        short = set()
        for dot in [match.start() for match in re.finditer(r"\.\.\.", text)]:
            for _ in range(rng.randrange(1, 5)):
                length = rng.randrange(4, 20)
                if rng.random() < 0.5 and dot - length >= 0:
                    piece = (dot - length, dot, "P")
                elif dot + 3 + length <= len(text):
                    piece = (dot + 3, dot + 3 + length, "P")
                else:
                    continue
                if length < 8:
                    short.add(len(candidates))
                candidates.append(piece)
        fixed = []
        if rng.random() < 0.3:
            start = rng.randrange(len(text))
            fixed = [(start, min(len(text), start + rng.randrange(1, 6)), "F")]
        standing = _whole_word_spans(
            text, candidates, fixed, sorted(short), underscore_joins_words=joined
        )
        assert standing == _greatest_fixed_point(
            text, candidates, fixed, short, underscore_joins_words=joined
        ), (
            text,
            candidates,
            fixed,
            short,
        )
        shorts_checked += len(short)
        shorts_standing += sum(1 for i in short if candidates[i] in standing)
        without_floor = _greatest_fixed_point(
            text, candidates, fixed, underscore_joins_words=joined
        )
        shorts_fallen_for_their_run += sum(
            1
            for i in short
            if candidates[i] in without_floor and candidates[i] not in standing
        )
    assert shorts_checked > 300
    assert shorts_standing > 20
    assert shorts_fallen_for_their_run > 20


@pytest.mark.parametrize("seed", [3, 4, *_PROPERTY_EXTRA_SEEDS])
@pytest.mark.parametrize("joined", [False, True], ids=["strict", "test-report"])
def test_the_standing_matches_on_underscore_runs_are_the_greatest_fixed_point(
    joined, seed
):
    """The same property on texts heavy in "_", with four- to seven-character
    candidates at arbitrary positions (all-"_" ones inside runs among them),
    an optional fixed span and an optional short marking. The other property
    generators anchor candidates at value forms, so they rarely form the shape
    where a standing candidate covers an inner "_" of a run: this one forms it
    often, and a revert of either side's multi-point witnesses goes red here
    where the hand cells cover one side each. Seeds 6 and 12 hold the left
    side's multi-point shapes; seed 4 holds the right side's (its case 88 is
    one whose candidates are word characters only), so neither side's
    witnesses rest on hand cells alone."""
    import random

    from automated_security_helper.config.config_validator import _whole_word_spans

    rng = random.Random(seed)
    for case in range(400):
        text = "".join(
            rng.choice("__________ab4 .") for _ in range(rng.randrange(8, 28))
        )
        candidates = []
        for _ in range(rng.randrange(1, 6)):
            length = rng.randrange(4, 8)
            if length > len(text):
                continue
            start = rng.randrange(0, len(text) - length + 1)
            candidates.append((start, start + length, f"C{len(candidates)}"))
        fixed = []
        if rng.random() < 0.3:
            start = rng.randrange(len(text))
            fixed = [(start, min(len(text), start + rng.randrange(1, 6)), "F")]
        short = set()
        if candidates and rng.random() < 0.2:
            short.add(rng.randrange(len(candidates)))
        assert _whole_word_spans(
            text, candidates, fixed, sorted(short), underscore_joins_words=joined
        ) == _greatest_fixed_point(
            text, candidates, fixed, short, underscore_joins_words=joined
        ), (text, candidates, fixed, short)


def test_the_cut_pieces_of_a_one_letter_value_are_found_in_bounded_time():
    """_cut_pieces over a 100000-character one-letter value printed before
    "...": the match lengths come from one linear scan per form, not a search
    at every occurrence. The one piece bounded on its far side is the whole
    value."""
    import time

    from automated_security_helper.config.config_validator import (
        _cut_pieces,
        _folded,
    )

    value = "a" * 100000
    text = value + "..."
    folded = _folded(text)
    started = time.monotonic()
    pieces = _cut_pieces(text, folded, value, [100000], [100003])
    elapsed = time.monotonic() - started
    assert [(start, end) for start, end, far_ok, _ in pieces if far_ok] == [(0, 100000)]
    assert elapsed < 1.0, elapsed


def test_a_long_value_is_hidden_in_bounded_time():
    """A 20000-character value over a long text with many cuts."""
    import time

    value = "qzab1234" * 2500
    text = ("input '" + value[:40] + "...' and ..." + value[-40:] + " ") * 200
    started = time.monotonic()
    redacted = redact_values(text, [value])
    assert time.monotonic() - started < 10
    assert value[:12] not in redacted
    assert value[-12:] not in redacted


def test_a_one_letter_value_a_message_cuts_is_hidden_in_bounded_time():
    """The one-letter value of the _cut_pieces cell above, through redact_values:
    every cut piece that starts inside the value's own full match lies inside a
    span already hidden, so none of them joins the whole-word fixed point.

    It is timed by how the time grows, not by a second on the clock: a bound of 2.0 s
    read 2.0039 s and 2.0175 s on two CI runs while the same code passed on others, so
    the host's load decided it and not the code. A value of 5000 letters and
    one of 20000, four times as long, are each hidden. Time linear in the length takes
    four times as long for the second; time in its square, which is what the cut
    pieces joining the fixed point cost, sixteen times. The second must be under eight
    times the first plus a tenth of a second (the floor for a first run so short that
    a pause shows), and eight sits between four and sixteen. Load that slows both runs
    slows them alike, and the ratio keeps its place. The shortest of three runs of
    each is timed (``_best_time``), and a run is cut off at its limit, so a square is
    ended at that limit and not run for minutes."""
    first_length, second_length = 5000, 20000
    absolute_bound = 30.0
    first = _best_time(
        "a" * first_length + "...",
        ["a" * first_length],
        f"{REDACTED}...",
        absolute_bound,
    )
    limit = 8 * first + 0.1
    second = _best_time(
        "a" * second_length + "...",
        ["a" * second_length],
        f"{REDACTED}...",
        absolute_bound,
        limit,
    )
    assert second < limit, (
        f"{second_length} letters took {second:.3f} s against {limit:.3f} s, "
        f"8 times the {first:.3f} s of {first_length} letters plus 0.1 s"
    )


#: Thirty long values a message never prints.
ABSENT = [f"absentvalue{n:02d}qwertyuiop12" for n in range(30)]


def test_long_values_a_message_never_prints_cost_no_cut_piece_work():
    """A cut piece starts where a value's start occurs, or ends where its end
    does. A value whose start and end occur nowhere in the text has no pieces,
    so none of its match lengths are computed, however long the text is."""
    import time

    text = "word " * 30000 + "..." + "tail " * 30000
    started = time.monotonic()
    redacted = redact_values(text, ABSENT)
    elapsed = time.monotonic() - started
    assert redacted == text
    assert elapsed < 1.0, elapsed


@pytest.mark.parametrize(
    ("text", "values", "options", "expected"),
    [
        pytest.param(
            "a" * 100000 + "...",
            ["a" * 100000],
            {},
            f"{REDACTED}...",
            id="a-cut-value-of-one-letter",
        ),
        pytest.param(
            "a" * 100000,
            ["a" * 100001],
            {},
            "a" * 100000,
            id="a-run-one-letter-short-of-the-value",
        ),
        pytest.param(
            "a" * 100000,
            ["a" * 100001],
            {"whole_words": True, "ignore_case": True},
            "a" * 100000,
            id="the-same-run-matched-as-whole-words-in-any-case",
        ),
    ],
)
def test_a_long_value_beside_a_long_run_of_its_letter_is_matched_in_bounded_time(
    text, values, options, expected
):
    """A long value matched in any case, over a text that is a long run of the
    value's own letter: each position's attempt at the value runs to the end of
    the run before it fails, so trying the value at every position costs time
    in the square of the run. A long value is found in time linear in the
    text instead. The whole-word case is a guard rather than a regression
    cell: there the pattern's lookbehind fails at every position but the
    first, so it was linear before too, and it is kept so."""
    import time

    started = time.monotonic()
    result = redact_values(text, values, **options)
    elapsed = time.monotonic() - started
    assert result == expected
    assert elapsed < 2.0, elapsed


def test_a_long_form_is_found_where_the_pattern_finds_it():
    """Property: a form too long for the one pattern is found exactly where a
    lookahead pattern of it finds it, overlapping places included, in any case
    by re's own rules (a long s matches "s", the Kelvin sign "k", a dotted
    capital I "i") and as a whole word with whole_words, over seeded random
    texts that print the forms in other cases."""
    import random
    import re

    from automated_security_helper.config.config_validator import (
        _LONG_FORM_LENGTH,
        _long_form_spans,
    )

    exotic = "".join(
        chr(code)
        for code in (0x17F, 0x212A, 0x130, 0x131, 0xDF, 0x1E9E, 0x3A3, 0x3C3, 0x3C2)
    ) + "".join(chr(code) for code in (0xB5, 0x3BC))
    alphabet = "aAsSkKiI _-1." + exotic
    swaps = {ord("s"): chr(0x17F), ord("k"): chr(0x212A), ord("I"): chr(0x130)}
    rng = random.Random(3)
    found = 0
    for case in range(150):
        forms = [
            "".join(
                rng.choice(alphabet)
                for _ in range(_LONG_FORM_LENGTH + rng.randrange(1, 12))
            )
            for _ in range(rng.randrange(1, 3))
        ]
        parts = []
        for _ in range(rng.randrange(1, 5)):
            form = rng.choice(forms)
            parts.append(
                rng.choice(
                    [
                        form,
                        form.upper(),
                        form.lower(),
                        form.translate(swaps),
                        "".join(
                            c.swapcase() if rng.random() < 0.5 else c for c in form
                        ),
                    ]
                )
            )
            parts.append(
                "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 8)))
            )
        text = "".join(parts)
        for whole_words, flags in (
            (False, re.IGNORECASE),
            (True, 0),
            (True, re.IGNORECASE),
        ):
            expected = set()
            for form in forms:
                before = r"(?<!\w)" if whole_words and re.match(r"\w", form[0]) else ""
                after = r"(?!\w)" if whole_words and re.match(r"\w", form[-1]) else ""
                pattern = f"(?=({before}{re.escape(form)}{after}))"
                expected.update(m.span(1) for m in re.finditer(pattern, text, flags))
            spans = _long_form_spans(text, forms, flags, whole_words)
            assert set(spans) == expected, (text, forms, whole_words, flags)
            found += len(expected)
    assert found > 100


def test_the_folded_text_is_each_character_lowered_alone():
    """Property: _folded gives each character's own lower case, or the character
    where that is longer, at the same index, for ASCII texts (lowered in one
    call) and others alike. A final sigma is folded alone, as "σ", where
    str.lower would give "ς" from its neighbors."""
    import random

    from automated_security_helper.config.config_validator import _folded

    def one_at_a_time(text):
        return "".join(c if len(c.lower()) != 1 else c.lower() for c in text)

    rng = random.Random(5)
    ascii_alphabet = "aAzZ09 _-./\0\t~"
    wide_alphabet = ascii_alphabet + "İıΣσςßKKſ"
    for alphabet in (ascii_alphabet, wide_alphabet):
        for _ in range(300):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 40)))
            assert _folded(text) == one_at_a_time(text), repr(text)
            assert len(_folded(text)) == len(text)
    assert _folded("ΑΣ ab") == "ασ ab"
    assert _folded("QZAB1234") == "qzab1234"


def test_the_window_prefilter_is_built_only_up_to_its_cap():
    """The set of every eight-character run of the listed values costs 81-121
    bytes a character, so it is built only while the values hold at most
    _PREFILTER_LISTED_CHARACTERS characters. Past that, no set is built and each
    window is searched for in the values directly, as before the set existed."""
    from automated_security_helper.config.config_validator import (
        _PREFILTER_LISTED_CHARACTERS,
        _window_prefilter,
    )

    under = [("v", "a" * 100 + "bcdefghij")]
    built = _window_prefilter(under)
    assert built is not None and "bcdefghi" in built
    at_cap = [("v", "x" * _PREFILTER_LISTED_CHARACTERS)]
    assert _window_prefilter(at_cap) is not None
    over = [
        ("a", "a" * (_PREFILTER_LISTED_CHARACTERS // 2)),
        ("b", "b" * (_PREFILTER_LISTED_CHARACTERS // 2 + 1)),
    ]
    assert _window_prefilter(over) is None


def test_values_past_the_prefilter_cap_add_no_prefilter_memory():
    """Values holding about twice _PREFILTER_LISTED_CHARACTERS characters, with
    four thousand parts cut at both ends: the peak of what redact_values
    allocates stays well under what the set of their eight-character runs
    would take (about 50 MiB), and the text comes back as it was."""
    import random
    import tracemalloc

    rng = random.Random(202)
    alphabet = "abcdefghijklmnopqrstuvwxy0123456789"
    values = ["".join(rng.choice(alphabet) for _ in range(2000)) for _ in range(300)]
    text = "..." + "".join(f"z{i:07d}zzzzzzzzzzzzzz..." for i in range(4000))
    tracemalloc.start()
    try:
        result = redact_values(text, values)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == text
    assert peak < 16 * 2**20, peak


@pytest.mark.parametrize("upper", [False, True], ids=["as-listed", "upper-cased"])
def test_a_window_of_a_value_past_the_prefilter_cap_is_still_hidden(upper):
    """Past _PREFILTER_LISTED_CHARACTERS no prefilter set is built, and a part a
    message cuts at both ends from one of the values is still found and hidden,
    in any case: leaving the set out changes what a window costs, not whether
    it is hidden."""
    import random

    from automated_security_helper.config.config_validator import (
        _PREFILTER_LISTED_CHARACTERS,
    )

    rng = random.Random(202)
    alphabet = "abcdefghijklmnopqrstuvwxy0123456789"
    values = ["".join(rng.choice(alphabet) for _ in range(2000)) for _ in range(300)]
    assert sum(map(len, values)) > _PREFILTER_LISTED_CHARACTERS
    part = values[5][100:130]
    text = "error: ..." + (part.upper() if upper else part) + "... while reading"
    assert redact_values(text, values) == f"error: ...{REDACTED}... while reading"


def test_a_message_with_few_windows_builds_no_prefilter_set(monkeypatch):
    """A normal message's windows are answered by direct searches alone. The
    prefilter set costs 20-30 MiB and tens of milliseconds at its cap, and
    redact_values runs once per message with the same values, so a message
    that lists two truncated inputs must not pay what only the many-windows
    shape needs: the set is built only once the message's distinct windows
    have cost _PREFILTER_AFTER_SEARCHES direct searches, and each search is
    one C-level find. The windows here are still hidden."""
    from automated_security_helper.config import config_validator

    built = []
    real_prefilter = config_validator._window_prefilter

    def counted(folded_forms):
        built.append(len(folded_forms))
        return real_prefilter(folded_forms)

    monkeypatch.setattr(config_validator, "_window_prefilter", counted)
    values = ["qzab1234middlerun5678", "qrst8765centerrun4321"]
    text = "read '...middlerun...' and '...centerrun...' while checking"
    assert (
        redact_values(text, values)
        == f"read '...{REDACTED}...' and '...{REDACTED}...' while checking"
    )
    assert built == [], "a message with two windows built the prefilter set"


def test_many_distinct_windows_build_the_prefilter_once_and_redact_the_same(
    monkeypatch,
):
    """The control for the gate: a message whose distinct windows pass
    _PREFILTER_AFTER_SEARCHES still builds the set, once, and every window is
    answered as the direct search would answer it -- the held ones hidden, the
    rejected ones left."""
    from automated_security_helper.config import config_validator

    built = []
    real_prefilter = config_validator._window_prefilter

    def counted(folded_forms):
        built.append(len(folded_forms))
        return real_prefilter(folded_forms)

    monkeypatch.setattr(config_validator, "_window_prefilter", counted)
    threshold = config_validator._PREFILTER_AFTER_SEARCHES
    value = "qzab1234" + "".join(f"heldrun{i:03d}" for i in range(threshold + 8))
    values = [value]
    held = [value[8 + 10 * i : 8 + 10 * (i + 1)] for i in range(threshold + 4)]
    rejected = [f"zz{i:07d}zz" for i in range(threshold + 4)]
    text = "".join(f"...{window}" for pair in zip(held, rejected) for window in pair)
    text += "..."
    expected = "".join(f"...{REDACTED}...zz{i:07d}zz" for i in range(threshold + 4))
    expected += "..."
    assert redact_values(text, values) == expected
    assert built == [1], "the many-windows shape must still build the set once"


@pytest.mark.parametrize(
    ("extra", "expected_built"),
    [
        pytest.param(0, [], id="at-the-gate"),
        pytest.param(1, [1], id="one-past-the-gate"),
    ],
)
def test_the_prefilter_set_is_built_at_the_window_after_the_gate(
    monkeypatch, extra, expected_built
):
    """Where the gate switches: a message with exactly _PREFILTER_AFTER_SEARCHES
    distinct windows answers them all by direct search and builds no set, and
    one more window builds it, once, before that window is answered. The
    windows alternate between parts of the value and parts of none, and each is
    answered as before either way."""
    from automated_security_helper.config import config_validator

    built = []
    real_prefilter = config_validator._window_prefilter

    def counted(folded_forms):
        built.append(len(folded_forms))
        return real_prefilter(folded_forms)

    monkeypatch.setattr(config_validator, "_window_prefilter", counted)
    count = config_validator._PREFILTER_AFTER_SEARCHES + extra
    value = "qzab1234" + "".join(f"heldrun{i:03d}" for i in range(count))
    windows = [
        value[8 + 10 * i : 8 + 10 * (i + 1)] if i % 2 == 0 else f"zz{i:07d}zz"
        for i in range(count)
    ]
    assert len(set(windows)) == count
    text = "".join(f"...{window}" for window in windows) + "..."
    expected = (
        "".join(
            f"...{REDACTED}" if i % 2 == 0 else f"...{window}"
            for i, window in enumerate(windows)
        )
        + "..."
    )
    assert redact_values(text, [value]) == expected
    assert built == expected_built, (count, built)


def test_a_message_with_few_windows_adds_no_prefilter_memory():
    """What the gate saves: beside values holding just under
    _PREFILTER_LISTED_CHARACTERS characters, whose set of eight-character runs
    takes about 20 MiB (measured at 20.8 with the gate taken out), a message
    with two windows peaks well under that, and both windows are still
    hidden."""
    import random
    import tracemalloc

    from automated_security_helper.config.config_validator import (
        _PREFILTER_LISTED_CHARACTERS,
    )

    rng = random.Random(203)
    alphabet = "abcdefghijklmnopqrstuvwxy0123456789"
    values = []
    left = _PREFILTER_LISTED_CHARACTERS - 4096
    while left:
        take = min(2000, left)
        values.append("".join(rng.choice(alphabet) for _ in range(take)))
        left -= take
    text = f"read '...{values[3][100:130]}...' and '...{values[60][500:530]}...'"
    tracemalloc.start()
    try:
        result = redact_values(text, values)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == f"read '...{REDACTED}...' and '...{REDACTED}...'"
    assert peak < 8 * 2**20, peak


def test_many_windows_beside_long_values_are_checked_in_bounded_time():
    """Forty thousand parts cut at both ends, each one distinct, in 1 MB of
    text, beside a hundred values of 2000 characters the message never prints.
    The values hold no "z", so no part, each a run of "z" and digits, can be a
    part of one: this measures REJECTED windows. Their 200000 characters are
    under _PREFILTER_LISTED_CHARACTERS (262144), so each part costs one lookup
    in the set of the values' eight-character runs, not a search of every
    value. Each run is stopped at its bound (_timed_run), and the best of
    three counts: one run on a loaded host can come close to the bound (0.975 s
    was measured, in 180 runs of this input), while a regression is slow on
    every run, so it still fails, within three bounds rather than running to
    its end."""
    import random

    from automated_security_helper.config.config_validator import (
        _PREFILTER_LISTED_CHARACTERS,
    )

    rng = random.Random(177)
    alphabet = "abcdefghijklmnopqrstuvwxy0123456789"
    values = ["".join(rng.choice(alphabet) for _ in range(2000)) for _ in range(100)]
    assert sum(map(len, values)) <= _PREFILTER_LISTED_CHARACTERS
    text = "..." + "".join(f"z{i:07d}zzzzzzzzzzzzzz..." for i in range(40000))
    assert len(text) >= 1_000_000
    runs = []
    for _ in range(3):
        runs.append(_timed_run(text, values, text, 1.0))
        if runs[-1] is not None:
            break
    assert runs[-1] is not None, f"all three runs reached the 1.0 s bound: {runs}"


@pytest.mark.parametrize(
    "alphabet",
    [
        pytest.param("abcdefghijklmnopqrstuvwxy0123456789", id="ascii"),
        pytest.param("abcdéèàüöß0123456789", id="latin-1"),
    ],
)
def test_the_window_prefilter_at_its_cap_stays_under_32_mib(alphabet):
    """The set _window_prefilter builds for values holding exactly
    _PREFILTER_LISTED_CHARACTERS characters costs 81-96 bytes a character for
    these characters, about 20-24 MiB at 262144, under 32 MiB. A cap twice as
    high would build 40 MiB or more and fail here, so this pins the cap from
    above; the many-windows cell needs its 200000 characters under the cap,
    which pins it from below."""
    import random
    import tracemalloc

    from automated_security_helper.config.config_validator import (
        _PREFILTER_LISTED_CHARACTERS,
        _folded,
        _window_prefilter,
    )

    rng = random.Random(7)
    forms = []
    left = _PREFILTER_LISTED_CHARACTERS
    while left:
        value = "".join(rng.choice(alphabet) for _ in range(min(2000, left)))
        forms.append((value, _folded(value)))
        left -= len(value)
    tracemalloc.start()
    try:
        built = _window_prefilter(forms)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert built is not None
    assert peak < 32 * 2**20, peak


def test_long_values_a_message_prints_are_found_in_bounded_time():
    """Thirty long values, each printed once in 1 MB of other text: each is
    found with a search over the text, not a pass over it a character at a time
    per value."""
    import random
    import time

    rng = random.Random(185)
    values = [
        "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(100))
        for _ in range(30)
    ]
    filler = "word " * 6700
    text = "".join(f"{filler}{value} " for value in values)
    expected = "".join(f"{filler}{REDACTED} " for _ in values)
    assert len(text) > 1_000_000
    started = time.monotonic()
    result = redact_values(text, values)
    elapsed = time.monotonic() - started
    assert result == expected
    assert elapsed < 1.0, elapsed


def test_a_long_periodic_form_is_found_where_the_pattern_finds_it():
    """Property: a long form that repeats a short unit, so its places in a run
    of the unit overlap, is found exactly where a lookahead pattern of it finds
    it, in any case, over seeded random runs of the unit and their neighbors."""
    import random
    import re

    from automated_security_helper.config.config_validator import (
        _LONG_FORM_LENGTH,
        _long_form_spans,
    )

    rng = random.Random(4)
    found = 0
    for case in range(200):
        unit = "".join(rng.choice("aAbB1_") for _ in range(rng.randrange(1, 5)))
        form = (unit * (_LONG_FORM_LENGTH // len(unit) + 2))[
            : _LONG_FORM_LENGTH + rng.randrange(1, 9)
        ]
        run = unit * rng.randrange(1, 4 * len(form) // len(unit) + 2)
        text = "".join(
            c.swapcase() if rng.random() < 0.1 else c
            for c in rng.choice(["", "x", " ", "ab"]) + run + rng.choice(["", "y", " "])
        )
        for whole_words, flags in ((False, re.IGNORECASE), (True, re.IGNORECASE)):
            before = r"(?<!\w)" if whole_words and re.match(r"\w", form[0]) else ""
            after = r"(?!\w)" if whole_words and re.match(r"\w", form[-1]) else ""
            pattern = f"(?=({before}{re.escape(form)}{after}))"
            expected = [m.span(1) for m in re.finditer(pattern, text, flags)]
            spans = _long_form_spans(text, [form], flags, whole_words)
            assert spans == expected, (text, form, whole_words)
            found += len(expected)
    assert found > 1000


class _RunPastLimit(BaseException):
    """Raised by the timer into a run of redact_values that reached its limit.
    A BaseException, so no ``except Exception`` on the way can swallow it."""


def _timed_run(text, values, expected, limit):
    """The time one run of redact_values takes, checked against *expected*, or
    None when it reaches *limit* seconds. Where signal.setitimer can be used (on
    the main thread), a timer stops the run at *limit* rather than waiting for
    it to end; elsewhere the run ends and is measured. The cell file is the only
    SIGALRM user: the repository runs no pytest-timeout.

    The timer is armed inside the try, so an alarm that comes at once, at the
    arming line or before the run begins, is caught like any other. It is armed
    with at least 10 ms, because setitimer disarms the timer at zero and refuses
    a negative time; the run's own time still counts against *limit* as given.

    The stop is raised only in the redaction code or in this file
    (_STOPPABLE_FILES). An alarm that comes while the run is in other code is put
    off a millisecond at a time until the run is back. Coverage's tracer is such
    code: it takes its data lock on each traced call and releases it right
    after, and a stop raised in between left the lock held after about one stop
    in fifteen under pytest-cov, so the next traced call waited on it for good.
    A stop that comes during one long call into another module therefore waits
    for that call to return: late, but never inside code that may hold a lock."""
    import signal
    import threading
    import time

    timer = (
        hasattr(signal, "setitimer")
        and threading.current_thread() is threading.main_thread()
    )
    if timer:

        def stop(signum, frame):
            if frame is not None and frame.f_code.co_filename in _STOPPABLE_FILES:
                raise _RunPastLimit
            signal.setitimer(signal.ITIMER_REAL, 0.001)

        previous = signal.signal(signal.SIGALRM, stop)
    try:
        try:
            if timer:
                signal.setitimer(signal.ITIMER_REAL, max(limit, 0.01))
            started = time.monotonic()
            result = redact_values(text, values)
        finally:
            if timer:
                signal.setitimer(signal.ITIMER_REAL, 0)
    except _RunPastLimit:
        return None
    finally:
        if timer:
            signal.signal(signal.SIGALRM, previous)
    elapsed = time.monotonic() - started
    assert result == expected
    return None if elapsed >= limit else elapsed


#: Where _timed_run may raise its stop: the redaction code, whose frames hold no
#: lock or shared state a stop could leave half-changed, and this file. Taken
#: from the functions themselves, before any cell replaces redact_values.
_STOPPABLE_FILES = frozenset(
    {redact_values.__code__.co_filename, _timed_run.__code__.co_filename}
)


def _best_time(text, values, expected, bound, limit=None):
    """The shortest of three timed runs of redact_values, each checked against
    *expected* and under *bound* seconds. A run that reaches *bound* fails the
    cell at once, stopped there by the timer (_timed_run). A lower *limit*
    stops a run too and only counts it as too slow: every run keeps the full
    limit, so one or two runs stopped on a busy host do not decide the cell,
    and only every run stopping fails it. A shape that is too slow therefore
    fails within about three limits of the larger size's start, and within
    *bound* where the limit is the bound itself."""
    best = None
    cap = bound if limit is None else min(limit, bound)
    for _ in range(3):
        elapsed = _timed_run(text, values, expected, cap)
        if elapsed is None:
            assert cap < bound, f"a run reached the {bound} s bound"
            continue
        best = elapsed if best is None else min(best, elapsed)
    assert best is not None, f"every run reached its {cap:.3f} s limit"
    return best


@pytest.mark.parametrize(
    ("text_at", "values_at", "expected_at", "n", "bound"),
    [
        # At 16n, 40000 candidates over 380 kB: about 0.5 s now, and over 10 s
        # for a fixed point that re-scans the pieces for each one checked.
        pytest.param(
            lambda k: " defaultus-east-..." * k,
            lambda k: ["default", "us-east-1"],
            lambda k: f" {REDACTED}..." * k,
            1250,
            3.0,
            id="value-then-cut-piece-pairs",
        ),
        pytest.param(
            lambda k: "..." + "A" * k + "x",
            lambda k: ["A" * (k + 8)],
            lambda k: "..." + "A" * k + "x",
            1500,
            2.0,
            id="tail-pieces-from-one-marker-that-all-fall",
        ),
        pytest.param(
            lambda k: "x" + "A" * k + "...",
            lambda k: ["AAAA", "A" * (k + 8)],
            lambda k: "x" + "A" * k + "...",
            1500,
            2.0,
            id="head-pieces-to-one-marker-that-all-fall",
        ),
        # Many cut pieces, each held up by a standing full match beside it:
        # none fall, so this scales the lookup-and-stand path where the
        # falling shapes above scale the cascade.
        pytest.param(
            lambda k: ("x" + "a" * 20 + "...") * k,
            lambda k: ["a" * 20, "aaaa"],
            lambda k: f"x{REDACTED}..." * k,
            250,
            2.0,
            id="cut-pieces-inside-full-matches",
        ),
    ],
)
def test_cut_pieces_take_time_linear_in_the_text(
    text_at, values_at, expected_at, n, bound
):
    """The time at sixteen times the size over the time at the size stays
    under 64: about 16 for time linear in the matches, 256 for their square, so
    the ratio separates the two even where the square's cost at the first size
    is still small. Each run is also under *bound*, the absolute limit. The
    shortest of three runs is timed, so one slow run on a busy host does not
    decide it. A run that reaches *bound* is stopped and fails the cell at once.
    At the larger size a run is also stopped at 64 times the smaller size's
    time, and the cell fails when all three are. So a shape that takes the
    square fails within *bound*, or three of those limits, of the larger size's
    start, rather than after running to the end."""
    small = _best_time(text_at(n), values_at(n), expected_at(n), bound)
    large = _best_time(
        text_at(16 * n), values_at(16 * n), expected_at(16 * n), bound, 64 * small
    )
    assert large / small < 64, (small, large)


@pytest.mark.skipif(
    not hasattr(__import__("signal"), "setitimer"),
    reason="stopping a run at its limit needs signal.setitimer",
)
def test_an_alarm_at_the_arming_line_is_caught_and_the_handler_restored(monkeypatch):
    """An alarm can be delivered right as the timer is armed, before the run
    begins. It counts as the run reaching its limit, and the handler that was
    installed before is restored, rather than the alarm escaping with the stop
    handler left in place."""
    import signal

    real_setitimer = signal.setitimer

    def alarm_at_arming(which, seconds):
        if seconds:
            raise _RunPastLimit
        return real_setitimer(which, seconds)

    before = signal.getsignal(signal.SIGALRM)
    monkeypatch.setattr(signal, "setitimer", alarm_at_arming)
    try:
        result = _timed_run(
            "got qzab1234 here", ["qzab1234"], f"got {REDACTED} here", 0.5
        )
        after = signal.getsignal(signal.SIGALRM)
    finally:
        signal.signal(signal.SIGALRM, before)
    assert result is None
    assert after is before


@pytest.mark.skipif(
    not hasattr(__import__("signal"), "setitimer"),
    reason="stopping a run at its limit needs signal.setitimer",
)
@pytest.mark.parametrize(
    "limit",
    [
        pytest.param(0.000001, id="microseconds"),
        pytest.param(0.0, id="zero"),
    ],
)
def test_a_limit_under_the_floor_is_armed_with_the_floor(monkeypatch, limit):
    """A limit under 10 ms is armed with 10 ms. Armed as given, a limit of zero
    would disarm the timer and leave the run unstopped, and a negative one is
    refused by setitimer. The run's own time still counts against the limit as
    given."""
    import signal

    armed = []

    def record_never_arm(which, seconds):
        armed.append(seconds)

    monkeypatch.setattr(signal, "setitimer", record_never_arm)
    result = _timed_run(
        "got qzab1234 here", ["qzab1234"], f"got {REDACTED} here", limit
    )
    assert result is None
    assert armed and armed[0] >= 0.01, armed


@pytest.mark.skipif(
    not hasattr(__import__("signal"), "setitimer"),
    reason="stopping a run at its limit needs signal.setitimer",
)
def test_a_stop_is_not_raised_inside_other_code_holding_a_lock(monkeypatch, tmp_path):
    """A run can be in code it called when its limit comes: coverage's tracer
    takes its data lock on each traced call and releases it right after. A stop
    raised in between leaves that lock held, and the next traced call waits on
    it for good. Here the code the run calls holds a lock past the limit; the
    lock must be released when the run returns, and the run still stopped."""
    import importlib.util
    import sys
    import threading

    path = tmp_path / "code_the_run_calls.py"
    path.write_text(
        "import time\n"
        "\n"
        "\n"
        "def hold_the_lock(lock, seconds):\n"
        "    lock.acquire()\n"
        "    until = time.monotonic() + seconds\n"
        "    while time.monotonic() < until:\n"
        "        pass\n"
        "    lock.release()\n",
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location("code_the_run_calls", path)
    other_code = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(other_code)
    module = sys.modules[__name__]
    real_redact = module.redact_values
    lock = threading.Lock()

    def run_calling_other_code(text, values):
        other_code.hold_the_lock(lock, 0.2)
        return real_redact(text, values)

    monkeypatch.setattr(module, "redact_values", run_calling_other_code)
    result = _timed_run("got qzab1234 here", ["qzab1234"], f"got {REDACTED} here", 0.05)
    held = lock.locked()
    if held:
        lock.release()
    assert not held
    assert result is None


@pytest.mark.skipif(
    not hasattr(__import__("signal"), "setitimer"),
    reason="stopping a run at its limit needs signal.setitimer",
)
def test_two_runs_stopped_by_a_busy_host_do_not_fail_the_check(monkeypatch):
    """Best of three holds for the larger size too: its first two runs stopping
    at the ratio limit, as on a busy host, do not decide the cell, and the
    third run keeps the full limit rather than what a budget left over. Only
    every run stopping fails the cell, so a shape that is too slow still fails
    within about three limits. Each run is a stand-in with a set result, so the
    cell checks that mechanism and not this host's speed: the size's three runs
    take 10 ms, and the larger size's third run a quarter of its limit."""
    import sys

    module = sys.modules[__name__]
    small = 0.01
    limits = []

    def stand_in_run(text, values, expected, limit):
        limits.append(limit)
        if len(limits) <= 3:
            return small
        if len(limits) <= 5:
            return None
        return limit / 4

    monkeypatch.setattr(module, "_timed_run", stand_in_run)
    test_cut_pieces_take_time_linear_in_the_text(
        lambda k: "x" + "A" * k + "...",
        lambda k: ["AAAA", "A" * (k + 8)],
        lambda k: "x" + "A" * k + "...",
        375,
        2.0,
    )
    assert limits == [2.0] * 3 + [64 * small] * 3, limits


@pytest.mark.skipif(
    not hasattr(__import__("signal"), "setitimer"),
    reason="stopping a run at its limit needs signal.setitimer",
)
def test_the_busy_host_check_never_runs_the_redaction(monkeypatch):
    """The check above is isolated from this host's speed: every run it counts
    is the stand-in's set result, so redact_values is never called, and nothing
    a busy host does to the real redaction can change what that check decides.
    This pins the isolation itself -- a stand-in that started calling through
    to the redaction would make the check hostage to host speed again."""
    import sys

    module = sys.modules[__name__]
    real_redact = module.redact_values
    calls = []

    def recorded(text, values):
        calls.append(len(text))
        return real_redact(text, values)

    monkeypatch.setattr(module, "redact_values", recorded)
    test_two_runs_stopped_by_a_busy_host_do_not_fail_the_check(monkeypatch)
    assert calls == [], "the busy-host check ran the real redaction"


@pytest.mark.skipif(
    not hasattr(__import__("signal"), "setitimer"),
    reason="stopping a run at its limit needs signal.setitimer",
)
@pytest.mark.parametrize(
    "n",
    [
        # Which limit stops the square shape at these sizes depends on the
        # host: around the sizes measured while writing this, 450 reaches the
        # bound and 75 the ratio limit, but a host three times faster or
        # slower swaps them. The cell asserts what holds on any host.
        pytest.param(450, id="mid-size"),
        pytest.param(75, id="small-size"),
        # Big enough that the small size itself is already past the bound.
        pytest.param(4800, id="large-size"),
    ],
)
def test_the_linear_time_check_fails_a_square_time_shape_quickly(monkeypatch, n):
    """The check above, run against the fixed point with its earlier tie order
    (ties by start alone, so every tail piece from one marker leans on the
    longest and all of them look again each time one falls, in time the square
    of the pieces), fails as soon as the timer stops the runs that decide it,
    rather than running a size to its end first (about 40 s at these sizes,
    about 300 s at the cell's own). Which limit stops the decisive run -- the
    bound, or 64 times the smaller size's time -- depends on this host's
    speed, so the cell asserts only what holds on any host: the failing run
    was stopped, every run ARMED its timer at exactly max(limit, 0.01) and
    re-armed it only with the deferral's one millisecond, every stopped run
    ended with the stop handler raising exactly once -- the read-back pins
    that catch a mis-armed, re-armed or swallowed timer under any load,
    since each is read back rather than timed -- every stopped run ended
    within half as much again as its armed limit plus a scheduling allowance
    measured in this process, and each run was armed with the limit the
    recorded runs before it call for. The allowance is measured, then floored at the old
    0.1 s slack and capped at 1 s: a stopped run was measured at five times
    its 0.145-second limit on a busy host (so a bare fixed slack flakes
    under load), one noisy calibration sample must not vacate the bound (50
    ms of wake lateness would give an uncapped 5 s), and this process's own
    full garbage collection at the alarm (93-133 ms measured) must fit (an
    unfloored allowance was STRICTER at idle than the slack it replaced and
    failed 8 of 9 idle runs)."""
    import sys
    import time

    from automated_security_helper.config import config_validator

    module = sys.modules[__name__]
    real_run = module._timed_run
    runs = []

    import signal as signal_module

    armed_now = []
    armings = []
    raise_counts = []
    real_setitimer = signal_module.setitimer
    real_signal = signal_module.signal

    def recording_setitimer(which, seconds, *rest):
        # A pass-through recorder: the first nonzero arming of each run is
        # the limit _timed_run armed; any later nonzero one may only be the
        # deferral's millisecond. The disarm (zero) is not recorded.
        if seconds:
            armed_now.append(seconds)
        return real_setitimer(which, seconds, *rest)

    def counting_signal(signum, handler):
        # A pass-through wrap of the stop handler _timed_run installs: a
        # raise out of it is counted against the current run. The restore
        # passes the previous disposition (not callable), untouched.
        if not callable(handler):
            return real_signal(signum, handler)

        def counted(signum_, frame):
            try:
                return handler(signum_, frame)
            except BaseException:
                raise_counts[-1] += 1
                raise

        return real_signal(signum, counted)

    monkeypatch.setattr(signal_module, "setitimer", recording_setitimer)
    monkeypatch.setattr(signal_module, "signal", counting_signal)

    def recorded_run(text, values, expected, limit):
        armed_now.clear()
        raise_counts.append(0)
        started = time.monotonic()
        elapsed = real_run(text, values, expected, limit)
        runs.append((elapsed, limit, time.monotonic() - started))
        armings.append(tuple(armed_now))
        return elapsed

    monkeypatch.setattr(module, "_timed_run", recorded_run)

    class StartOnlyTies(config_validator._StandingReach):
        # The earlier tie order: by start alone, so ties keep their written
        # order (sorted is stable) and every tail piece leans on the longest.
        # Built through the production _build, so a layout change there
        # cannot leave this variant on an outdated tree.
        def __init__(self, candidates):
            self._build(
                candidates,
                sorted(range(len(candidates)), key=lambda i: candidates[i][0]),
            )

    monkeypatch.setattr(config_validator, "_StandingReach", StartOnlyTies)
    bound = 2.0
    # How late this process wakes under the current load: the worst overshoot
    # of ten 5 ms sleeps, measured just before the runs it bounds. The stop
    # is a signal this process must wake to handle, and its deferral loop
    # re-arms a millisecond at a time, so a late stop is a chain of such
    # wakeups: the per-run allowance scales the measured lateness by a
    # hundred, room for a long chain, and stays near zero on an idle host.
    lateness = 0.0
    for _ in range(10):
        before = time.monotonic()
        time.sleep(0.005)
        lateness = max(lateness, time.monotonic() - before - 0.005)
    # Floored and capped: unfloored, the bound was stricter at idle than the
    # fixed slack it replaced (a full garbage collection at the alarm failed
    # 8 of 9 idle runs); uncapped, one noisy sample vacated it (a 50 ms wake
    # gives a 5 s allowance). The read-back pins below catch a mis-armed or
    # re-armed timer and a swallowed stop at any load; this wall bound
    # answers for how late a DELIVERED stop may land, and on its own it
    # answers for a stop that never lands only at the sizes armed with the
    # bound.
    allowance = max(0.1, min(100.0 * lateness, 1.0))
    with pytest.raises(AssertionError):
        test_cut_pieces_take_time_linear_in_the_text(
            lambda k: "..." + "A" * k + "x",
            lambda k: ["A" * (k + 8)],
            lambda k: "..." + "A" * k + "x",
            n,
            bound,
        )
    assert runs and runs[-1][0] is None, runs
    stopped = [run for run in runs if run[0] is None]
    assert stopped, runs
    # The armings are read back, not timed: a timer armed at anything but
    # max(limit, 0.01), or re-armed with anything but the deferral's one
    # millisecond, is caught here under any host load, which is what a
    # wall-time bound alone could not promise (its allowance stops seeing a
    # tripled timer once a sleep sample overshoots by a few milliseconds,
    # and it never sees a re-arm the run outlives).
    for (_, limit, _), recorded in zip(runs, armings, strict=True):
        assert recorded and recorded[0] == max(limit, 0.01), (recorded, limit)
        assert all(later == 0.001 for later in recorded[1:]), (recorded, limit)
    # Each stopped run ended with the stop handler raising exactly once: a
    # handler that returns, defers forever or is disarmed lets the run end
    # through the post-hoc elapsed >= limit branch with no raise, and only
    # this read-back sees that at a size the wall bound covers loosely. A
    # correct stop cannot end that way here: a stopped run of the square
    # shape is far (about 0.7 s at these sizes) from finishing inside the
    # deferral's millisecond, so a raise-free None is a swallowed stop, not
    # a run that finished just over its limit.
    for (elapsed, limit, _), count in zip(runs, raise_counts, strict=True):
        if elapsed is None:
            assert count == 1, (count, limit, raise_counts, runs)
    # _best_time arms each run with min(limit, bound), which is what the
    # recorder saw, so each stopped run's wall time answers to its own limit
    # within the measured, floored, capped allowance. A summed whole-check
    # bound was dropped: it only restated this per-run bound (a run that is
    # not stopped took less than its limit), never failed first, and the
    # bound-armed runs gave it about nine seconds of slack.
    for _, limit, took in stopped:
        assert took < 1.5 * limit + allowance, (lateness, runs)
    # Which limit stopped them follows from what the recorder saw, on any host.
    # The size's own runs are armed with the bound, and one of them reaching it
    # fails the cell there. Otherwise each run of the larger size is armed with
    # 64 times the size's best time, or the bound where that is less: one run
    # stopped at the bound fails the cell, and at the ratio limit only all three
    # stopped do.
    small_runs = runs[:3]
    assert all(limit == bound for _, limit, _ in small_runs), runs
    if any(elapsed is None for elapsed, _, _ in small_runs):
        assert len(runs) == len(small_runs), runs
    else:
        cap = min(64 * min(elapsed for elapsed, _, _ in small_runs), bound)
        larger = runs[3:]
        assert all(limit == cap for _, limit, _ in larger), runs
        assert len(larger) == (1 if cap == bound else 3), runs


@pytest.mark.parametrize("length", [600, 1500])
@pytest.mark.parametrize("command", ["validate", "lint"])
def test_a_check_reports_a_config_error_beside_a_long_environment_value(
    tmp_path, monkeypatch, length, command
):
    """`ash config validate` and `lint` report the config's own error, exit 3,
    when a field holds a long value read from the environment."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    value = ("qzab1234" * (length // 8 + 1))[:length]
    monkeypatch.setenv("ASH_TEST_LONG_VALUE", value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    config = tmp_path / "ash.yaml"
    config.write_text(
        "project_name: ${ASH_TEST_LONG_VALUE}\nfail_on_findings: maybe\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["config", command, "--config", str(config)])

    assert result.exit_code == 3, result.output
    assert "fail_on_findings" in result.output
    assert "recursion" not in result.output
    assert value[:12] not in result.output


@pytest.mark.parametrize(
    "text, values, expected",
    [
        pytest.param(
            "got qz4bqzab1234 here",
            ["qz4b", VALUE],
            f"got {REDACTED} here",
            id="before-a-hidden-long-value",
        ),
        pytest.param(
            "got qzab1234qz4b here",
            ["qz4b", VALUE],
            f"got {REDACTED} here",
            id="after-a-hidden-long-value",
        ),
        pytest.param(
            "got abcdefghij here",
            ["abcdefgh", "ghij"],
            f"got {REDACTED} here",
            id="overlapping-the-end-of-a-long-value",
        ),
        pytest.param(
            "got wxabcdefgh here",
            ["abcdefgh", "wxab"],
            f"got {REDACTED} here",
            id="overlapping-the-start-of-a-long-value",
        ),
        pytest.param(
            "got qz4brk5c here",
            ["qz4b", "rk5c"],
            f"got {REDACTED} here",
            id="two-back-to-back",
        ),
        pytest.param(
            "got 'qz4brk5c' here",
            ["qz4b", "rk5c"],
            f"got '{REDACTED}' here",
            id="two-back-to-back-quoted",
        ),
        pytest.param(
            "got qz4bxqz4bx here",
            ["qz4bx"],
            f"got {REDACTED} here",
            id="twice-in-a-row",
        ),
    ],
)
def test_a_four_to_seven_character_value_beside_another_is_hidden(
    text, values, expected
):
    """The edge of another value's match bounds a word in this band: a short
    value run into another value, or into a hidden longer one, is hidden with
    it."""
    assert redact_values(text, values) == expected


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("this is untrue", id="inside-a-word"),
        pytest.param("got xqz4b7cdx here", id="between-letters-and-digits"),
        pytest.param("got qz4b1 here", id="before-a-digit"),
        pytest.param("got xqz4b here", id="after-a-letter"),
        pytest.param("got éqz4b here", id="after-an-accented-letter"),
    ],
)
def test_control_a_four_to_seven_character_value_inside_a_word_is_left(text):
    """Run into letters or digits, a four- to seven-character value is shown
    under either word rule: a common word inside a longer one stays
    readable."""
    values = ["true"] if "untrue" in text else ["qz4b"]
    assert redact_values(text, values) == text


@pytest.mark.parametrize(
    "text, values, expected",
    [
        pytest.param(
            "/home/x/work/_temp/y",
            ["temp"],
            f"/home/x/work/_{REDACTED}/y",
            id="a-lone-underscore-path-piece",
        ),
        pytest.param(
            "/home/x/_work/_tool/y",
            ["work", "tool"],
            f"/home/x/_{REDACTED}/_{REDACTED}/y",
            id="two-lone-underscore-path-pieces",
        ),
    ],
)
@pytest.mark.parametrize("joined", [False, True], ids=["strict", "test-report"])
def test_a_value_after_a_lone_underscore_in_a_path_is_hidden_under_both_rules(
    joined, text, values, expected
):
    """A four- to seven-character value that IS the piece after a lone "_" in
    a path hides under both rules: the strict rule bounds on any
    non-alphanumeric character, and the test-report rule's look-past finds a
    path separator, which bounds a word itself. A CI working directory whose
    pieces equal such a value is mangled either way -- the band's accepted
    fail-closed cost, stated in the CHANGELOG."""
    rule = _redact_for_test_reports if joined else redact_values
    assert rule(text, values) == expected


@pytest.mark.parametrize(
    "text, values, strict_expected, report_expected",
    [
        pytest.param(
            "got __qz4b__ here",
            ["qz4b"],
            f"got __{REDACTED}__ here",
            "got __qz4b__ here",
            id="a-dunder-shaped-piece",
        ),
        pytest.param(
            "x=__qz4b",
            ["qz4b"],
            f"x=__{REDACTED}",
            "x=__qz4b",
            id="a-run-after-punctuation",
        ),
        pytest.param(
            "the __main__ module ran",
            ["main"],
            f"the __{REDACTED}__ module ran",
            "the __main__ module ran",
            id="a-real-dunder-name",
        ),
    ],
)
def test_a_piece_between_underscore_runs_splits_by_rule(
    text, values, strict_expected, report_expected
):
    """A value between runs of two or more "_" whose far sides are UNCOVERED
    (a space, punctuation) splits by rule. The strict product rule hides it:
    any non-alphanumeric character bounds, fail closed. The test-report rule
    shows it: the run clause closes a side only against the text's edge or a
    covered character, because report text is full of dunder names whose
    stems are common words -- hiding __main__ for a four-character value
    would mangle the very module names the backstop exists to keep readable.
    The runs that DO abut hidden text or the text's edge keep hiding (the
    double-underscore cells above)."""
    assert redact_values(text, values) == strict_expected
    assert _redact_for_test_reports(text, values) == report_expected


@pytest.mark.parametrize(
    "text, candidates, fixed",
    [
        pytest.param(
            "x_qzab ",
            [(2, 6, "qzab")],
            [(1, 2, "F")],
            id="a-covered-single-underscore",
        ),
        pytest.param(
            "x__qzab ",
            [(3, 7, "qzab")],
            [(2, 3, "F")],
            id="the-adjacent-underscore-of-a-run-covered",
        ),
        pytest.param(
            "x__qzab ",
            [(3, 7, "qzab")],
            [(1, 2, "F")],
            id="the-far-underscore-of-a-run-covered",
        ),
        pytest.param(
            " qzab_x",
            [(1, 5, "qzab")],
            [(5, 6, "F")],
            id="a-covered-single-underscore-on-the-right",
        ),
        pytest.param(
            " qzab__x",
            [(1, 5, "qzab")],
            [(5, 6, "F")],
            id="the-adjacent-underscore-of-a-right-run-covered",
        ),
        pytest.param(
            " qzab__x",
            [(1, 5, "qzab")],
            [(6, 7, "F")],
            id="the-far-underscore-of-a-right-run-covered",
        ),
        pytest.param(
            "x_qzab",
            [(2, 6, "qzab")],
            [(1, 3, "F")],
            id="a-fixed-span-over-the-underscore-into-the-candidate",
        ),
    ],
)
def test_a_covered_underscore_closes_the_side(text, candidates, fixed):
    """Under the test-report rule, a "_" another match covers is marker text,
    so the candidate beside it sits beside a marker, which bounds a word: the
    value hides however far the uncovered text past the "_" would have glued
    it. The product's walk and the property oracle agree on this -- the
    oracle masks every covered character, so a covered "_" reads as a
    non-word character there by construction."""
    from automated_security_helper.config.config_validator import _whole_word_spans

    product = _whole_word_spans(text, candidates, fixed, underscore_joins_words=True)
    oracle = _greatest_fixed_point(
        text, candidates, fixed, short=(), underscore_joins_words=True
    )
    assert product == candidates, product
    assert sorted(oracle) == sorted(candidates), oracle


def test_an_underscore_covered_by_a_standing_match_closes_the_side():
    """A "_" a STANDING candidate covers is marker text once that candidate
    hides, so it closes the side as a fixed-covered "_" does: here the second
    value's match covers the first "_" of the run, closing the first value's
    right side, and the two hold each other up. Without the second value
    nothing covers the "_" and the uncovered run keeps the first value
    joined to nothing hidden, so it prints."""
    assert (
        _redact_for_test_reports("x rk5c__ y", ("rk5c", "k5c_")) == f"x {REDACTED}_ y"
    )
    assert _redact_for_test_reports("x rk5c__ y", ("rk5c",)) == "x rk5c__ y"


def test_an_underscore_covered_by_a_standing_match_closes_the_left_side():
    """The left-side mirror: the second value's match covers the "_" at the
    first value's LEFT edge, which closes that side; the two hold each other
    up and hide together. Without the second value the "_" is uncovered and
    the first value stays joined through it, so it prints."""
    assert (
        _redact_for_test_reports("x __rk5c y", ("rk5c", "_rk5")) == f"x _{REDACTED} y"
    )
    assert _redact_for_test_reports("x __rk5c y", ("rk5c",)) == "x __rk5c y"


def test_the_standing_cover_agrees_with_the_oracle():
    """The product's witness points (every uncovered "_" of the run, or the
    character past it) read the same as the oracle's mask, which replaces a
    standing candidate's characters with non-word markers."""
    from automated_security_helper.config.config_validator import _whole_word_spans

    text = "x rk5c__ y"
    candidates = [(2, 6, "rk5c"), (3, 7, "k5c_")]
    product = _whole_word_spans(text, candidates, [], underscore_joins_words=True)
    oracle = _greatest_fixed_point(
        text, candidates, [], short=(), underscore_joins_words=True
    )
    assert sorted(product) == sorted(candidates), product
    assert sorted(oracle) == sorted(candidates), oracle


#: An inner "_" of the run covered by a standing candidate: the second
#: candidate covers only "_" characters beside the value, neither the
#: adjacent one nor the character past the run.
COVERED_INNER_UNDERSCORE_RUNS = [
    pytest.param(
        "x rk5c______ y",
        [(2, 6, "rk5c"), (7, 11, "U")],
        id="right-run6-inner-underscores",
    ),
    pytest.param(
        "x rk5c_____ y",
        [(2, 6, "rk5c"), (7, 11, "U")],
        id="right-run5-inner-underscores",
    ),
    pytest.param(
        "x ______rk5c y",
        [(8, 12, "rk5c"), (3, 7, "U")],
        id="left-run6-inner-underscores",
    ),
]


@pytest.mark.parametrize("text, candidates", COVERED_INNER_UNDERSCORE_RUNS)
def test_an_inner_underscore_covered_by_a_standing_match_closes_the_side(
    text, candidates
):
    """An INNER "_" of the run that a standing candidate covers is marker
    text once that candidate hides, the same as the adjacent one: every
    uncovered "_" the look-past walks is a witness alternative, so the two
    candidates hold each other up. The oracle reads it so through its mask,
    which replaces every standing candidate's characters -- the masked
    context then ends in a lone covered "_" and the side closes."""
    from automated_security_helper.config.config_validator import _whole_word_spans

    product = _whole_word_spans(text, candidates, [], underscore_joins_words=True)
    oracle = _greatest_fixed_point(
        text, candidates, [], short=(), underscore_joins_words=True
    )
    assert sorted(product) == sorted(candidates), product
    assert sorted(oracle) == sorted(candidates), oracle


@pytest.mark.parametrize("text, candidates", COVERED_INNER_UNDERSCORE_RUNS)
def test_control_a_fixed_span_on_the_same_inner_underscores_closes_it(text, candidates):
    """Control: the same inner span as a FIXED match already closed the side
    (the walk stops at a fixed-covered "_"), so only the standing case was
    open."""
    from automated_security_helper.config.config_validator import _whole_word_spans

    value, inner = candidates
    got = _whole_word_spans(text, [value], [inner], underscore_joins_words=True)
    assert got == [value], got


@pytest.mark.parametrize(
    "text, expected",
    [
        pytest.param(
            "got ASH_qz4b_logs here",
            f"got ASH_{REDACTED}_logs here",
            id="between-underscores",
        ),
        pytest.param(
            "a true_positive here",
            f"a {REDACTED}_positive here",
            id="before-an-underscore",
        ),
        pytest.param(
            "log group /aws/ash/teamx_findings missing",
            f"log group /aws/ash/{REDACTED}_findings missing",
            id="the-reviewed-leak-shape",
        ),
    ],
)
def test_a_value_glued_by_an_underscore_hides_by_default(text, expected):
    """The product's word rule is strict: "_" bounds a word like any other
    non-alphanumeric character, so a value glued into a longer name by "_"
    is a whole word and hides on every product message surface. The
    path-preserving rule survives only behind underscore_joins_words, which
    only the test-report backstop passes."""
    values = ["true"] if "true_positive" in text else ["qz4b", "teamx"]
    assert redact_values(text, values) == expected


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("got ASH_qz4b_logs here", id="between-underscores"),
        pytest.param("a true_positive here", id="before-an-underscore"),
    ],
)
def test_the_report_rule_keeps_a_value_glued_by_an_underscore(text):
    """Under the test-report rule (underscore_joins_words) "_" is a word
    character, so a glued short value prints -- the deliberate trade that
    keeps CI paths and module names readable in test reports, where the
    backstop sweeps the whole environment. The undo is reverting the
    boundary."""
    values = ["true"] if "true_positive" in text else ["qz4b"]
    assert _redact_for_test_reports(text, values) == text


@pytest.mark.parametrize(
    "text, values, expected",
    [
        pytest.param(
            "got qz4b_rk5c here",
            ["qz4b", "rk5c"],
            f"got {REDACTED}_{REDACTED} here",
            id="two-values-joined-by-an-underscore",
        ),
        pytest.param(
            f"got {VALUE}_qz4b here",
            [VALUE, "qz4b"],
            f"got {REDACTED}_{REDACTED} here",
            id="a-short-value-past-an-underscore-beside-a-hidden-one",
        ),
        pytest.param(
            "_qz4b at the start",
            ["qz4b"],
            f"_{REDACTED} at the start",
            id="an-underscore-at-the-text-s-edge",
        ),
        pytest.param(
            "got _qz4b here",
            ["qz4b"],
            f"got _{REDACTED} here",
            id="a-space-past-the-underscore",
        ),
        pytest.param(
            "got (_qz4b) here",
            ["qz4b"],
            f"got (_{REDACTED}) here",
            id="punctuation-past-the-underscore",
        ),
        pytest.param(
            "dir=/x/_qz4b read",
            ["qz4b"],
            f"dir=/x/_{REDACTED} read",
            id="a-path-separator-past-the-underscore",
        ),
        pytest.param(
            "got qz4b_ here",
            ["qz4b"],
            f"got {REDACTED}_ here",
            id="a-space-past-the-underscore-on-the-right",
        ),
    ],
)
def test_an_underscore_bounds_a_word_where_what_lies_past_it_cannot_glue_it(
    text, values, expected
):
    """Under the test-report rule, the "_" beside a match is a boundary where
    what lies past it cannot be gluing the value into a longer word: the
    text's edge, a character that itself bounds a word (space, punctuation,
    a path separator), or a character another match covers, so two values
    joined by "_" hold each other up and a short value beside a hidden one
    is hidden with it. Only a word character past the "_" (the CI-path
    controls above) keeps the word rule and the value prints; the one rule
    reads the same whichever side the "_" is on."""
    assert _redact_for_test_reports(text, values) == expected


@pytest.mark.parametrize(
    "text, values, expected",
    [
        pytest.param(
            "got qz4b__rk5c here",
            ["qz4b", "rk5c"],
            f"got {REDACTED}__{REDACTED} here",
            id="two-values-joined-by-a-double-underscore",
        ),
        pytest.param(
            f"got {VALUE}__qz4b here",
            [VALUE, "qz4b"],
            f"got {REDACTED}__{REDACTED} here",
            id="a-short-value-past-a-double-underscore-beside-a-hidden-one",
        ),
        pytest.param(
            "the __main__ module ran",
            ["main"],
            "the __main__ module ran",
            id="dunder-main-stays-whole",
        ),
        pytest.param(
            "__qz4b at the start",
            ["qz4b"],
            f"__{REDACTED} at the start",
            id="a-double-underscore-at-the-text-s-edge",
        ),
        pytest.param(
            "ends in qz4b__",
            ["qz4b"],
            f"ends in {REDACTED}__",
            id="a-run-to-the-text-edge-on-the-right",
        ),
        pytest.param(
            f"got qz4b__{VALUE} here",
            ["qz4b", VALUE],
            f"got {REDACTED}__{REDACTED} here",
            id="a-short-value-before-a-double-underscore-beside-a-hidden-one",
        ),
        # The two printing right-run shapes that reach the run rule's own
        # check: the run's far side is an uncovered word boundary that is
        # neither the text's edge (the edge cells return before the check)
        # nor a fixed cover, so reading the run as a single "_" would close
        # the side and hide what must stay readable.
        pytest.param(
            "__main__.py",
            ["main"],
            "__main__.py",
            id="dunder-main-at-left-edge-whole",
        ),
        pytest.param(
            "got qz4b__ here",
            ["qz4b"],
            "got qz4b__ here",
            id="a-right-run-past-a-space-prints",
        ),
    ],
)
def test_a_run_of_underscores_bounds_only_against_the_edge_or_coverage(
    text, values, expected
):
    """Under the test-report rule, a run of two or more "_" counts as a
    boundary only where what lies past the run is the text's edge or a
    character another match covers: two values joined by "__" hide together,
    while ``__main__`` stays whole even though the space past its run bounds
    a word -- the rejected shape was the single-"_" look-past applied to the
    run."""
    assert _redact_for_test_reports(text, values) == expected


@pytest.mark.parametrize(
    "text, values, expected",
    [
        pytest.param(
            f"got qz4b_{VALUE} here",
            ["qz4b", VALUE],
            f"got {REDACTED}_{REDACTED} here",
            id="the-fixed-witness-sits-past-the-underscore",
        ),
        pytest.param(
            "ends in qz4b_",
            ["qz4b"],
            f"ends in {REDACTED}_",
            id="an-underscore-at-the-text-s-right-edge",
        ),
    ],
)
def test_the_right_side_witness_is_the_character_past_the_underscore(
    text, values, expected
):
    """The right-side look-past reads the character PAST the "_", not the "_"
    itself: a long value's match covering that character holds the short one
    up, and a trailing "_" at the text's edge bounds."""
    assert _redact_for_test_reports(text, values) == expected


def test_a_seven_character_value_touching_a_hidden_eight_character_one_prints():
    """The test-report rule's named cost: a four- to seven-character value
    whose far side runs into an uncovered word character prints even when
    its other side touches a hidden longer value -- here glued by "_" on the
    left to a plain word. Taken with the boundary rule above; the undo is
    reverting the look-past. (The cost covers every value of the four- to
    seven-character band, not only seven-character ones.)"""
    seven = "qzab123"
    eight = "rk5c6789"
    text = f"x_{seven}{eight}_y"
    assert _redact_for_test_reports(text, [seven, eight]) == f"x_{seven}{REDACTED}_y"


def _every_character():
    import sys

    return (chr(code) for code in range(sys.maxunicode + 1))


def test_the_word_rule_differs_from_the_old_rule_only_at_underscore():
    """One pass over every code point pins the three boundary relations: the
    word rule and the alphanumeric rule (anything not alphanumeric bounds)
    disagree on exactly "_", so "-", "/", punctuation, whitespace and every
    other non-alphanumeric code point still bound and x-runner still hides;
    a long cut piece's far side IS the alphanumeric rule, "_" included; and
    no character bounds a word without also bounding a cut piece, so the
    fixed point never re-judges a piece's neighbor the other way."""
    from automated_security_helper.config.config_validator import (
        _bounds_strict,
        _bounds_report,
    )

    word_vs_old = []
    piece_vs_old = []
    word_without_piece = []
    for c in _every_character():
        old = not c.isalnum()
        word = _bounds_report(c)
        piece = _bounds_strict(c)
        if word != old:
            word_vs_old.append(c)
        if piece != old:
            piece_vs_old.append(c)
        if word and not piece:
            word_without_piece.append(c)
    assert word_vs_old == ["_"], [hex(ord(c)) for c in word_vs_old[:20]]
    assert piece_vs_old == [], [hex(ord(c)) for c in piece_vs_old[:20]]
    assert word_without_piece == [], [hex(ord(c)) for c in word_without_piece[:20]]


def test_a_short_value_holding_a_non_word_character_is_a_whole_word():
    """With min_length lowered to 1, a two-character "a." is a whole word: it is
    hidden where it stands alone, and "data." keeps its letters."""
    assert redact_values("a valid data. got a.", ["a."], min_length=1) == (
        f"a valid data. got {REDACTED}"
    )


def test_control_a_short_piece_of_a_long_value_is_left():
    """Under eight characters, a piece alone is left: it could be any word. It
    is hidden only in a run of eight characters or more, beside another match."""
    assert redact_values("input 'qzab12...' refused", [LONG]) == (
        "input 'qzab12...' refused"
    )


def test_a_model_error_s_own_input_is_replaced_as_a_whole_word():
    """``whole_words``: the replacement of an input the file wrote, which a
    validator's message quotes, leaves a longer word that holds it, even for a
    long input, and leaves a short input even quoted."""
    text = "Input 'LOWXYZAB' is not 'LOWXYZABC'"
    assert redact_values(text, ["LOWXYZAB"], whole_words=True) == (
        f"Input '{REDACTED}' is not 'LOWXYZABC'"
    )
    assert redact_values("Input 'LOW'", ["LOW"], whole_words=True) == "Input 'LOW'"
