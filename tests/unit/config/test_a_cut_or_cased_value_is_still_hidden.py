# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value a message cuts or re-cases is hidden; what only resembles one is not.

Three parts of ``redact_values`` carry this and had no targeted tests:

- ``_cut_windows``: the text between a "..." or "…" and the next one, eight
  characters or more, is hidden when a value holds it -- a message that
  shortens a value prints exactly such a window -- and left when none does,
  so ASH's own elisions stay readable. A message with many distinct windows
  crosses the prefilter threshold (``_PREFILTER_AFTER_SEARCHES``), after
  which a set of the values' runs answers windows instead of direct
  searches; the answers must not change with the path.
- ``_short_cut_pieces``: a four-to-seven character start of a value ending
  at a marker, or end of one beginning at a marker, is hidden only inside a
  whole-word run of eight characters or more (two cut values printed back to
  back, or a piece beside a full value). Alone it could be any word, and
  stays.
- ``_case_classes``: matching is case-insensitive. A value up to
  ``_LONG_FORM_LENGTH`` is matched by a pattern compiled with IGNORECASE, so
  the table decides nothing there; a longer value is found by the linear
  search (``_long_form_spans``), where the table is the only thing that
  makes a re-cased occurrence compare equal. The cells here cover both, the
  repeating long form (the Z-array branch) included.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.config_validator import (
    REDACTED,
    redact_values,
)

pytestmark = pytest.mark.unit

#: Two values in the anywhere band (eight characters or more).
A = "qzab1234wxyz"
B = "mnop5678stuv"
#: Past _LONG_FORM_LENGTH (64), so the linear search finds it, not the
#: pattern -- and NON-periodic (every chunk distinct), so it takes the
#: find-to-find path; the cell below pins that with _repeats_closely.
LONG = "".join(f"qk{i:02d}xw-" for i in range(11))
#: As long, and its own 5-character unit repeated under half its length, so
#: the linear search takes the Z-array branch rather than find-to-find.
REPEATING = "qz9m-qz9m-" + "qz9m-" * 12


@pytest.mark.parametrize(
    "name, text, values, expected",
    [
        pytest.param(
            "window-of-a-value",
            f"saw ...{A[2:10]}... here",
            [A],
            f"saw ...{REDACTED}... here",
            id="a middle window a value holds is hidden",
        ),
        pytest.param(
            "window-of-no-value",
            "saw ...notapiece... here",
            [A],
            "saw ...notapiece... here",
            id="a window no value holds stays",
        ),
        pytest.param(
            "window-under-the-bound",
            f"saw ...{A[2:7]}... here",
            [A],
            f"saw ...{A[2:7]}... here",
            id="a window under eight characters stays",
        ),
        pytest.param(
            "adjacent-pieces-between-markers",
            f"saw ...{A[-5:]}{B[:5]}... here",
            [A, B],
            f"saw ...{REDACTED}... here",
            id="two five-character pieces back to back are hidden together",
        ),
        pytest.param(
            "piece-beside-a-full-value",
            f"saw {A}{B[:5]}... here",
            [A, B],
            f"saw {REDACTED}... here",
            id="a piece beside a full value joins its replacement",
        ),
        pytest.param(
            "lone-start-piece",
            f"saw {A[:5]}... here",
            [A],
            f"saw {A[:5]}... here",
            id="a lone five-character piece could be any word and stays",
        ),
        pytest.param(
            "pieces-split-by-the-marker",
            f"saw {A[:5]}...{B[-5:]} here",
            [A, B],
            f"saw {A[:5]}...{B[-5:]} here",
            id="pieces on opposite sides of one marker are each alone",
        ),
        pytest.param(
            "re-cased-value",
            f"saw {A.upper()} here",
            [A],
            f"saw {REDACTED} here",
            id="a value printed in another case is hidden",
        ),
        pytest.param(
            "re-cased-window",
            f"saw ...{A[2:10].upper()}... here",
            [A],
            f"saw ...{REDACTED}... here",
            id="a cut window in another case is hidden",
        ),
        pytest.param(
            "re-cased-long-value",
            f"saw {LONG.upper()} here",
            [LONG],
            f"saw {REDACTED} here",
            id="a long value in another case is hidden by the linear search",
        ),
        pytest.param(
            "re-cased-repeating-long-value",
            f"saw {REPEATING.upper()} here",
            [REPEATING],
            f"saw {REDACTED} here",
            id="a long repeating value in another case is hidden too",
        ),
    ],
)
def test_a_cut_or_cased_value_is_still_hidden(name, text, values, expected):
    assert redact_values(text, values) == expected


def _non_finite_needles(written: str) -> list:
    """The needles a chain reading *written* produces: the value as written
    plus its typed spellings, the shape environment_record_read builds."""
    from automated_security_helper.config.config_validator import _typed_spellings

    return [written, *_typed_spellings(written)]


def test_a_non_finite_needle_does_not_eat_the_inside_of_a_word():
    """A float's non-finite word joins the needles whatever its length (the
    base failure-line cells pin that), and "-inf" is four characters with a
    non-word character, the shape redact_values otherwise replaces anywhere.
    Anywhere-matching it eats ordinary text: an option name ("--info") and a
    hyphenated word ("non-inference") both contain it. The word identifies
    nothing inside another word, so it is matched as a whole word: standing
    alone or quoted it is still hidden (the same cells' contract), and a word
    character following the match keeps the text. The leading "-" bounds
    itself, so text running into it from the left ("range 0-inf") still
    redacts."""
    values = _non_finite_needles("-1e999")
    # The control: the needle set holds the word this cell is about.
    assert "-inf" in values, values

    for line in ("run --info for details", "a non-inference step"):
        assert redact_values(line, values) == line, (line, values)
    # Standing as a word or quoted, the print is still hidden.
    assert "-inf" not in redact_values("limit -inf reached", values)
    assert "'-inf'" not in redact_values("limit '-inf' reached", values)


def test_a_short_numeric_needle_matches_only_at_a_number_boundary():
    """A joined short signed print ("-1.5" for the hidden "-1.50") is four
    characters with a non-word character, the shape otherwise replaced
    anywhere -- which eats hyphen-joined text ("requests-1.5.4") and the
    front of a longer number ("delta -1.55s"). A number stops being that
    number when a digit, or a dot attached to a digit, runs into it from
    either side, so the needle matches only at a number boundary: standing
    alone or quoted it is still hidden, and only a longer number keeps its
    text (a letter, "_" or a lone dot against the needle does not save it --
    the glued-value and lone-dot cells pin those sides)."""
    values = _non_finite_needles("-1.50")
    # The control: the derived print is a needle at all.
    assert "-1.5" in values, values

    for line in (
        "pip install requests-1.5.4",
        "delta -1.55s",
        "pip install requests-1.5.40",
        "delta -1.505s",
        # The lookbehind's own side: a digit running into the needle from
        # the left makes it a piece of a longer number too.
        "range 0-1.5 used",
    ):
        assert redact_values(line, values) == line, (line, values)
    # The same for an unsigned value: a digit, or a dot attached to a digit,
    # on the left bounds it.
    unsigned = _non_finite_needles("1.50")
    assert "1.50" in unsigned, unsigned
    for line in ("cost 21.50 total", "version 3.1.50"):
        assert redact_values(line, unsigned) == line, (line, unsigned)
    # The guard: standing alone or quoted, the print is still hidden.
    assert "-1.5" not in redact_values("delta -1.5s ago", values)
    assert "'-1.5'" not in redact_values("limit '-1.5' reached", values)


def test_a_dotted_version_needle_matches_only_at_a_number_boundary():
    """A dotted version is not a float, but it is digits and dots: left on
    the plain anywhere band, a written "1.5.4" eats the front of
    "requests-1.5.40". It takes the same number bound, so a longer version
    keeps its text while the value standing alone, quoted, named with a
    prefix or glued to a word is hidden."""
    from automated_security_helper.utils.numeric_text import number_bounded_form

    values = _non_finite_needles("1.5.4")
    # The control: a dotted version has no typed spellings; the written
    # value is the one needle.
    assert values == ["1.5.4"], values

    for line in ("pip install requests-1.5.40", "release 1.5.4.1 shipped"):
        assert redact_values(line, values) == line, (line, values)
    for line in (
        "version 1.5.4",
        "v1.5.4",
        "pkg-1.5.4",
        "limit '1.5.4' reached",
    ):
        assert "1.5.4" not in redact_values(line, values), (line,)
    # The arm: a dotted version takes the bound, and the 2-part form stays
    # on the numeric arm.
    assert number_bounded_form("1.5.4") is True
    assert number_bounded_form("1.5") is True


def test_a_lone_dot_does_not_protect_a_needle():
    """Sentence punctuation is not a longer number: a needle before or after
    a lone "." is still the value, and only a digit, or a dot attached to a
    digit, marks the longer number that keeps its text. Dotted and plain
    numeric needles take the same bound, and both shapes are pinned at the
    surface the needles use."""
    dotted = _non_finite_needles("1.5.4")
    for line in ("upgrade to 1.5.4.", "see .1.5.4", "ends -1.5.4."):
        assert "1.5.4" not in redact_values(line, dotted), (line,)
    # The longer-number side stays protected.
    for line in ("pip install requests-1.5.40", "release 1.5.4.1 shipped"):
        assert redact_values(line, dotted) == line, (line,)

    # The plain-number half: a derived print ("-1.5" for the hidden "-1.50")
    # and a written float ("4000.0") both reach the bound, and a lone dot
    # after either no longer protects it.
    signed = _non_finite_needles("-1.50")
    assert "-1.5" not in redact_values("limit -1.5.", signed)
    written = _non_finite_needles("4000.0")
    assert "4000.0" in written, written
    assert "4000.0" not in redact_values("port 4000.0.", written)
    # And per numeric class that reaches the bound -- a bare signed integer,
    # a dot-led float (no digit before its dot), and an exponent print -- so
    # a bound that mishandled any one class alone would fail here.
    assert "-4000" not in redact_values("limit -4000.", _non_finite_needles("-4000"))
    assert "-.25" not in redact_values("limit -.25.", _non_finite_needles("-.25"))
    exponent = _non_finite_needles("1e20")
    assert "1e+20" in exponent, exponent
    assert "1e+20" not in redact_values("x 1e+20.", exponent)


def test_a_bare_version_tail_is_the_value_once_nothing_continues_it():
    """The chosen trade-off, pinned: "requests-1.5" ends at the needle, so
    nothing marks it as a longer number and the glued short print is treated
    as the value ("requests-1.5.4" survives only because a digit, attached
    through a dot, continues it). Erring toward over-redaction is the chosen
    side."""
    values = _non_finite_needles("-1.50")
    # Exact equality, so eating MORE than the needle fails too: a match that
    # widened leftward into the word would still satisfy a bare absence check.
    shown = redact_values("pip install requests-1.5", values)
    assert shown == f"pip install requests{REDACTED}", shown


def test_an_exponent_tail_is_not_a_guarded_number_boundary():
    """The bound guards against digits, and dots attached to digits: in "factor -1.5e3
    applied" the needle is followed by "e3", so the match stands and the line
    shows the mask before "e3". The accepted display cost -- a lookahead that
    also skipped exponent tails would let the value's own digits print in
    clear whenever one follows."""
    values = _non_finite_needles("-1.50")
    shown = redact_values("factor -1.5e3 applied", values)
    assert "-1.5" not in shown, shown
    # The control: the rest of the line survives.
    assert "factor" in shown and "applied" in shown, shown


@pytest.mark.parametrize(
    ("written", "line"),
    [
        pytest.param("-1.50", "run_-1.50_dir", id="underscores-on-both-sides"),
        pytest.param("-1.50", "level-1.50 set", id="word-runs-into-the-sign"),
        pytest.param("1.50", "ASH_1.50_logs", id="unsigned-between-underscores"),
        pytest.param("1.50", "x1.50y", id="letters-on-both-sides"),
        pytest.param("0.50", "ratio_0.50", id="underscore-then-end"),
    ],
)
def test_a_short_numeric_value_glued_to_a_word_is_still_hidden(written, line):
    """The number boundary guards against longer NUMBERS, not words: a letter
    or "_" running into the value does not make it a different number, it
    makes it the value embedded in a word, and the value must not print.
    Only a digit, or a dot attached to a digit, on either side -- a version
    segment, a longer measurement -- keeps the text (the number-boundary
    cell pins that side)."""
    values = _non_finite_needles(written)
    assert written not in redact_values(line, values), (line, values)


def test_a_negative_zero_is_bounded_as_a_number():
    """ "-0.0" is MIN_REDACTED_LENGTH characters holding "." and a sign, a
    finite number, so it takes the number bound like any other short numeric
    needle: hidden inside a word, left inside a longer number."""
    values = _non_finite_needles("-0.0")
    # The control: the value is a needle at all.
    assert "-0.0" in values, values
    line = "pip install pkg-0.0.1"
    assert redact_values(line, values) == line, values
    assert "-0.0" not in redact_values("x-0.0y", values)


def test_a_negative_numbers_typed_spelling_no_longer_corrupts_a_version():
    """The companion shape: a negative number's float spelling ("-1.0") would
    eat "requests-1.0.4". The typed-spelling length rule already drops it, so
    the needles for "-1" are the value alone; this cell pins that the
    corruption cannot come back through the spelling list."""
    values = _non_finite_needles("-1")
    assert values == ["-1"], values
    line = "pip install requests-1.0.4"
    assert redact_values(line, values) == line, values


def test_each_long_cell_takes_the_branch_it_is_named_for():
    """The two long values are only two cells if they take two paths: a
    periodic LONG would ride the Z-array branch too and leave find-to-find
    untested for a re-cased long value."""
    from automated_security_helper.config.config_validator import _repeats_closely

    assert _repeats_closely(REPEATING) is True
    assert _repeats_closely(LONG) is False


def test_the_prefilter_path_answers_windows_the_same_way(monkeypatch):
    """Junk windows past ``_PREFILTER_AFTER_SEARCHES`` push ``_cut_windows``
    onto the prefilter set, so the real window after them is answered through
    it: it is still hidden, and the junk is still left. An inverted prefilter
    lookup changes the answers; the set is only a necessary condition, so
    leaving it out changes cost, not answers. The count comes from the
    constant and a spy pins that the prefilter was really built: a hard-coded
    count passes without ever reaching it once the threshold moves."""
    from automated_security_helper.config import config_validator

    built = []
    real = config_validator._window_prefilter

    def counting(folded_forms):
        built.append(len(folded_forms))
        return real(folded_forms)

    monkeypatch.setattr(config_validator, "_window_prefilter", counting)
    count = config_validator._PREFILTER_AFTER_SEARCHES + 8
    junk = " ".join(f"...wnd{1000 + i}xx..." for i in range(count))
    text = f"{junk} ...{A[2:10]}... end"

    redacted = redact_values(text, [A])

    assert redacted.endswith(f"...{REDACTED}... end"), redacted[-60:]
    assert "wnd1000xx" in redacted, redacted[:120]
    assert f"wnd{1000 + count - 1}xx" in redacted, redacted[-200:]
    assert built, "the prefilter path was never taken"
