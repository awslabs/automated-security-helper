# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which typed spellings join the redaction needles, and which never do.

``environment_record_read`` returns the values a chain read from the
environment, for redacting what is printed, and adds the spellings a model
that types a value as a number prints (``_typed_spellings``), under one
rule. A long integer rendering joins: an account id's typed digits identify
the value. A short print joins only when the value itself is hidden beyond
its quoted form (MIN_REDACTED_LENGTH or longer) and the print is not a bare
unsigned number -- a plugin's own exception can print the typed float, and
a line that hides "1e20" while printing "1e+20" hides nothing. Everything
else is dropped, bare numbers ("10.0" for "10", "1000" for "1_000") and
long float renderings ("100000.0") alike: hiding a generic number corrupts
text that legitimately contains it -- an address ("10.0.0.5"), a version
("grype 0.10.0"), a duration ("110.05s", "elapsed 1100000.05ms"). The value
itself joins the needles whatever its shape: an all-digits value can be an
identifier, which is exactly what the needles exist to hide.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_validator import environment_record_read
from automated_security_helper.utils.error_text import text_without_values

pytestmark = pytest.mark.unit

VARIABLE = "ASH_NUMERIC_NEEDLE"


@pytest.fixture
def values_read(tmp_path, monkeypatch):
    """The needle values a one-file chain reading ``VARIABLE`` produces."""

    def read(value: str) -> list:
        monkeypatch.setenv(VARIABLE, value)
        config = tmp_path / f"needle-{len(value)}-{abs(hash(value))}.yaml"
        config.write_text(
            "project_name: demo\n"
            "global_settings:\n"
            "  ignore_paths:\n"
            "    - path: 'vendor'\n"
            f"      reason: !ENV ${{{VARIABLE}}}\n",
            encoding="utf-8",
        )
        values, _ = environment_record_read([Path(config)], reads={})
        return values

    return read


def test_a_numeric_values_spellings_are_not_needles(values_read):
    values = values_read("10")
    assert "10" in values, values
    assert "10.0" not in values, values


def test_an_underscored_numbers_bare_spellings_are_not_needles(values_read):
    """float() and int() accept underscores, so "1_000" has bare-number
    spellings; the distinctive underscored text itself stays a needle."""
    values = values_read("1_000")
    assert "1_000" in values, values
    assert "1000" not in values, values
    assert "1000.0" not in values, values


def test_an_all_digits_identifier_stays_a_needle(values_read):
    """The value joins whatever its shape: twelve digits can be an account
    id, and dropping it would print it everywhere the needles redact."""
    values = values_read("123456789012")
    assert "123456789012" in values, values


@pytest.mark.parametrize(
    "written, typed",
    [
        ("012345678901", "12345678901"),
        ("123456789012.0", "123456789012"),
        ("+15551234567", "15551234567"),
    ],
    ids=["leading-zero", "float-written", "plus-signed"],
)
def test_a_long_identifiers_typed_form_stays_a_needle(values_read, written, typed):
    """A non-canonical long identifier -- a leading zero, a ``.0``, a ``+`` --
    prints as its TYPED digits once an int field loads it, and those digits
    are long enough to identify the value (an account id, a phone number):
    dropping them prints all but the stripped character everywhere the
    needles redact."""
    values = values_read(written)
    assert written in values, values
    assert typed in values, values

    line = f"the request used {typed} as the account"
    assert typed not in text_without_values(line, values), (
        text_without_values(line, values),
        values,
    )


@pytest.mark.parametrize(
    "written, absent, present",
    [
        ("-10", ["-10.0"], ["-10"]),
        ("-067", [], ["-067", "-67.0", "-67"]),
        ("1e20", [], ["1e20", "1e+20"]),
        ("0.50", ["0.5"], ["0.50"]),
    ],
    ids=["negative", "negative-padded", "exponent", "bare-number"],
)
def test_a_short_derived_print_joins_only_for_a_hidden_value_and_never_bare(
    values_read, written, absent, present
):
    """A short derived print joins when the value it spells is itself hidden
    beyond quotes (MIN_REDACTED_LENGTH or longer) and the print is not a bare
    unsigned number: a plugin's own exception can name the typed float, and a
    line that hides "1e20" while printing "1e+20" hides nothing (the base
    failure-line cells pin the leak). A bare unsigned number ("0.5") still
    joins nothing, whatever its value's length -- its redaction corrupts line
    numbers and versions. A value under MIN_REDACTED_LENGTH keeps the drop
    its own band gives it: "-10" is only quoted-redacted, so "-10.0"
    identifies nothing a line hides ("delta -10.05s" stays readable)."""
    values = values_read(written)
    for needle in present:
        assert needle in values, (needle, values)
    for spelling in absent:
        assert spelling not in values, (spelling, values)


@pytest.mark.parametrize(
    "written, absent, present",
    [
        ("100000", ["100000.0"], ["100000"]),
        ("1000000", ["1000000.0"], ["1000000", "1e+06"]),
        ("0.333333333", ["0.333333"], ["0.333333333"]),
    ],
    ids=["six-digits", "seven-digits", "repeating-fraction"],
)
def test_a_long_float_rendering_of_an_integer_is_not_a_needle(
    values_read, written, absent, present
):
    """Length is not distinctiveness for a float rendering: "100000.0" is
    eight characters and would match anywhere, so "elapsed 1100000.05ms"
    loses its middle, and the ``:g`` fraction "0.333333" eats "0.3333334".
    The long-form keep is for integer renderings only (digits with one
    optional sign) -- the account-id shape. A non-pure short print of a
    hidden value ("1e+06") still joins under the hidden-value rule, so a
    plugin printing the exponent form leaks nothing."""
    values = values_read(written)
    for needle in present:
        assert needle in values, (needle, values)
    for spelling in absent:
        assert spelling not in values, (spelling, values)


def test_a_long_float_rendering_does_not_eat_a_longer_number(values_read):
    values = values_read("100000")
    line = "elapsed 1100000.05ms"
    assert text_without_values(line, values) == line, (
        text_without_values(line, values),
        values,
    )


@pytest.mark.parametrize(
    "written, absent, present",
    [
        ("-67", ["-67.0"], []),
        ("-067", [], ["-67", "-67.0"]),
        ("+1234567", ["1234567"], []),
        ("+12345678", [], ["12345678"]),
        ("1", ["1.0"], []),
        ("0.0", ["0"], []),
        ("+0", ["0"], []),
    ],
    ids=[
        "value-under-the-band",
        "value-at-the-band",
        "pure-print-under-eight",
        "integer-print-at-eight",
        "one-digit",
        "zero-float",
        "signed-zero",
    ],
)
def test_the_rules_edges_hold_exactly(written, absent, present):
    """The edges, pinned so a drifted comparison or constant is caught: a
    value one character under MIN_REDACTED_LENGTH contributes no derived
    needle at all (one character or three, pure or signed) while at exactly
    MIN_REDACTED_LENGTH its non-pure prints join; a purely numeric print one
    character under MIN_ANYWHERE_LENGTH is dropped while the integer
    rendering at exactly MIN_ANYWHERE_LENGTH is kept."""
    from automated_security_helper.config.config_validator import _typed_spellings

    spellings = _typed_spellings(written)
    for needle in present:
        assert needle in spellings, (needle, spellings)
    for spelling in absent:
        assert spelling not in spellings, (spelling, spellings)


def test_the_measured_harm_line_stays_readable(values_read):
    """The harm the drop for short values exists for, asserted through the
    redaction itself and not only list membership: with the env value "-10",
    "delta -10.05s" is printed as it is."""
    values = values_read("-10")
    line = "delta -10.05s"
    assert text_without_values(line, values) == line, (
        text_without_values(line, values),
        values,
    )


def test_a_wordlike_value_keeps_its_needle(values_read):
    values = values_read("needleprobe-word")
    assert "needleprobe-word" in values, values


def test_text_containing_the_spelling_survives_redaction(values_read):
    """The measured harm: with the env value "10", text whose middle holds
    "10.0" is printed as it is -- the spelling is no needle, and the value
    "10" is too short for anything but its quoted form."""
    values = values_read("10")
    line = "listening on 10.0.0.5, grype 0.10.0 finished in 110.05s"
    assert text_without_values(line, values) == line, (
        text_without_values(line, values),
        values,
    )
