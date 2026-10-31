# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The bare-number boundary, in a leaf module on purpose.

config_validator's derived-spelling rule and the Bedrock reporter's
numeric-knob exclusion both call :func:`purely_numeric` at module load (the
reporter builds its default needle set while it is being imported), and the
config package imports the plugin modules at start-up. A definition inside
either package would make one of those loads import the other mid-import.
This module imports no ASH module, so both can import it at the top.
"""

from __future__ import annotations

import math
import re

#: The redaction bands, by a printed form's length: under MIN_REDACTED_LENGTH
#: a value is replaced only where the text quotes it whole; from
#: MIN_REDACTED_LENGTH it is replaced as a word (or anywhere, with a non-word
#: character); from MIN_ANYWHERE_LENGTH it is replaced anywhere. The numbers
#: live here with the predicates that read them, so the validator's rules and
#: any other surface that redacts a written numeric value share one boundary;
#: config_validator re-exports them.
MIN_REDACTED_LENGTH = 4
MIN_ANYWHERE_LENGTH = 8

#: Digits separated by single dots, with an optional sign: a dotted version
#: ("1.5.4"). Not a float, but digits and dots, so it takes the number bound.
_DOTTED_VERSION = re.compile(r"[+-]?\d+(?:\.\d+)+")


def purely_numeric(value: str) -> bool:
    """ASCII digits with at most one dot: "0", "0.50", "4000".

    The one definition of this boundary: a change here moves the validator's
    derived-spelling rule and the Bedrock knob exclusion together. The
    Bedrock site layers one leading sign on top at its own call.

    ASCII decimal digits only. ``str.isdigit`` is wider: a superscript, a
    circled digit and another script's digits all pass it, while ``int()`` and
    ``float()`` refuse the first two, so a knob value spelled with one read as a
    bare number here and as a non-number everywhere else."""
    digits = value.replace(".", "", 1)
    return digits.isascii() and digits.isdecimal()


def number_bounded_form(form: str) -> bool:
    """Whether a form is a short numeric print, matched only at a number
    boundary: not preceded or followed by a digit, or a dot attached to a
    digit, so a longer number keeps its text, while a letter, "_" or a lone
    dot against it does not save it -- a value glued into a word, or ending
    a sentence, is still the value. The guard covers digit continuations
    only: an exponent tail ("-1.5e3") is not one, so there the match stands
    and the mask shows before the tail, the over-redaction side. Under
    MIN_ANYWHERE_LENGTH only -- a longer form
    is distinctive on its own -- finite numbers, and dotted versions: a
    "1.5.4" is not a float, but it is digits and dots, and unbounded it eats
    the front of "requests-1.5.40". The non-finite words take the whole-word
    route instead. Shared by the validator's needle matching and any surface
    that redacts a written numeric value of the same band."""
    if len(form) >= MIN_ANYWHERE_LENGTH:
        return False
    try:
        return math.isfinite(float(form))
    except ValueError:
        return _DOTTED_VERSION.fullmatch(form) is not None


def bounded_number_pattern(form: str) -> str:
    """The pattern that matches a number-bounded form: *form* where no digit,
    and no dot attached to a digit, runs into it on either side.
    "requests-1.5.4" and "delta -1.55s" keep their text (a digit or ".4"
    continues the form there), while the form standing alone, quoted, next
    to a LONE dot ("port 4000.", "see .1.5.4" -- sentence punctuation is not
    a longer number), ending a word ("-1.5s"), glued into one ("x1.50y",
    "run_-1.50_dir"), or continued only by an exponent tail ("-1.5e3", where
    the mask shows before "e3") is hidden."""
    return rf"(?<!\d)(?<!\d\.){re.escape(form)}(?!\d|\.\d)"
