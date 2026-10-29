# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The joined-redaction pass redacts the command line once, then probes only the changed window.

``_arguments_in_joined_redactions`` names the arguments that take part in a
redaction only the joined command line makes. It probes an argument by
swapping that argument for a filler, redacting the line again, and comparing.
The probe is only needed for an argument that overlaps the part of the line
the joined redaction changed, so the number of full-line redactions does not
grow with the number of arguments.

The cells here pin three things:

* the number of full-line redactions is bounded by the changed window, not by
  the argument count (the call-count cells);
* an argument far from the changed window is never probed (the argument log);
* the answer is identical to the answer of the one-probe-per-argument
  reference below for every input shape, whether the caller passes the line
  it already redacted or not (the equivalence cells).
"""

import re
import shlex

import pytest

from automated_security_helper.base import scanner_plugin as scanner_plugin_module
from automated_security_helper.base.scanner_plugin import (
    _arguments_in_joined_redactions,
)
from automated_security_helper.utils.error_text import text_without_values

pytestmark = pytest.mark.unit

SPAN_VALUE = "--tok alpha-secret-one"
HEAD = ["scanner", "--tok", "alpha-secret-one"]


def _targets(count):
    """Targets of distinct lengths, so a probe's filler (a run of the same
    length) names the piece it replaced."""
    return [f"target-path-{'x' * (8 + index)}" for index in range(count)]


def _reference(arguments, values):
    """The one-probe-per-argument shape the function had before the window."""
    values = list(values)
    pieces = [shlex.quote(argument) for argument in arguments]
    joined = " ".join(pieces)
    redacted = text_without_values(joined, values)
    if redacted == joined:
        return [False] * len(arguments)
    covered = []
    for index, piece in enumerate(pieces):
        filler = "\x01" * max(len(piece), 1)
        probe = " ".join(filler if i == index else p for i, p in enumerate(pieces))
        restored = text_without_values(probe, values).replace(filler, piece, 1)
        covered.append(restored != redacted)
    return covered if any(covered) else [True] * len(arguments)


class _Log:
    def __init__(self):
        self.texts = []

    def probed_indexes(self, arguments):
        """The argument indexes the probes replaced, read off each filler's length."""
        lengths = {
            len(shlex.quote(argument)): index
            for index, argument in enumerate(arguments)
        }
        found = []
        for text in self.texts:
            runs = re.findall("\x01+", text)
            if runs:
                found.append(lengths[len(runs[0])])
        return found

    def full_line_redactions(self):
        return len(self.texts)


@pytest.fixture
def log(monkeypatch):
    seen = _Log()
    real = scanner_plugin_module.text_without_values

    def counting(text, values, *args, **kwargs):
        seen.texts.append(text)
        return real(text, values, *args, **kwargs)

    monkeypatch.setattr(scanner_plugin_module, "text_without_values", counting)
    return seen


def _split_value_arguments(target_count):
    return [*HEAD, *_targets(target_count)]


# -- call-count cells (red before the window; green after) --------------------


def test_full_line_redactions_do_not_grow_with_the_argument_count(monkeypatch):
    counts = {}
    for target_count in (10, 60):
        seen = _Log()
        real = text_without_values

        def counting(text, values, *args, _seen=seen, _real=real, **kwargs):
            _seen.texts.append(text)
            return _real(text, values, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(scanner_plugin_module, "text_without_values", counting)
            taking_part = _arguments_in_joined_redactions(
                _split_value_arguments(target_count), (SPAN_VALUE,)
            )
        assert taking_part[1:3] == [True, True]
        counts[target_count] = seen.full_line_redactions()
    assert counts[10] == counts[60], counts


def test_a_split_value_costs_a_constant_number_of_full_line_redactions(log):
    arguments = _split_value_arguments(40)
    _arguments_in_joined_redactions(arguments, (SPAN_VALUE,))
    assert log.full_line_redactions() <= 8, log.full_line_redactions()


def test_the_callers_redacted_line_is_not_computed_again(log):
    arguments = _split_value_arguments(40)
    joined = shlex.join(arguments)
    redacted = text_without_values(joined, (SPAN_VALUE,))
    log.texts.clear()
    taking_part = _arguments_in_joined_redactions(
        arguments, (SPAN_VALUE,), redacted=redacted
    )
    assert taking_part[1:3] == [True, True]
    assert joined not in log.texts
    assert log.full_line_redactions() <= 7, log.full_line_redactions()


# -- the argument log (red before the window; green after) --------------------


def test_an_argument_outside_the_changed_window_is_never_probed(log):
    arguments = _split_value_arguments(40)
    _arguments_in_joined_redactions(arguments, (SPAN_VALUE,))
    probed = log.probed_indexes(arguments)
    far = set(range(len(HEAD) + 2, len(arguments)))
    assert far.isdisjoint(probed), sorted(far.intersection(probed))
    assert {1, 2}.issubset(probed), probed


def test_the_pieces_that_make_up_the_span_are_probed(log):
    arguments = _split_value_arguments(5)
    result = _arguments_in_joined_redactions(arguments, (SPAN_VALUE,))
    assert result[1] is True
    assert result[2] is True
    assert result[-1] is False
    assert {1, 2}.issubset(log.probed_indexes(arguments))


# -- equivalence cells (green before and after) -------------------------------

SHAPES = {
    "split-value-between-two-arguments": (
        ["scanner", "--tok", "alpha-secret-one", "tail"],
        ("--tok alpha-secret-one",),
    ),
    "value-at-the-line-start": (
        ["--tok", "alpha-secret-one", "middle", "tail"],
        ("--tok alpha-secret-one",),
    ),
    "value-at-the-line-end": (
        ["scanner", "middle", "--tok", "alpha-secret-one"],
        ("--tok alpha-secret-one",),
    ),
    "several-values-apart": (
        ["a1-secret", "b1-secret", "gap", "c1-secret", "d1-secret", "gap-two"],
        ("a1-secret b1-secret", "c1-secret d1-secret"),
    ),
    "chain-of-overlapping-values": (
        ["a1-secret", "b1-secret", "c1-secret", "d1-secret"],
        ("a1-secret b1-secret", "b1-secret c1-secret", "c1-secret d1-secret"),
    ),
    "whole-value-in-one-argument": (
        ["scanner", "alpha-secret-one", "tail"],
        ("alpha-secret-one",),
    ),
    "value-the-quoting-makes-visible": (
        ["scanner", "marker-quote'carrier-value", "tail"],
        ("marker-quote'carrier-value",),
    ),
    "no-value-in-the-line": (
        ["scanner", "--flag", "plain", "tail"],
        ("not-in-the-line-at-all",),
    ),
    "no-values-at-all": (["scanner", "--flag", "plain"], ()),
    "unicode-value-split-across-arguments": (
        ["scanner", "--clé", "sécret-ünï-ça", "queue"],
        ("--clé sécret-ünï-ça",),
    ),
    "unicode-neighbors-around-an-ascii-value": (
        ["日本語", "--tok", "alpha-secret-one", "ключ"],
        ("--tok alpha-secret-one",),
    ),
    "escape-code-splits-a-value": (
        ["scanner", "EDGE\x1b[KSECRET", "other", "EDGE", "SECRET"],
        ("EDGESECRET", "EDGE SECRET"),
    ),
    "argument-with-a-space": (
        ["scanner", "two words", "alpha-secret-one", "tail"],
        ("two words alpha-secret-one",),
    ),
    "empty-argument-between-values": (
        ["scanner", "", "alpha-secret-one", "tail"],
        ("alpha-secret-one",),
    ),
    "marker-lookalike-text-before-a-value": (
        ["<value", "--tok", "alpha-secret-one", "tail"],
        ("--tok alpha-secret-one",),
    ),
    "marker-text-already-in-the-line": (
        ["<value>", "--tok", "alpha-secret-one", "<value>"],
        ("--tok alpha-secret-one",),
    ),
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_answer_equals_the_one_probe_per_argument_reference(shape):
    arguments, values = SHAPES[shape]
    assert _arguments_in_joined_redactions(arguments, values) == _reference(
        arguments, values
    )


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_answer_is_the_same_when_the_caller_passes_its_redacted_line(shape):
    arguments, values = SHAPES[shape]
    redacted = text_without_values(shlex.join(arguments), values)
    assert _arguments_in_joined_redactions(
        arguments, values, redacted=redacted
    ) == _reference(arguments, values)


def test_a_changed_line_no_probe_explains_hides_every_entry(monkeypatch):
    """When the redaction changes the line but swapping any one entry for a
    filler leaves the redacted line as it was, no entry can be named, so all
    of them are reported."""
    fixed_line = "fixed line"

    def constant(text, values, *args, **kwargs):
        return fixed_line

    monkeypatch.setattr(scanner_plugin_module, "text_without_values", constant)
    arguments = ["scanner", "alpha-secret", "tail"]
    assert _arguments_in_joined_redactions(arguments, ("anything-secret",)) == [
        True,
        True,
        True,
    ]


def test_a_long_line_with_a_split_value_answers_as_the_reference_does():
    arguments = _split_value_arguments(30)
    values = (SPAN_VALUE,)
    answer = _arguments_in_joined_redactions(arguments, values)
    assert answer == _reference(arguments, values)
    assert answer[1:3] == [True, True]
    assert not any(answer[4:])


@pytest.mark.parametrize("position", [0, 7, 14, 21])
def test_a_split_value_anywhere_in_a_long_line_answers_as_the_reference_does(position):
    targets = _targets(24)
    arguments = [*targets[:position], "--tok", "alpha-secret-one", *targets[position:]]
    values = (SPAN_VALUE,)
    answer = _arguments_in_joined_redactions(arguments, values)
    assert answer == _reference(arguments, values)
    assert answer[position : position + 2] == [True, True]
