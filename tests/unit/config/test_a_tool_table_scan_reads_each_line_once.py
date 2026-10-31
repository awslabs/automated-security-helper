# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading an unparsable pyproject for an ``ash`` key costs a pass over its lines.

``_tool_ash_declared`` finds each bare ``[tool]`` header and reads the table
under it to the next real header (``_table_end``). An array left open hides every
header after it, so in a file of repeated ``[tool]`` and ``x = [`` pairs each
header's table ran to the end of the text, and the file cost the square of its
length: a repository that holds one such file, an ignored one included, stalled
the discovery that reads every pyproject candidate. A ``[tool]`` header that sits
inside a table already read to its end is inside a value that table left open, so
it is no header and its lines were searched with that table's.

Red at the base: the work count (calls to ``_brackets_left_open``, the per-line
step of the table scan) is on the order of ``pairs ** 2``, so the counting stand-in
raises long before the text is read through. At the fix it is one call per line.
The tests that read the answer are controls that hold at both ends.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import _tool_ash_declared

pytestmark = pytest.mark.unit

PAIRS = 2000
PAIR = "[tool]\nx = [\n"


def _count_line_steps(monkeypatch: pytest.MonkeyPatch, limit: int) -> list:
    """Wrap the per-line step of the table scan; raise once it runs past ``limit``
    calls, so a scan that repeats its work fails at once instead of running on."""
    calls: list = []
    real = config_sources._brackets_left_open

    def counting(line, depth, multiline):
        calls.append(None)
        if len(calls) > limit:
            raise AssertionError(
                f"the table scan made more than {limit} line reads for a text "
                f"of {limit} lines"
            )
        return real(line, depth, multiline)

    monkeypatch.setattr(config_sources, "_brackets_left_open", counting)
    return calls


def test_repeated_open_array_pairs_are_read_in_one_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = PAIR * PAIRS
    lines = text.count("\n")
    calls = _count_line_steps(monkeypatch, limit=lines)

    assert _tool_ash_declared(text) is None
    assert 0 < len(calls) <= lines


def test_repeated_pairs_closed_early_are_read_in_one_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A closing line followed by a real header ends every scan just before the
    end of the text, so cutting each scan at the end alone does not cure it."""
    text = PAIR * PAIRS + "]" * PAIRS + "\n[other]\nash = 1\n"
    lines = text.count("\n")
    calls = _count_line_steps(monkeypatch, limit=lines)

    assert _tool_ash_declared(text) is None
    assert 0 < len(calls) <= lines


def test_an_ash_key_after_repeated_pairs_is_still_read() -> None:
    """The control: the first table runs to the end of the text, so the ``ash``
    key written last is read as the ``[tool]`` table's, as before."""
    text = PAIR * 50 + "ash = 1\n"

    offset = _tool_ash_declared(text)

    assert offset is not None
    assert text[offset:].startswith("ash = 1")


def test_an_ash_key_between_repeated_pairs_is_read_at_its_own_line() -> None:
    text = PAIR * 5 + "ash = 1\n" + PAIR * 5

    offset = _tool_ash_declared(text)

    assert offset is not None
    assert text[offset:].startswith("ash = 1")


def test_repeated_pairs_closed_early_leave_a_later_table_alone() -> None:
    """The control: once the array closes, a real header ends the table, so an
    ``ash`` key under it is not the ``[tool]`` table's."""
    text = PAIR * 50 + "]" * 50 + "\n[other]\nash = 1\n"

    assert _tool_ash_declared(text) is None


def test_a_second_tool_header_after_a_closed_table_is_still_read() -> None:
    """The control: a ``[tool]`` header that follows a real header is a header,
    not part of the earlier table, so the key under it counts."""
    text = "[tool]\nx = 1\n[other]\ny = 2\n[tool]\nash = 1\n"

    offset = _tool_ash_declared(text)

    assert offset is not None
    assert text[offset:].startswith("ash = 1")
