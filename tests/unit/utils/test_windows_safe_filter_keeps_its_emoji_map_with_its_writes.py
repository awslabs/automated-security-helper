# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""WindowsSafeFilter's emoji map follows the function that says what the console writes.

The filter replaces an emoji with a bracketed word only where the console cannot
write it, so its emoji map is what the console's ``writes`` function leaves over.
The map was computed once, in ``__init__``, from the function the filter read
off the console, while tests assigned ``_writes`` afterwards and left the map as
it was. Tests that built the filter and then marked it active got no ``writes``
function only because the host they ran on had no encoding issue when the filter
was built, so on a Windows host off a CI runner, with a cp1252 console, they read
the host and failed.

``writes`` is now an argument of the filter, left out to read the console as
before, and ``_writes`` rebuilds the map whenever it is assigned.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.utils import log
from automated_security_helper.utils.log import WindowsSafeFilter

pytestmark = pytest.mark.unit

CHECK = "\N{WHITE HEAVY CHECK MARK}"
E_ACUTE = "\N{LATIN SMALL LETTER E WITH ACUTE}"


def _writes_the_check_mark(character: str) -> bool:
    return character == CHECK


def _shown(windows: WindowsSafeFilter, message: str) -> str:
    record = logging.LogRecord("ash", logging.INFO, __file__, 1, message, (), None)
    assert windows.filter(record)
    return str(record.msg)


def test_a_filter_built_with_a_writes_function_does_not_replace_an_emoji_it_writes():
    windows = WindowsSafeFilter(writes=_writes_the_check_mark)

    assert CHECK not in windows._emoji_map
    assert windows._writes is _writes_the_check_mark
    windows._active = True
    assert _shown(windows, f"{CHECK} done") == f"{CHECK} done"


def test_a_filter_built_with_no_writes_function_replaces_every_emoji():
    windows = WindowsSafeFilter(writes=None)

    assert windows._writes is None
    assert windows._emoji_map[CHECK] == "[OK]"
    windows._active = True
    assert _shown(windows, f"{CHECK} done") == "[OK] done"


def test_a_writes_function_assigned_later_rebuilds_the_map():
    windows = WindowsSafeFilter()

    windows._writes = _writes_the_check_mark

    assert CHECK not in windows._emoji_map
    # And back: the map is what the function leaves, whichever function it is.
    windows._writes = None
    assert windows._emoji_map[CHECK] == "[OK]"


def test_a_filter_told_nothing_reads_the_console_when_the_host_has_an_issue(
    monkeypatch,
):
    monkeypatch.setattr(log, "_detect_encoding_issues", lambda: True)
    monkeypatch.setattr(log, "_console_writes", lambda: _writes_the_check_mark)

    windows = WindowsSafeFilter()

    assert windows._active is True
    assert windows._writes is _writes_the_check_mark
    assert CHECK not in windows._emoji_map


def test_a_filter_told_nothing_knows_nothing_of_the_console_off_an_issue_host(
    monkeypatch,
):
    monkeypatch.setattr(log, "_detect_encoding_issues", lambda: False)
    monkeypatch.setattr(log, "_console_writes", lambda: _writes_the_check_mark)

    windows = WindowsSafeFilter()

    assert windows._active is False
    assert windows._writes is None
    assert windows._emoji_map[CHECK] == "[OK]"


def test_a_filter_told_it_writes_nothing_ignores_a_console_the_host_would_read(
    monkeypatch,
):
    # The shape of a test helper that builds the filter and marks it active: on a
    # host with an encoding issue and a console that writes the accented letter,
    # it still gets the ASCII rule it asked for.
    monkeypatch.setattr(log, "_detect_encoding_issues", lambda: True)
    monkeypatch.setattr(log, "_console_writes", lambda: lambda character: True)

    asked_for_ascii = WindowsSafeFilter(writes=None)
    left_to_read = WindowsSafeFilter()

    assert _shown(asked_for_ascii, f"caf{E_ACUTE}") == "caf\\xe9"
    assert _shown(left_to_read, f"caf{E_ACUTE}") == f"caf{E_ACUTE}"
