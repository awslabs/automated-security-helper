# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every snapshot test prints through the console ASH really uses.

rich.print, rich.get_console and anything that prints with no console of its own go
through rich's one global Console. utils/console.py gives that console ASH's stream,
which checks each line, and ASH's class, which does not wrap text off a terminal.
The snapshot conftest replaces it before each test, so it is built under the pinned
terminal. Dropping it instead would have rich build a plain Console: the
goldens of every test that does not go through support/cli.run_cli would record
wraps a real ``ash`` does not make, and lines no check had seen.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
import rich
import rich.console

from automated_security_helper.utils.console import CommandSafeStream

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module", autouse=True)
def _a_host_rich_takes_for_legacy_windows() -> Iterator[None]:
    """Make rich's legacy-Windows detection answer yes until the conftest pins it.

    Module-scoped, so it is in place before the conftest's function-scoped
    _pinned_terminal runs. A global console built before that fixture turns the
    detection off reads True here, on any OS, as it would on windows-latest, where
    a capture stream is never a VT console.
    """
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(rich.console, "detect_legacy_windows", lambda: True)
        yield


def test_the_global_console_is_ashs():
    console = rich.get_console()

    assert isinstance(console.file, CommandSafeStream), console.file
    assert type(console).__name__ == "_AshConsole", type(console)


def test_text_printed_off_a_terminal_is_one_line_and_checked(capsys):
    """Printed off a terminal, this stays on one line and goes through the
    stream's check, so no part of it is a line a CI runner reads as a command."""
    rich.print("a" * 150 + "\n::error::own line")

    assert capsys.readouterr().out == "a" * 150 + "\n\\x3a:error::own line\n"


def test_the_global_console_is_built_in_the_pinned_terminal():
    """Built after every other pin: the pinned width, no color, and not legacy
    Windows, which would render one column narrower."""
    console = rich.get_console()

    assert console.legacy_windows is False
    assert console.width == 100, console.width
    assert console.color_system is None, console.color_system
