# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin's log line shows each part of its message once.

PluginBase._plugin_log shows the message itself, with escape_markup, which writes a
control or a lone surrogate as its escape (utils/terminal_text.py). A part a call
site already showed, a ShownText from shown_not_obeyed or shown_on_one_line, is
left as it is there. Joined with the other parts before being escaped, it would be
a plain str again and shown a second time: the backslash of each of its escapes
would double (``secr\\\\udce9t``), on the console and in ash.log. So each part is
escaped on its own, and a part given as raw text is shown at the sink.

A record whose message holds a lone surrogate cannot be sent between pytest-xdist
workers. _plugin_log's message is shown before it is logged, so a name tarfile read
with a surrogate passes either way; the last cell runs that under xdist.
"""

from __future__ import annotations

import logging
import os
import subprocess  # nosec B404 - the test's own interpreter, fixed argv
import sys
from types import SimpleNamespace

import pytest
from rich.text import Text

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.utils.log import TextFileFormatter, console_text
from automated_security_helper.utils.terminal_text import (
    shown_not_obeyed,
    shown_on_one_line,
)
from tests.utils.helpers import REPO_ROOT, checkout_env

#: Where _plugin_log reads the plugin's name and appends its errors.
_PLUGIN = SimpleNamespace(
    config=SimpleNamespace(name="snyk-code"), errors=[], output=[]
)

#: A member's name as tarfile reads a latin-1 byte in it.
NAME = "secr\udce9t/x.js"


@pytest.fixture
def ash_records():
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def _logged(records, *parts) -> list[str]:
    """What the console and ash.log show for _plugin_log(*parts)."""
    PluginBase._plugin_log(_PLUGIN, *parts, level=logging.WARNING)
    (record,) = records
    record.getMessage().encode("utf-8")
    shown = [
        console_text(record, record.getMessage()),
        TextFileFormatter("%(message)s").format(record),
    ]
    for text in shown:
        text.encode("utf-8")
    return shown


@pytest.mark.parametrize(
    "parts",
    [
        pytest.param(
            [shown_on_one_line(f"its member '{NAME}' is held back")], id="one-part"
        ),
        pytest.param(
            [
                shown_not_obeyed(f"lib/b.tar is not sent: its member '{NAME}'"),
                shown_on_one_line(f"and '{NAME}' again"),
            ],
            id="two-parts",
        ),
    ],
)
@pytest.mark.unit
def test_a_part_shown_already_is_shown_once(ash_records, parts):
    for shown in _logged(ash_records, *parts):
        assert "'secr\\udce9t/x.js'" in shown, ascii(shown)
        assert "secr\\\\udce9t" not in shown, ascii(shown)


@pytest.mark.unit
def test_a_raw_part_is_shown_at_the_sink(ash_records):
    raw = f"its member '{NAME}' is held back\n::add-mask::x\x1b[2J"
    for shown in _logged(ash_records, raw):
        assert "'secr\\udce9t/x.js'" in shown, ascii(shown)
        assert "secr\\\\udce9t" not in shown, ascii(shown)
        # No line of the sink text is a workflow command. How each sink breaks
        # the form is its own business (the console splits a "::" pair with a
        # no-op tag pair, ash.log keeps the escaped lead); the property is
        # pinned, not the mechanism.
        assert not any(
            line.lstrip().startswith(("::", "##")) for line in shown.splitlines()
        ), ascii(shown)
        assert "\x1b" not in shown
        # Rendered with markup on, the sink text reads as it did before: the
        # escaped lead and the member name, with nothing added or lost.
        assert "\n\\x3a:add-mask::x\\x1b[2J" in Text.from_markup(shown).plain, ascii(
            shown
        )


@pytest.mark.unit
def test_a_shown_part_and_a_raw_part_are_each_shown_once(ash_records):
    parts = [shown_on_one_line(f"first '{NAME}'"), f"second '{NAME}'"]
    for shown in _logged(ash_records, *parts):
        assert shown.count("'secr\\udce9t/x.js'") == 2, ascii(shown)
        assert "secr\\\\udce9t" not in shown, ascii(shown)


_UNDER_XDIST = """
import logging
from pathlib import Path
from types import SimpleNamespace

import automated_security_helper
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.utils.terminal_text import shown_on_one_line

PLUGIN = SimpleNamespace(config=SimpleNamespace(name="snyk-code"), errors=[], output=[])
NAME = "secr\\udce9t/x.js"
CHECKOUT = Path(@CHECKOUT@)


def test_the_ash_imported_is_this_checkout():
    imported = Path(automated_security_helper.__file__).resolve()
    assert imported.is_relative_to(CHECKOUT.resolve()), imported


def test_a_raw_name():
    PluginBase._plugin_log(PLUGIN, f"its member '{NAME}'", level=logging.WARNING)


def test_a_shown_name():
    PluginBase._plugin_log(
        PLUGIN, shown_on_one_line(f"its member '{NAME}'"), level=logging.WARNING
    )
"""


@pytest.mark.integration
def test_a_name_with_a_surrogate_logged_under_xdist_reaches_the_report(tmp_path):
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "test_logged_names.py").write_text(
        _UNDER_XDIST.replace("@CHECKOUT@", repr(str(REPO_ROOT))), encoding="utf-8"
    )
    # The child, and the workers it starts, import ASH from this checkout: it runs
    # without -I, which would ignore PYTHONPATH, and checkout_env puts the checkout
    # first on it. Its first cell checks that.
    env = checkout_env(
        {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
    )
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-m",
            "pytest",
            "-n",
            "2",
            "-p",
            "no:cacheprovider",
            "-q",
            "test_logged_names.py",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=tmp_path,
        env=env,
    )
    output = completed.stdout + completed.stderr
    assert "INTERNALERROR" not in output, output[-3000:]
    assert completed.returncode == 0, output[-3000:]
    assert "3 passed" in output, output[-3000:]
