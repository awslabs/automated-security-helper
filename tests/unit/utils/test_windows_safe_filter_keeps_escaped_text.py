# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Windows log filter keeps a markup record's escaped values as text.

Why this exists
---------------
On a Windows console that cannot write Unicode, and on a Windows CI runner,
``WindowsSafeFilter`` rewrites each record's message to ASCII: it replaces some
characters (an arrow "↓" becomes "v") and writes the rest as escapes (an "é"
becomes the four characters of ``\\xe9``; nothing is dropped). A record that asks
for Rich markup (``extra=MARKUP``) has had each value escaped with
``escape_markup`` before that, and the rewrite can undo the escape: the escape
text put between a value's own backslash and the tag changes what stands before
"[/x]", and "[↓x]", which is no tag, would become "[vx]", which is one, and its
text be dropped. A record whose rewrite would change the text it shows is
written as that text's ASCII form, without markup; one whose rewrite changes
nothing but characters keeps its styles.

The filter is active on Windows only, so these cells turn it on.
"""

from __future__ import annotations

import logging

import pytest
from rich.text import Text

from automated_security_helper.utils.log import (
    MARKUP,
    WindowsSafeFilter,
    escape_markup,
)

pytestmark = pytest.mark.unit


def _filtered(message: str, args=(), markup: bool = True) -> logging.LogRecord:
    """A record through the active filter; with *markup* it asks for Rich markup."""
    # A console that is known to write only ASCII, whatever host the test is on.
    windows_filter = WindowsSafeFilter(writes=None)
    windows_filter._active = True
    record = logging.LogRecord("ash", logging.INFO, __file__, 1, message, args, None)
    if markup:
        record.__dict__.update(MARKUP)
    assert windows_filter.filter(record)
    return record


def _filtered_plain(message: str, args=()) -> logging.LogRecord:
    """A plain (no markup) record through the active filter."""
    return _filtered(message, args, markup=False)


def test_an_ascii_message_keeps_its_own_escape_text():
    """A suggested command quotes a JSON document whose non-ASCII character is
    JSON's own escape, four ASCII characters after one backslash. Shown, that
    run was doubled and the pasted command read the escape as text; a message
    the console can already write is left as it was logged."""
    import json
    import shlex

    message = "ash --config-overrides " + shlex.quote(
        json.dumps({"ignore_paths": ["café dir/.ash/ash_output"]})
    )
    assert message.isascii() and "\\u00e9" in message

    record = _filtered_plain(message)

    assert record.getMessage() == message
    (quoted,) = shlex.split(record.getMessage())[2:]
    assert json.loads(quoted) == {"ignore_paths": ["café dir/.ash/ash_output"]}


def test_an_ascii_message_with_ascii_arguments_is_left_as_logged():
    """Left as logged on purpose: the filter rewrites only what the console cannot
    write. ASH's own sinks show every message themselves, once, and break its CI
    command forms, so this record's "::" and "##vso[" do not reach a console or
    ash.log as commands; that is pinned through the console with the filter on, in
    test_log_console_shows_controls.py
    (test_no_line_of_the_console_is_a_workflow_command, "windows-ci"). A handler an
    application put on the logger gets the record as written, which is
    CommandSafeFormatter's to handle."""
    record = _filtered_plain("scan %s in %d ms", ("a::b ##vso[x]", 3))

    assert record.msg == "scan %s in %d ms"
    assert record.args == ("a::b ##vso[x]", 3)


@pytest.mark.parametrize("lead", ["", " ", "\t"], ids=["bare", "space", "tab"])
def test_a_message_the_console_cannot_write_is_folded_and_shown(lead):
    """The folded text is shown once: the letter the console cannot write as its
    escape, and a CI command form broken. A "::" is a command only at the start
    of a line, after whitespace the runner trims (an ARN's "::" is mid-line and
    stays readable), so the argument puts one there."""
    record = _filtered_plain("%s", (lead + "::add-mask::café",))

    assert record.args == ()
    assert record.getMessage().isascii()
    assert "caf\\xe9" in record.getMessage()
    assert not record.getMessage().lstrip().startswith("::")
    assert "add-mask::caf" in record.getMessage()


def _suggested_ignore_paths(message: str) -> list:
    """The ignore_paths entries the suggested command in *message* adds, read the
    way a POSIX shell and ASH's override parser read it."""
    import shlex

    from automated_security_helper.config.resolve_config import (
        _apply_config_override,
    )

    words = shlex.split(message.split("--config-overrides ", 1)[1].rstrip("."))
    assert len(words) == 1, words
    key, _, value = words[0].partition("=")
    config: dict = {"global_settings": {"ignore_paths": []}}
    _apply_config_override(config, key, value)
    return config["global_settings"]["ignore_paths"]


def test_the_real_warning_through_the_active_filter_keeps_its_command(caplog):
    """The warning ASH writes, not a copy of its shape: captured from
    warn_about_scanned_output_dir and passed through the active filter, so a change
    to how the warning builds its command (its quoting, ``ensure_ascii``) is read
    here as the Windows console would show it."""
    from automated_security_helper.utils.scan_output_dirs import (
        warn_about_scanned_output_dir,
    )

    relative = "café dir/.ash/ash_output"
    with caplog.at_level(logging.WARNING):
        warn_about_scanned_output_dir(relative, 2)
    [captured] = caplog.records
    windows_filter = WindowsSafeFilter()
    windows_filter._active = True

    assert windows_filter.filter(captured)

    shown = captured.getMessage()
    assert shown.isascii(), shown
    assert shown.startswith("caf\\xe9 dir/.ash/ash_output is not"), shown
    assert _suggested_ignore_paths(shown) == [
        {"path": f"{relative}/", "reason": "earlier ASH output"}
    ]


def test_a_suggested_command_in_a_message_the_console_cannot_write_is_kept():
    """The warning that suggests the command names the directory raw in its
    prose and as JSON's escape inside the quoted document. The prose makes the
    message one the console cannot write, so it is shown and put in ASCII: the
    raw letter becomes ``\\xe9``, and the JSON escape, whose run the default
    showing doubled, stays as logged, so the pasted command adds the directory
    the warning names."""
    import json
    import shlex

    relative = "café dir/.ash/ash_output"
    entry = json.dumps([{"path": f"{relative}/", "reason": "earlier ASH output"}])
    override = shlex.quote(f"global_settings.ignore_paths+={entry}")
    message = (
        f"{relative} is not this scan's output directory. "
        f"For example: --config-overrides {override}."
    )
    assert not message.isascii() and "\\u00e9" in message

    record = _filtered_plain(message)

    shown = record.getMessage()
    assert shown.isascii()
    assert shown.startswith("caf\\xe9 dir/.ash/ash_output is not")
    assert _suggested_ignore_paths(shown) == [
        {"path": f"{relative}/", "reason": "earlier ASH output"}
    ]


def _shown(record: logging.LogRecord) -> Text:
    message = record.getMessage()
    if getattr(record, "markup", False):
        return Text.from_markup(message)
    return Text(message)


@pytest.mark.parametrize(
    "value, shown",
    [
        pytest.param("C:\\\u00e9[/x]", "C:\\\\xe9[/x]", id="escaped-after-a-backslash"),
        pytest.param(
            "C:\\\u00e9[bold]x[/bold]",
            "C:\\\\xe9[bold]x[/bold]",
            id="style-after-a-backslash",
        ),
        pytest.param("[\u2193x]", "[vx]", id="replaced-into-a-tag"),
    ],
)
def test_an_escaped_value_is_shown_as_its_ascii_text(value, shown):
    record = _filtered(f"[yellow]p[/yellow] {escape_markup(value)}")

    assert _shown(record).plain == f"p {shown}"


def test_a_record_the_rewrite_leaves_whole_keeps_its_styles():
    record = _filtered(f"[yellow]p[/yellow] \u2705 {escape_markup('x[/x]')}")

    text = _shown(record)
    assert text.plain == "p [OK] x[/x]"
    assert getattr(record, "markup", False) is True
    assert [span.style for span in text.spans] == ["yellow"]
