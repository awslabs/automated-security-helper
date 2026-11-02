# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused ignore rule is shown once in the warning that skips it.

The log sinks (the console, ash.log) show a record's message as a terminal shows
text: a control character is written as its escape. The warning for a rule the
parser refuses put the rule in already shown, and as its repr, so the sink showed
the shown text again: one ESC in a rule came out as ``\\\\\\\\x1b``, four
backslashes for the one of its escape. The sinks also keep a tab, a newline and
a carriage return of a plain message as they are, so a rule holding one would
lay out, overwrite or add a line of the log. The warning shows its whole message
once, on one line (shown_on_one_line), and the sinks leave it as it is.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import get_scan_set
from automated_security_helper.utils.get_scan_set import (
    get_ash_ignorespec_with_attribution,
)
from automated_security_helper.utils.log import TextFileFormatter, console_text

pytestmark = pytest.mark.unit


def _refuse(self, pattern, base_path=None):
    raise ValueError("refused for the test")


#: A rule, and the text both sinks must show for it. The sinks keep a tab, a
#: newline and a carriage return of a plain message as they are (they lay the
#: text out), so the warning has to write those three as escapes itself, as
#: well as leave the escape of an ESC single. gitignore_rule_for_igittigitt
#: keeps a tab or a carriage return inside a line, wraps one at either end in
#: brackets, and a rule from a caller's list can hold a newline.
_RULES = [
    pytest.param("build" + chr(0x1B) + "[31m", "build\\x1b[31m", id="escape"),
    pytest.param("ab[" + chr(0x0D) + "scan clean", "ab[\\x0dscan clean", id="cr"),
    pytest.param("a" + chr(0x09) + "b.py", "a\\x09b.py", id="tab"),
    pytest.param("one" + chr(0x0A) + "two", "one\\x0atwo", id="newline"),
    pytest.param(chr(0x09) + "lead.py", "[\\x09]lead.py", id="tab-at-the-edge"),
]


@pytest.mark.parametrize(("rule", "shown_rule"), _RULES)
def test_a_refused_ignore_rule_is_shown_once_in_the_skip_warning(
    tmp_path, rule, shown_rule
):
    """The parser is made to refuse every rule, so the warning's text is what is
    measured, not which patterns igittigitt refuses. The message is formatted
    the way ash.log formats it (TextFileFormatter) and the way the console
    handler renders it (console_text, which ConsoleHandler.render_message
    calls): both sinks show the rule once, on one line, with no control in it."""
    warning = MagicMock()
    with (
        patch.object(get_scan_set.IgnoreParser, "add_rule", _refuse),
        patch.object(get_scan_set.ASH_LOGGER, "warning", warning),
    ):
        get_ash_ignorespec_with_attribution([rule], tmp_path)

    assert warning.call_count == 1, warning.call_args_list
    message = warning.call_args.args[0]
    record = logging.LogRecord("ash", logging.WARNING, __file__, 1, message, None, None)
    written = TextFileFormatter("%(message)s").format(record)

    shown = console_text(record, record.getMessage())

    for text in (written, shown):
        assert "Skipped ignore rule" in text, text
        assert shown_rule in text, text
        assert "\\\\x" not in text, text
        for control in (chr(0x1B), chr(0x09), chr(0x0A), chr(0x0D)):
            assert control not in text, (control, text)
        assert len(text.splitlines()) == 1, text
