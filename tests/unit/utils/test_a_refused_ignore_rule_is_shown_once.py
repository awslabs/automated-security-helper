# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused ignore rule is shown once in the warning that skips it.

The log sinks (the console, ash.log) show a record's message as a terminal shows
text: a control character is written as its escape. The warning for a rule the
parser refuses put the rule in already shown, and as its repr, so the sink showed
the shown text again: one ESC in a rule came out as ``\\\\\\\\x1b``, four
backslashes for the one of its escape. The raw rule goes into the message and
the sink shows it once.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils import get_scan_set
from automated_security_helper.utils.get_scan_set import (
    get_ash_ignorespec_with_attribution,
)
from automated_security_helper.utils.log import TextFileFormatter

pytestmark = pytest.mark.unit


def _refuse(self, pattern, base_path=None):
    raise ValueError("refused for the test")


def test_a_refused_ignore_rule_is_shown_once_in_the_skip_warning(tmp_path):
    """The parser is made to refuse every rule, so the warning's text is what is
    measured, not which patterns igittigitt refuses. The message is formatted
    the way ash.log formats it (TextFileFormatter), which is the sink's show."""
    rule = "build" + chr(0x1B) + "[31m"
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

    assert "Skipped ignore rule" in written, written
    assert "build\\x1b[31m" in written, written
    assert "\\\\x1b" not in written, written
    assert chr(0x1B) not in written, written
