# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``without_process_ids`` drops each ``(pid N)`` parenthetical and nothing else.

A remote client is shown the reason for a tool that could not be ended without
the process id the executor recorded in it. The MCP scan runner stores a remote
caller's coverage through this helper, so the helper has to exist and has to
leave every other part of the text as it was.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_REASON,
    could_not_stop_default,
    could_not_stop_sentence,
    without_process_ids,
)

pytestmark = pytest.mark.unit


def test_the_default_reason_for_a_real_pid_becomes_the_pidless_reason():
    assert "4242" in could_not_stop_default(4242)

    assert without_process_ids(could_not_stop_default(4242)) == COULD_NOT_STOP_REASON


def test_a_referent_that_carries_a_pid_reads_as_the_bare_referent():
    with_pid = could_not_stop_sentence("python3 (pid 7)")

    assert without_process_ids(with_pid) == could_not_stop_sentence("python3")


def test_every_pid_parenthetical_in_a_text_is_dropped():
    text = "bandit (pid 11) and semgrep (pid 2048) were still running"

    assert without_process_ids(text) == "bandit and semgrep were still running"


@pytest.mark.parametrize(
    "text",
    [
        "",
        "the tool was still running",
        "a parenthetical (the second one) stays",
        "a pid named in words (pid seven) stays",
        "an empty pid (pid ) stays",
        "a process id outside parentheses, pid 7, stays",
    ],
)
def test_a_text_with_no_pid_parenthetical_is_returned_as_it_is(text):
    assert without_process_ids(text) == text
