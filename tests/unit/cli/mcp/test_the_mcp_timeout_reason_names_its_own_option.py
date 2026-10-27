# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP timeout reason names its own option, once, in both of its shapes.

The server's limit is ``scan_timeout_seconds``. The reason printed its limit
through the shared token, whose no-number fallback names the SCANNER option:
with an environment value typing to the limit the client read "Scan exceeded
the server's scan_timeout_seconds of the configured scan_timeout and was
cancelled" -- repeating itself and sending the reader to the wrong knob. The
reason now builds through the shared phrase formatter with its own option
name, and the no-number contract stands: a limit an environment value types
to never prints as a number.
"""

from __future__ import annotations

from automated_security_helper.cli.mcp_tools import _scan_timeout_reason
from automated_security_helper.utils.error_text import (
    timeout_limit_phrase,
    timeout_limit_token,
)


def test_a_typed_limit_names_the_servers_own_option():
    reason = _scan_timeout_reason(600, ("600",))

    assert reason == (
        "Scan exceeded the server's configured scan_timeout_seconds and was cancelled"
    ), reason
    # Never the scanner's option, and never the number a value types to.
    assert "the configured scan_timeout " not in reason, reason
    assert "of the configured" not in reason, reason
    assert "600" not in reason, reason


def test_an_untyped_limit_keeps_the_option_and_the_quoted_number():
    reason = _scan_timeout_reason(600, ())

    assert reason == (
        "Scan exceeded the server's scan_timeout_seconds of '600' s and was cancelled"
    ), reason


def test_the_phrase_formatter_carries_the_callers_option_name():
    assert timeout_limit_phrase(67, ()) == "scan_timeout of '67' s"
    assert timeout_limit_phrase(67, ("67",)) == "configured scan_timeout"
    assert (
        timeout_limit_phrase(67, ("67",), option_name="scan_timeout_seconds")
        == "configured scan_timeout_seconds"
    )


def test_the_phrase_and_the_token_agree_on_the_typed_check():
    """One check decides both formatters, so their fallbacks cannot drift."""
    for values in ((), ("67",), ("067",), ("unrelated",)):
        token_fell_back = timeout_limit_token(67, values) == (
            "the configured scan_timeout"
        )
        phrase_fell_back = timeout_limit_phrase(67, values).startswith("configured")
        assert token_fell_back == phrase_fell_back, values
