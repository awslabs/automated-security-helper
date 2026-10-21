# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stopped workspace's context carries the limit only where its text does.

The reason names the limit through ``timeout_limit_phrase`` (under this tool's
own option name): the number where no environment value typed it, the option's
name where one did. The context's machine-readable copy has to follow the same
decision, or it would carry the number the text hides. It asks the shared
predicate, ``limit_typed_by_a_value``, and does not read the shape of the
token, so a change in how the token is quoted cannot flip it.

The cells read the response's ``context`` mapping, never the whole response:
on the branch where a value typed the limit, the reason's own text names the
option, so a substring probe on the whole response finds the name there and
says nothing about the context.
"""

from automated_security_helper.cli.mcp import workspace
from automated_security_helper.utils import error_text


def _stopped(timeout_seconds, environment_values, reason="the scan stopped"):
    response = workspace._stopped_response(
        reason, {}, timeout_seconds, environment_values
    )
    return response["context"]


def test_a_limit_typed_by_an_environment_value_is_absent_from_the_context():
    shown = _stopped(67, ("067",))
    assert "scan_timeout_seconds" not in shown, shown


def test_a_limit_no_environment_value_typed_is_in_the_context():
    shown = _stopped(67, ("unrelated",))
    assert shown.get("scan_timeout_seconds") == 67, shown


def test_a_limit_with_no_environment_values_is_in_the_context():
    shown = _stopped(67, ())
    assert shown.get("scan_timeout_seconds") == 67, shown


def test_the_reasons_own_text_does_not_stand_in_for_the_contexts_key():
    """The reason a real stop carries names the option where a value typed the
    limit; the context still omits the key, and the cell reads the context."""
    reason = (
        "Workspace scan exceeded the server's configured scan_timeout_seconds "
        "and was cancelled"
    )
    response = workspace._stopped_response(reason, {}, 67, ("067",))
    assert "scan_timeout_seconds" in response["error"], response["error"]
    assert "scan_timeout_seconds" not in response["context"], response["context"]


def test_the_decision_does_not_read_the_tokens_quoting(monkeypatch):
    """The token's spelling changes; the context still follows the predicate."""
    respelled = lambda limit, values: f'"{limit}" s'  # noqa: E731
    monkeypatch.setattr(error_text, "timeout_limit_token", respelled, raising=False)
    assert _stopped(67, ()).get("scan_timeout_seconds") == 67
    assert "scan_timeout_seconds" not in _stopped(67, ("067",))


def test_the_public_predicate_agrees_with_both_cases():
    from automated_security_helper.utils.error_text import limit_typed_by_a_value

    assert limit_typed_by_a_value(67, ("067",)) is True
    assert limit_typed_by_a_value(67, ("unrelated",)) is False
    assert limit_typed_by_a_value(67, ()) is False


def test_the_context_carries_the_number_exactly_where_the_phrase_prints_it():
    """The real invariant, end to end: the context holds the limit iff the
    reason's phrase prints the number rather than the option's name."""
    for values in ((), ("67",), ("067",), ("unrelated",)):
        phrase = error_text.timeout_limit_phrase(
            67, values, option_name="scan_timeout_seconds"
        )
        response = workspace._stopped_response("the scan stopped", {}, 67, values)
        assert ("'67' s" in phrase) == (
            "scan_timeout_seconds" in response["context"]
        ), (values, phrase, response["context"])
