# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The debug dump's fallback command text hides recorded values.

The container run attaches the command as it may be shown (``shown_command``),
with the spawn's recorded values hidden. A result that never reached the run
carries no such text, and the dump falls back to joining the raw arguments.
Today every such result also carries empty arguments, so the fallback prints
nothing it could leak; this file pins that the fallback stays safe when that
stops being true, instead of relying on it. The attached text, when present,
wins verbatim, even when it is empty.
"""

import subprocess

from automated_security_helper.interactions.run_ash_scan import (
    _shown_container_command,
)
from automated_security_helper.utils import subprocess_utils


def _result_without_attached_text(args):
    return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="")


def test_the_fallback_hides_the_spawns_recorded_values():
    """A result with no attached text, whose raw arguments carry a recorded
    value (an ``-e`` pair's), is shown without that value."""
    value = "a-recorded-environment-value-5c41"
    result = _result_without_attached_text(
        ["runner", "run", "-e", f"TOKEN={value}", "image:tag"]
    )

    token = subprocess_utils._SPAWN_VALUES.set((value,))
    try:
        shown = _shown_container_command(result)
    finally:
        subprocess_utils._SPAWN_VALUES.reset(token)

    assert value not in shown, shown
    # The control: redaction removed the value, not the command.
    assert "runner" in shown and "image:tag" in shown, shown


def test_the_attached_text_wins_verbatim():
    result = _result_without_attached_text(["raw", "arguments"])
    result.shown_command = "the run's own shown text"

    assert _shown_container_command(result) == "the run's own shown text"


def test_an_attached_empty_text_is_not_a_reason_to_fall_back():
    """An empty attached text is the run's answer, not an absence: falling
    back on it would print the raw arguments the run chose to withhold."""
    result = _result_without_attached_text(["raw", "arguments"])
    result.shown_command = ""

    assert _shown_container_command(result) == ""


def test_a_result_with_no_arguments_is_shown_as_nothing():
    """The shape every refusal result has today: no attached text and empty
    arguments. The fallback prints nothing rather than raising."""
    shown = _shown_container_command(_result_without_attached_text([]))

    assert shown == ""
