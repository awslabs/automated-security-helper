# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""shown_arguments keeps an argument that is not a string as it is.

It writes each --config-overrides value as its key and returns every other
argument unchanged, a Path, an int or None included, so the caller decides how
to show it. A value slot that holds no string ends the option: the string after
it is an argument of its own. The subprocess helpers show the line with str() of
each argument, so a command with such an argument is still reported as one that
never ran (test_a_spawn_that_raises_is_a_tool_that_never_started.py).
"""

from __future__ import annotations

from pathlib import Path

from automated_security_helper.utils.subprocess_utils import shown_arguments


def test_an_argument_that_is_not_a_string_is_kept_as_it_is():
    path, number = Path("scan-target"), 7

    shown = shown_arguments(["tool", path, number, None])

    assert shown == ["tool", path, number, None]
    assert shown[1] is path and shown[2] is number and shown[3] is None


def test_a_value_slot_that_holds_no_string_ends_the_option():
    shown = shown_arguments(["--config-overrides", 7, "project_name=demo"])

    assert shown == ["--config-overrides", 7, "project_name=demo"]
    assert type(shown[1]) is int
