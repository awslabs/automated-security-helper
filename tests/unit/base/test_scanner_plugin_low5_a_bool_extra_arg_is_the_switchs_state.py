# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A bool extra-arg value is the switch's state, not a word after the key.

A bool was spelled "true" or "false" and appended after its key. A tool whose
flag is a plain on/off switch (argparse ``store_true``, a ``pflag`` bool) then ran
with the flag ON for ``value=False``, because the key was there, and the word
was left behind as a stray positional, which bandit reads as a target. A True
value is now the key alone and a False value leaves the key out. These tests
read the command the way such a tool would, with a parser, not the spelling of
the list.
"""

from __future__ import annotations

import argparse

import pytest

from automated_security_helper.models.core import ToolArgs, ToolExtraArg
from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


def _resolved(tmp_path, *extra_args):
    scanner = _scanner(
        _context(tmp_path, ()), args=ToolArgs(extra_args=list(extra_args))
    )
    return scanner._resolve_arguments(tmp_path / "t", tmp_path / "r.json")


def _as_the_tool_reads_it(args):
    """What a tool with a ``--strict`` on/off switch, a ``--mode`` option and
    positional targets makes of the command ASH built."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--mode", default=None)
    parser.add_argument("rest", nargs="*")
    # The command word is the tool's own name; the tool never parses it.
    known, unknown = parser.parse_known_args(args[1:])
    return known, unknown


def test_a_true_value_turns_the_switch_on_and_leaves_no_word_behind(tmp_path):
    args = _resolved(tmp_path, ToolExtraArg(key="--strict", value=True))

    known, unknown = _as_the_tool_reads_it(args)

    assert known.strict is True
    assert "true" not in args and "True" not in args
    assert "true" not in known.rest + unknown


def test_a_false_value_leaves_the_switch_off_and_leaves_no_word_behind(tmp_path):
    args = _resolved(tmp_path, ToolExtraArg(key="--strict", value=False))

    known, unknown = _as_the_tool_reads_it(args)

    assert known.strict is False
    assert "--strict" not in args
    assert "false" not in args and "False" not in args
    assert "false" not in known.rest + unknown


def test_the_arguments_after_a_false_switch_are_those_of_a_run_without_it(tmp_path):
    with_false = _resolved(
        tmp_path,
        ToolExtraArg(key="--depth", value=5),
        ToolExtraArg(key="--strict", value=False),
    )
    without = _resolved(tmp_path, ToolExtraArg(key="--depth", value=5))

    assert with_false == without


def test_a_value_given_as_text_is_still_handed_over_as_that_word(tmp_path):
    args = _resolved(tmp_path, ToolExtraArg(key="--mode", value="true"))

    known, _ = _as_the_tool_reads_it(args)

    assert known.mode == "true"


def test_every_argument_handed_to_a_spawn_is_text(tmp_path):
    args = _resolved(
        tmp_path,
        ToolExtraArg(key="--strict", value=True),
        ToolExtraArg(key="--off", value=False),
        ToolExtraArg(key="--depth", value=5),
        ToolExtraArg(key="--ratio", value=1.5),
        ToolExtraArg(key="--quiet"),
    )

    assert all(isinstance(argument, str) for argument in args), args
    assert "--off" not in args
