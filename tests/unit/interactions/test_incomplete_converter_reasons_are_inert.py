# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The completeness gate's reasons show the scanned tree's file names as inert text.

``incomplete_converters`` names the files a converter could not convert and the
archives refused for an extraction limit. Those names are chosen by the scanned
tree, and the reasons reach the terminal in the exit-1 message, the gate's log
line, the workspace verdict and the MCP payload. ``escape_markup`` escapes rich
markup only, so an escape sequence in a name (``ESC c`` resets the reader's
terminal) went through raw. Each name is now passed through ``inert_text``.
"""

from __future__ import annotations

from automated_security_helper.interactions.run_ash_scan import (
    incomplete_converters,
    print_incompleteness_message,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    FailedInputInfo,
    RefusedInputInfo,
)

ESCAPE_RESET = "a\x1bcz.zip"
REORDERED = "b\u202ex.tar"


def gate(failed=(), refused=()):
    model = AshAggregatedResults()
    model.converter_results["archive"] = ConverterStatusInfo(
        failed_inputs=[FailedInputInfo(path=p, reason="damaged") for p in failed],
        refused_inputs=[
            RefusedInputInfo(path=p, reason="over", limit="max_members")
            for p in refused
        ],
    )
    return incomplete_converters(model)


def assert_inert(text: str) -> None:
    assert "\x1b" not in text and "\u202e" not in text, repr(text)
    assert "a\\x1bcz.zip" in text, text
    assert "b\\u202ex.tar" in text, text


def test_a_failed_input_name_is_inert_in_the_gate_reason():
    ((name, reason),) = gate(failed=[ESCAPE_RESET, REORDERED])

    assert name == "archive"
    assert_inert(reason)


def test_a_limit_refusal_name_is_inert_in_the_gate_reason():
    ((_, reason),) = gate(refused=[ESCAPE_RESET, REORDERED])

    assert_inert(reason)
    assert "(max_members)" in reason


def test_the_exit_message_prints_the_names_inert(capsys):
    print_incompleteness_message([], gate(failed=[ESCAPE_RESET], refused=[REORDERED]))

    assert_inert(capsys.readouterr().out)


def test_a_converter_failure_is_inert_in_the_gate_reason():
    """A crashed converter's exception text can quote a file name too."""
    model = AshAggregatedResults()
    model.converter_results["archive"] = ConverterStatusInfo(
        failure=f"OSError: cannot read {ESCAPE_RESET} or {REORDERED}"
    )

    ((name, reason),) = incomplete_converters(model)

    assert name == "archive"
    assert_inert(reason)


def test_more_than_five_failed_inputs_are_named_up_to_five_and_counted():
    names = [f"f{i}.zip" for i in range(7)]

    ((_, reason),) = gate(failed=names)

    assert reason.startswith("could not convert 7 inputs: ")
    assert ", ".join(names[:5]) + " and 2 more" in reason
    assert "f5.zip" not in reason
