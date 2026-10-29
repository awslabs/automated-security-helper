# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The runner's "Creating process with pipes" record hides carried values.

The record quotes the spawn's full argv. A ``--mount`` source or destination
in that argv can hold a value the operator's configuration chain read from
the environment: a chain that extends a file through ``${VAR}`` mounts the
resolved file, so the variable's value sits inside the mount path.
``shown_arguments`` rewrites option values only and passes mounts through,
so the record is decorated with the spawn's carried values, like the
runner's other log lines. A path that is not a carried value prints as it
is: the hiding is driven by the carried values, never by the text's shape.
"""

from __future__ import annotations

from typing import List

import pytest

from automated_security_helper.utils import subprocess_utils

#: A value the configuration chain reads from the environment. Nothing
#: secret: a recognizable marker whose absence from the record is asserted.
CARRIED = "ash-carried-value-6a1d-0123456789"
#: The record is logged at the verbose level, between DEBUG and INFO.
VERBOSE = 15


class _Reached(Exception):
    """Raised in place of the spawn, after the record is emitted."""


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    """Capture the verbose record; the spawn itself never runs."""

    def no_spawn(*args, **kwargs):
        raise _Reached

    monkeypatch.setattr(subprocess_utils.subprocess, "Popen", no_spawn)
    with caplog.at_level(VERBOSE, logger="ash"):
        yield caplog


def _mount_argv(path_piece: str) -> List[str]:
    return [
        "/bin/true",
        "run",
        "--mount",
        f"type=bind,source=/host/{path_piece},destination=/src/{path_piece}",
    ]


def test_a_carried_value_in_a_mount_path_never_reaches_the_record(recorded):
    with subprocess_utils._spawn_values((CARRIED,)):
        with pytest.raises(_Reached):
            subprocess_utils.create_process_with_pipes(_mount_argv(CARRIED))

    text = "\n".join(
        record.getMessage()
        for record in recorded.records
        if "Creating process with pipes" in record.getMessage()
    )
    assert text, [record.getMessage() for record in recorded.records]
    assert CARRIED not in text, text
    # The record still names the command and the mount flag.
    assert "--mount" in text, text


def test_the_same_text_uncarried_prints_as_it_is(recorded):
    """The literal twin: with nothing carried, an identical mount path is
    the operator's own text and prints unchanged."""
    with pytest.raises(_Reached):
        subprocess_utils.create_process_with_pipes(_mount_argv(CARRIED))

    text = "\n".join(
        record.getMessage()
        for record in recorded.records
        if "Creating process with pipes" in record.getMessage()
    )
    assert text, [record.getMessage() for record in recorded.records]
    assert CARRIED in text, text
