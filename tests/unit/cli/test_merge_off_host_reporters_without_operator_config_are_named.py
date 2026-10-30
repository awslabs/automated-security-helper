# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Off-host reporters selected with no operator configuration are named, not skipped.

Why this file exists
--------------------
``ash merge`` ran its off-host reporters only under
``operator_config is not None``. ``select_merge_reporters`` refuses every
off-host reporter when there is no operator configuration, so the list is empty
then and the guard could not fire; but had the selection ever changed, the merge
would have skipped the reporters in silence and read as a merge that never asked
for them. The guard is now a named step that returns the list to run and says at
ERROR which reporters did not run when the invariant breaks.

Splitting ``--output-formats`` between the two report phases opened a second
silence: a requested off-host format whose reporter the operator did not enable
is run by neither phase, where the local phase used to say ``No report will be
written for requested format ...`` for it. ``log_off_host_formats_not_run`` says
that line for the formats that fall between the phases.
"""

from __future__ import annotations

import logging
from typing import ClassVar

import pytest

from automated_security_helper.cli.merge import (
    log_off_host_formats_not_run,
    off_host_formats_to_run,
    off_host_reporters_to_run,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

NO_PRODUCER = "No report will be written for requested format"


# Named as the reporter classes are, because plugin_config_key falls back to the
# class's own name lowered when it declares no config class. A `__name__ = ...`
# in a class body does not rename a class: type's descriptor answers first, so
# an earlier `_OffHost` with `__name__ = "FakeOffHost"` read as `_offhost` and
# every assertion on `fakeoffhost` and `s3` below went red at the venue.
class FakeOffHost:
    sends_off_host: ClassVar[bool] = True


class S3:
    sends_off_host: ClassVar[bool] = True


_OffHost = FakeOffHost
_S3 = S3


# ``capture`` (conftest) routes ASH's logger into caplog: plain ``caplog`` sees
# nothing of it, so ``records == []`` below would pass with no capture at all.


def test_an_empty_list_stays_empty_and_says_nothing(capture):
    assert off_host_reporters_to_run([], None) == []
    assert capture.records == []


def test_with_an_operator_config_the_list_is_returned_unchanged():
    assert off_host_reporters_to_run([_OffHost], AshConfig()) == [_OffHost]


def test_without_an_operator_config_the_reporters_are_named_and_not_run(capture):
    assert off_host_reporters_to_run([_OffHost], None) == []
    messages = [record.getMessage() for record in capture.records]
    assert any(
        "fakeoffhost" in message and "did not run" in message for message in messages
    ), messages


def test_a_requested_format_whose_reporter_runs_is_not_named(capture):
    assert log_off_host_formats_not_run(["s3"], [_S3]) == []
    assert capture.records == []


def test_a_requested_format_no_phase_runs_keeps_the_report_phases_line(capture):
    assert log_off_host_formats_not_run(["s3", "s3", "fakeoffhost"], [_S3]) == [
        "fakeoffhost"
    ]
    messages = [record.getMessage() for record in capture.records]
    assert len(messages) == 1, messages
    assert messages[0].startswith(f"{NO_PRODUCER} 'fakeoffhost':"), messages
    assert "reporters.fakeoffhost.enabled=true" in messages[0], messages
    assert all(record.levelno == logging.ERROR for record in capture.records)


def test_the_off_host_phase_is_given_only_the_formats_it_runs():
    """A format no reporter of the phase produces is not handed to the phase.

    The phase accounts for every requested format its reporters do not produce,
    so handing it the format log_off_host_formats_not_run has just named made
    the operator read two ERROR lines for one format with two different reasons.
    """
    assert off_host_formats_to_run(["s3", "fakeoffhost", "s3"], [_S3]) == ["s3"]


def test_a_request_naming_no_running_reporter_leaves_the_phase_nothing():
    assert off_host_formats_to_run(["fakeoffhost"], [_S3]) == []


def test_no_format_request_leaves_the_phase_to_its_own_reporters():
    assert off_host_formats_to_run([], [_S3]) == []
