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
"""

from __future__ import annotations

import logging
from typing import ClassVar

import pytest

from automated_security_helper.cli.merge import off_host_reporters_to_run
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


class _OffHost:
    sends_off_host: ClassVar[bool] = True
    __name__ = "FakeOffHost"


def test_an_empty_list_stays_empty_and_says_nothing(caplog):
    with caplog.at_level(logging.ERROR):
        assert off_host_reporters_to_run([], None) == []
    assert caplog.records == []


def test_with_an_operator_config_the_list_is_returned_unchanged():
    assert off_host_reporters_to_run([_OffHost], AshConfig()) == [_OffHost]


def test_without_an_operator_config_the_reporters_are_named_and_not_run(caplog):
    with caplog.at_level(logging.ERROR):
        assert off_host_reporters_to_run([_OffHost], None) == []
    messages = [record.getMessage() for record in caplog.records]
    assert any(
        "fakeoffhost" in message and "did not run" in message for message in messages
    ), messages
