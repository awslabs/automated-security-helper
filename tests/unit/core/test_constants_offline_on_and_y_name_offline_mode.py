# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH_OFFLINE accepts ON and Y as the opposites of the OFF and N it accepts.

Why these tests exist
---------------------
``is_offline_mode`` took ``OFF`` and ``N`` as plain online values but treated
``ON`` and ``Y`` as unrecognized, so an air-gapped run that set
``ASH_OFFLINE=on`` went online with a warning. The recognized values are now
pairs: YES/NO, TRUE/FALSE, 1/0, ON/OFF and Y/N.

One limit is stated, not tested: the container's init script keeps its own list
of values, which is outside this repository, so a value only this reader accepts
(``on``, ``y``) is offline for the scan and may be read as online by that script.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from automated_security_helper.core import constants
from automated_security_helper.core.constants import is_offline_mode

pytestmark = pytest.mark.unit


@pytest.fixture
def logger(monkeypatch):
    monkeypatch.setattr(constants, "_warned_relative_values", set())
    from automated_security_helper.utils import log as ash_log

    recorder = MagicMock()
    monkeypatch.setattr(ash_log, "ASH_LOGGER", recorder)
    return recorder


@pytest.mark.parametrize("value", ["on", "ON", " On ", "y", "Y", "\ty\n"])
def test_on_and_y_name_offline_mode(monkeypatch, logger, value):
    monkeypatch.setenv("ASH_OFFLINE", value)

    # Red at the base: False, with a warning that the value is not recognized.
    assert is_offline_mode() is True
    logger.warning.assert_not_called()


@pytest.mark.parametrize(
    "value", ["yes", "true", "1", "no", "false", "0", "off", "n", ""]
)
def test_the_other_paired_values_keep_their_meaning(monkeypatch, logger, value):
    """The control: the values that were accepted before read as they did."""
    monkeypatch.setenv("ASH_OFFLINE", value)

    assert is_offline_mode() is (value in ("yes", "true", "1"))
    logger.warning.assert_not_called()


def test_a_word_in_no_pair_still_runs_online_and_says_so(monkeypatch, logger):
    monkeypatch.setenv("ASH_OFFLINE", "enabled")

    assert is_offline_mode() is False
    logger.warning.assert_called_once()
    message = logger.warning.call_args.args[0]
    assert "ASH_OFFLINE='enabled' is not recognized" in message
    assert "YES, TRUE, ON, Y or 1" in message
