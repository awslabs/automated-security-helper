# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporters override the trusted base cannot take does not refuse the load.

``confine_reporter_destinations`` replays the ``reporters`` overrides onto the
trusted base to read the operator's destinations. The scan's own apply accepted
each of them against the resolved configuration, but the trusted base is a
different document, and an override can fail to apply to it. The operator view's
replay drops such an override with a warning and keeps the others
(``resolve_config._with_reporter_overrides``); the confinement does the same
instead of raising out of the whole config resolution.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.reporter_trust import (
    confine_reporter_destinations,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

#: A path nothing reads: the confinement only names it in its warning.
CONFIG_FILE = Path("/elsewhere/.ash.yaml")


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


def test_an_override_the_base_cannot_take_is_dropped_with_a_warning(ash_log):
    config = AshConfig.model_validate({"reporters": {"other-reporter": {}}})

    confine_reporter_destinations(
        config,
        AshConfig(),
        ["reporters.s3.enabled=true", "reporters.csv.enabled=maybe"],
        [CONFIG_FILE],
    )

    named = [
        record.getMessage()
        for record in ash_log
        if "reporters.csv.enabled" in record.getMessage()
    ]
    assert len(named) == 1, named
    assert "do not apply" in named[0], named


def test_the_overrides_that_apply_are_still_replayed():
    config = AshConfig.model_validate({"reporters": {"other-reporter": {}}})

    confine_reporter_destinations(
        config,
        AshConfig(),
        ["reporters.s3.enabled=true", "reporters.csv.enabled=maybe"],
        [CONFIG_FILE],
    )

    base = config._trusted_reporter_base
    assert base is not None
    assert base.get_plugin_config("reporter", "s3")["enabled"] is True
