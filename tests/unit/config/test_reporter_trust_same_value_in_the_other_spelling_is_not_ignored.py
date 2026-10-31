# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A destination option written with the same value as the trusted base is not named.

A config merge reads ``-`` and ``_`` in an option name as one key, so the
confinement matches an option under every mix of them. A config that writes
``aws-region`` where the trusted base writes ``aws_region`` (or the reverse) with
the same value chose nothing the operator did not, and the warning must not say it
was ignored. The section is still rewritten to the trusted base's spelling, and a
different value is still named under the spelling the config wrote.
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

REGION = "us-east-1"
OTHER_REGION = "eu-west-1"

SPELLINGS = [
    pytest.param("aws-region", "aws_region", id="config-dashed-base-underscored"),
    pytest.param("aws_region", "aws-region", id="config-underscored-base-dashed"),
]


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


def _confined(config_spelling: str, base_spelling: str, config_value: str, ash_log):
    config = AshConfig.model_validate(
        {"reporters": {"s3": {"options": {config_spelling: config_value}}}}
    )
    trusted = AshConfig.model_validate(
        {"reporters": {"s3": {"options": {base_spelling: REGION}}}}
    )

    confine_reporter_destinations(config, trusted, [], [CONFIG_FILE])

    warnings = [
        record.getMessage()
        for record in ash_log
        if record.getMessage().startswith("Ignoring ")
    ]
    return config.reporters.__pydantic_extra__["s3"]["options"], warnings


@pytest.mark.parametrize(("config_spelling", "base_spelling"), SPELLINGS)
def test_the_same_value_under_the_other_spelling_is_not_named(
    config_spelling, base_spelling, ash_log
):
    options, warnings = _confined(config_spelling, base_spelling, REGION, ash_log)

    assert not warnings, warnings
    assert options == {base_spelling: REGION}, options


@pytest.mark.parametrize(("config_spelling", "base_spelling"), SPELLINGS)
def test_a_different_value_is_named_under_the_spelling_the_config_wrote(
    config_spelling, base_spelling, ash_log
):
    options, warnings = _confined(config_spelling, base_spelling, OTHER_REGION, ash_log)

    [warning] = warnings
    assert f"reporters.s3.options.{config_spelling}" in warning, warning
    assert options == {base_spelling: REGION}, options
