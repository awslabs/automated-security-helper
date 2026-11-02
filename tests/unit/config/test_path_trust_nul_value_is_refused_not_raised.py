# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tool path holding a NUL names no file, and no helper raises for it.

``honored_path`` already drops such a value. The scanners also call
``resolved_path`` for their existence checks and ``refused_derived_product`` for the
derived-directory clause on their own, so those two answer for the value as well: a
path that does not exist, and a refusal that does not print the value.
"""

from __future__ import annotations

import logging
from typing import List

import pytest

from automated_security_helper.config.path_trust import (
    refused_derived_product,
    reset_path_refusal_warnings,
    resolved_path,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

KEY = "scanners.bandit.options.config_file"


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture
def ash_warnings():
    messages: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield messages
    finally:
        ASH_LOGGER.removeHandler(handler)


def test_a_value_holding_a_nul_resolves_to_a_path_that_does_not_exist(tmp_path):
    resolved = resolved_path("rules\x00.yaml", tmp_path)

    assert resolved.name == "rules\x00.yaml"
    assert not resolved.exists()


def test_a_value_holding_a_nul_is_refused_as_a_derived_product_not_raised(
    tmp_path, ash_warnings
):
    refused = refused_derived_product("rules\x00.yaml", source_dir=tmp_path, key=KEY)

    assert refused is True
    logged = [message for message in ash_warnings if KEY in message]
    assert logged, ash_warnings
    assert all("\x00" not in message and "rules" not in message for message in logged)


def test_an_operator_written_value_holding_a_nul_is_refused_too(tmp_path):
    refused = refused_derived_product(
        "rules\x00.yaml", source_dir=tmp_path, key=KEY, operator_written=True
    )

    assert refused is True


def test_a_value_without_a_nul_is_still_judged_as_before(tmp_path):
    # Control: an ordinary value outside every derived directory is not refused.
    assert refused_derived_product("rules.yaml", source_dir=tmp_path, key=KEY) is False
