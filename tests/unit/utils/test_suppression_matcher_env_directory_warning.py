# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trailing-slash warning does not advise a spelling that matches nothing.

Why this file exists
--------------------
A suppression path read from the environment (``${SUPPRESS_DIR}``) that resolves
to a value ending in ``/`` is warned about as a path that matches only that
literal name. The warning quotes the written form and advises
``<written>/**/*``; with no slash in the written form that is ``${SUPPRESS_DIR}``
plus ``/**/*``, which resolves to ``build//**/*`` and matches nothing. The written
form is now used only where it ends in a separator itself, and otherwise the
advice names no spelling.
"""

import logging
from typing import List

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.suppression_matcher import (
    warn_unmatched_directory_suppressions,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def warnings_logged():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    yield records
    ASH_LOGGER.removeHandler(handler)


def test_a_written_form_without_a_slash_is_not_advised_with_one(warnings_logged):
    """Red at the base: the advice read '${SUPPRESS_DIR}/**/*'."""
    suppression = AshSuppression(path="build/", rule_id="R1", reason="r")
    recorded = {id(suppression): {"path": "${SUPPRESS_DIR}"}}

    warn_unmatched_directory_suppressions(
        [suppression], used_ids=set(), recorded=recorded
    )

    messages = [record.getMessage() for record in warnings_logged]
    assert len(messages) == 1, messages
    assert "'${SUPPRESS_DIR}'" in messages[0]
    assert "${SUPPRESS_DIR}/**/*" not in messages[0]
    assert "build" not in messages[0]


def test_a_written_form_that_ends_in_a_slash_is_still_advised(warnings_logged):
    """The positive control: the written form carries the slash itself."""
    suppression = AshSuppression(path="build/", rule_id="R1", reason="r")
    recorded = {id(suppression): {"path": "${SUPPRESS_DIR}/"}}

    warn_unmatched_directory_suppressions(
        [suppression], used_ids=set(), recorded=recorded
    )

    messages = [record.getMessage() for record in warnings_logged]
    assert len(messages) == 1, messages
    assert "'${SUPPRESS_DIR}/'" in messages[0]
    assert "'${SUPPRESS_DIR}/**/*'" in messages[0]
