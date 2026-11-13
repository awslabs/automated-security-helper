# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused `tool_version` or release tag is named by its key, not its value.

The warning names the refused key and not its value, because the value is
whatever a config file held, values read from the environment included: `ash
merge` prints the warning for a shard's ash_config and `ash scan` for a
repository's config.
"""

from __future__ import annotations

import logging
from typing import Annotated

import pytest
from pydantic import BaseModel

from automated_security_helper.base.options import (
    release_tag,
    reset_refused_tool_version_warnings,
    tool_version_constraint,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

VALUE = "SECRETVALUEZQ x"


@pytest.fixture(autouse=True)
def _fresh_warnings(caplog):
    reset_refused_tool_version_warnings()
    caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)
    yield
    reset_refused_tool_version_warnings()


class _Options(BaseModel):
    tool_version: Annotated[
        str | None, tool_version_constraint("scanners.probe.options.tool_version")
    ] = ">=1.0"
    version: Annotated[str, release_tag("scanners.probe.options.version")] = "v1.0.0"


@pytest.mark.parametrize(
    "field, key, reason",
    [
        pytest.param(
            "tool_version",
            "scanners.probe.options.tool_version",
            "not a version constraint",
            id="tool_version",
        ),
        pytest.param(
            "version",
            "scanners.probe.options.version",
            "not a release tag",
            id="release-tag",
        ),
    ],
)
def test_the_warning_names_the_key_and_not_the_value(caplog, field, key, reason):
    with caplog.at_level(logging.WARNING):
        options = _Options(**{field: VALUE})

    assert getattr(options, field) == _Options().model_dump()[field]
    assert key in caplog.text, caplog.text
    assert reason in caplog.text, caplog.text
    assert "SECRETVALUEZQ" not in caplog.text, caplog.text
