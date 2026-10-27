# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file that changed after it was checked is reported as that.

``config_sources.config_file_changed`` tells a read refused because the file is no
longer the one that was checked from any other failure, by type and by the mark
an error carries when its cause was dropped on purpose (a base the environment
chose is reworded with no cause, because the original's text can name the path).
``get_config`` and the scan tools answer a config that cannot be loaded through
``_config_load_failure`` and ``config_load_category``, which are where that fact
reaches the client: as a path problem with the reason said, and not as a file
whose format the client should repair.
"""

from __future__ import annotations

import errno
import json
from pathlib import Path

from automated_security_helper.cli import mcp_tools
from automated_security_helper.config import config_sources
from automated_security_helper.core.exceptions import ASHConfigSourceError
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)

CHANGED = "changed after it was checked"


def _reworded_changed_base() -> ASHConfigSourceError:
    """What a chain walk raises for a hidden base whose file changed: the reason
    without the base's name, no cause, and the mark."""
    error = ASHConfigSourceError(
        "Base config <value>, extended by <value>, could not be read (ESTALE)"
    )
    setattr(error, config_sources._FILE_CHANGED_MARK, True)
    return error


def test_a_changed_file_that_lost_its_cause_is_a_path_problem() -> None:
    error = _reworded_changed_base()

    assert error.__cause__ is None, "premise: the cause was dropped"
    assert mcp_tools.config_load_category(error) is ErrorCategory.INVALID_PATH


def test_a_changed_file_that_lost_its_cause_is_reported_as_changed(tmp_path) -> None:
    config = tmp_path / "ash-config.yaml"

    response = mcp_tools._config_load_failure(_reworded_changed_base(), config)

    text = json.dumps(response, default=str)
    assert CHANGED in text, response
    assert ErrorCategory.INVALID_PATH.value in text, response


def test_a_refusal_raised_from_a_changed_file_is_reported_as_changed(tmp_path) -> None:
    cause = config_sources.ConfigFileChangedError(errno.ESTALE, CHANGED)
    try:
        try:
            raise cause
        except OSError as caught:
            raise ASHConfigSourceError("Base config could not be read") from caught
    except ASHConfigSourceError as error:
        response = mcp_tools._config_load_failure(error, Path(tmp_path / "c.yaml"))

    assert CHANGED in json.dumps(response, default=str), response


def test_control_a_read_that_failed_for_another_reason_is_not_reported_as_changed(
    tmp_path,
) -> None:
    error = ASHConfigSourceError(
        "Base config <value>, extended by <value>, could not be read (EIO)"
    )

    response = mcp_tools._config_load_failure(error, tmp_path / "ash-config.yaml")

    assert mcp_tools.config_load_category(error) is ErrorCategory.INVALID_FORMAT
    assert CHANGED not in json.dumps(response, default=str), response
