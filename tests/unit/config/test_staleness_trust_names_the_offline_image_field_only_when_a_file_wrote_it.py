# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The offline-image setting is named in the warning only when a file wrote it.

``content_db_staleness_offline_image_default`` defaults to true, and true is the
relaxing value. When the operator turned it off, a config that never mentions the
field resolves to true, and ``confine_content_db_staleness`` sets it back to false.
The warning says the setting came "from" the config files, so it names the field
only for a file that wrote it. Setting the value back does not depend on that.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.staleness_trust import (
    confine_content_db_staleness,
)

pytestmark = pytest.mark.unit

_FIELD = "content_db_staleness_offline_image_default"


def _operators() -> AshConfig:
    return AshConfig.model_validate({_FIELD: False})


def _confine(config: AshConfig, tmp_path: Path) -> None:
    confine_content_db_staleness(
        config, _operators(), [], [tmp_path / "repo" / ".ash" / ".ash.yaml"]
    )


def test_a_config_that_never_mentions_the_field_is_set_back_without_a_warning(
    tmp_path, ash_log: List[logging.LogRecord]
):
    config = AshConfig.model_validate({})
    assert getattr(config, _FIELD) is True

    _confine(config, tmp_path)

    assert getattr(config, _FIELD) is False
    assert [record.getMessage() for record in ash_log] == []


def test_a_config_that_writes_true_is_set_back_and_named(
    tmp_path, ash_log: List[logging.LogRecord]
):
    config = AshConfig.model_validate({_FIELD: True})

    _confine(config, tmp_path)

    assert getattr(config, _FIELD) is False
    messages = [record.getMessage() for record in ash_log]
    assert len(messages) == 1
    assert _FIELD in messages[0]


def test_another_relaxation_is_named_without_the_field_the_file_left_out(
    tmp_path, ash_log: List[logging.LogRecord]
):
    config = AshConfig.model_validate({"content_db_staleness": "warn"})

    _confine(config, tmp_path)

    assert getattr(config, _FIELD) is False
    messages = [record.getMessage() for record in ash_log]
    assert len(messages) == 1
    assert "content_db_staleness" in messages[0]
    assert _FIELD not in messages[0]
