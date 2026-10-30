# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A recorded config that leaves a reporter out is not given a section for it.

``ash merge`` holds a shard's recorded config to the trusted base with
``SHARD_RECORDED``, whose ``fills_missing_sections`` is false: the merge's
``--config`` supplies values for what a shard recorded and adds nothing to it. The
destination options already follow that flag. ``enabled`` has to follow it too,
or the merged config records a reporter as on, with its default destinations, that
the shards never configured. A file inside the tree replaces the operator's config
and is still given the section.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.reporter_trust import (
    confine_reporter_destinations,
)
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.config.untrusted_source import SHARD_RECORDED

pytestmark = pytest.mark.unit

#: A path nothing reads: the confinement only names it in its warning.
CONFIG_FILE = Path("/elsewhere/.ash.yaml")


def _config_without_s3() -> AshConfig:
    return AshConfig.model_validate({"reporters": {"other-reporter": {}}})


def _trusted_with_s3_on() -> AshConfig:
    return apply_config_overrides(AshConfig(), ["reporters.s3.enabled=true"])


def test_a_recorded_config_with_no_s3_section_is_not_given_one():
    config = _config_without_s3()

    confine_reporter_destinations(
        config,
        _trusted_with_s3_on(),
        [],
        [CONFIG_FILE],
        source=SHARD_RECORDED,
    )

    assert "s3" not in config.reporters.__pydantic_extra__


def test_a_file_in_the_tree_with_no_s3_section_is_given_the_operators_enabled():
    """Control: that file replaces the operator's config, so the section is filled."""
    config = _config_without_s3()

    confine_reporter_destinations(config, _trusted_with_s3_on(), [], [CONFIG_FILE])

    assert config.reporters.__pydantic_extra__["s3"] == {"enabled": True}
