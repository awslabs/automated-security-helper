# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reporter is confined by its own section, not by one named for another reporter.

A section is read as a reporter's when the reporter's lookup would find it, and two
names that differ only by the reporter word reduce to the same string
(``bedrock-summary`` and ``bedrock-summary-reporter``). When both reporters are
loaded, each reads the section named exactly as it, so the confinement of one must
not replace the options and ``enabled`` of the other's section with its own
trusted values.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Literal, Tuple

import pytest

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.reporter_trust import (
    confine_declared_reporter_destinations,
)

pytestmark = pytest.mark.unit

#: A path nothing reads: the confinement only names it in its warning.
CONFIG_FILE = Path("/elsewhere/.ash.yaml")


class _FeedOptions(ReporterOptionsBase):
    region: str = "default-region"


class _ShortConfig(ReporterPluginConfigBase):
    name: Literal["sample-feed"] = "sample-feed"
    options: _FeedOptions = _FeedOptions()


class _ShortReporter(ReporterPluginBase[_ShortConfig]):
    """Declares its region as a destination, under the shorter name."""

    destination_options: ClassVar[Tuple[str, ...]] = ("region",)

    def report(self, model):
        return None


class _LongConfig(ReporterPluginConfigBase):
    name: Literal["sample-feed-reporter"] = "sample-feed-reporter"
    options: _FeedOptions = _FeedOptions()


class _LongReporter(ReporterPluginBase[_LongConfig]):
    """Declares its region as a destination, under the name with the reporter word."""

    destination_options: ClassVar[Tuple[str, ...]] = ("region",)

    def report(self, model):
        return None


def _confined(file_sections: dict, operator_sections: dict, classes: list) -> dict:
    config = AshConfig.model_validate({"reporters": file_sections})
    config._trusted_reporter_base = AshConfig.model_validate(
        {"reporters": operator_sections}
    )
    config._in_tree_config_files = (CONFIG_FILE,)

    confine_declared_reporter_destinations(config, classes)

    return config.reporters.__pydantic_extra__


def test_each_reporter_gets_its_own_trusted_region():
    sections = _confined(
        {
            "sample-feed": {"options": {"region": "file-short"}},
            "sample-feed-reporter": {"options": {"region": "file-long"}},
        },
        {
            "sample-feed": {"options": {"region": "operator-short"}},
            "sample-feed-reporter": {"options": {"region": "operator-long"}},
        },
        [_ShortReporter, _LongReporter],
    )

    assert sections["sample-feed"]["options"]["region"] == "operator-short", sections
    assert sections["sample-feed-reporter"]["options"]["region"] == "operator-long", (
        sections
    )


def test_a_section_no_loaded_reporter_owns_is_still_confined():
    """Control: with only the shorter name loaded, the longer name's section is
    one its lookup could read and no other reporter reads it by name."""
    sections = _confined(
        {"sample-feed-reporter": {"options": {"region": "file-long"}}},
        {"sample-feed": {"options": {"region": "operator-short"}}},
        [_ShortReporter],
    )

    assert sections["sample-feed-reporter"]["options"]["region"] == "operator-short", (
        sections
    )
