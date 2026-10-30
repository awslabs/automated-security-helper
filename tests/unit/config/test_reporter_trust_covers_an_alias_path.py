# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A destination option read through an ``AliasPath`` is confined by its first key.

A reporter lists its destination options by field name, and a file writes a field
under its alias. For a field whose ``validation_alias`` is an ``AliasPath``
(``connection.endpoint``), pydantic reads the value from the mapping nested under
the path's first key, so a repository config that writes ``connection`` sets the
option. That key has to be among the spellings the confinement matches, as a
string alias is.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Literal, Tuple

import pytest
from pydantic import AliasChoices, AliasPath, Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.reporter_trust import (
    confine_declared_reporter_destinations,
    declared_destination_options,
)

pytestmark = pytest.mark.unit

#: A path nothing reads: the confinement only names it in its warning.
CONFIG_FILE = Path("/elsewhere/.ash.yaml")

FILE_ENDPOINT = "https://file.invalid/"


class _PathOptions(ReporterOptionsBase):
    endpoint: str = Field(
        "https://default.invalid/",
        validation_alias=AliasPath("connection", "endpoint"),
    )
    title: str = "default title"


class _PathConfig(ReporterPluginConfigBase):
    name: Literal["aliaspath-reporter"] = "aliaspath-reporter"
    options: _PathOptions = _PathOptions()


class _PathReporter(ReporterPluginBase[_PathConfig]):
    """Declares ``endpoint``, which a file sets under ``connection.endpoint``."""

    destination_options: ClassVar[Tuple[str, ...]] = ("endpoint",)

    def report(self, model):
        return None


class _ChoicesOptions(ReporterOptionsBase):
    endpoint: str = Field(
        "https://default.invalid/",
        validation_alias=AliasChoices("url", AliasPath("connection", "endpoint")),
    )


class _ChoicesConfig(ReporterPluginConfigBase):
    name: Literal["aliaschoices-reporter"] = "aliaschoices-reporter"
    options: _ChoicesOptions = _ChoicesOptions()


class _ChoicesReporter(ReporterPluginBase[_ChoicesConfig]):
    """Declares ``endpoint``, which a file sets under ``url`` or the path."""

    destination_options: ClassVar[Tuple[str, ...]] = ("endpoint",)

    def report(self, model):
        return None


def test_the_first_key_of_an_alias_path_is_a_declared_spelling():
    declared = declared_destination_options([_PathReporter])

    assert declared == {"aliaspath-reporter": ("endpoint", "connection")}, declared


def test_an_alias_path_inside_alias_choices_is_a_declared_spelling():
    declared = declared_destination_options([_ChoicesReporter])

    assert declared == {"aliaschoices-reporter": ("endpoint", "url", "connection")}, (
        declared
    )


def test_a_file_cannot_set_the_option_through_the_alias_path():
    config = AshConfig.model_validate(
        {
            "reporters": {
                "aliaspath-reporter": {
                    "options": {
                        "connection": {"endpoint": FILE_ENDPOINT},
                        "title": "file title",
                    }
                }
            }
        }
    )
    config._trusted_reporter_base = AshConfig()
    config._in_tree_config_files = (CONFIG_FILE,)

    confine_declared_reporter_destinations(config, [_PathReporter])

    options = config.reporters.__pydantic_extra__["aliaspath-reporter"]["options"]
    assert "connection" not in options, options
    assert FILE_ENDPOINT not in repr(options), options
    assert options["title"] == "file title", options
