# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The literal reading of a config refuses every YAML alias, as the load does.

``parse_config_text`` parses YAML with ``load_yaml_config``, whose loader
refuses every alias. ``parse_config_text_literally``, the reading that keeps
each environment reference as written, said it refused aliases as that loader
does, but its loader refused only a recursive one: an alias to a finished
anchor was expanded, so the literal reading returned a document the load
never reads.

Red at the base: the literal reading of the aliased text returned a mapping.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.config_sources import (
    parse_config_text,
    parse_config_text_literally,
)

pytestmark = pytest.mark.unit

ALIASED = "project_name: &name demo\nscan_name: *name\n"


@pytest.mark.parametrize("keep_env_tags", [False, True], ids=["literal", "as-written"])
def test_the_literal_reading_refuses_an_alias(keep_env_tags: bool) -> None:
    with pytest.raises(yaml.YAMLError, match="alias"):
        parse_config_text_literally(
            Path("aliased.yaml"), ALIASED, keep_env_tags=keep_env_tags
        )


def test_the_load_refuses_the_same_text() -> None:
    """The parity the literal reading keeps: the load refuses it too."""
    with pytest.raises(yaml.YAMLError, match="alias"):
        parse_config_text(Path("aliased.yaml"), ALIASED)


def test_an_anchor_with_no_alias_still_reads() -> None:
    """The control: an anchor nothing refers to is harmless, as for the load."""
    assert parse_config_text_literally(
        Path("anchored.yaml"), "project_name: &name demo\n"
    ) == {"project_name": "demo"}
