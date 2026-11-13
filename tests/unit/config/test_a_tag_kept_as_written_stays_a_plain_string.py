# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An explicit ``!ENV`` tag kept as written is a plain string for every reader.

The tag-keeping literal reader feeds the as-written records that are shown and
dumped (``ash config get``, the MCP config answer, the environment record).
``yaml.safe_dump`` refuses a ``str`` subclass, so the marker type that tells
the extends reader a loader-added prefix from a file's own bytes is returned
only to a reader that asks for it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.config_sources import (
    TagWrittenReference,
    parse_config_text_literally,
    read_config_file_as_written,
)

pytestmark = pytest.mark.unit

TEXT = (
    "project_name: !ENV ${ASH_TAG_CELL_NAME}\n"
    "extends:\n"
    "  - !ENV ${ASH_TAG_CELL_BASE}\n"
    "  - plain.yaml\n"
)


def _kinds(value):
    if isinstance(value, dict):
        return [kind for item in value.values() for kind in _kinds(item)]
    if isinstance(value, list):
        return [kind for item in value for kind in _kinds(item)]
    return [type(value)]


def test_the_as_written_reader_returns_plain_strings(tmp_path: Path):
    config = tmp_path / "ash.yaml"
    config.write_text(TEXT, encoding="utf-8")

    written = read_config_file_as_written(config)

    assert written["project_name"] == "!ENV ${ASH_TAG_CELL_NAME}"
    assert written["extends"][0] == "!ENV ${ASH_TAG_CELL_BASE}"
    assert set(_kinds(written)) == {str}, _kinds(written)


def test_an_as_written_record_holding_a_tagged_scalar_can_be_dumped(tmp_path: Path):
    config = tmp_path / "ash.yaml"
    config.write_text(TEXT, encoding="utf-8")

    dumped = yaml.safe_dump(read_config_file_as_written(config))

    assert yaml.safe_load(dumped) == {
        "project_name": "!ENV ${ASH_TAG_CELL_NAME}",
        "extends": ["!ENV ${ASH_TAG_CELL_BASE}", "plain.yaml"],
    }


def test_the_tag_keeping_text_parser_returns_plain_strings_unless_asked(
    tmp_path: Path,
):
    config = tmp_path / "ash.yaml"

    plain = parse_config_text_literally(config, TEXT, keep_env_tags=True)

    assert set(_kinds(plain)) == {str}, _kinds(plain)
    assert yaml.safe_dump(plain)


def test_the_extends_reader_can_ask_for_the_marked_type(tmp_path: Path):
    """The must-flag twin: with the mark requested, a loader-added prefix is a
    TagWrittenReference and a plain entry is not."""
    config = tmp_path / "ash.yaml"

    marked = parse_config_text_literally(
        config, TEXT, keep_env_tags=True, mark_written_tags=True
    )

    assert isinstance(marked["extends"][0], TagWrittenReference)
    assert type(marked["extends"][1]) is str
