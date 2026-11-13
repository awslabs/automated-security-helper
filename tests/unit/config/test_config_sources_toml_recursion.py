# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A TOML config nested past the recursion limit is an unparsed config.

``read_config_file`` reads a TOML file through ``toml_config_table``, which
worded every parser error as an unparsed config except the RecursionError
tomllib raises for a text nested past the interpreter's recursion limit: that
one left ``read_config_file`` raw, where ``parse_config_text`` and
``pyproject_has_ash_table`` word it as a file that does not parse.

Red at the base: both calls below raised RecursionError.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import (
    read_config_file,
    toml_config_table,
)
from automated_security_helper.core.exceptions import ASHConfigUnparsedError

pytestmark = pytest.mark.unit

DEPTH = 20000
DEEP_TOML = "x = " + "[" * DEPTH + "]" * DEPTH + "\n"


def test_the_table_of_a_deep_text_is_refused_as_unparsed() -> None:
    with pytest.raises(ASHConfigUnparsedError, match="could not be parsed"):
        toml_config_table(Path("deep.toml"), DEEP_TOML)


def test_read_config_file_refuses_a_deep_file_as_unparsed(tmp_path: Path) -> None:
    deep = tmp_path / ".ash.toml"
    deep.write_text(DEEP_TOML, encoding="utf-8")

    with pytest.raises(ASHConfigUnparsedError, match="could not be parsed"):
        read_config_file(deep)


def test_a_shallow_file_still_reads(tmp_path: Path) -> None:
    """The control."""
    flat = tmp_path / ".ash.toml"
    flat.write_text("project_name = 'flat'\n", encoding="utf-8")

    assert read_config_file(flat) == {"project_name": "flat"}
