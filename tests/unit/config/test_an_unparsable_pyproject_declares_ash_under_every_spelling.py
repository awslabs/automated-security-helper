# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unparsable pyproject.toml that declares ASH settings is refused, not skipped.

A pyproject.toml that does not parse is skipped as a config source unless its
text declares a ``tool.ash`` table, in which case the scan is refused rather than
run with the defaults while the repository's config sits unread. The text check
read a ``[tool.ash]`` or ``[tool.ash.*]`` header and a top-level dotted
``tool.ash...`` key only: a ``[[tool.ash.*]]`` array of tables, and an ``ash``
key under a bare ``[tool]`` table, went unread, so such a file was skipped
silently.

Red at the base: ``pyproject_has_ash_table`` returned False for the two files
below, and ``discover_config_source`` selected nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import (
    discover_config_source,
    pyproject_has_ash_table,
)
from automated_security_helper.core.exceptions import ASHConfigUnparsedError

pytestmark = pytest.mark.unit

ARRAY_OF_TABLES = '[[tool.ash.scanners]]\nname = "bandit"\nbroken = \n'
UNDER_TOOL_TABLE = '[tool]\nash = { severity_threshold = "HIGH"\n'
# The same file as a Windows editor writes it: the text is decoded with no
# newline translation, so each line ends in a carriage return before the
# line feed, the header line included.
UNDER_TOOL_TABLE_CRLF = UNDER_TOOL_TABLE.replace("\n", "\r\n")


@pytest.mark.parametrize(
    "text",
    [ARRAY_OF_TABLES, UNDER_TOOL_TABLE, UNDER_TOOL_TABLE_CRLF],
    ids=["array-of-tables", "tool-table", "tool-table-crlf"],
)
def test_an_unparsable_declaration_is_refused(tmp_path: Path, text: str) -> None:
    pyproject = tmp_path / "pyproject.toml"
    # Bytes, so the test's own line endings reach the file as written.
    pyproject.write_bytes(text.encode("utf-8"))

    with pytest.raises(ASHConfigUnparsedError, match="could not be parsed"):
        pyproject_has_ash_table(pyproject)
    with pytest.raises(ASHConfigUnparsedError):
        discover_config_source(tmp_path)


def test_an_ash_key_under_another_table_declares_nothing(tmp_path: Path) -> None:
    """The control: an ``ash`` key under a table other than ``[tool]`` is not
    ASH's, so the unparsable file is skipped as before."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[other]\nash = { x = "y"\n', encoding="utf-8")

    assert pyproject_has_ash_table(pyproject) is False
    assert discover_config_source(tmp_path).selected is None


def test_a_parsable_declaration_still_counts(tmp_path: Path) -> None:
    """The control: the parsable spellings answer as before."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.ash]\nfail_on_findings = false\n", encoding="utf-8")

    assert pyproject_has_ash_table(pyproject) is True
