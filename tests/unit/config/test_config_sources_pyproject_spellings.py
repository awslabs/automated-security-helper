# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unparsable pyproject.toml declares ASH under every key spelling TOML has.

A pyproject.toml that does not parse is refused when its text declares ASH
settings and skipped otherwise, and the text is read by its lines. Those lines
were read for bare keys only: a quoted key (``[tool."ash"]``, ``["tool".ash]``,
``"ash" = ...`` under ``[tool]``) names the same table in TOML, a top-level
``tool = { ash = ... }`` inline table holds it too, and a file that starts with
a UTF-8 byte order mark and is not UTF-8 after it was read with the mark in
front of its first header. Each such file was skipped as holding no ASH
settings, and the scan ran with the defaults.

Red at the base: ``pyproject_has_ash_table`` returned False for each declaring
file below.
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

DECLARING = {
    "quoted-ash-in-header": b'[tool."ash"]\nbroken = \n',
    "quoted-tool-in-header": b"['tool'.ash]\nbroken = \n",
    "quoted-dotted-key": b'"tool"."ash".fail_on_findings = \n',
    "quoted-ash-under-tool": b'[tool]\n"ash" = { fail_on_findings = false\n',
    "inline-tool-table": b"tool = { ash = { fail_on_findings = false }\n",
    "inline-tool-table-second-key": b"tool = { black = {}, ash = {}\n",
    # Not UTF-8 after the mark: the byte e9 is Latin-1 for an accented e.
    "byte-order-mark": b"\xef\xbb\xbf[tool.ash]\nproject_name = 'caf\xe9'\n",
}

NOT_DECLARING = {
    "quoted-other-key-under-tool": b'[tool]\n"flash" = { x = "y"\n',
    "inline-tool-table-without-ash": b"tool = { flash = 1\n",
    "byte-order-mark-other-table": b"\xef\xbb\xbf[project]\nname = 'caf\xe9'\n",
}


@pytest.mark.parametrize("name", sorted(DECLARING))
def test_an_unparsable_declaration_is_refused(tmp_path: Path, name: str) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_bytes(DECLARING[name])

    with pytest.raises(ASHConfigUnparsedError, match="could not be parsed"):
        pyproject_has_ash_table(pyproject)
    with pytest.raises(ASHConfigUnparsedError):
        discover_config_source(tmp_path)


@pytest.mark.parametrize("name", sorted(NOT_DECLARING))
def test_an_unparsable_file_that_declares_nothing_is_skipped(
    tmp_path: Path, name: str
) -> None:
    """The control: a key that only contains ``ash``, and a file with a byte
    order mark that names another table, are not ASH's."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_bytes(NOT_DECLARING[name])

    assert pyproject_has_ash_table(pyproject) is False
    assert discover_config_source(tmp_path).selected is None
