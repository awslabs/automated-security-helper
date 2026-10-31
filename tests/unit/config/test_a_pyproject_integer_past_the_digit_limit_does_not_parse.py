# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A pyproject.toml holding an integer past Python's digit limit is "does not parse".

``int()`` refuses a number longer than ``sys.int_info.str_digits_check_threshold``
digits with a plain ValueError, which tomllib lets through undressed: not a
TOMLDecodeError, so discovery's handlers did not catch it and the scan was refused
with a raw ValueError even when a higher-precedence config existed. The TOML
parse sites now take any ValueError as the file not parsing.

Red at the base: ``discover_config_source`` raised ValueError.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import (
    discover_config_source,
    pyproject_has_ash_table,
    toml_config_table,
)
from automated_security_helper.core.exceptions import ASHConfigUnparsedError

pytestmark = pytest.mark.unit

HUGE = "[tool.other]\nn = " + "9" * 6000 + "\n"


def test_discovery_skips_an_unparsable_pyproject_behind_a_config(
    tmp_path: Path,
) -> None:
    (tmp_path / ".ash.yaml").write_text("fail_on_findings: false\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(HUGE, encoding="utf-8")

    discovery = discover_config_source(tmp_path)

    assert discovery.selected is not None
    assert discovery.selected.path.name == ".ash.yaml"


def test_a_pyproject_with_no_ash_table_is_skipped_not_raised(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(HUGE, encoding="utf-8")

    assert pyproject_has_ash_table(pyproject) is False


def test_a_declared_table_that_does_not_parse_is_an_unparsed_config(
    tmp_path: Path,
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.ash]\n" + HUGE, encoding="utf-8")

    with pytest.raises(ASHConfigUnparsedError) as refused:
        toml_config_table(pyproject, pyproject.read_text(encoding="utf-8"))

    message = str(refused.value)
    assert "could not be parsed" in message and "ValueError" in message, message
