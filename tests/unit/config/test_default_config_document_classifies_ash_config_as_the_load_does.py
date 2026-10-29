# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``default_config_document`` judges ASH_CONFIG as ``get_default_config`` does.

It classified the variable with ``Path.exists()``: a path under an unsearchable
directory raised the stat's PermissionError on Python 3.10 to 3.13, and a
symlink loop, a whitespace value or a file absent at that instant answered None.
``trusted_default_config`` reads the document first to judge the chain for a
client-delivered file and then loads the file again with ``get_default_config``,
so a file that appeared between the two reads was loaded as the trusted config
without that check. Both now classify through ``_ash_config_file``: a value that
names no file is refused with the same error, never answered with None.

Red at the base: ``default_config_document()`` returned None for a whitespace
value and for a missing file, where ``get_default_config`` refused them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.default_config import (
    default_config_document,
    get_default_config,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("value", [" ", "{tmp}/missing.yaml"], ids=["blank", "missing"])
def test_a_value_naming_no_file_is_refused_as_the_load_refuses_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("ASH_CONFIG", value.format(tmp=tmp_path))

    with pytest.raises(ASHConfigValidationError):
        get_default_config()
    with pytest.raises(ASHConfigValidationError):
        default_config_document()


def test_an_unset_variable_answers_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    assert default_config_document() is None


def test_a_named_file_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The control."""
    config = tmp_path / "ash.yaml"
    config.write_text("fail_on_findings: false\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    document = default_config_document()

    assert document is not None
    assert document.data["fail_on_findings"] is False
