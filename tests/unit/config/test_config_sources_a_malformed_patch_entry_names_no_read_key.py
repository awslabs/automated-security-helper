# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A malformed ``patch`` entry's refusal names no key read from the environment.

A ``patch`` entry without a ``path`` is refused with the keys it holds. A key
the file wrote as an environment reference is, by then, the value the
variable holds, and the refusal listed it, so the value reached the message an
operator, ash.log and an MCP client read. Such a key is now named as
``<value>``, as every other refusal of an operation names what the file read.

Red at the base: the refusal held the variable's value.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import resolve_config_document
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit

READ_VALUE = "value-read-for-a-patch-key"


@pytest.fixture(autouse=True)
def _value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASH_MALFORMED_PATCH_KEY", READ_VALUE)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _refusal(tmp_path: Path, key: str) -> str:
    config = tmp_path / "top.yaml"
    config.write_text(
        f"project_name: demo\npatch:\n  - op: add\n    {key}: x\n", encoding="utf-8"
    )
    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config_document(config)
    return str(refused.value)


def test_a_key_read_from_the_environment_is_not_quoted(tmp_path: Path) -> None:
    message = _refusal(tmp_path, "${ASH_MALFORMED_PATCH_KEY}")

    assert "must be a mapping with 'op' and 'path'" in message, message
    assert READ_VALUE not in message, message
    assert "<value>" in message, message


def test_a_key_the_file_wrote_itself_is_named(tmp_path: Path) -> None:
    """The control: a key written as text is named as it is."""
    message = _refusal(tmp_path, "pth")

    assert "keys op, pth" in message, message
