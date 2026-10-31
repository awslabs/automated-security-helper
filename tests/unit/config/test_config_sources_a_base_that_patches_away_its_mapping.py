# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A base whose own ``patch`` replaces its whole document with a non-mapping
is refused.

A base file must be a mapping, and one that is not is refused when it is read.
A base that is a mapping but whose own ``patch`` replaces the whole document
(the root pointer ``""``) with a list was not refused: merged, the list
replaced what every earlier base set, and the extending file's own keys then
replaced the list, so the base and each base before it were dropped with no
word.

Red at the base: the chain resolved, without the first base's settings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import resolve_config_document
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit


def _chain(tmp_path: Path, replacement: str) -> Path:
    (tmp_path / "first.yaml").write_text("first_label: first\n", encoding="utf-8")
    (tmp_path / "second.yaml").write_text(
        f"patch:\n  - op: replace\n    path: ''\n    value: {replacement}\n",
        encoding="utf-8",
    )
    top = tmp_path / "top.yaml"
    top.write_text(
        "extends: [first.yaml, second.yaml]\ntop_label: top\n", encoding="utf-8"
    )
    return top


def test_a_base_patched_into_a_list_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ASHConfigSourceError, match="must be a mapping") as refused:
        resolve_config_document(_chain(tmp_path, "[1, 2]"))

    assert "second.yaml" in str(refused.value), str(refused.value)


def test_a_base_patched_into_another_mapping_still_merges(tmp_path: Path) -> None:
    """The control: a whole-document replace with a mapping is a base like any
    other, merged over the bases before it."""
    document = resolve_config_document(_chain(tmp_path, "{second_label: second}"))

    assert document.data == {
        "first_label": "first",
        "second_label": "second",
        "top_label": "top",
    }
