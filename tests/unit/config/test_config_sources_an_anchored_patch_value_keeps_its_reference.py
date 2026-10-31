# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``patch`` value an operator file reads from the environment is recorded
where it lands, also when its path is anchored.

An operator file's relative paths are taken from its directory, the values its
``patch`` operations set included (``anchor_patch_operations``). Each
reference an operation's value read is followed through the operations to the
place it lands, by matching the value as it was read; the operations followed
were the anchored ones, whose value no longer matched, so the reference was
dropped from ``environment_references``, and every view that writes the
configuration out showed the path as a literal the file never wrote.

Red at the base: no reference was recorded at the option's place.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import resolve_config_document

pytestmark = pytest.mark.unit

READ_PATH = "bandit-rules.yaml"


@pytest.fixture(autouse=True)
def _value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASH_ANCHORED_PATCH_VALUE", READ_PATH)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _operator_file(tmp_path: Path) -> Path:
    config = tmp_path / "operator.yaml"
    config.write_text(
        "scanners:\n"
        "  bandit:\n"
        "    options: {}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /scanners/bandit/options/config_file\n"
        "    value: ${ASH_ANCHORED_PATCH_VALUE}\n",
        encoding="utf-8",
    )
    return config


def _places(document) -> list:
    return [
        tuple(reference.path)
        for reference in document.environment_references
        if reference.resolved == READ_PATH
    ]


def test_an_anchored_value_is_recorded_at_its_place(tmp_path: Path) -> None:
    document = resolve_config_document(
        _operator_file(tmp_path), anchor_relative_paths=lambda path: True
    )

    landed = document.data["scanners"]["bandit"]["options"]["config_file"]
    assert Path(landed).is_absolute() and landed.endswith(READ_PATH), landed
    assert _places(document) == [("scanners", "bandit", "options", "config_file")]


def test_a_value_left_as_written_is_recorded_at_its_place(tmp_path: Path) -> None:
    """The control: without anchoring the value lands as read, and its
    reference with it."""
    document = resolve_config_document(_operator_file(tmp_path))

    assert document.data["scanners"]["bandit"]["options"]["config_file"] == READ_PATH
    assert _places(document) == [("scanners", "bandit", "options", "config_file")]
