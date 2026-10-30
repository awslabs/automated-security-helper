# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reference whose list a later file wrote a string over is not displayed.

``displayed_environment_references`` keeps the references the merged document
still holds at their places (``_still_describes``). The walk to a place indexed
whatever it met, so a base's reference at a list entry, whose list the
extending file replaced with a string, was looked up as one character of that
string; a character equal to the value read kept the reference, and a view of
the merged configuration showed the string's place as read from the
environment.

Red at the base: the reference was in ``displayed_environment_references``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import resolve_config_document

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASH_SCALAR_OVER_LIST_VALUE", "x")
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _chain(tmp_path: Path, top_value: str) -> Path:
    (tmp_path / "base.yaml").write_text(
        "custom_list:\n  - ${ASH_SCALAR_OVER_LIST_VALUE}\n", encoding="utf-8"
    )
    top = tmp_path / "top.yaml"
    top.write_text(f"extends: base.yaml\n{top_value}", encoding="utf-8")
    return top


def _read_from_the_list(references) -> list:
    return [
        reference
        for reference in references
        if tuple(reference.path)[:1] == ("custom_list",) and reference.resolved == "x"
    ]


def test_a_string_over_the_list_drops_the_reference_from_the_display(
    tmp_path: Path,
) -> None:
    document = resolve_config_document(_chain(tmp_path, "custom_list: xyz\n"))

    assert document.data["custom_list"] == "xyz"
    # Still an environment read, so redaction keeps masking the value.
    assert _read_from_the_list(document.environment_references)
    assert _read_from_the_list(document.displayed_environment_references) == []


def test_the_list_left_in_place_keeps_the_reference_displayed(tmp_path: Path) -> None:
    """The control: with the base's list in place the reference is shown."""
    document = resolve_config_document(_chain(tmp_path, "project_name: top\n"))

    assert document.data["custom_list"] == ["x"]
    assert _read_from_the_list(document.displayed_environment_references)
