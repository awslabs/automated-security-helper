# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A mapping key that is not a string merges as itself.

YAML reads an unquoted ``7`` or ``on`` key as a number or a boolean (and ``~``
as null, which the merge refuses: see the null-key tests).
``deep_merge`` and ``_resolve_dict_key`` read every key as text
(``str.replace``, and ``plugin_key_lookup_names`` for a plugin's section), so a
file of an ``extends`` chain that held such a key failed the whole chain with an
AttributeError or a TypeError, wrapped as "Could not resolve 'extends'/'patch'",
although the same file loaded alone. Such a key is now matched only as itself.

Red at the base: each merge below that is not marked as a control raised
AttributeError or TypeError.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_sources import (
    deep_merge,
    resolve_config_document,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit


def test_a_number_and_a_boolean_key_merge_as_themselves() -> None:
    merged = deep_merge({"project_name": "base"}, {7: "seven", True: "yes"}, AshConfig)

    assert merged == {"project_name": "base", 7: "seven", True: "yes"}


def test_a_null_key_is_refused_by_the_merge() -> None:
    """A null key is what a key written as a reference to a set but empty
    variable resolves to. It spells no key, so the merge refuses it rather than
    carrying it; the chain words the refusal (next test)."""
    with pytest.raises(ValueError, match="null"):
        deep_merge({"project_name": "base"}, {None: "none"}, AshConfig)


def test_a_key_written_as_a_reference_to_an_empty_variable_refuses_the_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The chain refuses the file and names the variable, never its value.

    Red when the merge carried a null key: the chain loaded and the variable
    was never named, so a container scan could run on a file whose key the host
    and the scan inside read differently.
    """
    monkeypatch.setenv("ASH_U35_BLANK_FIELD", "")
    monkeypatch.setenv("ASH_U35_BASE", "base.yaml")
    (tmp_path / "base.yaml").write_text("project_name: base\n", encoding="utf-8")
    top = tmp_path / "top.yaml"
    top.write_text(
        "${ASH_U35_BLANK_FIELD}: other\nextends: ${ASH_U35_BASE}\n", encoding="utf-8"
    )

    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config_document(top)

    message = str(refused.value)
    assert "ASH_U35_BLANK_FIELD" in message, message
    assert "does not resolve with the values its environment references hold" in (
        message
    ), message


def test_a_number_key_meets_the_same_key_in_the_base() -> None:
    """The control: a key the base holds exactly was found before any text
    was read from it, and still merges key by key."""
    merged = deep_merge({7: {"a": 1}}, {7: {"b": 2}}, AshConfig)

    assert merged == {7: {"a": 1, "b": 2}}


def test_a_number_key_in_a_plugin_segment_joins_no_section() -> None:
    """Under ``scanners``, the plugin-section join reads every key as a plugin
    name; a number key names no plugin and lands beside the base's sections."""
    merged = deep_merge(
        {"scanners": {"bandit": {"enabled": True}}},
        {"scanners": {7: {"enabled": False}}},
        AshConfig,
    )

    assert merged["scanners"][7] == {"enabled": False}
    assert merged["scanners"]["bandit"] == {"enabled": True}


def test_a_string_spelling_still_joins_its_twin() -> None:
    """The control: a key that differs only in "-" versus "_" still reaches the
    base's spelling of it."""
    merged = deep_merge({"custom-section": {"a": 1}}, {"custom_section": {"b": 2}})

    assert merged == {"custom-section": {"a": 1, "b": 2}}


def test_a_chain_whose_file_holds_a_number_key_resolves(tmp_path: Path) -> None:
    (tmp_path / "base.yaml").write_text("project_name: base\n", encoding="utf-8")
    top = tmp_path / "top.yaml"
    top.write_text("extends: base.yaml\n7: seven\n", encoding="utf-8")

    document = resolve_config_document(top)

    assert document.data[7] == "seven"
    assert document.data["project_name"] == "base"
