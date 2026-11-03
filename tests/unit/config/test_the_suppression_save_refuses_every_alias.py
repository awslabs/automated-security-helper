# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The suppression save refuses a YAML alias as every other config reader does.

``load_config_yaml`` refuses every alias for every reader of a config, so a
config that uses one never loads for a scan. The save's own loader refused only
a recursive alias and edited an aliased file, which the scan then refused; and
the save's write-check walks the loaded document, so an alias that fans out cost
that walk the document's expansion. The save's loader now refuses every alias
at parse, in the save's left-unchanged words, with the file's bytes kept.

Red at the base: ``add_suppression_to_config`` returned True and wrote the
aliased file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.models.core import AshSuppression

pytestmark = pytest.mark.unit

ALIASED = (
    "shared: &opts\n"
    "  mirror: true\n"
    "global_settings:\n"
    "  suppressions: []\n"
    "reporters:\n"
    "  stub:\n"
    "    options: *opts\n"
)


def test_an_aliased_config_is_refused_unchanged(tmp_path: Path) -> None:
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(ALIASED, encoding="utf-8")
    before = config_path.read_bytes()

    with pytest.raises(ValueError) as refused:
        add_suppression_to_config(
            config_path, AshSuppression(rule_id="R1", path="a.py", reason="kept")
        )

    message = str(refused.value)
    assert "could not be parsed (ComposerError at line" in message, message
    assert message.endswith(f"{config_path} is unchanged"), message
    assert config_path.read_bytes() == before


def test_the_alias_free_spelling_still_saves(tmp_path: Path) -> None:
    """The control: the same document with the value written out saves."""
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "global_settings:\n  suppressions: []\nreporters:\n  stub:\n"
        "    options:\n      mirror: true\n",
        encoding="utf-8",
    )

    assert (
        add_suppression_to_config(
            config_path, AshSuppression(rule_id="R1", path="a.py", reason="kept")
        )
        is True
    )
