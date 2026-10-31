# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``global_settings`` block with no children is edited as text, comments kept.

A ``global_settings: {}``, a spelled null, or a ``global_settings:`` key with
only comments under it holds nothing to anchor on, so the save fell through to
the whole rewrite, which drops every comment in the file. The empty value is now
dropped from its line as ``suppressions: []`` is, and the key is inserted under
it with a two-space indent.

Red at the base: the saved file no longer held the comment.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.config.config_sources import load_config_document
from automated_security_helper.models.core import AshSuppression

pytestmark = pytest.mark.unit

NEW = AshSuppression(rule_id="NEW-1", path="a.py", reason="kept")


@pytest.mark.parametrize(
    "before",
    [
        "# the operator's note\nglobal_settings: {}\n",
        "# the operator's note\nglobal_settings: ~\n",
        "# the operator's note\nglobal_settings: {} # trailing\n",
        "# the operator's note\nglobal_settings:\n  # nothing yet\n",
    ],
    ids=["flow-empty", "null", "flow-empty-comment", "comment-only-block"],
)
def test_the_comment_survives_the_first_suppression(
    tmp_path: Path, before: str
) -> None:
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(before, encoding="utf-8")

    assert add_suppression_to_config(config_path, NEW) is True

    text = config_path.read_text(encoding="utf-8")
    assert "# the operator's note" in text, text
    entries = load_config_document(config_path)["global_settings"]["suppressions"]
    assert [entry["rule_id"] for entry in entries] == ["NEW-1"]


def test_a_trailing_comment_on_the_key_line_is_kept(tmp_path: Path) -> None:
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text("global_settings: {} # trailing\n", encoding="utf-8")

    add_suppression_to_config(config_path, NEW)

    assert config_path.read_text(encoding="utf-8").startswith(
        "global_settings: # trailing\n  suppressions:\n"
    )
