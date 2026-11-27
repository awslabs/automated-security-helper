# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression an MCP client supplied saves, and is recognized as saved.

``client_supplied`` is set by ASH and never written to a config (the writer
drops it and a value in a file is ignored), so it is no part of what a saved
entry holds. Compared with it, a ``client_supplied=True`` save never matched the
entry it had just written: the pre-write check refused the save, and a second
save was never seen as a duplicate.

The writer also makes the config's directory only after its refusals: a link
that leads outside the directory the config is confined to got directories
created through it before the save said the file was unchanged.
"""

from __future__ import annotations

import os
import sys

import pytest

from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.models.core import AshSuppression

pytestmark = pytest.mark.unit


def _suppression(**extra) -> AshSuppression:
    return AshSuppression(rule_id="RULE-1", path="src/app.py", reason="test", **extra)


def test_a_client_supplied_save_round_trips_and_a_second_is_a_duplicate(tmp_path):
    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    suppression = _suppression(client_supplied=True)

    assert add_suppression_to_config(config, suppression) is True
    text = config.read_text(encoding="utf-8")
    assert "RULE-1" in text and "client_supplied" not in text

    # Control: the same suppression without the flag is found as well.
    assert add_suppression_to_config(config, suppression) is False
    assert add_suppression_to_config(config, _suppression()) is False
    assert config.read_text(encoding="utf-8") == text


@pytest.mark.skipif(sys.platform == "win32", reason="links need privileges on Windows")
def test_a_link_leading_outside_the_root_creates_no_directory(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    # Dangling: nothing exists at the far end, so a mkdir through the link
    # would make it.
    (root / ".ash").symlink_to(outside / "made-through-the-link")
    config = root / ".ash" / ".ash.yaml"

    with pytest.raises(ValueError, match="is unchanged"):
        add_suppression_to_config(config, _suppression())

    assert not os.path.lexists(outside), "a directory was made through the link"
