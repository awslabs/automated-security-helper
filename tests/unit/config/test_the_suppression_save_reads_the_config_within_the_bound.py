# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The suppression save reads the config it edits within ``ASH_CONFIG_MAX_FILE_BYTES``.

The save reads the config twice: once to build the new bytes, and once more
right before the replace, to see that nobody wrote to the file meanwhile. The
second read goes through ``read_config_bytes``, which refuses a file longer than
the bound. The first read was a plain ``Path.read_bytes`` with no bound, so a
config just over the bound was read, edited and staged, and then refused at the
second read, which the save reported as "the config changed while the
suppression was being saved" -- a wrong reason, and the same answer however
often the save is repeated. Both reads now use ``read_config_bytes``, and a
config over the bound is refused at the first read in the bound's own words.

Each case lowers the bound to a few bytes under the file's size, as the sibling
bound tests do, so no file is large.

Red at the base: the save raised ValueError saying the config "changed while"
it was being saved, and the "larger than" words were absent. The controls pass
at the base and at the tip.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config import config_sources
from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.models.core import AshSuppression

pytestmark = pytest.mark.unit

NEW = AshSuppression(rule_id="NEW-1", path="a.py", reason="kept")

YAML_CONFIG = "# padding, padding, padding\nglobal_settings:\n  suppressions: []\n"
JSON_CONFIG = json.dumps({"global_settings": {"suppressions": []}}) + " " * 24

_SHAPES = pytest.mark.parametrize(
    ("name", "content"),
    [(".ash.yaml", YAML_CONFIG), ("ash.json", JSON_CONFIG)],
    ids=["yaml", "json"],
)


def _rules(config_path: Path) -> list:
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    entries = (data.get("global_settings") or {}).get("suppressions") or []
    return [entry["rule_id"] for entry in entries]


@_SHAPES
def test_a_config_over_the_bound_is_refused_as_too_large_not_as_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, content: str
):
    config_path = tmp_path / name
    # Bytes, not write_text: text mode would write CRLF on Windows and move the
    # size by a byte per line.
    config_path.write_bytes(content.encode("utf-8"))
    bound = len(content.encode("utf-8")) - 1
    monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", bound)

    with pytest.raises(ValueError) as refused:
        add_suppression_to_config(config_path, NEW)

    monkeypatch.undo()
    message = str(refused.value)
    assert f"larger than {bound} bytes" in message, message
    assert "changed while" not in message, message
    assert message.endswith(f"{config_path} is unchanged"), message
    assert config_path.read_bytes() == content.encode("utf-8")
    assert [p.name for p in tmp_path.iterdir()] == [name], "nothing was staged"


@_SHAPES
def test_control_a_config_at_the_bound_takes_the_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, content: str
):
    """A file exactly at the bound is read by both reads, so the save goes through."""
    config_path = tmp_path / name
    config_path.write_bytes(content.encode("utf-8"))
    monkeypatch.setattr(
        config_sources, "ASH_CONFIG_MAX_FILE_BYTES", len(content.encode("utf-8"))
    )

    assert add_suppression_to_config(config_path, NEW) is True

    monkeypatch.undo()
    if name.endswith(".json"):
        entries = json.loads(config_path.read_text(encoding="utf-8"))[
            "global_settings"
        ]["suppressions"]
        assert [entry["rule_id"] for entry in entries] == ["NEW-1"]
    else:
        assert _rules(config_path) == ["NEW-1"]
