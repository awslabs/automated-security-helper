# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``add_suppression_to_config`` saves into config shapes it used to refuse or
misjudge, and refuses the ones whose entry would not be read.

Each case is red at the base:

* A quoted ``global_settings`` key, or one with a space before its colon, was
  no key to the line scan: a second block was appended and the save refused
  the file it made. Red: ``add_suppression_to_config`` raised ValueError.
* A line of a block scalar starting with ``#`` was skipped as a comment, so the
  new lines went inside the scalar and the save refused itself as changing
  a setting. Red: ValueError.
* A top-level mapping in flow style took a text edit that cannot parse, so
  the save was refused instead of reaching the full rewrite. Red: ValueError.
* The full rewrite read whether the file uses environment references by
  opening it again, and a failed open answered no, so the rewrite dropped
  the !ENV tag. Red: the save returned True and the tag was gone.
* A file whose own ``patch`` replaces the list was saved into, and the entry
  never reached the list a scan reads. Red: the save returned True.
* A change written to the file between the save's read and its replace was
  overwritten. Red: the save returned True and the change was gone.
* A JSON config starting with a byte order mark, which every scan loads, was
  refused as unparseable. Red: ValueError.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config import ash_config, config_sources
from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.models.core import AshSuppression

pytestmark = pytest.mark.unit

NEW = AshSuppression(rule_id="NEW-1", path="a.py", reason="kept")

BOM = chr(0xFEFF)


def _rules(config_path: Path) -> list:
    data = yaml.safe_load(config_path.read_text(encoding="utf-8").lstrip(BOM))
    entries = (data.get("global_settings") or {}).get("suppressions") or []
    return [entry["rule_id"] for entry in entries]


@pytest.mark.parametrize(
    "head",
    [
        '"global_settings":',
        "'global_settings':",
        "global_settings :",
    ],
    ids=["double-quoted", "single-quoted", "space-before-colon"],
)
def test_a_global_settings_key_in_another_spelling_takes_the_entry(
    tmp_path: Path, head: str
):
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        f"# the operator's note\n{head}\n  severity_threshold: HIGH\n",
        encoding="utf-8",
    )

    assert add_suppression_to_config(config_path, NEW) is True

    text = config_path.read_text(encoding="utf-8")
    assert "# the operator's note" in text, text
    assert yaml.safe_load(text)["global_settings"]["severity_threshold"] == "HIGH"
    assert _rules(config_path) == ["NEW-1"], text


def test_a_quoted_suppressions_key_takes_the_entry_in_its_list(tmp_path: Path):
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "global_settings:\n"
        '  "suppressions":\n'
        "    - rule_id: OLD-1\n"
        "      path: old.py\n"
        "      reason: held\n",
        encoding="utf-8",
    )

    assert add_suppression_to_config(config_path, NEW) is True

    assert _rules(config_path) == ["OLD-1", "NEW-1"]


def test_an_entry_ending_in_a_block_scalar_with_a_hash_line_keeps_it(tmp_path: Path):
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: OLD-1\n"
        "      path: old.py\n"
        "      reason: |\n"
        "        first line\n"
        "        # second line\n",
        encoding="utf-8",
    )

    assert add_suppression_to_config(config_path, NEW) is True

    entries = yaml.safe_load(config_path.read_text(encoding="utf-8"))[
        "global_settings"
    ]["suppressions"]
    assert [entry["rule_id"] for entry in entries] == ["OLD-1", "NEW-1"]
    assert entries[0]["reason"] == "first line\n# second line\n"


def test_a_block_ending_in_a_block_scalar_with_a_hash_line_keeps_it(tmp_path: Path):
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: build\n"
        "      reason: |\n"
        "        generated\n"
        "        # by the build\n",
        encoding="utf-8",
    )

    assert add_suppression_to_config(config_path, NEW) is True

    settings = yaml.safe_load(config_path.read_text(encoding="utf-8"))[
        "global_settings"
    ]
    assert settings["ignore_paths"][0]["reason"] == "generated\n# by the build\n"
    assert _rules(config_path) == ["NEW-1"]


def test_a_comment_at_the_lists_end_is_still_kept(tmp_path: Path):
    """The control: a real comment line under the list stays in the file."""
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: OLD-1\n"
        "      path: old.py\n"
        "      reason: held\n"
        "    # reviewed\n"
        "  severity_threshold: HIGH\n",
        encoding="utf-8",
    )

    assert add_suppression_to_config(config_path, NEW) is True

    text = config_path.read_text(encoding="utf-8")
    assert "    # reviewed\n" in text, text
    assert _rules(config_path) == ["OLD-1", "NEW-1"]
    assert yaml.safe_load(text)["global_settings"]["severity_threshold"] == "HIGH"


def test_a_flow_style_top_level_mapping_takes_the_full_rewrite(tmp_path: Path):
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "{project_name: demo, fail_on_findings: false}\n", encoding="utf-8"
    )

    assert add_suppression_to_config(config_path, NEW) is True

    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert data["project_name"] == "demo"
    assert data["fail_on_findings"] is False
    assert _rules(config_path) == ["NEW-1"]


@pytest.mark.parametrize(
    "head",
    ["!!map ", "--- !!map "],
    ids=["tag", "marker-and-tag"],
)
def test_a_flow_style_root_behind_a_tag_takes_the_full_rewrite(
    tmp_path: Path, head: str
):
    """The tag before the brace does not make the root a block mapping.

    Red at the base: the text edits ran on it and the save was refused as a
    result that does not parse.
    """
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(f"{head}{{project_name: demo}}\n", encoding="utf-8")

    assert add_suppression_to_config(config_path, NEW) is True

    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert data["project_name"] == "demo"
    assert _rules(config_path) == ["NEW-1"]


def test_a_config_swapped_for_a_directory_during_the_save_is_refused_as_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The re-read before the replace answers in the save's own words.

    Red at the base: the re-read raised IsADirectoryError, which is no
    ValueError, so the refusal never came.
    """
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text("global_settings:\n  suppressions: []\n", encoding="utf-8")
    real_check = ash_config._why_it_would_not_load

    def check_then_swap(*args, **kwargs):
        problem = real_check(*args, **kwargs)
        config_path.unlink()
        config_path.mkdir()
        return problem

    monkeypatch.setattr(ash_config, "_why_it_would_not_load", check_then_swap)

    with pytest.raises(ValueError) as refused:
        add_suppression_to_config(config_path, NEW)

    monkeypatch.undo()
    assert "changed while" in str(refused.value), refused.value
    assert config_path.is_dir()
    assert [p.name for p in tmp_path.iterdir()] == [config_path.name]


def test_the_full_rewrite_reads_references_from_the_text_it_edits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config_path = tmp_path / ".ash.yaml"
    before = (
        "project_name: !ENV ${ASH_U35_PROJECT_NAME}\n"
        "global_settings: {severity_threshold: HIGH}\n"
    )
    config_path.write_text(before, encoding="utf-8")

    def refused_read(*args, **kwargs):
        raise PermissionError("planted: a second read of the config fails")

    # Only config_sources' own module-level names: the save's first read goes
    # through Path.read_bytes, which this leaves alone. Both are planted, the
    # builtin open and read_config_bytes, so the test holds whichever of the
    # two a second read of the file goes through.
    monkeypatch.setattr(config_sources, "open", refused_read, raising=False)
    monkeypatch.setattr(config_sources, "read_config_bytes", refused_read)

    with pytest.raises(ValueError) as refused:
        add_suppression_to_config(config_path, NEW)

    monkeypatch.undo()
    assert "environment" in str(refused.value), refused.value
    assert config_path.read_text(encoding="utf-8") == before


@pytest.mark.parametrize(
    "op",
    [
        {"op": "replace", "path": "/global_settings/suppressions", "value": []},
        {"op": "test", "path": "/global_settings/suppressions", "value": []},
        {"op": "remove", "path": "/global_settings"},
        {"op": "add", "path": "/global-settings/suppressions", "value": []},
        {"op": "move", "from": "/global_settings/suppressions", "path": "/x"},
    ],
    ids=["replace", "test", "remove-parent", "respelled-add", "move-away"],
)
def test_a_file_whose_own_patch_decides_the_list_is_refused(tmp_path: Path, op: dict):
    config_path = tmp_path / ".ash.yaml"
    before = "global_settings:\n  suppressions: []\n" + yaml.safe_dump(
        {"patch": [op]}, sort_keys=False
    )
    config_path.write_text(before, encoding="utf-8")

    with pytest.raises(ValueError) as refused:
        add_suppression_to_config(config_path, NEW)

    assert "patch" in str(refused.value), refused.value
    assert config_path.read_text(encoding="utf-8") == before


def test_a_patch_that_appends_to_the_list_does_not_stop_the_save(tmp_path: Path):
    """The control: an append leaves the saved entry in the list."""
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "global_settings:\n  suppressions: []\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /global_settings/suppressions/-\n"
        "    value: {rule_id: PATCHED-1, path: p.py, reason: by patch}\n",
        encoding="utf-8",
    )

    assert add_suppression_to_config(config_path, NEW) is True

    assert _rules(config_path) == ["NEW-1"]


def test_a_json_file_whose_own_patch_replaces_the_list_is_refused(tmp_path: Path):
    config_path = tmp_path / "ash.json"
    before = json.dumps(
        {
            "global_settings": {"suppressions": []},
            "patch": [
                {"op": "replace", "path": "/global_settings/suppressions", "value": []}
            ],
        }
    )
    config_path.write_text(before, encoding="utf-8")

    with pytest.raises(ValueError):
        add_suppression_to_config(config_path, NEW)

    assert config_path.read_text(encoding="utf-8") == before


def test_a_change_written_during_the_save_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text("global_settings:\n  suppressions: []\n", encoding="utf-8")
    meanwhile = "global_settings:\n  suppressions: []\n# written meanwhile\n"
    real_check = ash_config._why_it_would_not_load

    def check_then_write(*args, **kwargs):
        problem = real_check(*args, **kwargs)
        # Another writer, after the save read the file and before it replaces it.
        config_path.write_text(meanwhile, encoding="utf-8")
        return problem

    monkeypatch.setattr(ash_config, "_why_it_would_not_load", check_then_write)

    with pytest.raises(ValueError) as refused:
        add_suppression_to_config(config_path, NEW)

    monkeypatch.undo()
    assert "changed while" in str(refused.value), refused.value
    assert config_path.read_text(encoding="utf-8") == meanwhile
    assert [p.name for p in tmp_path.iterdir()] == [config_path.name]


def test_a_json_config_with_a_byte_order_mark_takes_the_entry(tmp_path: Path):
    config_path = tmp_path / "ash.json"
    config_path.write_bytes(
        (BOM + json.dumps({"project_name": "demo"})).encode("utf-8")
    )

    assert add_suppression_to_config(config_path, NEW) is True

    raw = config_path.read_bytes()
    assert raw.startswith(BOM.encode("utf-8")), raw[:8]
    data = json.loads(raw.decode("utf-8-sig"))
    assert data["project_name"] == "demo"
    assert [e["rule_id"] for e in data["global_settings"]["suppressions"]] == ["NEW-1"]
