# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--fix-unused`` edits the list at ``global_settings.suppressions`` and no other.

Why this file exists
--------------------
The text walker that comments unused suppressions out found its list by
scanning for a line that starts with ``suppressions:``. Any such line reset its
entry counter and started a new list: the ``suppressions`` option of a plugin
section, a block-scalar reason whose text happened to start with the word, a
nested list under another key. The wrong entries were commented out, entries
of other lists were commented out by the global list's indices, and a file
could no longer parse.

The list is now located by its place in the document, through the node and
token positions PyYAML records while composing it, so only the entries of
``global_settings.suppressions`` are edited, and an entry's lines are the
lines between its own ``-`` and the next entry's, whatever text they hold.

The fixer also reports only the entries the walker commented out. A list it
cannot edit line by line (a flow sequence, ``[{...}]``) is left as it is, and
the fix reports no change, where it used to report one per matched entry with
the file text unchanged.
"""

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.config_linter import ConfigLinter

pytestmark = pytest.mark.unit


def _active_yaml(text: str) -> dict:
    """The config as a scan would read it: comment lines dropped."""
    return yaml.safe_load(
        "\n".join(line for line in text.split("\n") if not line.strip().startswith("#"))
    )


def _setup(tmp_path: Path, config_text: str, unused: list) -> Path:
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(config_text, encoding="utf-8")
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps({"unused_suppressions": unused}), encoding="utf-8"
    )
    return config_path


def test_another_sections_suppressions_list_is_left_alone(tmp_path):
    """Red at the base: the walker took the scanner option's list for the global
    one and commented its first entry out by the global list's index."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "scanners:\n"
        "  custom-tool:\n"
        "    options:\n"
        "      suppressions:\n"
        "        - path: tool/a.py\n"
        "          rule_id: X1\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n"
        "    - path: src/b.py\n"
        "      rule_id: B102\n"
        "      reason: two\n",
        [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}],
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert [i.path for i in fixed_issues] == ["global_settings.suppressions[0]"]
    assert "# - path: tool/a.py" not in fixed_content
    data = _active_yaml(fixed_content)
    assert data["scanners"]["custom-tool"]["options"]["suppressions"] == [
        {"path": "tool/a.py", "rule_id": "X1"}
    ]
    assert [s["path"] for s in data["global_settings"]["suppressions"]] == ["src/b.py"]


def test_a_block_scalar_line_starting_with_the_key_does_not_reset_the_count(
    tmp_path,
):
    """Red at the base: the reason's line reset the counter, so the third entry
    was never reached and stayed active while the fix reported it commented out."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: |\n"
        "        suppressions: this line is prose\n"
        "        - path: not an entry either\n"
        "    - path: src/b.py\n"
        "      rule_id: B102\n"
        "      reason: two\n"
        "    - path: src/c.py\n"
        "      rule_id: B103\n"
        "      reason: three\n",
        [{"path": "src/c.py", "rule_id": "B103", "reason": "three"}],
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert [i.path for i in fixed_issues] == ["global_settings.suppressions[2]"]
    assert "# - path: src/c.py" in fixed_content
    data = _active_yaml(fixed_content)
    assert [s["path"] for s in data["global_settings"]["suppressions"]] == [
        "src/a.py",
        "src/b.py",
    ]
    assert data["global_settings"]["suppressions"][0]["reason"] == (
        "suppressions: this line is prose\n- path: not an entry either\n"
    )


def test_a_flow_sequence_is_left_as_it_is_and_nothing_is_reported_fixed(tmp_path):
    """Red at the base: the text was unchanged while two fixes were reported."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions: [{path: src/a.py, rule_id: B101, reason: one}, "
        "{path: src/b.py, rule_id: B102, reason: two}]\n",
        [
            {"path": "src/a.py", "rule_id": "B101", "reason": "one"},
            {"path": "src/b.py", "rule_id": "B102", "reason": "two"},
        ],
    )
    before = config_path.read_text(encoding="utf-8")

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert fixed_issues == []
    assert fixed_content == before


def test_every_entry_commented_out_leaves_an_empty_list_in_a_crlf_file(tmp_path):
    """The line endings of the file are kept, and the key reads ``suppressions: []``
    so a scan loads the file."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\r\n"
        "global_settings:\r\n"
        "  severity_threshold: MEDIUM\r\n"
        "  suppressions:\r\n"
        "  - path: src/a.py\r\n"
        "    rule_id: B101\r\n"
        "    reason: one\r\n"
        "  -\r\n"
        "    path: src/b.py\r\n"
        "    rule_id: B102\r\n"
        "    reason: two\r\n"
        "  ignore_paths:\r\n"
        "    - path: vendor/**\r\n",
        [
            {"path": "src/a.py", "rule_id": "B101", "reason": "one"},
            {"path": "src/b.py", "rule_id": "B102", "reason": "two"},
        ],
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert len(fixed_issues) == 2
    assert "\n" not in fixed_content.replace("\r\n", "")
    assert fixed_content.count("# [ash-lint") == 2
    data = _active_yaml(fixed_content.replace("\r\n", "\n"))
    assert data["global_settings"]["suppressions"] == []
    assert data["global_settings"]["severity_threshold"] == "MEDIUM"
    assert data["global_settings"]["ignore_paths"] == [{"path": "vendor/**"}]


@pytest.mark.parametrize(
    "unused, kept_paths, all_commented",
    [
        pytest.param(
            [{"path": "src/b.py", "rule_id": "B102", "reason": "two"}],
            ["src/a.py"],
            False,
            id="last-entry-with-a-kept-one-before",
        ),
        pytest.param(
            [
                {"path": "src/a.py", "rule_id": "B101", "reason": "one"},
                {"path": "src/b.py", "rule_id": "B102", "reason": "two"},
            ],
            [],
            True,
            id="every-entry",
        ),
    ],
)
def test_a_file_with_no_final_line_break_is_rewritten_whole(
    tmp_path, unused, kept_paths, all_commented
):
    """Red at the base of this walker: with no final line break the stream
    end sits on the last line, the last entry's range left that line out, and
    `reason: two` stayed active under the comments (joining the kept entry as a
    duplicate key, or orphaned under `suppressions: []`)."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n"
        "    - path: src/b.py\n"
        "      rule_id: B102\n"
        "      reason: two",
        unused,
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert len(fixed_issues) == len(unused)
    assert "# reason: two" in fixed_content
    data = yaml.safe_load(fixed_content)
    suppressions = data["global_settings"]["suppressions"]
    assert [s["path"] for s in suppressions] == kept_paths
    if kept_paths:
        assert suppressions[0] == {
            "path": "src/a.py",
            "rule_id": "B101",
            "reason": "one",
        }
    assert ("suppressions: []" in fixed_content) is all_commented


def test_a_dash_on_the_files_last_line_gets_its_own_line(tmp_path):
    config_path = _setup(
        tmp_path,
        "project_name: demo\nglobal_settings:\n  suppressions:\n    - {path: src/a.py, rule_id: B101, reason: one}",
        [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}],
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert len(fixed_issues) == 1
    assert "# [ash-lint" in fixed_content
    assert "(not matched in last scan)    # - {path" not in fixed_content
    assert yaml.safe_load(fixed_content)["global_settings"]["suppressions"] == []


@pytest.mark.parametrize(
    "unused, kept_paths",
    [
        pytest.param(
            [{"path": "src/b.py", "rule_id": "B102", "reason": "two"}],
            ["src/a.py"],
            id="the-last-entry",
        ),
        pytest.param(
            [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}],
            ["src/b.py"],
            id="the-first-entry",
        ),
    ],
)
def test_a_second_entry_whose_dash_is_on_the_files_last_line_is_counted(
    tmp_path, unused, kept_paths
):
    """Red before the end line was settled ahead of the dash collection: the
    last `-` sat on the unadjusted end line, fell outside the half-open range,
    the token and node counts disagreed, and nothing was edited or reported
    (the safe side, but the fix for a file with no final line break did not
    reach a list whose last entry is written on that line)."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n"
        "    - {path: src/b.py, rule_id: B102, reason: two}",
        unused,
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert len(fixed_issues) == 1
    assert fixed_content.count("# [ash-lint") == 1
    data = yaml.safe_load(fixed_content)
    assert [s["path"] for s in data["global_settings"]["suppressions"]] == kept_paths


def test_a_repeated_suppressions_key_is_left_alone(tmp_path):
    """The loader keeps the last list, a text walk would edit the first; the
    file is left as it is and nothing is reported commented out."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/x.py\n"
        "      rule_id: B101\n"
        "      reason: shadowed\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n",
        [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}],
    )
    before = config_path.read_text(encoding="utf-8")

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert fixed_issues == []
    assert fixed_content == before


def test_a_comment_between_entries_is_kept_as_it_is(tmp_path):
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n"
        "    # kept as written\n"
        "    - path: src/b.py\n"
        "      rule_id: B102\n"
        "      reason: two\n",
        [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}],
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert len(fixed_issues) == 1
    assert "    # kept as written\n" in fixed_content
    assert "# # kept" not in fixed_content
    data = _active_yaml(fixed_content)
    assert [s["path"] for s in data["global_settings"]["suppressions"]] == ["src/b.py"]
