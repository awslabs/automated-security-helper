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

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    UnusedSuppressionsNotEditable,
)

pytestmark = pytest.mark.unit


def _active_yaml(text: str) -> dict:
    """The config as a scan would read it: comment lines dropped."""
    return yaml.safe_load(
        "\n".join(line for line in text.split("\n") if not line.strip().startswith("#"))
    )


def _setup(tmp_path: Path, config_text: str, unused: list) -> Path:
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    # Bytes: write_text turns every "\n" into "\r\n" on Windows, so a test
    # about line breaks wrote a different file there (a CRLF text became
    # "\r\r\n"), and the fixer, which keeps the file's own breaks, read back
    # text no "\n"-written assertion matched.
    config_path.write_bytes(config_text.encode("utf-8"))
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


def test_a_flow_sequence_is_refused_with_a_reason_and_left_as_it_is(tmp_path):
    """Red at the base: the text was unchanged while two fixes were reported.
    The refusal now names the shape, so the CLI can say the file could not be
    edited instead of "nothing to comment out" after lint listed the entries."""
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

    with pytest.raises(UnusedSuppressionsNotEditable, match="flow sequence"):
        ConfigLinter.fix_unused_suppressions(config_path)

    assert config_path.read_text(encoding="utf-8") == before


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
    assert "#   reason: two" in fixed_content
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


def test_a_repeated_suppressions_key_is_refused_with_a_reason(tmp_path):
    """The loader keeps the last list, a text walk would edit the first; the
    file is left as it is and the refusal names the repeated key."""
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

    with pytest.raises(UnusedSuppressionsNotEditable, match="more than once"):
        ConfigLinter.fix_unused_suppressions(config_path)

    assert config_path.read_text(encoding="utf-8") == before


def test_a_list_with_nothing_unused_in_it_is_not_refused_for_its_shape(tmp_path):
    """The shape is checked only when there is something to comment out: a
    flow sequence whose entries are all in use reads as nothing to do. The
    report names an entry the file does not hold, so the run gets past the
    empty-report return and the matching step and reaches the point where the
    shape would be checked, with nothing unused to check it for; an empty
    report returned before either and would not have noticed the check moving
    ahead of the matching."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions: [{path: src/a.py, rule_id: B101, reason: one}]\n",
        [{"path": "src/gone.py", "rule_id": "B999", "reason": "x"}],
    )
    # The bytes as written: the fixer keeps the file's own line breaks, and
    # ``read_text`` would fold a Windows CRLF to LF before the comparison.
    before = config_path.read_bytes().decode("utf-8")

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
    # Read with the file's line breaks folded: on Windows the file, and so the
    # fixed text, carries CRLF.
    fixed = fixed_content.replace("\r\n", "\n")
    assert "    # kept as written\n" in fixed
    assert "# # kept" not in fixed
    data = _active_yaml(fixed)
    assert [s["path"] for s in data["global_settings"]["suppressions"]] == ["src/b.py"]


# --- refusals: an edit that would break the file, or a list that cannot be found ---


@pytest.mark.parametrize(
    "config_text",
    [
        pytest.param(
            "project_name: demo\n"
            "global_settings:\n"
            "  suppressions:\n"
            "    - &b101 {rule_id: B101, path: tests/a.py, reason: r}\n"
            "    - <<: *b101\n"
            "      path: tests/b.py\n",
            id="entry-merged-into-a-kept-one",
        ),
        pytest.param(
            "project_name: demo\n"
            "global_settings:\n"
            "  suppressions:\n"
            "    - path: tests/a.py\n"
            "      rule_id: B101\n"
            '      reason: &shared "Test code"\n'
            "    - path: tests/b.py\n"
            "      rule_id: B102\n"
            "      reason: *shared\n",
            id="reason-aliased-by-a-kept-entry",
        ),
    ],
)
def test_an_unused_entry_whose_anchor_a_kept_entry_uses_is_refused(
    tmp_path, config_text
):
    """Red at the base: the first entry was commented out, its anchor with it,
    the alias in the kept entry pointed at nothing, and the written file no
    longer parsed ("found undefined alias"); the next lint exited 3 on it."""
    config_path = _setup(
        tmp_path,
        config_text,
        [{"path": "tests/a.py", "rule_id": "B101", "reason": "r"}],
    )
    before = config_path.read_bytes()

    with pytest.raises(UnusedSuppressionsNotEditable, match="anchor"):
        ConfigLinter.fix_unused_suppressions(config_path)

    assert config_path.read_bytes() == before


def test_an_anchor_inside_the_commented_entries_only_is_no_refusal(tmp_path):
    """The control: an anchor whose every alias is in an entry commented out
    with it leaves a file that parses, and the edit is made."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: tests/a.py\n"
        "      rule_id: B101\n"
        '      reason: &shared "Test code"\n'
        "    - path: tests/b.py\n"
        "      rule_id: B102\n"
        "      reason: *shared\n"
        "    - path: tests/c.py\n"
        "      rule_id: B103\n"
        "      reason: three\n",
        [
            {"path": "tests/a.py", "rule_id": "B101", "reason": "Test code"},
            {"path": "tests/b.py", "rule_id": "B102", "reason": "Test code"},
        ],
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert len(fixed_issues) == 2
    data = _active_yaml(fixed_content)
    assert [s["path"] for s in data["global_settings"]["suppressions"]] == [
        "tests/c.py"
    ]


def test_a_list_supplied_through_a_merge_key_is_refused_not_called_done(tmp_path):
    """Red at the base: the loaded document holds the entries (the merge key
    supplies them), the composer does not flatten the merge, so the walker
    found no list and reported nothing to do, right after lint listed the
    entries as fixable."""
    config_path = _setup(
        tmp_path,
        "base: &base\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n"
        "project_name: demo\n"
        "global_settings:\n"
        "  <<: *base\n",
        [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}],
    )
    before = config_path.read_bytes()

    with pytest.raises(UnusedSuppressionsNotEditable, match="merge key"):
        ConfigLinter.fix_unused_suppressions(config_path)

    assert config_path.read_bytes() == before


def test_a_tagged_list_is_refused_for_its_tag(tmp_path):
    """Red at the base: the tag placed the node at the tag, no dash was found
    at its column, and the refusal read "1 entries but 0 list dashes"."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions: !!seq\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n",
        [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}],
    )

    with pytest.raises(UnusedSuppressionsNotEditable, match="tag"):
        ConfigLinter.fix_unused_suppressions(config_path)


def test_a_repeated_global_settings_key_is_refused_with_a_reason(tmp_path):
    """The loader keeps the last mapping, a text walk would edit the first; the
    file is left as it is and the refusal names the repeated key."""
    config_path = _setup(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/x.py\n"
        "      rule_id: B101\n"
        "      reason: shadowed\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n",
        [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}],
    )
    before = config_path.read_bytes()

    with pytest.raises(UnusedSuppressionsNotEditable, match="global_settings"):
        ConfigLinter.fix_unused_suppressions(config_path)

    assert config_path.read_bytes() == before


def test_an_entry_read_from_the_environment_in_a_crlf_file_is_matched(
    tmp_path, monkeypatch
):
    """The text with its CRLF breaks goes to the environment-reference record
    too: the references are read by the YAML parser, not line by line, so a
    carriage return never reaches an entry's written form and the report's
    entry (the written form, ``${VAR}``) still matches."""
    monkeypatch.setenv("ASH_U06_CRLF_PATH", "src/a.py")
    config_path = _setup(
        tmp_path,
        "project_name: demo\r\n"
        "global_settings:\r\n"
        "  suppressions:\r\n"
        "    - path: ${ASH_U06_CRLF_PATH}\r\n"
        "      rule_id: B101\r\n"
        "      reason: one\r\n"
        "    - path: src/b.py\r\n"
        "      rule_id: B102\r\n"
        "      reason: two\r\n",
        [{"path": "${ASH_U06_CRLF_PATH}", "rule_id": "B101", "reason": "one"}],
    )

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert [i.path for i in fixed_issues] == ["global_settings.suppressions[0]"]
    assert "\r\n" in fixed_content
    assert "# - path: ${ASH_U06_CRLF_PATH}" in fixed_content
    data = _active_yaml(fixed_content.replace("\r\n", "\n"))
    assert [s["path"] for s in data["global_settings"]["suppressions"]] == ["src/b.py"]
