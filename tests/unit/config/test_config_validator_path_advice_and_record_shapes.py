# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""config_validator's path advice, record rewrites and structural checks, on
the shapes that advised a dead pattern, lost an entry or read the wrong text.

- path_pattern_advice read '/' as the only separator while the matcher reads a
  backslash as one too, stripped only one './' and advised the rest unchecked
  ('.//x' as the absolute '/x', './.' as './', '../x' as '../x/'), and the './'
  branch kept a spelling the tree holds only in another case; a '**/<dir>'
  pattern names a file of that name and got no warning.
- shows_a_changed_input spliced the letters either side of a redaction marker.
- A reference whose variable is set to a blank value counted as read from the
  environment, so the file's own text after it joined the redaction list.
- A patch pointer segment of non-ASCII digits raised out of int(); a mapping
  key '-' was read as a patch append and the rewrite dropped.
- record_of_config replaced every occurrence of a value's part and a key rename
  onto a key the mapping already holds overwrote that entry.
- absolute_path_warning advised another absolute path after a doubled slash,
  and no spelling for a pattern spelled through a symlinked root.
- describe_validation_error left a short environment-read key in a location.
- A str source_dir crashed check_config_file; a project_name or path list an
  override supplies was read from the file alone; the duplicate top-level
  check missed quoted keys, JSON files and a byte order mark and repeated its
  warning; a refused internal field was read back from the redacted message;
  a folded section spelling was not found; validate_and_raise numbered the
  warnings with the errors.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from automated_security_helper.config.config_validator import (
    REDACTED,
    ConfigValidationError,
    ConfigValidator,
    EnvironmentRewrite,
    _interpolated_pairs,
    _placed_rewrites,
    absolute_path_warning,
    describe_validation_error,
    path_pattern_advice,
    placed_at_appends,
    record_of_config,
    shows_a_changed_input,
)
from automated_security_helper.utils.unknown_keys import (
    INTERNAL_SECTION_FIELDS,
    internal_field_message,
)

pytestmark = pytest.mark.unit

BARE = "matches no path. Name the paths"
PREFIX = "starts with './' and matches no path"
DIRECTORY = "points to a directory but matches no file in it"


def _tree(tmp_path: Path) -> Path:
    """The fixture tree under ``tmp_path``; a second call in one test finds it
    built and returns the same root."""
    root = tmp_path / "root"
    for name in ("src/lib", "tests", "build", "vendor", "deep/a/node_modules"):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    return root


class TestPathPatternAdvice:
    @pytest.mark.parametrize(
        ("pattern", "shown"),
        [
            pytest.param(
                ".\\src", f"Path '.\\src' {PREFIX}. Use 'src/'", id="dot-backslash"
            ),
            pytest.param(
                "src\\lib",
                f"Path 'src\\lib' {DIRECTORY}. Use 'src\\lib/'",
                id="backslash",
            ),
        ],
    )
    def test_a_backslash_is_a_separator(self, tmp_path, pattern, shown):
        advice = path_pattern_advice(pattern, _tree(tmp_path), ignore_path=True)
        assert advice is not None and shown in advice, advice

    def test_a_doubled_slash_after_the_prefix_is_not_an_absolute_path(self, tmp_path):
        advice = path_pattern_advice(".//src", _tree(tmp_path), ignore_path=True)
        assert (
            advice
            == f"Path './/src' {PREFIX}. Use 'src/' to ignore every file inside the directory."
        )
        assert "'/src" not in advice

    @pytest.mark.parametrize(
        "pattern", ["./.", "./..", "./../src", "../src", "src/.", "a/./b"]
    )
    def test_a_dot_component_names_no_path(self, tmp_path, pattern):
        advice = path_pattern_advice(pattern, _tree(tmp_path), ignore_path=True)
        assert advice is not None and BARE in advice, advice
        assert "Use '" not in advice, advice

    def test_control_a_slash_the_operator_typed_keeps_the_plain_wording(self, tmp_path):
        """'./tests/' already spells the directory, so the advice drops the
        prefix and says "to ignore it", as before; only a slash the tree's
        respelling adds is not read as the operator's."""
        advice = path_pattern_advice("./tests/", _tree(tmp_path), ignore_path=True)
        assert advice == f"Path './tests/' {PREFIX}. Use 'tests/' to ignore it."

    def test_the_dot_prefix_advice_takes_the_trees_spelling(self, tmp_path):
        """The respelling covers the leading names the tree holds in another
        case; a file the pattern names has to exist for its path to be
        respelled, so the second case writes it under the tree's spelling."""
        root = _tree(tmp_path)
        advice = path_pattern_advice("./Tests", root, ignore_path=True)
        assert advice == (
            f"Path './Tests' {PREFIX}. Use 'tests/' to ignore every file inside the directory."
        )
        (root / "tests" / "app.py").write_text("x = 1\n", encoding="utf-8")
        advice = path_pattern_advice("./Tests/app.py", root, ignore_path=False)
        assert (
            advice
            == f"Path './Tests/app.py' {PREFIX}. Use 'tests/app.py' to suppress its findings."
        )

    def test_a_recursive_pattern_naming_a_directory_is_advised(self, tmp_path):
        root = _tree(tmp_path)
        advice = path_pattern_advice("**/node_modules", root, ignore_path=True)
        assert advice == (
            f"Path '**/node_modules' {DIRECTORY}. Use '**/node_modules/' to ignore "
            "every file inside the directory."
        )
        assert path_pattern_advice("**/node_modules", root, ignore_path=False) == (
            f"Path '**/node_modules' {DIRECTORY}. Use '**/node_modules/**/*' to "
            "suppress the findings in every file inside the directory."
        )

    @pytest.mark.parametrize("pattern", ["**/nothing-here", "src/**", "**/*.py", "**"])
    def test_control_a_recursive_pattern_that_matches_gets_no_advice(
        self, tmp_path, pattern
    ):
        assert path_pattern_advice(pattern, _tree(tmp_path), ignore_path=True) is None


class TestChangedInput:
    def test_letters_either_side_of_a_marker_are_not_spliced(self):
        assert not shows_a_changed_input(f"qzsplice{REDACTED}value", ["qzsplicevalue"])

    def test_control_a_changed_input_is_still_seen(self):
        assert shows_a_changed_input("qz splice value", ["qzsplicevalue"])


class TestBlankEnvironmentValue:
    def test_a_blank_variable_pairs_nothing(self, monkeypatch):
        monkeypatch.setenv("ASH_BLANK_PAIRING", " ")
        assert _interpolated_pairs("${ASH_BLANK_PAIRING}/suffix", " /suffix") == []

    def test_control_a_set_variable_pairs(self, monkeypatch):
        monkeypatch.setenv("ASH_BLANK_PAIRING", "qzvalue")
        pairs = _interpolated_pairs("${ASH_BLANK_PAIRING}/suffix", "qzvalue/suffix")
        assert ("qzvalue/suffix", "${ASH_BLANK_PAIRING}/suffix") in pairs


class _Holder(BaseModel):
    model_config = ConfigDict(extra="allow")


def _value_rewrite(
    path, written, resolved, part=None, reference=None
) -> EnvironmentRewrite:
    return EnvironmentRewrite(
        "value", tuple(path), resolved, written, part or resolved, reference or written
    )


class TestPlacedRewrites:
    def test_a_non_ascii_digit_segment_stays_text(self):
        rewrite = _value_rewrite(("patch", 0, "value"), "${V}", "x")
        data = {"patch": [{"op": "add", "path": "/scanners/²/x", "value": "x"}]}
        placed = _placed_rewrites([rewrite], data)
        assert placed[0].path == ("scanners", "²", "x")

    def test_control_an_ascii_digit_segment_is_an_index(self):
        rewrite = _value_rewrite(("patch", 0, "value"), "${V}", "x")
        data = {"patch": [{"op": "add", "path": "/a/12/x", "value": "x"}]}
        assert _placed_rewrites([rewrite], data)[0].path == ("a", 12, "x")

    def test_a_mapping_key_dash_is_not_an_append(self):
        config = _Holder(section={"-": "x"})
        rewrite = _value_rewrite(("section", "-"), "${V}", "x")
        assert placed_at_appends(config, [rewrite]) == [rewrite]

    def test_control_an_append_into_a_list_takes_its_index(self):
        config = _Holder(items=["a", "x"])
        rewrite = _value_rewrite(("items", "-"), "${V}", "x")
        assert placed_at_appends(config, [rewrite])[0].path == ("items", 1)


class TestRecordOfConfig:
    def test_a_value_inside_other_text_is_replaced_where_it_stands(self):
        config = SimpleNamespace(
            _written_references=[_value_rewrite(("a",), "${V}", "xy", "xy", "${V}")]
        )
        assert record_of_config(config, {"a": "xy-tail"}) == {"a": "${V}-tail"}
        assert record_of_config(config, {"a": "head-xy"}) == {"a": "head-${V}"}

    def test_a_record_hides_a_repeated_value_at_every_occurrence(self):
        """A record never holds the value: where the string holds it again, the
        other occurrences are hidden too."""
        config = SimpleNamespace(
            _written_references=[_value_rewrite(("a",), "${V}", "xy", "xy", "${V}")]
        )
        assert record_of_config(config, {"a": "xyxy"}) == {"a": "${V}${V}"}

    def test_a_file_to_be_loaded_again_keeps_a_repeated_value_unwritten(self):
        """With ``mark`` (a file written to be loaded again) a string that holds
        the value twice is left as the configuration holds it, for the writer to
        refuse: one reference beside the value as text would write the value."""
        config = SimpleNamespace(
            _written_references=[_value_rewrite(("a",), "${V}", "xy", "xy", "${V}")]
        )
        marks: list = []

        def mark(text):
            marks.append(text)
            return text

        assert record_of_config(config, {"a": "xyxy"}, mark=mark) == {"a": "xyxy"}
        assert marks == []

    def test_a_value_inside_its_own_references_spelling_occurs_once(self, monkeypatch):
        """``AB`` under ``${TAB}``: the value is found again inside the reference
        once written. Counted on the string as held, it occurs once, so the
        record holds one clean reference.

        For a file written to be loaded again the string is left as the
        configuration holds it: the loader reads a reference the scalar starts
        with (``resolve_env_references``), under a name the configuration may
        interpolate, and this reference stands inside other text under a name it
        does not admit, so nothing written would read back as the same string
        and nothing is marked."""
        monkeypatch.setenv("TAB", "AB")
        config = SimpleNamespace(
            _written_references=[_value_rewrite(("a",), "${TAB}", "AB", "AB", "${TAB}")]
        )
        assert record_of_config(config, {"a": "xABy"}) == {"a": "x${TAB}y"}
        marks: list = []

        def mark(text):
            marks.append(text)
            return text

        assert record_of_config(config, {"a": "xABy"}, mark=mark) == {"a": "xABy"}
        assert marks == []

    def test_a_reference_the_loader_reads_back_is_written_tagged(self, monkeypatch):
        """``AB`` under ``${ASH_TAB}`` at the start of the string: the value is
        found again inside the reference once written and occurs once as held,
        so the record holds one clean reference; the loader reads the reference
        back to the same string (an admitted name, at the scalar's start), so a
        file written to be loaded again gets it tagged, and marked."""
        monkeypatch.setenv("ASH_TAB", "AB")
        config = SimpleNamespace(
            _written_references=[
                _value_rewrite(("a",), "${ASH_TAB}", "AB", "AB", "${ASH_TAB}")
            ]
        )
        assert record_of_config(config, {"a": "ABy"}) == {"a": "${ASH_TAB}y"}
        marks: list = []

        def mark(text):
            marks.append(text)
            return text

        assert record_of_config(config, {"a": "ABy"}, mark=mark) == {
            "a": "!ENV ${ASH_TAB}y"
        }
        assert marks == ["!ENV ${ASH_TAB}y"]

    def test_a_key_rename_onto_an_existing_key_keeps_both_entries(self):
        """Both entries stay, and the key the environment gave does not: a
        record never holds the value, so the entry moves to the reference with
        a number after it instead of staying under the resolved key."""
        rewrite = EnvironmentRewrite("key", ("m",), "k", "${K}", "k", "${K}")
        config = SimpleNamespace(_written_references=[rewrite])
        recorded = record_of_config(config, {"m": {"k": 1, "${K}": 2}})
        assert recorded == {"m": {"${K}#2": 1, "${K}": 2}}
        assert "k" not in recorded["m"]
        # The number steps past a key the mapping already holds.
        crowded = record_of_config(config, {"m": {"k": 1, "${K}": 2, "${K}#2": 3}})
        assert crowded == {"m": {"${K}#3": 1, "${K}": 2, "${K}#2": 3}}

    def test_a_file_to_be_loaded_again_keeps_the_resolved_key_on_a_collision(self):
        """With ``mark`` the writer refuses to write a key it cannot rename, so
        the record leaves the resolved key for it to refuse; a renamed key would
        load back as another key."""
        rewrite = EnvironmentRewrite("key", ("m",), "k", "${K}", "k", "${K}")
        config = SimpleNamespace(_written_references=[rewrite])
        assert record_of_config(config, {"m": {"k": 1, "${K}": 2}}, mark=str) == {
            "m": {"k": 1, "${K}": 2}
        }

    def test_control_a_key_is_renamed(self):
        rewrite = EnvironmentRewrite("key", ("m",), "k", "${K}", "k", "${K}")
        config = SimpleNamespace(_written_references=[rewrite])
        assert record_of_config(config, {"m": {"k": 1, "o": 2}}) == {
            "m": {"${K}": 1, "o": 2}
        }


class TestAbsolutePathWarning:
    def test_a_doubled_slash_advises_the_relative_path(self, tmp_path):
        root = _tree(tmp_path)
        warning = absolute_path_warning(
            f"{root.as_posix()}//build", root, ignore_path=True
        )
        assert warning is not None and "Use 'build/'" in warning, warning
        assert "'/build" not in warning

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symbolic links")
    def test_a_pattern_through_a_linked_root_is_spelled_under_the_root(self, tmp_path):
        root = _tree(tmp_path)
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        warning = absolute_path_warning(
            f"{alias.as_posix()}/vendor/**", root.resolve(), ignore_path=True
        )
        assert warning is not None and "Use 'vendor/**'" in warning, warning


class TestDescribeValidationError:
    def test_a_short_key_read_from_the_environment_is_hidden_in_the_location(self):
        error = ValidationError.from_exception_data(
            "AshConfig",
            [{"type": "int_type", "loc": ("reporters", "ab", "x"), "input": "v"}],
        )
        text = describe_validation_error(error, ["ab"])
        assert f"reporters.{REDACTED}.x" in text, text
        assert "reporters.ab" not in text


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def _no_ash_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)


@pytest.mark.usefixtures("_no_ash_config")
class TestCheckConfigFile:
    def test_a_str_source_dir_is_accepted(self, tmp_path):
        root = _tree(tmp_path)
        config = _write(root / "ash.yaml", "project_name: demo\n")
        with_str = ConfigValidator.check_config_file(config, source_dir=str(root))
        with_path = ConfigValidator.check_config_file(config, source_dir=root)
        assert with_str.errors == with_path.errors == []
        assert with_str.warnings == with_path.warnings

    def test_a_project_name_an_override_supplies_is_not_missing(self, tmp_path):
        root = _tree(tmp_path)
        config = _write(root / "ash.yaml", "fail_on_findings: true\n")
        without = ConfigValidator.check_config_file(config, source_dir=root)
        assert ConfigValidator.MISSING_PROJECT_NAME_MESSAGE in without.warnings
        check = ConfigValidator.check_config_file(
            config, source_dir=root, config_overrides=["project_name=demo"]
        )
        assert check.errors == []
        assert ConfigValidator.MISSING_PROJECT_NAME_MESSAGE not in check.warnings

    def test_the_path_checks_read_the_lists_the_overrides_leave(self, tmp_path):
        root = _tree(tmp_path)
        config = _write(
            root / "ash.yaml",
            "project_name: demo\nglobal_settings:\n  ignore_paths:\n"
            "    - path: ./src\n      reason: probe\n",
        )
        without = ConfigValidator.check_config_file(config, source_dir=root)
        assert any(PREFIX in warning for warning in without.warnings), without.warnings
        check = ConfigValidator.check_config_file(
            config,
            source_dir=root,
            config_overrides=["global_settings.ignore_paths=[]"],
        )
        assert check.errors == []
        assert not any(PREFIX in warning for warning in check.warnings), check.warnings

    def test_validate_and_raise_numbers_the_errors_alone(self, tmp_path):
        root = _tree(tmp_path)
        config = _write(root / "ash.yaml", "global_settings: 7\n")
        check = ConfigValidator.check_config_file(config, source_dir=root)
        assert (
            check.errors
            and ConfigValidator.MISSING_PROJECT_NAME_MESSAGE in check.warnings
        )
        with pytest.raises(ConfigValidationError) as raised:
            ConfigValidator.validate_and_raise(config)
        text = str(raised.value)
        assert "  1. " in text and "  2. " not in text, text
        assert "project_name" not in text, text


class TestDuplicateTopLevelFields:
    def test_a_quoted_key_counts_and_warns_once(self):
        text = "'project_name': a\nproject_name: b\n\"project_name\": c\n"
        assert ConfigValidator._duplicate_top_level_fields(Path("ash.yaml"), text) == [
            "project_name"
        ]

    def test_a_byte_order_mark_does_not_hide_the_first_key(self):
        text = chr(0xFEFF) + "project_name: a\nproject_name: b\n"
        assert ConfigValidator._duplicate_top_level_fields(Path("ash.yaml"), text) == [
            "project_name"
        ]

    def test_a_json_files_repeated_key_is_found(self):
        text = '{\n  "project_name": "a",\n  "fail_on_findings": true,\n  "project_name": "b"\n}\n'
        assert ConfigValidator._duplicate_top_level_fields(Path("ash.json"), text) == [
            "project_name"
        ]

    def test_control_a_nested_json_key_is_not_a_top_level_duplicate(self):
        text = '{"project_name": "a", "global_settings": {"project_name": "b"}}'
        assert ConfigValidator._duplicate_top_level_fields(Path("ash.json"), text) == []


class TestInternalFieldsRefused:
    def test_a_folded_section_spelling_is_found(self):
        data = {"scanners": {"Bandit": {"enabled": True}}}
        assert (
            ConfigValidator.section_key_in_file(data, "scanners", "bandit") == "Bandit"
        )

    def test_the_refused_fields_are_read_from_the_models_own_text(self):
        field = min(INTERNAL_SECTION_FIELDS["scanners"])
        message = internal_field_message("scanners", "bandit", field)
        error = ValidationError.from_exception_data(
            "AshConfig",
            [
                {
                    "type": "value_error",
                    "loc": ("scanners", "bandit"),
                    # The refused input holds a word of the sentence, so the
                    # formatted message has the field's name redacted.
                    "input": {field: field},
                    "ctx": {"error": message},
                }
            ],
        )
        refusal = SimpleNamespace(validation_error=error, after_overrides=False)
        data: Dict[str, Any] = {"scanners": {"bandit": {field: "x"}}}
        found: List = ConfigValidator._internal_fields_refused(
            ConfigValidator._unredacted_refusal_messages(refusal), data
        )
        assert found == [("scanners", "bandit", field)]
