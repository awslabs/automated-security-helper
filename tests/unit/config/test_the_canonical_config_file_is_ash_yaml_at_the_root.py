# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The canonical config file is ``<root>/.ash.yaml``.

Discovery looks there first, every command that creates a config writes there,
and every other location ASH has accepted (``.ash/.ash.yaml``, ``.ash.yml``,
``ash.yaml``, the ``ashrc`` names and the rest of ``ASH_CONFIG_FILE_NAMES``)
keeps loading as a legacy location that warns once, naming the file and the
canonical path. When both a canonical file and a legacy one exist the canonical
one is read and the warning names the shadowed file. An explicit config path
reads its file and warns nothing. The legacy locations are removed in ASH 4.0.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import (
    discover_config_source,
    discovery_warnings,
)
from automated_security_helper.config.resolve_config import (
    find_config_file,
    resolve_config,
)
from automated_security_helper.core.constants import (
    ASH_CANONICAL_CONFIG_FILE_NAME,
    ASH_CONFIG_FILE_NAMES,
    ASH_DEFAULT_CONFIG_FILE_NAME,
    ASH_RC_FILE_NAMES,
)
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

# Every location discovery accepted before the canonical name, except the one
# that is now canonical: each dedicated name at the root and in .ash/, then the
# ashrc names at the root.
LEGACY_LOCATIONS = [
    location
    for name in ASH_CONFIG_FILE_NAMES
    for location in (name, f".ash/{name}")
    if location != ASH_CANONICAL_CONFIG_FILE_NAME
] + list(ASH_RC_FILE_NAMES)

# The legacy locations by the language their name says. The canonical file is
# read as YAML, so a TOML file cannot be moved there, and a JSON file can only
# once each tab and each value YAML reads another way is rewritten.
TOML_LEGACY = [location for location in LEGACY_LOCATIONS if location.endswith(".toml")]
JSON_LEGACY = [location for location in LEGACY_LOCATIONS if location.endswith(".json")]
YAML_LEGACY = [
    location
    for location in LEGACY_LOCATIONS
    if location not in TOML_LEGACY + JSON_LEGACY
]

# A file in .ash/ moves to the root above it, and a relative extends path is read
# from the directory of the file that names it, so it must change with the move.
ASH_DIR_YAML = [location for location in YAML_LEGACY if location.startswith(".ash/")]
ROOT_YAML = [location for location in YAML_LEGACY if location not in ASH_DIR_YAML]
ASH_DIR_JSON = [location for location in JSON_LEGACY if location.startswith(".ash/")]
ROOT_JSON = [location for location in JSON_LEGACY if location not in ASH_DIR_JSON]
# The 13 names the top level of a directory can hold, whatever that directory is
# called: a directory named `.ash` that ASH searches keeps its own files there.
ROOT_LEGACY = ROOT_YAML + ROOT_JSON + TOML_LEGACY

# The sentences the warning adds after its move advice, each for one kind of
# file, in the order it adds them.
EXTENDS_CAVEAT = (
    "A relative extends path is read from the file's own directory, so rewrite "
    "any in this file for the scan root before you move it."
)
TAB_CAVEAT = (
    "Replace each tab character in this file with spaces before you move it: "
    ".ash.yaml is read as YAML, which refuses a tab (the parse error gives the "
    "tab's line and column)."
)
JSON_CAVEAT = (
    "Before you move it, also write each DEL (U+007F), C1 control (U+0080 to "
    "U+009F), U+2028, U+2029, U+FFFE or U+FFFF in a string as its four-digit "
    "Unicode escape and each character above U+FFFF that is written as two "
    "escapes as the character itself, give each number that has an exponent a "
    "decimal point and a sign after the e, such as 1.0e+3 for 1e3, write Infinity "
    "as .inf, and keep each key on the same line as its colon: otherwise YAML "
    "reads another value or refuses the file."
)
ENV_CAVEAT = (
    "In the YAML, put !ENV and a space before the opening quote of each string "
    "value from this file whose text starts with ${, and keep its quotes if it "
    "has one quote mark on each side: a quoted value without the tag is read as "
    "literal text, not from the environment. Write a string that has three "
    "quote marks on each side as a one-line double-quoted string with the text "
    "TOML reads: leave out a line break that directly follows the opening marks "
    "and, from three double quote marks, an unescaped backslash that ends a line "
    "(only spaces or tabs after it on that line), with the spaces, tabs and line "
    "breaks after it; write each other line feed as \\n; from three single quote "
    'marks, also write each backslash as \\\\ and each double quote as \\"; from '
    "three double quote marks, keep each escape and write each unescaped double "
    'quote as \\". A string whose text holds a C1 control (U+0080 to U+009F), '
    "U+2028, U+2029, U+FFFE or U+FFFF, whatever its quote marks, becomes a "
    "double-quoted string, a literal string's backslashes and double quotes "
    "escaped, with each such character written as its four-digit Unicode escape: "
    "YAML reads U+0085, U+2028 and U+2029 inside quotes as line breaks and "
    "refuses a file that holds one of the others. Give each number that has an "
    "exponent a decimal point and a sign after the e, with no underscore after "
    "it, such as 1.0e+3 for 1e3, write each octal number, such as 0o17, in "
    "decimal, and write inf as .inf: YAML reads another spelling of each as text."
)

# The ashrc names include TOML and JSON files, so each location is written in
# the language its name says.
_YAML_SUFFIXES = (".yaml", ".yml")


def _write(root: Path, location: str, project_name: str) -> Path:
    path = root / location
    path.parent.mkdir(parents=True, exist_ok=True)
    if location.endswith(".json"):
        text = f'{{"project_name": "{project_name}"}}\n'
    elif location.endswith(".toml"):
        text = f'project_name = "{project_name}"\n'
    else:
        assert location.endswith(_YAML_SUFFIXES), location
        text = f"project_name: {project_name}\n"
    path.write_text(text, encoding="utf-8")
    return path


def _write_lines(path: Path, lines: list[str], ending: str = "\n") -> Path:
    """Write ``lines``, each followed by ``ending``, on every platform.

    ``write_text`` turns a line feed into the platform's own line ending unless it
    is given ``newline``, so a file meant to hold LF would hold CRLF on Windows.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline=ending)
    return path


def _toml_and_yaml_roots(
    tmp_path: Path,
    toml_lines: list[str],
    yaml_lines: list[str],
    ending: str = "\n",
) -> tuple[Path, Path]:
    """The same setting in a TOML file and in a YAML file, each in a root of its own,
    so that one read of each root compares what the two languages read."""
    toml_root = tmp_path / "toml"
    yaml_root = tmp_path / "yaml"
    _write_lines(toml_root / ".ashrc.toml", toml_lines, ending)
    _write_lines(yaml_root / ".ash.yaml", yaml_lines, ending)
    return toml_root, yaml_root


def _json_and_yaml_roots(
    tmp_path: Path, json_text: str, yaml_text: str
) -> tuple[Path, Path]:
    """The same setting in a JSON file and in a YAML file, each in a root of its own,
    so that one read of each root compares what JSON and YAML read. Both files are
    written with LF line endings on every platform."""
    json_root = tmp_path / "json"
    yaml_root = tmp_path / "yaml"
    for root, name, text in (
        (json_root, ".ash.json", json_text),
        (yaml_root, ".ash.yaml", yaml_text),
    ):
        root.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8", newline="\n")
    return json_root, yaml_root


def _json_object(project_name: str) -> str:
    """A JSON object that sets only `project_name`, as written, and a line feed."""
    return '{"project_name": "' + project_name + '"}\n'


@pytest.fixture
def ash_warnings():
    """The warnings ASH_LOGGER logs; it does not propagate, so caplog sees none."""
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield lambda: [r.getMessage() for r in records if r.levelno == logging.WARNING]
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def test_the_canonical_name_is_ash_yaml_and_it_is_what_commands_write():
    assert ASH_CANONICAL_CONFIG_FILE_NAME == ".ash.yaml"
    assert ASH_DEFAULT_CONFIG_FILE_NAME == ASH_CANONICAL_CONFIG_FILE_NAME


def test_every_legacy_location_is_listed():
    # .ash.yaml at the root is the only accepted location that is now canonical.
    assert ".ash/.ash.yaml" in LEGACY_LOCATIONS
    assert ".ash.yml" in LEGACY_LOCATIONS
    assert ".ashrc.yaml" in LEGACY_LOCATIONS
    assert ASH_CANONICAL_CONFIG_FILE_NAME not in LEGACY_LOCATIONS


def test_the_legacy_locations_by_language_are_there_to_test():
    """The parametrized tests below have cases, and every location is in one list."""
    assert TOML_LEGACY == [".ashrc.toml", "ashrc.toml"]
    assert sorted(JSON_LEGACY) == sorted(
        [
            ".ash.json",
            ".ash/.ash.json",
            "ash.json",
            ".ash/ash.json",
            ".ashrc.json",
            "ashrc.json",
        ]
    )
    assert all(location.endswith(_YAML_SUFFIXES) for location in YAML_LEGACY)
    assert sorted(TOML_LEGACY + JSON_LEGACY + YAML_LEGACY) == sorted(LEGACY_LOCATIONS)
    assert sorted(ASH_DIR_YAML) == [
        ".ash/.ash.yaml",
        ".ash/.ash.yml",
        ".ash/ash.yaml",
        ".ash/ash.yml",
    ]
    assert sorted(ASH_DIR_JSON) == [".ash/.ash.json", ".ash/ash.json"]
    assert sorted(ROOT_YAML + ASH_DIR_YAML) == sorted(YAML_LEGACY)
    assert sorted(ROOT_JSON + ASH_DIR_JSON) == sorted(JSON_LEGACY)
    assert len(ROOT_YAML) == 7 and len(ROOT_JSON) == 4
    assert len(ROOT_LEGACY) == 13
    assert sorted(ROOT_LEGACY + ASH_DIR_YAML + ASH_DIR_JSON) == sorted(LEGACY_LOCATIONS)


class TestCanonicalIsFirst:
    def test_the_canonical_file_is_found(self, tmp_path):
        canonical = _write(tmp_path, ".ash.yaml", "canonical")
        assert find_config_file(tmp_path) == canonical
        assert resolve_config(source_dir=tmp_path).project_name == "canonical"

    @pytest.mark.parametrize("legacy", LEGACY_LOCATIONS)
    def test_the_canonical_file_wins_over_every_legacy_location(self, tmp_path, legacy):
        canonical = _write(tmp_path, ".ash.yaml", "canonical")
        _write(tmp_path, legacy, "legacy")
        assert find_config_file(tmp_path) == canonical
        assert resolve_config(source_dir=tmp_path).project_name == "canonical"

    def test_the_canonical_file_wins_over_a_pyproject_table(self, tmp_path):
        canonical = _write(tmp_path, ".ash.yaml", "canonical")
        (tmp_path / "pyproject.toml").write_text(
            '[tool.ash]\nproject_name = "pyproject"\n', encoding="utf-8"
        )
        assert find_config_file(tmp_path) == canonical

    def test_the_other_legacy_names_keep_their_relative_order(self, tmp_path):
        # Without the canonical file, .ash.yml at the root still beats
        # .ash/.ash.yaml, as it did before the canonical name existed.
        _write(tmp_path, ".ash/.ash.yaml", "dot-ash")
        _write(tmp_path, ".ash.yml", "root-yml")
        assert find_config_file(tmp_path) == tmp_path / ".ash.yml"

    def test_discovery_reports_the_legacy_files_as_ignored(self, tmp_path):
        _write(tmp_path, ".ash.yaml", "canonical")
        _write(tmp_path, ".ash/.ash.yaml", "legacy")
        discovery = discover_config_source(tmp_path)
        assert discovery.selected.path == tmp_path / ".ash.yaml"
        assert [source.path for source in discovery.ignored] == [
            tmp_path / ".ash" / ".ash.yaml"
        ]


class TestWarnings:
    def test_the_canonical_file_alone_warns_nothing(self, tmp_path, ash_warnings):
        _write(tmp_path, ".ash.yaml", "canonical")
        resolve_config(source_dir=tmp_path)
        assert ash_warnings() == []

    @pytest.mark.parametrize("legacy", LEGACY_LOCATIONS)
    def test_a_legacy_location_alone_warns_once_and_names_the_canonical_path(
        self, tmp_path, ash_warnings, legacy
    ):
        found = _write(tmp_path, legacy, "legacy")
        config = resolve_config(source_dir=tmp_path)
        assert config.project_name == "legacy"
        warnings = ash_warnings()
        assert len(warnings) == 1, warnings
        assert "deprecated" in warnings[0]
        assert found.as_posix() in warnings[0]
        assert ".ash.yaml" in warnings[0]
        assert "4.0" in warnings[0]

    @pytest.mark.parametrize("legacy", LEGACY_LOCATIONS)
    def test_the_canonical_file_over_a_legacy_one_warns_once_naming_the_shadowed_file(
        self, tmp_path, ash_warnings, legacy
    ):
        _write(tmp_path, ".ash.yaml", "canonical")
        shadowed = _write(tmp_path, legacy, "legacy")
        resolve_config(source_dir=tmp_path)
        warnings = ash_warnings()
        assert len(warnings) == 1, warnings
        assert shadowed.as_posix() in warnings[0]
        assert "deprecated" in warnings[0]
        assert "never merged" in warnings[0]

    def test_the_warning_is_returned_by_discovery_for_the_scan_results(self, tmp_path):
        _write(tmp_path, ".ash/.ash.yaml", "legacy")
        warnings = discovery_warnings(discover_config_source(tmp_path))
        assert len(warnings) == 1
        assert "deprecated" in warnings[0]

    def test_a_pyproject_table_alone_is_not_a_deprecated_location(
        self, tmp_path, ash_warnings
    ):
        (tmp_path / "pyproject.toml").write_text(
            '[tool.ash]\nproject_name = "pyproject"\n', encoding="utf-8"
        )
        resolve_config(source_dir=tmp_path)
        assert ash_warnings() == []

    @pytest.mark.parametrize("legacy", [".ash/.ash.yaml", ".ash.yml", ".ashrc.yaml"])
    def test_an_explicit_config_path_warns_nothing(
        self, tmp_path, ash_warnings, legacy
    ):
        _write(tmp_path, ".ash.yaml", "canonical")
        explicit = _write(tmp_path, legacy, "explicit")
        config = resolve_config(config_path=explicit, source_dir=tmp_path)
        assert config.project_name == "explicit"
        assert ash_warnings() == []

    def test_the_legacy_warning_names_the_root_the_file_belongs_to(self, tmp_path):
        _write(tmp_path, ".ash/.ash.yaml", "legacy")
        [warning] = discovery_warnings(discover_config_source(tmp_path))
        # A file under .ash/ is moved to the root above .ash/, not into .ash/.
        assert (tmp_path / ".ash.yaml").as_posix() in warning

    @pytest.mark.parametrize("legacy", TOML_LEGACY)
    def test_a_toml_legacy_file_is_to_be_rewritten_as_yaml_not_moved(
        self, tmp_path, legacy
    ):
        _write(tmp_path, legacy, "legacy")
        [warning] = discovery_warnings(discover_config_source(tmp_path))
        canonical = (tmp_path / ".ash.yaml").as_posix()
        assert f"rewrite this file as YAML in {canonical}" in warning, warning
        assert "move this file to" not in warning, warning
        assert warning.endswith(
            f"renaming the TOML file is not enough. {ENV_CAVEAT}"
        ), warning
        assert EXTENDS_CAVEAT not in warning, warning
        assert TAB_CAVEAT not in warning, warning

    @pytest.mark.parametrize("legacy", ROOT_YAML)
    def test_a_yaml_legacy_file_at_the_root_keeps_the_advice_to_move_it(
        self, tmp_path, legacy
    ):
        _write(tmp_path, legacy, "legacy")
        [warning] = discovery_warnings(discover_config_source(tmp_path))
        canonical = (tmp_path / ".ash.yaml").as_posix()
        assert warning.endswith(f"move this file to {canonical}."), warning

    @pytest.mark.parametrize("legacy", ASH_DIR_YAML)
    def test_a_yaml_legacy_file_in_ash_says_to_rewrite_a_relative_extends(
        self, tmp_path, legacy
    ):
        _write(tmp_path, legacy, "legacy")
        [warning] = discovery_warnings(discover_config_source(tmp_path))
        canonical = (tmp_path / ".ash.yaml").as_posix()
        assert warning.endswith(f"move this file to {canonical}. {EXTENDS_CAVEAT}"), (
            warning
        )

    @pytest.mark.parametrize("legacy", ROOT_JSON)
    def test_a_json_legacy_file_at_the_root_is_moved_after_its_tabs_are_replaced(
        self, tmp_path, legacy
    ):
        _write(tmp_path, legacy, "legacy")
        [warning] = discovery_warnings(discover_config_source(tmp_path))
        canonical = (tmp_path / ".ash.yaml").as_posix()
        assert warning.endswith(
            f"move this file to {canonical}. {TAB_CAVEAT} {JSON_CAVEAT}"
        ), warning
        assert EXTENDS_CAVEAT not in warning, warning

    @pytest.mark.parametrize("legacy", ASH_DIR_JSON)
    def test_a_json_legacy_file_in_ash_gets_both_caveats(self, tmp_path, legacy):
        _write(tmp_path, legacy, "legacy")
        [warning] = discovery_warnings(discover_config_source(tmp_path))
        canonical = (tmp_path / ".ash.yaml").as_posix()
        assert warning.endswith(
            f"move this file to {canonical}. "
            f"{EXTENDS_CAVEAT} {TAB_CAVEAT} {JSON_CAVEAT}"
        ), warning

    @pytest.mark.parametrize("legacy", ROOT_LEGACY)
    def test_a_file_at_the_top_of_a_scan_root_named_ash_stays_in_that_directory(
        self, tmp_path, legacy
    ):
        """A directory that is itself named `.ash` holds the config at its top
        level; moving it to `.ash.yaml` does not change directory."""
        scan_root = tmp_path / ".ash"
        _write(scan_root, legacy, "legacy")
        [warning] = discovery_warnings(discover_config_source(scan_root))
        assert (scan_root / ".ash.yaml").as_posix() in warning, warning
        assert (tmp_path / ".ash.yaml").as_posix() not in warning, warning
        assert EXTENDS_CAVEAT not in warning, warning

    def test_a_file_in_the_ash_subdirectory_of_a_scan_root_named_ash_moves_up_into_it(
        self, tmp_path
    ):
        scan_root = tmp_path / ".ash"
        _write(scan_root, ".ash/.ash.yml", "legacy")
        [warning] = discovery_warnings(discover_config_source(scan_root))
        canonical = (scan_root / ".ash.yaml").as_posix()
        assert warning.endswith(f"move this file to {canonical}. {EXTENDS_CAVEAT}"), (
            warning
        )


#: JSON with one tab, each in a different place. `json.loads` accepts a tab
#: between tokens, so each loads as `.ash.json`; the YAML loader skips only
#: spaces between tokens, so each is refused as `.ash.yaml`.
TABBED_JSON = {
    "leading": '{\n\t"project_name": "x"\n}\n',
    "after_colon": '{\n  "project_name":\t"x"\n}\n',
    "after_comma": '{\n  "project_name": "x",\t"fail_on_findings": false\n}\n',
    "after_brace": '{\t\n  "project_name": "x"\n}\n',
    "before_newline": '{\n  "project_name": "x"\t\n}\n',
}


class TestAMovedJsonFileIsRefusedWhenItHoldsATab:
    """Why the JSON advice says to replace each tab character, wherever it is:
    `.ash.yaml` is parsed as YAML, which skips only spaces between tokens."""

    @pytest.mark.parametrize("text", TABBED_JSON.values(), ids=TABBED_JSON.keys())
    def test_json_with_a_tab_loads_as_json(self, tmp_path, text):
        (tmp_path / ".ash.json").write_text(text, encoding="utf-8")
        assert resolve_config(source_dir=tmp_path).project_name == "x"

    @pytest.mark.parametrize("text", TABBED_JSON.values(), ids=TABBED_JSON.keys())
    def test_the_same_text_in_the_canonical_file_is_refused(self, tmp_path, text):
        (tmp_path / ".ash.yaml").write_text(text, encoding="utf-8")
        with pytest.raises(ASHConfigValidationError):
            resolve_config(source_dir=tmp_path)

    @pytest.mark.parametrize("text", TABBED_JSON.values(), ids=TABBED_JSON.keys())
    def test_the_same_text_with_each_tab_replaced_by_a_space_is_read(
        self, tmp_path, text
    ):
        (tmp_path / ".ash.yaml").write_text(text.replace("\t", " "), encoding="utf-8")
        assert resolve_config(source_dir=tmp_path).project_name == "x"

    def test_the_refusal_gives_the_line_and_column_of_the_tab(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text(
            TABBED_JSON["after_colon"], encoding="utf-8"
        )
        with pytest.raises(ASHConfigValidationError, match=r"line 2, column 18"):
            resolve_config(source_dir=tmp_path)

    def test_a_tab_inside_a_json_string_is_refused_as_json(self, tmp_path):
        """So in a JSON file that loads, every tab is between tokens."""
        (tmp_path / ".ash.json").write_text(
            '{"project_name": "a\tb"}\n', encoding="utf-8"
        )
        with pytest.raises(ASHConfigValidationError):
            resolve_config(source_dir=tmp_path)


#: Characters a JSON string holds as written and YAML refuses, each as its code point:
#: DEL, a C1 control other than U+0085, and the noncharacters U+FFFE and U+FFFF.
JSON_REFUSED_CHARACTERS = {
    "delete": 0x7F,
    "c1_control": 0x92,
    "noncharacter_fffe": 0xFFFE,
    "noncharacter_ffff": 0xFFFF,
}
#: Characters a JSON string holds as written and YAML reads as a line break inside
#: quotes, each as the text before the character, its code point, the text after it
#: and what YAML reads in place of the three: U+0085 becomes a space, and U+2028 and
#: U+2029 are kept while the space beside them is dropped.
JSON_LINE_BREAKS = {
    "next_line": ("", 0x85, "", " "),
    "line_separator_after_space": (" ", 0x2028, "", chr(0x2028)),
    "paragraph_separator_before_space": ("", 0x2029, " ", chr(0x2029)),
}


class TestAMovedJsonStringOrKeyIsReadAnotherWay:
    """Why the JSON advice says to write some characters in a string as escapes, a
    character above U+FFFF as itself, and each key on the line of its colon: JSON
    reads each of them, while YAML refuses a file that holds DEL, a C1 control other
    than U+0085, U+FFFE or U+FFFF, reads U+0085, U+2028 and U+2029 inside quotes as
    line breaks, reads the two escapes of a surrogate pair as two characters, and
    refuses a key whose colon is on another line."""

    @pytest.mark.parametrize("character", list(JSON_REFUSED_CHARACTERS))
    def test_a_json_string_with_a_character_yaml_refuses_is_refused_as_yaml(
        self, tmp_path, character
    ):
        """JSON holds each of them in a string as written. The YAML loader refuses a
        file that holds one, and the refusal is the kind a scan reports with exit 3."""
        value = f"x{chr(JSON_REFUSED_CHARACTERS[character])}y"
        text = _json_object(value)
        json_root, yaml_root = _json_and_yaml_roots(tmp_path, text, text)
        assert resolve_config(source_dir=json_root).project_name == value
        with pytest.raises(
            ASHConfigSourceError, match=r"could not be parsed \(ReaderError"
        ):
            resolve_config(source_dir=yaml_root)

    @pytest.mark.parametrize("character", list(JSON_LINE_BREAKS))
    def test_a_json_string_with_a_character_yaml_reads_as_a_line_break_is_read_another_way(
        self, tmp_path, ash_warnings, character
    ):
        """JSON holds the text as written. Inside quotes YAML takes U+0085, U+2028 and
        U+2029 for line breaks: U+0085 becomes a space, and U+2028 and U+2029 are
        kept while the space beside them is dropped, with nothing said."""
        before, code_point, after, yaml_piece = JSON_LINE_BREAKS[character]
        value = f"x{before}{chr(code_point)}{after}y"
        text = _json_object(value)
        json_root, yaml_root = _json_and_yaml_roots(tmp_path, text, text)
        # The YAML read comes first: reading `.ash.json` logs its deprecation
        # warning into the same list.
        assert resolve_config(source_dir=yaml_root).project_name == f"x{yaml_piece}y"
        assert ash_warnings() == []
        assert resolve_config(source_dir=json_root).project_name == value

    def test_a_json_surrogate_pair_is_not_read_as_one_character_by_yaml(self, tmp_path):
        """JSON joins the two escapes of a surrogate pair into one character. YAML
        reads each escape alone, so the file either is refused or is read as two lone
        surrogates, which is not the character JSON reads."""
        pair = f"{BACKSLASH}u{0xD83D:04X}{BACKSLASH}u{0xDE00:04X}"
        text = _json_object(f"x{pair}y")
        json_root, yaml_root = _json_and_yaml_roots(tmp_path, text, text)
        character = f"x{chr(0x1F600)}y"
        assert resolve_config(source_dir=json_root).project_name == character

        def read_as_yaml():
            """The value YAML reads, or the class of the refusal."""
            try:
                return resolve_config(source_dir=yaml_root).project_name
            except ASHConfigValidationError as refusal:
                return type(refusal)

        assert read_as_yaml() != character

    @pytest.mark.parametrize("character", [*JSON_REFUSED_CHARACTERS, *JSON_LINE_BREAKS])
    def test_each_written_as_its_escape_reads_what_json_reads(
        self, tmp_path, character
    ):
        """YAML takes the escape for the character, with the spaces beside it kept,
        so it reads the string as JSON reads the character written as itself."""
        if character in JSON_REFUSED_CHARACTERS:
            before, code_point, after = "", JSON_REFUSED_CHARACTERS[character], ""
        else:
            before, code_point, after, _ = JSON_LINE_BREAKS[character]
        escape = f"{BACKSLASH}u{code_point:04X}"
        expected = f"x{before}{chr(code_point)}{after}y"
        json_root, yaml_root = _json_and_yaml_roots(
            tmp_path,
            _json_object(expected),
            _json_object(f"x{before}{escape}{after}y"),
        )
        assert resolve_config(source_dir=json_root).project_name == expected
        assert resolve_config(source_dir=yaml_root).project_name == expected

    def test_a_character_above_u_ffff_written_as_itself_reads_what_its_surrogate_pair_reads(
        self, tmp_path
    ):
        """JSON reads the two escapes as one character. Written as itself, the
        character is read by YAML as the same one."""
        pair = f"{BACKSLASH}u{0xD83D:04X}{BACKSLASH}u{0xDE00:04X}"
        expected = f"x{chr(0x1F600)}y"
        json_root, yaml_root = _json_and_yaml_roots(
            tmp_path, _json_object(f"x{pair}y"), _json_object(expected)
        )
        assert resolve_config(source_dir=json_root).project_name == expected
        assert resolve_config(source_dir=yaml_root).project_name == expected

    def test_a_key_whose_colon_is_on_the_next_line_is_refused_as_yaml(self, tmp_path):
        """JSON skips a line break between a key and its colon. YAML reads a key as
        one only when its colon is on the same line, so it reads the key with an
        empty value and refuses the colon after it, and the refusal is the kind a
        scan reports with exit 3."""
        text = '{"project_name"\n: "x"}\n'
        json_root, yaml_root = _json_and_yaml_roots(tmp_path, text, text)
        assert resolve_config(source_dir=json_root).project_name == "x"
        with pytest.raises(
            ASHConfigSourceError, match=r"could not be parsed \(ParserError"
        ):
            resolve_config(source_dir=yaml_root)

    def test_a_key_on_the_line_of_its_colon_reads_what_json_reads(self, tmp_path):
        """The same object with its key on the line of its colon is read by both."""
        json_root, yaml_root = _json_and_yaml_roots(
            tmp_path, '{"project_name"\n: "x"}\n', '{"project_name": "x"}\n'
        )
        assert resolve_config(source_dir=json_root).project_name == "x"
        assert resolve_config(source_dir=yaml_root).project_name == "x"


class TestAMovedFileKeepsItsRelativeBasesOnlyIfTheyAreRewritten:
    """Why a file in `.ash/` needs its relative `extends` path rewritten: a base
    is read from the directory of the file that names it, and the move changes it."""

    @staticmethod
    def _ash_directory_with_a_base(tmp_path: Path) -> None:
        (tmp_path / ".ash").mkdir()
        (tmp_path / ".ash" / "base.yaml").write_text(
            "project_name: from-base\n", encoding="utf-8"
        )

    def test_a_relative_extends_in_ash_names_a_file_beside_it(self, tmp_path):
        self._ash_directory_with_a_base(tmp_path)
        (tmp_path / ".ash" / ".ash.yaml").write_text(
            "extends: base.yaml\n", encoding="utf-8"
        )
        assert resolve_config(source_dir=tmp_path).project_name == "from-base"

    def test_the_same_file_moved_to_the_root_names_a_file_that_is_not_there(
        self, tmp_path
    ):
        self._ash_directory_with_a_base(tmp_path)
        (tmp_path / ".ash.yaml").write_text("extends: base.yaml\n", encoding="utf-8")
        with pytest.raises(ASHConfigSourceError, match="does not exist"):
            resolve_config(source_dir=tmp_path)

    def test_the_moved_file_is_read_when_the_path_is_rewritten_for_the_root(
        self, tmp_path
    ):
        self._ash_directory_with_a_base(tmp_path)
        (tmp_path / ".ash.yaml").write_text(
            "extends: .ash/base.yaml\n", encoding="utf-8"
        )
        assert resolve_config(source_dir=tmp_path).project_name == "from-base"


#: TOML strings that start with a `${...}` reference, each as TOML writes it with
#: its quotes, and the default the reference carries (what it reads when the
#: variable is not set). The defaults hold a space and a hash, a colon and a
#: space, a single quote, and a backslash, in a TOML literal string (none of its
#: characters is an escape) and in a TOML basic string (the backslash is escaped).
ENV_SPELLINGS = {
    "hash": ('"${ASH_SERVICE_NAME:payments #api}"', "payments #api"),
    "colon": ('"${ASH_SERVICE_NAME:a: b}"', "a: b"),
    "single_quote": ('"${ASH_SERVICE_NAME:it\'s}"', "it's"),
    "literal_backslash": ("'${ASH_SERVICE_NAME:a\\b}'", "a\\b"),
    "escaped_backslash": ('"${ASH_SERVICE_NAME:a\\\\b}"', "a\\b"),
}
ENV_PAIRS = [
    pytest.param(value, state, id=f"{value}-{state}")
    for value in ENV_SPELLINGS
    for state in ("set", "unset")
]

#: TOML strings with three quote marks on each side, as the advice rewrites them. A
#: case holds the lines of the TOML string (the first opens it and the last closes
#: it), the one-line double-quoted YAML copy the advice gives for it, the default of
#: the reference the string starts with, and the text after the reference once TOML
#: has read the string. The first case is a literal string, where each character is
#: itself; the others are basic strings: one with an escape and unescaped double
#: quotes, one with a backslash that ends a line before an indented line, and one with
#: an escaped backslash at the end of a line, whose line break is kept.
THREE_QUOTE_SPELLINGS = {
    "literal_backslash_quote": (
        ["'''", '${ASH_SERVICE_NAME:pay"ments} a\\tb "c"', "d'''"],
        '"${ASH_SERVICE_NAME:pay\\"ments} a\\\\tb \\"c\\"\\nd"',
        'pay"ments',
        ' a\\tb "c"\nd',
    ),
    "basic_escape_quote": (
        ['"""', '${ASH_SERVICE_NAME:pay\\"ments} a\\tb "c"', 'd"""'],
        '"${ASH_SERVICE_NAME:pay\\"ments} a\\tb \\"c\\"\\nd"',
        'pay"ments',
        ' a\tb "c"\nd',
    ),
    "basic_line_ending_backslash": (
        ['"""', "${ASH_SERVICE_NAME:payments-api} first \\ \t", "", '    second"""'],
        '"${ASH_SERVICE_NAME:payments-api} first second"',
        "payments-api",
        " first second",
    ),
    "basic_escaped_backslash_line_end": (
        ['"""', "${ASH_SERVICE_NAME:payments-api} first\\\\", '  tail"""'],
        '"${ASH_SERVICE_NAME:payments-api} first\\\\\\n  tail"',
        "payments-api",
        " first\\\n  tail",
    ),
}
THREE_QUOTE_PAIRS = [
    pytest.param(case, ending, state, id=f"{case}-{name}-{state}")
    for case in THREE_QUOTE_SPELLINGS
    for name, ending in (("lf", "\n"), ("crlf", "\r\n"))
    for state in ("set", "unset")
]

#: Copies that skip one rule of the advice, each as the case it copies and the lines of
#: the YAML value (the first line follows `!ENV `): the line break after the opening
#: marks kept; a line break written as a real one; a literal string's backslash
#: written once; the escape of a basic string with its backslash written twice; the
#: backslash that ends a line kept, with the whitespace after it; and an escaped
#: backslash at the end of a line dropped as if it ended the line.
THREE_QUOTE_SKIPS = {
    "first_line_break_kept": (
        "literal_backslash_quote",
        ['"\\n${ASH_SERVICE_NAME:pay\\"ments} a\\\\tb \\"c\\"\\nd"'],
    ),
    "line_break_written_raw": (
        "literal_backslash_quote",
        ['"${ASH_SERVICE_NAME:pay\\"ments} a\\\\tb \\"c\\"', 'd"'],
    ),
    "literal_backslash_single": (
        "literal_backslash_quote",
        ['"${ASH_SERVICE_NAME:pay\\"ments} a\\tb \\"c\\"\\nd"'],
    ),
    "escape_backslash_doubled": (
        "basic_escape_quote",
        ['"${ASH_SERVICE_NAME:pay\\"ments} a\\\\tb \\"c\\"\\nd"'],
    ),
    "line_ending_backslash_kept": (
        "basic_line_ending_backslash",
        ['"${ASH_SERVICE_NAME:payments-api} first \\ \t\\n\\n    second"'],
    ),
    "escaped_backslash_dropped": (
        "basic_escaped_backslash_line_end",
        ['"${ASH_SERVICE_NAME:payments-api} first\\tail"'],
    ),
}


class TestATomlReferenceToTheEnvironmentInYaml:
    """Why the TOML advice says to put `!ENV` before the opening quote of a `${...}`
    value, to keep its quotes when it has one quote mark on each side, and to rewrite
    it as a one-line double-quoted string when it has three: TOML resolves every
    string value that starts with a reference; YAML resolves a quoted value only when
    it is tagged `!ENV`; without quotes it cuts the value short at a space and a hash,
    and refuses one that holds a colon and a space or sits inside brackets or braces;
    and with three quote marks kept, it reads another value from three single ones
    or refuses the file, and refuses three double ones. Rewritten as the advice says,
    the string reads as TOML reads it; with one of the rules skipped, it does not."""

    REFERENCE = "${ASH_SERVICE_NAME:payments-api}"

    @pytest.fixture(autouse=True)
    def _variable(self, monkeypatch):
        monkeypatch.setenv("ASH_SERVICE_NAME", "from-env")

    def test_a_toml_string_that_starts_with_a_reference_is_read_from_the_environment(
        self, tmp_path
    ):
        (tmp_path / ".ashrc.toml").write_text(
            f'project_name = "{self.REFERENCE}"\n', encoding="utf-8"
        )
        assert resolve_config(source_dir=tmp_path).project_name == "from-env"

    @pytest.mark.parametrize(
        "line",
        [f"project_name: {REFERENCE}", f"project_name: !ENV '{REFERENCE}'"],
        ids=["unquoted", "tagged"],
    )
    def test_the_yaml_rewrite_is_read_from_the_environment(self, tmp_path, line):
        (tmp_path / ".ash.yaml").write_text(f"{line}\n", encoding="utf-8")
        assert resolve_config(source_dir=tmp_path).project_name == "from-env"

    def test_the_yaml_rewrite_that_keeps_the_quotes_reads_the_literal_text(
        self, tmp_path
    ):
        (tmp_path / ".ash.yaml").write_text(
            f'project_name: "{self.REFERENCE}"\n', encoding="utf-8"
        )
        assert resolve_config(source_dir=tmp_path).project_name == self.REFERENCE

    def test_the_rewrite_that_keeps_three_single_quotes_reads_literal_text_with_quotes(
        self, tmp_path, ash_warnings
    ):
        """TOML reads the text between three single quote marks as the reference.
        YAML reads the same marks as a single-quoted value with a quote mark at each
        end, which is no reference, so the tag changes nothing and nothing is said."""
        triple = f"'''{self.REFERENCE}'''"
        toml_root = tmp_path / "toml"
        yaml_root = tmp_path / "yaml"
        toml_root.mkdir()
        yaml_root.mkdir()
        (toml_root / ".ashrc.toml").write_text(
            f"project_name = {triple}\n", encoding="utf-8"
        )
        (yaml_root / ".ash.yaml").write_text(
            f"project_name: !ENV {triple}\n", encoding="utf-8"
        )
        literal = f"'{self.REFERENCE}'"
        # The YAML read comes first: reading `.ashrc.toml` logs its deprecation
        # warning into the same list.
        assert resolve_config(source_dir=yaml_root).project_name == literal
        assert ash_warnings() == []
        assert resolve_config(source_dir=toml_root).project_name == "from-env"

    def test_the_rewrite_that_keeps_three_double_quotes_does_not_parse(self, tmp_path):
        """TOML reads the text between three double quote marks as the reference.
        YAML reads the first two marks as an empty value and the third as the start of
        a second value, which the mapping refuses: the file does not parse, and the
        refusal is the kind a scan reports with exit 3."""
        triple = f'"""{self.REFERENCE}"""'
        toml_root = tmp_path / "toml"
        yaml_root = tmp_path / "yaml"
        toml_root.mkdir()
        yaml_root.mkdir()
        (toml_root / ".ashrc.toml").write_text(
            f"project_name = {triple}\n", encoding="utf-8"
        )
        (yaml_root / ".ash.yaml").write_text(
            f"project_name: !ENV {triple}\n", encoding="utf-8"
        )
        assert resolve_config(source_dir=toml_root).project_name == "from-env"
        with pytest.raises(
            ASHConfigSourceError, match=r"could not be parsed \(ParserError"
        ):
            resolve_config(source_dir=yaml_root)

    def test_the_rewrite_that_keeps_three_single_quotes_over_several_lines_reads_literal_text(
        self, tmp_path, ash_warnings
    ):
        """Over several lines YAML reads each line break inside the single-quoted
        value as a space, so the value is a quote mark, a space, the reference, a
        space and a quote mark: still no reference, and still nothing said."""
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            ["project_name = '''", self.REFERENCE, "'''"],
            ["project_name: !ENV '''", self.REFERENCE, "'''"],
        )
        literal = f"' {self.REFERENCE} '"
        # The YAML read comes first: reading `.ashrc.toml` logs its deprecation
        # warning into the same list.
        assert resolve_config(source_dir=yaml_root).project_name == literal
        assert ash_warnings() == []
        assert resolve_config(source_dir=toml_root).project_name == "from-env"

    def test_the_rewrite_that_keeps_three_double_quotes_over_several_lines_does_not_parse(
        self, tmp_path
    ):
        """Over several lines the three double quote marks are refused as they are on
        one line: the first two are an empty value, the third starts a second value
        that the mapping refuses, and the refusal is the kind a scan reports with
        exit 3."""
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            ['project_name = """', self.REFERENCE, '"""'],
            ['project_name: !ENV """', self.REFERENCE, '"""'],
        )
        assert resolve_config(source_dir=toml_root).project_name == "from-env"
        with pytest.raises(
            ASHConfigSourceError, match=r"could not be parsed \(ParserError"
        ):
            resolve_config(source_dir=yaml_root)

    def test_three_single_quotes_kept_around_a_lone_single_quote_are_refused(
        self, tmp_path
    ):
        """TOML ends a string in three single quote marks only at three single quote
        marks, so a lone one belongs to the text. YAML ends the single-quoted value at
        the lone one, and the text after it is a second value that the mapping
        refuses, which a scan reports with exit 3."""
        triple = "'''${ASH_SERVICE_NAME:it's}'''"
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path, [f"project_name = {triple}"], [f"project_name: !ENV {triple}"]
        )
        assert resolve_config(source_dir=toml_root).project_name == "from-env"
        with pytest.raises(
            ASHConfigSourceError, match=r"could not be parsed \(ParserError"
        ):
            resolve_config(source_dir=yaml_root)

    def test_three_single_quotes_kept_around_a_lone_single_quote_and_a_hash_cut_it_short(
        self, tmp_path, ash_warnings
    ):
        """When a space and a hash follow the lone single quote mark, YAML reads the
        hash as the start of a comment: the value ends at the mark, with no refusal
        and no warning, as a quote mark and the text before the mark."""
        triple = "'''${ASH_SERVICE_NAME:it' #x}'''"
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path, [f"project_name = {triple}"], [f"project_name: !ENV {triple}"]
        )
        cut_short = "'${ASH_SERVICE_NAME:it"
        # The YAML read comes first: reading `.ashrc.toml` logs its deprecation
        # warning into the same list.
        assert resolve_config(source_dir=yaml_root).project_name == cut_short
        assert ash_warnings() == []
        assert resolve_config(source_dir=toml_root).project_name == "from-env"

    def test_three_single_quotes_kept_around_a_text_that_ends_with_a_single_quote_are_refused(
        self, tmp_path
    ):
        """TOML ends a string in three single quote marks at the first three and
        takes the marks after them as text, so a text that ends with a single quote
        mark has four at its end. YAML reads each pair of single quote marks inside
        single quotes as one text mark, so the last four are two text marks, the
        value runs on past the line and the file is refused at its end, which a
        scan reports with exit 3."""
        value = "'''${ASH_SERVICE_NAME:it}''''"
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path, [f"project_name = {value}"], [f"project_name: !ENV {value}"]
        )
        assert resolve_config(source_dir=toml_root).project_name == "from-env'"
        with pytest.raises(
            ASHConfigSourceError, match=r"could not be parsed \(ScannerError"
        ):
            resolve_config(source_dir=yaml_root)

    def test_three_single_quotes_kept_around_a_text_that_ends_with_a_single_quote_run_on_into_the_next_lines(
        self, tmp_path, ash_warnings
    ):
        """When a later line ends with a single quote mark, YAML closes the value
        there and folds the lines between into it, each line break as a space: with
        no refusal and no warning, a setting on a line after the string is never
        set."""
        value = "'''${ASH_SERVICE_NAME:it}''''"
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            [f"project_name = {value}", "fail_on_findings = false", "# note'"],
            [f"project_name: !ENV {value}", "fail_on_findings: false", "# note'"],
        )
        # The YAML read comes first: reading `.ashrc.toml` logs its deprecation
        # warning into the same list.
        yaml_config = resolve_config(source_dir=yaml_root)
        assert yaml_config.project_name == (
            "'${ASH_SERVICE_NAME:it}'' fail_on_findings: false # note"
        )
        assert yaml_config.fail_on_findings is True
        assert ash_warnings() == []
        toml_config = resolve_config(source_dir=toml_root)
        assert toml_config.project_name == "from-env'"
        assert toml_config.fail_on_findings is False

    @pytest.mark.parametrize(("case", "ending", "state"), THREE_QUOTE_PAIRS)
    def test_a_three_quote_string_rewritten_as_advised_reads_what_toml_reads(
        self, tmp_path, monkeypatch, case, ending, state
    ):
        """The one-line double-quoted copy the advice gives reads what TOML reads, with
        the variable set and unset and with either line ending."""
        lines, copy, default, rest = THREE_QUOTE_SPELLINGS[case]
        if state == "unset":
            monkeypatch.delenv("ASH_SERVICE_NAME")
        expected = ("from-env" if state == "set" else default) + rest
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            [f"project_name = {lines[0]}", *lines[1:]],
            [f"project_name: !ENV {copy}"],
            ending,
        )
        assert resolve_config(source_dir=toml_root).project_name == expected
        assert resolve_config(source_dir=yaml_root).project_name == expected

    @pytest.mark.parametrize("skip", list(THREE_QUOTE_SKIPS))
    def test_a_three_quote_rewrite_that_skips_a_rule_reads_something_else(
        self, tmp_path, ash_warnings, skip
    ):
        """Each copy is read without a refusal and with no warning, and what it reads
        is not what TOML reads, so the advice has to give every one of these rules."""
        case, copy_lines = THREE_QUOTE_SKIPS[skip]
        lines, _, _, rest = THREE_QUOTE_SPELLINGS[case]
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            [f"project_name = {lines[0]}", *lines[1:]],
            [f"project_name: !ENV {copy_lines[0]}", *copy_lines[1:]],
        )
        # The YAML read comes first: reading `.ashrc.toml` logs its deprecation
        # warning into the same list.
        yaml_read = resolve_config(source_dir=yaml_root).project_name
        assert ash_warnings() == []
        toml_read = resolve_config(source_dir=toml_root).project_name
        assert toml_read == "from-env" + rest
        assert yaml_read != toml_read

    @pytest.mark.parametrize(("value", "state"), ENV_PAIRS)
    def test_the_rewrite_with_env_in_front_and_its_toml_quotes_reads_what_toml_reads(
        self, tmp_path, monkeypatch, value, state
    ):
        quoted, default = ENV_SPELLINGS[value]
        if state == "unset":
            monkeypatch.delenv("ASH_SERVICE_NAME")
        expected = "from-env" if state == "set" else default
        toml_root = tmp_path / "toml"
        yaml_root = tmp_path / "yaml"
        toml_root.mkdir()
        yaml_root.mkdir()
        (toml_root / ".ashrc.toml").write_text(
            f"project_name = {quoted}\n", encoding="utf-8"
        )
        (yaml_root / ".ash.yaml").write_text(
            f"project_name: !ENV {quoted}\n", encoding="utf-8"
        )
        assert resolve_config(source_dir=toml_root).project_name == expected
        assert resolve_config(source_dir=yaml_root).project_name == expected

    @pytest.mark.parametrize("tag", ["", "!ENV "], ids=["untagged", "tagged"])
    def test_the_rewrite_without_quotes_is_cut_short_at_a_space_and_hash(
        self, tmp_path, ash_warnings, tag
    ):
        """A hash after a space starts a YAML comment, so the value ends there:
        without a closing brace it is no reference, tagged or not, and is read as
        the text it is, with no warning."""
        (tmp_path / ".ash.yaml").write_text(
            "project_name: " + tag + "${ASH_SERVICE_NAME:payments #api}\n",
            encoding="utf-8",
        )
        config = resolve_config(source_dir=tmp_path)
        assert config.project_name == "${ASH_SERVICE_NAME:payments"
        assert ash_warnings() == []

    @pytest.mark.parametrize(
        "text",
        [
            "project_name: ${ASH_SERVICE_NAME:a: b}\n",
            "external_reports_to_include: [${ASH_SERVICE_NAME:payments-api}]\n",
            "{project_name: ${ASH_SERVICE_NAME:payments-api}}\n",
        ],
        ids=["colon_space", "flow_list", "flow_mapping"],
    )
    def test_the_rewrite_without_quotes_is_refused(self, tmp_path, text):
        (tmp_path / ".ash.yaml").write_text(text, encoding="utf-8")
        with pytest.raises(ASHConfigValidationError):
            resolve_config(source_dir=tmp_path)

    @pytest.mark.parametrize(
        ("text", "field", "expected"),
        [
            pytest.param(
                'external_reports_to_include: [!ENV "${ASH_SERVICE_NAME:payments-api}"]\n',
                "external_reports_to_include",
                ["from-env"],
                id="flow_list",
            ),
            pytest.param(
                '{project_name: !ENV "${ASH_SERVICE_NAME:payments-api}"}\n',
                "project_name",
                "from-env",
                id="flow_mapping",
            ),
        ],
    )
    def test_the_rewrite_with_env_in_front_and_its_quotes_is_read_in_flow_style(
        self, tmp_path, text, field, expected
    ):
        (tmp_path / ".ash.yaml").write_text(text, encoding="utf-8")
        value = getattr(resolve_config(source_dir=tmp_path), field)
        if isinstance(value, list):
            value = [str(entry) for entry in value]
        else:
            value = str(value)
        assert value == expected


class TestAThreeQuoteStringWithoutAReference:
    """Why the three-quote rules are given for every string, not only for a reference:
    kept in its marks, YAML reads another value, and rewritten as the advice says, it
    reads what TOML reads."""

    def test_three_single_quotes_kept_around_a_plain_text_read_it_with_a_quote_mark_at_each_end(
        self, tmp_path, ash_warnings
    ):
        """TOML reads the text between three single quote marks as the text. YAML
        reads the same marks as a single-quoted value with a quote mark at each end,
        and says nothing."""
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path, ["project_name = '''abc'''"], ["project_name: '''abc'''"]
        )
        # The YAML read comes first: reading `.ashrc.toml` logs its deprecation
        # warning into the same list.
        assert resolve_config(source_dir=yaml_root).project_name == "'abc'"
        assert ash_warnings() == []
        assert resolve_config(source_dir=toml_root).project_name == "abc"

    @pytest.mark.parametrize(
        "case", ["literal_line_separator", "basic_unescaped_quotes"]
    )
    def test_a_three_quote_string_without_a_reference_rewritten_as_advised_reads_what_toml_reads(
        self, tmp_path, case
    ):
        """The one-line double-quoted copy the advice gives reads what TOML reads: a
        literal string that holds a U+2028, and a basic string with unescaped double
        quotes."""
        if case == "literal_line_separator":
            separator = chr(0x2028)
            toml_lines = ["project_name = '''", f"x {separator}y", "z'''"]
            yaml_lines = [f'project_name: "x {BACKSLASH}u2028y{BACKSLASH}nz"']
            expected = f"x {separator}y\nz"
        else:
            toml_lines = ['project_name = """', 'say "hi"', 'there"""']
            yaml_lines = ['project_name: "say \\"hi\\"\\nthere"']
            expected = 'say "hi"\nthere'
        toml_root, yaml_root = _toml_and_yaml_roots(tmp_path, toml_lines, yaml_lines)
        assert resolve_config(source_dir=toml_root).project_name == expected
        assert resolve_config(source_dir=yaml_root).project_name == expected


#: Characters that TOML reads as written and that YAML does not keep as written inside
#: quotes, each as the text before the character (a space or nothing) and its code
#: point: U+0085 is read as a line break, which becomes a space; U+2028 and U+2029 are
#: read as line breaks that drop the spaces and tabs beside them; a C1 control other
#: than U+0085 and the noncharacters U+FFFE and U+FFFF make YAML refuse the file.
ESCAPED_CHARACTERS = {
    "next_line": ("", 0x85),
    "line_separator_after_space": (" ", 0x2028),
    "c1_control": ("", 0x86),
    "noncharacter": ("", 0xFFFF),
    "paragraph_separator": ("", 0x2029),
    "noncharacter_fffe": ("", 0xFFFE),
}
ESCAPE_PAIRS = [
    pytest.param(character, form, id=f"{character}-{form}")
    for character in ESCAPED_CHARACTERS
    for form in ("basic", "literal")
]
BACKSLASH = chr(92)

#: A raw U+2028 or U+2029 with a space or a tab beside it, each as the text TOML reads
#: and the text YAML reads inside quotes, which keeps the character and drops the
#: spaces and tabs beside it.
RAW_SEPARATORS = {
    "line_separator_after_space": (f"x {chr(0x2028)}y", f"x{chr(0x2028)}y"),
    "line_separator_before_tab": (f"x{chr(0x2028)}\ty", f"x{chr(0x2028)}y"),
    "paragraph_separator_after_space": (f"x {chr(0x2029)}y", f"x{chr(0x2029)}y"),
}


class TestACharacterYamlReadsAsALineBreakOrRefuses:
    """Why the TOML advice says to write a string that holds a C1 control, U+2028,
    U+2029, U+FFFE or U+FFFF as a double-quoted string with each such character as its
    escape: TOML reads each of them as written, while inside quotes YAML reads U+0085,
    U+2028 and U+2029 as line breaks, and refuses a file that holds one of the
    others."""

    def test_a_raw_next_line_character_in_quotes_reads_as_a_space(self, tmp_path):
        """TOML reads U+0085 inside a string as written. YAML takes it for a line
        break inside quotes, and a line break there is read as a space."""
        value = f"x{chr(0x85)}y"
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path, [f'project_name = "{value}"'], [f'project_name: "{value}"']
        )
        assert resolve_config(source_dir=toml_root).project_name == value
        assert resolve_config(source_dir=yaml_root).project_name == "x y"

    def test_a_raw_c1_control_makes_yaml_refuse_the_file(self, tmp_path):
        """TOML reads a C1 control other than U+0085 as written. YAML refuses a file
        that holds one, and the refusal is the kind a scan reports with exit 3."""
        value = f"x{chr(0x86)}y"
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path, [f'project_name = "{value}"'], [f'project_name: "{value}"']
        )
        assert resolve_config(source_dir=toml_root).project_name == value
        with pytest.raises(
            ASHConfigSourceError, match=r"could not be parsed \(ReaderError"
        ):
            resolve_config(source_dir=yaml_root)

    @pytest.mark.parametrize(("character", "form"), ESCAPE_PAIRS)
    def test_each_written_as_its_escape_in_double_quotes_reads_what_toml_reads(
        self, tmp_path, character, form
    ):
        """A basic string keeps its tab escape; a literal string's backslash and
        double quote are escaped, as the advice says for three quote marks."""
        space, code_point = ESCAPED_CHARACTERS[character]
        piece = space + chr(code_point)
        escape = f"{BACKSLASH}u{code_point:04X}"
        if form == "basic":
            toml_value = f'"a\\tb{piece}c"'
            yaml_value = f'"a\\tb{space}{escape}c"'
            expected = f"a\tb{piece}c"
        else:
            toml_value = f"'a\\b{piece}\"c'"
            yaml_value = f'"a\\\\b{space}{escape}\\"c"'
            expected = f'a\\b{piece}"c'
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path, [f"project_name = {toml_value}"], [f"project_name: {yaml_value}"]
        )
        assert resolve_config(source_dir=toml_root).project_name == expected
        assert resolve_config(source_dir=yaml_root).project_name == expected

    @pytest.mark.parametrize("case", list(RAW_SEPARATORS))
    def test_a_raw_line_or_paragraph_separator_drops_the_whitespace_beside_it(
        self, tmp_path, case
    ):
        """TOML reads the text as written. Inside quotes YAML takes U+2028 and U+2029
        for line breaks: it keeps the character and drops the spaces and tabs beside
        it, with nothing said."""
        toml_text, yaml_text = RAW_SEPARATORS[case]
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            [f'project_name = "{toml_text}"'],
            [f'project_name: "{toml_text}"'],
        )
        assert resolve_config(source_dir=toml_root).project_name == toml_text
        assert resolve_config(source_dir=yaml_root).project_name == yaml_text

    @pytest.mark.parametrize("code_point", [0xFFFE, 0xFFFF], ids=["fffe", "ffff"])
    def test_a_raw_noncharacter_makes_yaml_refuse_the_file(self, tmp_path, code_point):
        """TOML reads U+FFFE and U+FFFF as written. YAML refuses a file that holds
        one, and the refusal is the kind a scan reports with exit 3."""
        value = f"x{chr(code_point)}y"
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path, [f'project_name = "{value}"'], [f'project_name: "{value}"']
        )
        assert resolve_config(source_dir=toml_root).project_name == value
        with pytest.raises(
            ASHConfigSourceError, match=r"could not be parsed \(ReaderError"
        ):
            resolve_config(source_dir=yaml_root)

    def test_a_one_quote_reference_holding_a_line_separator_kept_in_single_quotes_reads_another_default(
        self, tmp_path, monkeypatch
    ):
        """TOML reads the default of the reference as written. Inside quotes YAML takes
        U+2028 for a line break and drops the space before it, so the reference that
        keeps its single quotes has another default."""
        monkeypatch.delenv("ASH_SERVICE_NAME", raising=False)
        separator = chr(0x2028)
        reference = "${ASH_SERVICE_NAME:a " + separator + "b}"
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            [f"project_name = '{reference}'"],
            [f"project_name: !ENV '{reference}'"],
        )
        assert resolve_config(source_dir=toml_root).project_name == f"a {separator}b"
        assert resolve_config(source_dir=yaml_root).project_name == f"a{separator}b"

    def test_the_same_reference_written_double_quoted_with_its_escape_reads_what_toml_reads(
        self, tmp_path, monkeypatch
    ):
        """Written as a double-quoted string with the escape for U+2028, the default
        keeps its space and its character, as TOML reads it."""
        monkeypatch.delenv("ASH_SERVICE_NAME", raising=False)
        separator = chr(0x2028)
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            ["project_name = '${ASH_SERVICE_NAME:a " + separator + "b}'"],
            ['project_name: !ENV "${ASH_SERVICE_NAME:a ' + BACKSLASH + 'u2028b}"'],
        )
        expected = f"a {separator}b"
        assert resolve_config(source_dir=toml_root).project_name == expected
        assert resolve_config(source_dir=yaml_root).project_name == expected


#: Spellings of one number as TOML and JSON write it, each with the spelling YAML reads
#: as that number and the number itself. YAML reads a number with an exponent as one
#: only with a decimal point and, after the `e`, a sign: it reads the first as text.
NUMBER_SPELLINGS = {
    "no_point": ("1e3", "1.0e+3", 1000.0),
    "no_sign": ("2.5e2", "2.5e+2", 250.0),
    "negative_exponent_no_point": ("25e-1", "25.0e-1", 2.5),
}


class TestANumberInYamlNeedsAPointAndASignInItsExponent:
    """Why the TOML and JSON advice says to give a number with an exponent a decimal
    point and a sign after the e, to write a TOML octal number in decimal, and to
    write an infinity as .inf: TOML and JSON read each such spelling as a number, YAML
    reads it as text, and a setting that takes a number refuses text."""

    @pytest.mark.parametrize("spelling", list(NUMBER_SPELLINGS))
    def test_a_toml_number_with_an_exponent_and_no_point_or_sign_is_refused_as_yaml(
        self, tmp_path, spelling
    ):
        """TOML reads the number. YAML reads the same text as text, which the setting
        refuses, and the refusal is the kind a scan reports with exit 3."""
        written, _, number = NUMBER_SPELLINGS[spelling]
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            ["[workspace]", f"project_timeout = {written}"],
            ["workspace:", f"  project_timeout: {written}"],
        )
        assert resolve_config(source_dir=toml_root).workspace.project_timeout == number
        with pytest.raises(
            ASHConfigValidationError, match="Configuration validation failed for"
        ):
            resolve_config(source_dir=yaml_root)

    @pytest.mark.parametrize("spelling", list(NUMBER_SPELLINGS))
    def test_a_json_number_with_an_exponent_and_no_point_or_sign_is_refused_as_yaml(
        self, tmp_path, spelling
    ):
        """JSON reads the number. The same text as YAML is refused the same way."""
        written, _, number = NUMBER_SPELLINGS[spelling]
        text = '{"workspace": {"project_timeout": ' + written + "}}\n"
        json_root, yaml_root = _json_and_yaml_roots(tmp_path, text, text)
        assert resolve_config(source_dir=json_root).workspace.project_timeout == number
        with pytest.raises(
            ASHConfigValidationError, match="Configuration validation failed for"
        ):
            resolve_config(source_dir=yaml_root)

    @pytest.mark.parametrize("spelling", list(NUMBER_SPELLINGS))
    def test_a_toml_number_rewritten_with_a_point_and_a_sign_reads_what_toml_reads(
        self, tmp_path, spelling
    ):
        written, rewritten, number = NUMBER_SPELLINGS[spelling]
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            ["[workspace]", f"project_timeout = {written}"],
            ["workspace:", f"  project_timeout: {rewritten}"],
        )
        assert resolve_config(source_dir=toml_root).workspace.project_timeout == number
        assert resolve_config(source_dir=yaml_root).workspace.project_timeout == number

    @pytest.mark.parametrize("spelling", list(NUMBER_SPELLINGS))
    def test_a_json_number_rewritten_with_a_point_and_a_sign_reads_what_json_reads(
        self, tmp_path, spelling
    ):
        written, rewritten, number = NUMBER_SPELLINGS[spelling]
        prefix = '{"workspace": {"project_timeout": '
        json_root, yaml_root = _json_and_yaml_roots(
            tmp_path, prefix + written + "}}\n", prefix + rewritten + "}}\n"
        )
        assert resolve_config(source_dir=json_root).workspace.project_timeout == number
        assert resolve_config(source_dir=yaml_root).workspace.project_timeout == number

    def test_a_toml_octal_number_is_refused_as_yaml(self, tmp_path):
        """TOML reads `0o17` as 15. YAML has no octal spelling with the letter o, so it
        reads the same text as text, which the setting refuses."""
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            ["[global_settings.history]", "keep_runs = 0o17"],
            ["global_settings:", "  history:", "    keep_runs: 0o17"],
        )
        toml_config = resolve_config(source_dir=toml_root)
        assert toml_config.global_settings.history.keep_runs == 15
        with pytest.raises(
            ASHConfigValidationError, match="Configuration validation failed for"
        ):
            resolve_config(source_dir=yaml_root)

    def test_a_toml_octal_number_written_in_decimal_reads_what_toml_reads(
        self, tmp_path
    ):
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            ["[global_settings.history]", "keep_runs = 0o17"],
            ["global_settings:", "  history:", "    keep_runs: 15"],
        )
        toml_config = resolve_config(source_dir=toml_root)
        yaml_config = resolve_config(source_dir=yaml_root)
        assert toml_config.global_settings.history.keep_runs == 15
        assert yaml_config.global_settings.history.keep_runs == 15

    def test_a_toml_infinity_is_refused_as_yaml(self, tmp_path):
        """TOML reads `inf` as an infinite float. YAML reads `inf` as text, which the
        setting refuses."""
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            ["[workspace]", "project_timeout = inf"],
            ["workspace:", "  project_timeout: inf"],
        )
        toml_config = resolve_config(source_dir=toml_root)
        assert toml_config.workspace.project_timeout == float("inf")
        with pytest.raises(
            ASHConfigValidationError, match="Configuration validation failed for"
        ):
            resolve_config(source_dir=yaml_root)

    def test_a_toml_infinity_written_as_dot_inf_reads_what_toml_reads(self, tmp_path):
        toml_root, yaml_root = _toml_and_yaml_roots(
            tmp_path,
            ["[workspace]", "project_timeout = inf"],
            ["workspace:", "  project_timeout: .inf"],
        )
        toml_config = resolve_config(source_dir=toml_root)
        yaml_config = resolve_config(source_dir=yaml_root)
        assert toml_config.workspace.project_timeout == float("inf")
        assert yaml_config.workspace.project_timeout == float("inf")

    def test_a_json_infinity_is_refused_as_yaml(self, tmp_path):
        """JSON reads `Infinity` as an infinite float, though it is outside the JSON
        specification. YAML reads it as text, which the setting refuses."""
        text = '{"workspace": {"project_timeout": Infinity}}\n'
        json_root, yaml_root = _json_and_yaml_roots(tmp_path, text, text)
        json_config = resolve_config(source_dir=json_root)
        assert json_config.workspace.project_timeout == float("inf")
        with pytest.raises(
            ASHConfigValidationError, match="Configuration validation failed for"
        ):
            resolve_config(source_dir=yaml_root)

    def test_a_json_infinity_written_as_dot_inf_reads_what_json_reads(self, tmp_path):
        json_root, yaml_root = _json_and_yaml_roots(
            tmp_path,
            '{"workspace": {"project_timeout": Infinity}}\n',
            '{"workspace": {"project_timeout": .inf}}\n',
        )
        json_config = resolve_config(source_dir=json_root)
        yaml_config = resolve_config(source_dir=yaml_root)
        assert json_config.workspace.project_timeout == float("inf")
        assert yaml_config.workspace.project_timeout == float("inf")

    def test_yaml_reads_a_number_with_an_exponent_and_no_point_as_text(self, tmp_path):
        """The premise of the refusals above: YAML reads `1e3` as the text it is."""
        (tmp_path / ".ash.yaml").write_text("project_name: 1e3\n", encoding="utf-8")
        assert resolve_config(source_dir=tmp_path).project_name == "1e3"


class TestAMovedTomlFileIsRefused:
    """Why the advice above is not "rename it": `.ash.yaml` is parsed as YAML."""

    @pytest.mark.parametrize(
        "text",
        [
            'project_name = "x"\n\n[global_settings]\nseverity_threshold = "HIGH"\n',
            '[global_settings]\nseverity_threshold = "HIGH"\n',
        ],
        ids=["key_first", "table_first"],
    )
    def test_toml_text_in_the_canonical_file_is_refused(self, tmp_path, text):
        (tmp_path / ".ash.yaml").write_text(text, encoding="utf-8")
        with pytest.raises(ASHConfigValidationError):
            resolve_config(source_dir=tmp_path)
