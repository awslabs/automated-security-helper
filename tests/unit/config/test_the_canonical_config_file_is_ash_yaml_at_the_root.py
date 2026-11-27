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
# when it holds no tab character.
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
ENV_CAVEAT = (
    "In the YAML, put !ENV in front of each value from this file that starts "
    "with ${ and keep its quotes: a quoted value without the tag is read as "
    "literal text, not from the environment."
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
        assert warning.endswith(f"move this file to {canonical}. {TAB_CAVEAT}"), warning
        assert EXTENDS_CAVEAT not in warning, warning

    @pytest.mark.parametrize("legacy", ASH_DIR_JSON)
    def test_a_json_legacy_file_in_ash_gets_both_caveats(self, tmp_path, legacy):
        _write(tmp_path, legacy, "legacy")
        [warning] = discovery_warnings(discover_config_source(tmp_path))
        canonical = (tmp_path / ".ash.yaml").as_posix()
        assert warning.endswith(
            f"move this file to {canonical}. {EXTENDS_CAVEAT} {TAB_CAVEAT}"
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


class TestATomlReferenceToTheEnvironmentInYaml:
    """Why the TOML advice says to put `!ENV` in front of a `${...}` value and keep
    its quotes: TOML resolves every string that starts with a reference; YAML
    resolves a quoted value only when it is tagged `!ENV`; and without quotes it
    cuts the value short at a space and a hash, and refuses one that holds a colon
    and a space or sits inside brackets or braces."""

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
