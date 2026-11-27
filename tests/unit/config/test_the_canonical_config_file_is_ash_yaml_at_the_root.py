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
from automated_security_helper.core.exceptions import ASHConfigValidationError
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
# when it is not indented with tabs.
TOML_LEGACY = [location for location in LEGACY_LOCATIONS if location.endswith(".toml")]
JSON_LEGACY = [location for location in LEGACY_LOCATIONS if location.endswith(".json")]
YAML_LEGACY = [
    location
    for location in LEGACY_LOCATIONS
    if location not in TOML_LEGACY + JSON_LEGACY
]

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
        assert "renaming the TOML file is not enough" in warning, warning
        assert "move this file to" not in warning, warning

    @pytest.mark.parametrize("legacy", YAML_LEGACY)
    def test_a_yaml_legacy_file_keeps_the_advice_to_move_it(self, tmp_path, legacy):
        _write(tmp_path, legacy, "legacy")
        [warning] = discovery_warnings(discover_config_source(tmp_path))
        canonical = (tmp_path / ".ash.yaml").as_posix()
        assert warning.endswith(f"move this file to {canonical}."), warning

    @pytest.mark.parametrize("legacy", JSON_LEGACY)
    def test_a_json_legacy_file_is_moved_after_its_tabs_are_replaced(
        self, tmp_path, legacy
    ):
        _write(tmp_path, legacy, "legacy")
        [warning] = discovery_warnings(discover_config_source(tmp_path))
        canonical = (tmp_path / ".ash.yaml").as_posix()
        caveat = (
            ".ash.yaml is read as YAML, so re-indent this file with spaces first "
            "if it is indented with tabs."
        )
        assert warning.endswith(f"move this file to {canonical}; {caveat}"), warning


class TestAMovedFileIsRefusedWhenYamlCannotReadIt:
    """Why the advice above is not "rename it": `.ash.yaml` is parsed as YAML."""

    def test_json_indented_with_tabs_in_the_canonical_file_is_refused(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text(
            '{\n\t"project_name": "x"\n}\n', encoding="utf-8"
        )
        with pytest.raises(ASHConfigValidationError):
            resolve_config(source_dir=tmp_path)

    def test_the_same_json_indented_with_spaces_is_read(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text(
            '{\n  "project_name": "x"\n}\n', encoding="utf-8"
        )
        assert resolve_config(source_dir=tmp_path).project_name == "x"


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
