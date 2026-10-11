# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The rest of "a config file that does not load is refused, never the defaults".

``test_resolve_config_load_failures.py`` covers the named and discovered YAML and
JSON files. This covers the other ways a config file reaches resolution -- the
operator's trusted config, a ``pyproject.toml`` probed during discovery, an empty
path, ``ASH_CONFIG`` with a schema error -- and the discovery warnings
``resolve_config`` now records, which are the resolution warnings a scan reports
with its results.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


class TestOtherConfigInputs:
    def test_an_empty_config_path_is_refused_as_empty(self, tmp_path):
        """Path("") is the working directory; the refusal says the path is empty."""
        with pytest.raises(ASHConfigSourceError, match="path is empty"):
            resolve_config(config_path="", source_dir=tmp_path)

    def test_a_named_trusted_config_that_does_not_exist_is_refused(self, tmp_path):
        """The operator's file the sandbox grants come from must exist when named.

        Refused like any named config, so the grants of an in-tree config are
        always decided against the file the operator named.
        """
        (tmp_path / ".ash").mkdir()
        (tmp_path / ".ash" / ".ash.yaml").write_text(
            "project_name: in-tree\n", encoding="utf-8"
        )

        with pytest.raises(ASHConfigValidationError, match="operator.yaml"):
            resolve_config(
                source_dir=tmp_path, trusted_config_path=tmp_path / "operator.yaml"
            )

    def test_a_trusted_config_that_does_not_parse_is_refused(self, tmp_path):
        source = tmp_path / "src"
        (source / ".ash").mkdir(parents=True)
        (source / ".ash" / ".ash.yaml").write_text(
            "project_name: in-tree\n", encoding="utf-8"
        )
        operator = tmp_path / "operator.yaml"
        operator.write_text("sandbox: [unclosed\n", encoding="utf-8")

        with pytest.raises(ASHConfigSourceError, match="could not parse"):
            resolve_config(source_dir=source, trusted_config_path=operator)

    def test_an_ash_config_variable_naming_a_schema_invalid_file_is_a_config_error(
        self, tmp_path, monkeypatch
    ):
        """Not pydantic's ValidationError, which ``ash scan`` reports as exit 1."""
        env_file = tmp_path / "env.yaml"
        env_file.write_text("global_settings: 7\n", encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(env_file))
        source = tmp_path / "src"
        source.mkdir()

        with pytest.raises(ASHConfigValidationError, match="env.yaml"):
            resolve_config(source_dir=source)

    def test_control_an_empty_ash_config_variable_is_unset(self, tmp_path, monkeypatch):
        """As click treats it for --config, so an empty CI input keeps working."""
        monkeypatch.setenv("ASH_CONFIG", "")

        config = resolve_config(source_dir=tmp_path)

        assert config.global_settings.suppressions == []


class TestDiscoveryLocations:
    def test_a_directory_at_a_config_name_is_refused(self, tmp_path):
        (tmp_path / ".ash" / ".ash.yaml").mkdir(parents=True)

        with pytest.raises(ASHConfigSourceError, match="not a regular file"):
            resolve_config(source_dir=tmp_path)

    def test_an_unreadable_pyproject_that_would_be_selected_is_refused(self, tmp_path):
        """It may hold the repository's [tool.ash] table, and that cannot be told."""
        (tmp_path / "pyproject.toml").symlink_to(tmp_path / "absent.toml")

        with pytest.raises(ASHConfigSourceError, match="pyproject.toml"):
            resolve_config(source_dir=tmp_path)

    def test_control_an_unreadable_pyproject_behind_a_dedicated_file_is_ignored(
        self, tmp_path
    ):
        """Shadowed, it would be ignored even if readable, so it is only logged."""
        (tmp_path / "pyproject.toml").symlink_to(tmp_path / "absent.toml")
        (tmp_path / ".ash.yaml").write_text("project_name: used\n", encoding="utf-8")

        assert resolve_config(source_dir=tmp_path).project_name == "used"


def _two_sources(root: Path) -> Path:
    (root / ".ash").mkdir()
    used = root / ".ash" / ".ash.yaml"
    used.write_text("project_name: used\n", encoding="utf-8")
    (root / ".ashrc.toml").write_text('project_name = "ignored"\n', encoding="utf-8")
    return used


class TestIgnoredSourcesAreResolutionWarnings:
    def test_discovery_records_the_ignored_source(self, tmp_path):
        _two_sources(tmp_path)

        config = resolve_config(source_dir=tmp_path)

        assert config.project_name == "used"
        assert len(config._resolution_warnings) == 1
        assert ".ashrc.toml" in config._resolution_warnings[0]

    def test_the_file_discovery_selects_records_it_when_passed_by_path(self, tmp_path):
        """``ash scan`` and workspace mode discover first and pass the path."""
        used = _two_sources(tmp_path)

        config = resolve_config(config_path=used, source_dir=tmp_path)

        assert [".ashrc.toml" in w for w in config._resolution_warnings] == [True]

    def test_the_warning_survives_config_overrides(self, tmp_path):
        """An override rebuilds the config object; the warning is added after it."""
        _two_sources(tmp_path)

        config = resolve_config(
            source_dir=tmp_path, config_overrides=["project_name=overridden"]
        )

        assert config.project_name == "overridden"
        assert len(config._resolution_warnings) == 1

    def test_control_a_file_chosen_over_discovery_records_nothing(self, tmp_path):
        """Naming the ignored source itself, or a file elsewhere, is a choice."""
        _two_sources(tmp_path)
        elsewhere = tmp_path / "configs" / "ci.yaml"
        elsewhere.parent.mkdir()
        elsewhere.write_text("project_name: ci\n", encoding="utf-8")

        for path in (tmp_path / ".ashrc.toml", elsewhere):
            config = resolve_config(config_path=path, source_dir=tmp_path)
            assert config._resolution_warnings == [], path

    def test_control_a_single_source_records_nothing(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text("project_name: only\n", encoding="utf-8")

        assert resolve_config(source_dir=tmp_path)._resolution_warnings == []
