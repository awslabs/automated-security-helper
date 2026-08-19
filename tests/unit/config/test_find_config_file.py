# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import pytest

from automated_security_helper.config.resolve_config import find_config_file
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES


def test_finds_config_in_cwd(tmp_path):
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text("version: 1")
    result = find_config_file(search_dir=tmp_path)
    assert result == config_file


def test_finds_config_in_ash_subdir(tmp_path):
    ash_dir = tmp_path / ".ash"
    ash_dir.mkdir()
    config_file = ash_dir / ".ash.yaml"
    config_file.write_text("version: 1")
    result = find_config_file(search_dir=tmp_path)
    assert result == config_file


def test_prefers_cwd_over_ash_subdir(tmp_path):
    cwd_config = tmp_path / ".ash.yaml"
    cwd_config.write_text("version: 1")
    ash_dir = tmp_path / ".ash"
    ash_dir.mkdir()
    ash_config = ash_dir / ".ash.yaml"
    ash_config.write_text("version: 2")
    result = find_config_file(search_dir=tmp_path)
    assert result == cwd_config


def test_returns_none_when_no_config(tmp_path):
    result = find_config_file(search_dir=tmp_path)
    assert result is None


def test_accepts_none_search_dir_defaults_to_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text("version: 1")
    result = find_config_file()
    assert result == config_file


def test_iterates_all_config_file_names(tmp_path):
    for name in ASH_CONFIG_FILE_NAMES:
        single_dir = tmp_path / name
        single_dir.mkdir()
        config_file = single_dir / name
        config_file.write_text("version: 1")
        result = find_config_file(search_dir=single_dir)
        assert result == config_file, f"Expected to find {name}"


def test_finds_ash_yml_in_cwd(tmp_path):
    config_file = tmp_path / ".ash.yml"
    config_file.write_text("version: 1")
    result = find_config_file(search_dir=tmp_path)
    assert result == config_file


def test_finds_ash_json_in_cwd(tmp_path):
    config_file = tmp_path / ".ash.json"
    config_file.write_text("{}")
    result = find_config_file(search_dir=tmp_path)
    assert result == config_file


def test_finds_ash_json_in_ash_subdir(tmp_path):
    ash_dir = tmp_path / ".ash"
    ash_dir.mkdir()
    config_file = ash_dir / "ash.json"
    config_file.write_text("{}")
    result = find_config_file(search_dir=tmp_path)
    assert result == config_file


def test_returns_path_object(tmp_path):
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text("version: 1")
    result = find_config_file(search_dir=tmp_path)
    assert isinstance(result, Path)
