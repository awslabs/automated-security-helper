# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Config discovery from pyproject.toml [tool.ash] and ashrc files (#313).

The precedence under test, highest first:

1. an explicit config path;
2. ASH_CONFIG_FILE_NAMES, each at the scan root and then in .ash/;
3. ASH_RC_FILE_NAMES at the scan root;
4. pyproject.toml at the scan root, only when it has a [tool.ash] table.

Exactly one source is used. The rest are logged as ignored and never merged.
"""

import logging
import textwrap
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import (
    find_config_file,
    resolve_config,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_RC_FILE_NAMES,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import ASH_LOGGER

DEFAULT_PROJECT_NAME = AshConfig().project_name


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


def _pyproject(root: Path, ash_table: str | None, project: str = "demo") -> Path:
    body = f'[project]\nname = "{project}"\nversion = "0.1.0"\n\n[tool.ruff]\nline-length = 100\n'
    if ash_table is not None:
        body += "\n[tool.ash]\n" + textwrap.dedent(ash_table).lstrip()
    return _write(root / "pyproject.toml", body)


def _source_file(root: Path, name: str, project_name: str) -> Path:
    """Write a config named `name` whose only distinguishing value is project_name."""
    if name.endswith(".json"):
        return _write(root / name, f'{{"project_name": "{project_name}"}}\n')
    if name.endswith(".toml"):
        return _write(root / name, f'project_name = "{project_name}"\n')
    return _write(root / name, f"project_name: {project_name}\n")


@pytest.fixture
def ash_log():
    """Capture ASH_LOGGER records; it does not propagate, so caplog sees nothing."""
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def _warnings(records) -> list[str]:
    return [r.getMessage() for r in records if r.levelno == logging.WARNING]


class TestPyprojectToolAsh:
    def test_tool_ash_table_is_read_when_it_is_the_only_source(self, tmp_path):
        _pyproject(
            tmp_path,
            """
            project_name = "from-pyproject"
            fail_on_findings = false

            [tool.ash.global_settings]
            severity_threshold = "HIGH"

            [tool.ash.scanners.bandit]
            enabled = false
            """,
        )
        config = resolve_config(source_dir=tmp_path)
        assert config.project_name == "from-pyproject"
        assert config.fail_on_findings is False
        assert config.global_settings.severity_threshold == "HIGH"
        assert config.scanners.bandit.enabled is False

    def test_pyproject_without_tool_ash_is_not_a_config_source(self, tmp_path):
        _pyproject(tmp_path, None)
        assert find_config_file(tmp_path) is None
        config = resolve_config(source_dir=tmp_path)
        assert config.project_name == DEFAULT_PROJECT_NAME

    def test_pyproject_with_only_other_tool_tables_is_not_a_source(self, tmp_path):
        _write(
            tmp_path / "pyproject.toml",
            "[tool.ashlar]\nx = 1\n[tool.black]\nline-length = 88\n",
        )
        assert find_config_file(tmp_path) is None

    def test_pyproject_is_found_by_find_config_file(self, tmp_path):
        pyproject = _pyproject(tmp_path, 'project_name = "p"\n')
        assert find_config_file(tmp_path) == pyproject

    def test_pyproject_in_dot_ash_is_not_discovered(self, tmp_path):
        _pyproject(tmp_path / ".ash", 'project_name = "nested"\n')
        assert find_config_file(tmp_path) is None

    def test_explicit_pyproject_path_reads_tool_ash(self, tmp_path):
        pyproject = _pyproject(tmp_path, 'project_name = "explicit-pyproject"\n')
        config = resolve_config(config_path=pyproject)
        assert config.project_name == "explicit-pyproject"

    def test_explicit_pyproject_without_tool_ash_is_an_error(self, tmp_path):
        pyproject = _pyproject(tmp_path, None)
        with pytest.raises(ASHConfigValidationError, match=r"no \[tool\.ash\] table"):
            resolve_config(config_path=pyproject)

    def test_validation_error_names_the_pyproject_table_and_line(self, tmp_path):
        pyproject = _pyproject(
            tmp_path,
            """
            project_name = "bad"
            fail_on_findings = "sometimes"
            """,
        )
        header_line = pyproject.read_text().splitlines().index("[tool.ash]") + 1
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=tmp_path)
        message = str(excinfo.value)
        assert f"pyproject.toml [tool.ash] (line {header_line})" in message
        assert "fail_on_findings" in message

    def test_malformed_pyproject_without_tool_ash_is_skipped(self, tmp_path):
        _write(tmp_path / "pyproject.toml", "[project\nname = 'broken'\n")
        assert find_config_file(tmp_path) is None
        assert resolve_config(source_dir=tmp_path).project_name == DEFAULT_PROJECT_NAME

    def test_malformed_pyproject_declaring_tool_ash_fails_closed(self, tmp_path):
        _write(
            tmp_path / "pyproject.toml",
            '[tool.ash]\nproject_name = "unterminated\n',
        )
        with pytest.raises(ASHConfigValidationError, match="not valid TOML"):
            resolve_config(source_dir=tmp_path)

    def test_tool_ash_that_is_not_a_table_is_an_error(self, tmp_path):
        _write(tmp_path / "pyproject.toml", '[tool]\nash = "yes"\n')
        with pytest.raises(ASHConfigValidationError, match="must be a table"):
            resolve_config(source_dir=tmp_path)

    def test_toml_values_use_the_env_var_allowlist(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_TEST_PYPROJECT_NAME", "resolved-from-env")
        monkeypatch.setenv("DEMO_UNLISTED_PYPROJECT_VAR", "must-not-appear")
        _pyproject(
            tmp_path,
            """
            project_name = "${ASH_TEST_PYPROJECT_NAME:None}"

            [tool.ash.global_settings]
            ignore_paths = [{path = "${DEMO_UNLISTED_PYPROJECT_VAR:None}", reason = "r"}]
            """,
        )
        config = resolve_config(source_dir=tmp_path)
        assert config.project_name == "resolved-from-env"
        assert (
            config.global_settings.ignore_paths[0].path
            == "${DEMO_UNLISTED_PYPROJECT_VAR:None}"
        )


class TestAshrcFiles:
    @pytest.mark.parametrize("name", ASH_RC_FILE_NAMES)
    def test_each_ashrc_name_is_read(self, tmp_path, name):
        _source_file(tmp_path, name, "from-" + name.replace(".", "-"))
        config = resolve_config(source_dir=tmp_path)
        assert config.project_name == "from-" + name.replace(".", "-")

    def test_ashrc_names_follow_list_order(self, tmp_path):
        for name in ASH_RC_FILE_NAMES:
            _source_file(tmp_path, name, "from-" + name.replace(".", "-"))
        first = ASH_RC_FILE_NAMES[0]
        assert find_config_file(tmp_path) == tmp_path / first

    def test_ashrc_in_dot_ash_is_not_discovered(self, tmp_path):
        _source_file(tmp_path / ".ash", "ashrc.yaml", "nested")
        assert find_config_file(tmp_path) is None


class TestPrecedenceMatrix:
    """Each row: the sources present, and the one whose project_name wins."""

    @pytest.mark.parametrize(
        "present, winner",
        [
            (["pyproject"], "pyproject"),
            (["ashrc", "pyproject"], "ashrc"),
            ([".ash/.ash.yaml", "pyproject"], ".ash/.ash.yaml"),
            ([".ash/.ash.yaml", "ashrc"], ".ash/.ash.yaml"),
            ([".ash/.ash.yaml", "ashrc", "pyproject"], ".ash/.ash.yaml"),
            ([".ash.yaml", ".ash/.ash.yaml", "ashrc", "pyproject"], ".ash.yaml"),
            (["ash.json", "ashrc", "pyproject"], "ash.json"),
        ],
    )
    def test_highest_precedence_source_wins(self, tmp_path, present, winner):
        for source in present:
            if source == "pyproject":
                _pyproject(tmp_path, f'project_name = "{source}"\n')
            elif source == "ashrc":
                _source_file(tmp_path, ".ashrc.yaml", source)
            else:
                _source_file(tmp_path, source, source.replace("/", "-"))
        expected = (
            winner if winner in ("pyproject", "ashrc") else winner.replace("/", "-")
        )
        assert resolve_config(source_dir=tmp_path).project_name == expected

    def test_explicit_path_beats_every_discovered_source(self, tmp_path, ash_log):
        _source_file(tmp_path / ".ash", ".ash.yaml", "legacy")
        _source_file(tmp_path, "ashrc.yaml", "ashrc")
        _pyproject(tmp_path, 'project_name = "pyproject"\n')
        explicit = _source_file(tmp_path / "configs", "ci.yaml", "explicit")
        config = resolve_config(config_path=explicit, source_dir=tmp_path)
        assert config.project_name == "explicit"
        assert not [w for w in _warnings(ash_log) if "Ignoring ASH configuration" in w]

    def test_sources_are_never_merged(self, tmp_path):
        # The ignored ashrc sets a field the winning file leaves at its default.
        _source_file(tmp_path / ".ash", ".ash.yaml", "legacy")
        _write(
            tmp_path / "ashrc.yaml", "project_name: ashrc\nfail_on_findings: false\n"
        )
        _pyproject(
            tmp_path, 'project_name = "p"\nfail_on_incomplete_scanners = false\n'
        )
        config = resolve_config(source_dir=tmp_path)
        assert config.project_name == "legacy"
        assert config.fail_on_findings is True
        assert config.fail_on_incomplete_scanners is True

    def test_selected_and_ignored_sources_are_logged(self, tmp_path, ash_log):
        _source_file(tmp_path, ".ashrc.yaml", "ashrc")
        pyproject = _pyproject(tmp_path, 'project_name = "p"\n')
        resolve_config(source_dir=tmp_path)
        infos = [r.getMessage() for r in ash_log if r.levelno == logging.INFO]
        assert any(
            "Using ASH configuration from" in m and ".ashrc.yaml" in m for m in infos
        )
        ignored = [w for w in _warnings(ash_log) if "Ignoring ASH configuration" in w]
        assert len(ignored) == 1
        assert pyproject.as_posix() in ignored[0]
        assert "never merged" in ignored[0]
        # Neither of these is a deprecated name.
        assert "deprecated" not in ignored[0]

    def test_dedicated_file_shadowing_a_newer_source_warns_deprecation(
        self, tmp_path, ash_log
    ):
        _source_file(tmp_path / ".ash", ".ash.yaml", "legacy")
        _pyproject(tmp_path, 'project_name = "p"\n')
        config = resolve_config(source_dir=tmp_path)
        assert config.project_name == "legacy"
        ignored = [w for w in _warnings(ash_log) if "Ignoring ASH configuration" in w]
        assert len(ignored) == 1
        assert "deprecated" in ignored[0]
        assert "[tool.ash]" in ignored[0]

    def test_dedicated_file_alone_logs_no_deprecation(self, tmp_path, ash_log):
        _source_file(tmp_path / ".ash", ".ash.yaml", "legacy")
        resolve_config(source_dir=tmp_path)
        assert not [w for w in _warnings(ash_log) if "deprecated" in w]

    def test_existing_dedicated_name_order_is_unchanged(self, tmp_path):
        # Name-major, root before .ash/, exactly as before #313.
        for name in ASH_CONFIG_FILE_NAMES:
            _source_file(tmp_path / ".ash", name, "x")
        _source_file(tmp_path, ASH_CONFIG_FILE_NAMES[1], "y")
        assert (
            find_config_file(tmp_path) == tmp_path / ".ash" / ASH_CONFIG_FILE_NAMES[0]
        )
