# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file ASH was given or found, and cannot load, refuses resolution.

``resolve_config`` is what every scan entry point calls: ``ash scan``, the Python
API, workspace mode and the MCP server. A config file that is named but missing, or
present but unreadable or unparseable, must raise ``ASHConfigValidationError``
(which ``ash scan`` reports as exit 3), for an explicit path and a discovered file
alike. Falling back to the built-in defaults would scan with every suppression,
ignore path, threshold and sandbox setting of the intended file switched off, and
the scan would still report success.

Only a source directory with no config file at all resolves to the defaults; the
controls below pin that, and the TOML parse error that already fails closed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigValidationError

# One suppression and a non-default verdict field, so a config that was loaded can be
# told apart from the defaults (no suppressions, fail_on_findings true).
GOOD_YAML = """\
fail_on_findings: false
global_settings:
  suppressions:
    - rule_id: B101
      path: "**"
      reason: fixture
"""

# The same document with a flow sequence that never closes.
BAD_YAML = GOOD_YAML + "  extra: [unclosed\n"

BAD_JSON = '{"fail_on_findings": false,'

# Valid UTF-8 up to the comment, then two bytes that are not.
NON_UTF8 = b"fail_on_findings: false\n# \xff\xfe\n"


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    """ASH_CONFIG changes what the defaults are; only the tests that set it see it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _resolve(**kwargs: Any) -> Tuple[Optional[AshConfig], Optional[BaseException]]:
    """resolve_config's result: (config, None) when it returned, (None, exc) when it raised."""
    try:
        return resolve_config(**kwargs), None
    except Exception as exc:  # the tests assert on the type
        return None, exc


def _describe(config: Optional[AshConfig]) -> Dict[str, Any]:
    if config is None:
        return {}
    return {
        "fail_on_findings": config.fail_on_findings,
        "suppressions": len(config.global_settings.suppressions or []),
    }


def _assert_refused(
    config: Optional[AshConfig], error: Optional[BaseException], path: Path
) -> None:
    assert config is None, (
        f"resolve_config returned a config instead of refusing {path.name}: "
        f"{_describe(config)}"
    )
    assert isinstance(error, ASHConfigValidationError), (
        f"expected ASHConfigValidationError for {path.name}, got {error!r}"
    )
    assert path.name in str(error), f"the refusal does not name {path.name}: {error}"


EXPLICIT_UNLOADABLE = [
    pytest.param("cfg.yaml", BAD_YAML, id="yaml_syntax_error"),
    pytest.param("cfg.yml", BAD_YAML, id="yml_syntax_error"),
    pytest.param("cfg.json", BAD_JSON, id="json_syntax_error"),
    pytest.param("cfg.yaml", NON_UTF8, id="yaml_not_utf8"),
    pytest.param("cfg.json", NON_UTF8, id="json_not_utf8"),
]


class TestExplicitConfigPath:
    """``config_path`` set by the caller: ``--config``, the Python API, MCP."""

    def test_missing_file_is_refused(self, tmp_path):
        missing = tmp_path / "nope.yaml"
        _assert_refused(*_resolve(config_path=missing, source_dir=tmp_path), missing)

    def test_missing_file_given_as_a_string_is_refused(self, tmp_path):
        missing = tmp_path / "nope.yaml"
        _assert_refused(
            *_resolve(config_path=str(missing), source_dir=str(tmp_path)), missing
        )

    @pytest.mark.parametrize(("name", "content"), EXPLICIT_UNLOADABLE)
    def test_unloadable_file_is_refused(self, tmp_path, name, content):
        path = _write(tmp_path / name, content)
        _assert_refused(*_resolve(config_path=path, source_dir=tmp_path), path)

    def test_path_that_is_a_directory_is_refused(self, tmp_path):
        directory = tmp_path / "config.yaml"
        directory.mkdir()
        _assert_refused(
            *_resolve(config_path=directory, source_dir=tmp_path), directory
        )

    def test_unloadable_file_is_refused_with_overrides(self, tmp_path):
        """Overrides are applied on top of a file, never on top of the defaults instead."""
        path = _write(tmp_path / "cfg.yaml", BAD_YAML)
        _assert_refused(
            *_resolve(
                config_path=path,
                source_dir=tmp_path,
                config_overrides=["project_name=override"],
            ),
            path,
        )

    def test_control_loadable_file_is_used(self, tmp_path):
        path = _write(tmp_path / "cfg.yaml", GOOD_YAML)
        config, error = _resolve(config_path=path, source_dir=tmp_path)
        assert error is None
        assert _describe(config) == {"fail_on_findings": False, "suppressions": 1}


DISCOVERED_UNLOADABLE = [
    pytest.param(".ash/.ash.yaml", BAD_YAML, id="dot_ash_dir_yaml_syntax_error"),
    pytest.param(".ash.yaml", BAD_YAML, id="root_yaml_syntax_error"),
    pytest.param(".ash.yml", BAD_YAML, id="root_yml_syntax_error"),
    pytest.param("ash.yaml", BAD_YAML, id="undotted_yaml_syntax_error"),
    pytest.param(".ash.json", BAD_JSON, id="root_json_syntax_error"),
    pytest.param(".ashrc.yaml", BAD_YAML, id="ashrc_yaml_syntax_error"),
    pytest.param(".ashrc.json", BAD_JSON, id="ashrc_json_syntax_error"),
    pytest.param(".ash/.ash.yaml", NON_UTF8, id="dot_ash_dir_yaml_not_utf8"),
]


class TestDiscoveredConfigFile:
    """No ``config_path``: the file discovery picks in the source directory."""

    @pytest.mark.parametrize(("relative", "content"), DISCOVERED_UNLOADABLE)
    def test_unloadable_file_is_refused(self, tmp_path, relative, content):
        path = _write(tmp_path / relative, content)
        _assert_refused(*_resolve(source_dir=tmp_path), path)

    def test_dangling_symlink_in_a_config_location_is_refused(self, tmp_path):
        """A config name that points at nothing is a config that cannot be read.

        Typical cause: ``.ash/.ash.yaml`` linked to a shared file that is not checked
        out in CI. Treating it as "no config" scans with the defaults.
        """
        link = tmp_path / ".ash" / ".ash.yaml"
        link.parent.mkdir()
        link.symlink_to(tmp_path / "shared" / "ash.yaml")
        _assert_refused(*_resolve(source_dir=tmp_path), link)

    def test_control_toml_parse_error_is_already_refused(self, tmp_path):
        path = _write(tmp_path / ".ashrc.toml", "fail_on_findings = false\n[global\n")
        _assert_refused(*_resolve(source_dir=tmp_path), path)

    def test_control_loadable_discovered_file_is_used(self, tmp_path):
        _write(tmp_path / ".ash" / ".ash.yaml", GOOD_YAML)
        config, error = _resolve(source_dir=tmp_path)
        assert error is None
        assert _describe(config) == {"fail_on_findings": False, "suppressions": 1}


class TestAshConfigVariable:
    """ASH_CONFIG names the config file when the caller passes no ``config_path``."""

    def test_missing_file_named_by_the_variable_is_refused(self, tmp_path, monkeypatch):
        missing = tmp_path / "nope.yaml"
        monkeypatch.setenv("ASH_CONFIG", str(missing))
        source = tmp_path / "src"
        source.mkdir()
        _assert_refused(*_resolve(source_dir=source), missing)

    def test_unparseable_file_named_by_the_variable_is_refused(
        self, tmp_path, monkeypatch
    ):
        path = _write(tmp_path / "env.yaml", BAD_YAML)
        monkeypatch.setenv("ASH_CONFIG", str(path))
        source = tmp_path / "src"
        source.mkdir()
        _assert_refused(*_resolve(source_dir=source), path)


class TestNoConfigFile:
    """The one case that resolves to the defaults: nothing to load."""

    def test_control_empty_source_dir_resolves_to_the_defaults(self, tmp_path):
        config, error = _resolve(source_dir=tmp_path)
        assert error is None
        assert _describe(config) == {"fail_on_findings": True, "suppressions": 0}

    def test_control_unrelated_files_are_not_a_config(self, tmp_path):
        _write(tmp_path / "settings.yaml", BAD_YAML)
        _write(tmp_path / "pyproject.toml", "[project]\nname = 'x'\n")
        config, error = _resolve(source_dir=tmp_path)
        assert error is None
        assert _describe(config) == {"fail_on_findings": True, "suppressions": 0}
