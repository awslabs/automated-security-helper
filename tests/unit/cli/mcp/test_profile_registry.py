# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MCP config-profile registry (Track 10.3).

These cover the *startup-time* surface only — parsing CLI specs, loading the
files via :meth:`AshConfig.from_file`, rejecting duplicate / missing /
malformed inputs, and seeding the process-local registry singleton. The
per-session bind path (``mcp_select_profile``) lives in a sibling test file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    ProfileEntry,
    ProfileRegistryError,
    clear_profile_registry,
    get_profile_registry,
    parse_profile_spec,
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.config.ash_config import AshConfig


@pytest.fixture(autouse=True)
def _isolate_registry() -> None:
    """Ensure each test runs against an empty global registry."""
    clear_profile_registry()
    yield
    clear_profile_registry()


def _write_yaml(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _valid_config_yaml(project_name: str = "registry-fixture") -> str:
    # AshConfig accepts an empty document, but giving it a unique
    # `project_name` makes assertions stronger downstream.
    return f"project_name: {project_name}\n"


class TestParseProfileSpec:
    def test_valid_spec_parses_name_and_path(self, tmp_path: Path) -> None:
        cfg = _write_yaml(tmp_path / "p.yaml", _valid_config_yaml())
        name, path = parse_profile_spec(f"default={cfg}")
        assert name == "default"
        assert path == cfg

    def test_spec_strips_whitespace(self, tmp_path: Path) -> None:
        cfg = _write_yaml(tmp_path / "p.yaml", _valid_config_yaml())
        name, path = parse_profile_spec(f"  strict  =  {cfg}  ")
        assert name == "strict"
        assert str(path) == str(cfg)

    def test_missing_equals_rejected(self) -> None:
        with pytest.raises(ProfileRegistryError) as exc:
            parse_profile_spec("default-only-name")
        assert "NAME=path" in str(exc.value)

    def test_missing_name_rejected(self, tmp_path: Path) -> None:
        cfg = _write_yaml(tmp_path / "p.yaml", _valid_config_yaml())
        with pytest.raises(ProfileRegistryError) as exc:
            parse_profile_spec(f"={cfg}")
        assert "missing name" in str(exc.value)

    def test_missing_path_rejected(self) -> None:
        with pytest.raises(ProfileRegistryError) as exc:
            parse_profile_spec("default=")
        assert "missing path" in str(exc.value)


class TestRegisterProfiles:
    def test_single_profile_loads_and_validates(self, tmp_path: Path) -> None:
        cfg = _write_yaml(
            tmp_path / "default.yaml",
            _valid_config_yaml("p-default"),
        )
        registry = register_profiles([f"default={cfg}"])
        assert "default" in registry
        entry = registry["default"]
        assert isinstance(entry, ProfileEntry)
        assert isinstance(entry.config, AshConfig)
        assert entry.config.project_name == "p-default"
        # SHA-256 of an absolute path is a 64-char hex string.
        assert len(entry.path_sha256) == 64
        assert all(c in "0123456789abcdef" for c in entry.path_sha256)

    def test_multiple_profiles_register_independently(
        self, tmp_path: Path
    ) -> None:
        a = _write_yaml(tmp_path / "a.yaml", _valid_config_yaml("a"))
        b = _write_yaml(tmp_path / "b.yaml", _valid_config_yaml("b"))
        registry = register_profiles([f"alpha={a}", f"beta={b}"])
        assert set(registry) == {"alpha", "beta"}
        assert registry["alpha"].config.project_name == "a"
        assert registry["beta"].config.project_name == "b"
        # Different absolute paths → different hashes.
        assert registry["alpha"].path_sha256 != registry["beta"].path_sha256

    def test_duplicate_name_rejected(self, tmp_path: Path) -> None:
        a = _write_yaml(tmp_path / "a.yaml", _valid_config_yaml("a"))
        b = _write_yaml(tmp_path / "b.yaml", _valid_config_yaml("b"))
        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"dup={a}", f"dup={b}"])
        assert "duplicate" in str(exc.value)
        assert "dup" in str(exc.value)

    def test_missing_file_rejected(self, tmp_path: Path) -> None:
        ghost = tmp_path / "does-not-exist.yaml"
        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"missing={ghost}"])
        assert "missing file" in str(exc.value)
        assert str(ghost) in str(exc.value)

    def test_invalid_yaml_rejected(self, tmp_path: Path) -> None:
        # Genuinely malformed YAML — unclosed flow mapping.
        bad = _write_yaml(tmp_path / "bad.yaml", "project_name: {unclosed\n")
        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"broken={bad}"])
        # The wrapper preserves the underlying YAML parser message.
        assert "broken" in str(exc.value)

    def test_invalid_schema_rejected(self, tmp_path: Path) -> None:
        # Valid YAML but violates AshConfig (extra='forbid').
        bad = _write_yaml(
            tmp_path / "schema-bad.yaml",
            "definitely_not_a_real_field: 1\n",
        )
        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"badschema={bad}"])
        assert "badschema" in str(exc.value)

    def test_atomic_failure_does_not_partially_install(
        self, tmp_path: Path
    ) -> None:
        # The registry singleton must remain empty when registration fails;
        # callers like ``mcp_command`` rely on "all-or-nothing" so a half-
        # registered set never leaks into the running server.
        good = _write_yaml(tmp_path / "good.yaml", _valid_config_yaml("g"))
        ghost = tmp_path / "ghost.yaml"
        with pytest.raises(ProfileRegistryError):
            register_profiles([f"good={good}", f"bad={ghost}"])
        assert get_profile_registry() == {}


class TestRegistrySingleton:
    def test_set_then_get_round_trips(self, tmp_path: Path) -> None:
        cfg = _write_yaml(tmp_path / "x.yaml", _valid_config_yaml("x"))
        registry = register_profiles([f"x={cfg}"])
        set_profile_registry(registry)
        retrieved = get_profile_registry()
        assert "x" in retrieved
        assert retrieved["x"].config.project_name == "x"

    def test_get_returns_copy_not_live_dict(self, tmp_path: Path) -> None:
        cfg = _write_yaml(tmp_path / "x.yaml", _valid_config_yaml("x"))
        set_profile_registry(register_profiles([f"x={cfg}"]))
        snapshot = get_profile_registry()
        snapshot.clear()
        # Mutating the returned dict must not affect the singleton.
        assert "x" in get_profile_registry()

    def test_set_overwrites_previous(self, tmp_path: Path) -> None:
        a = _write_yaml(tmp_path / "a.yaml", _valid_config_yaml("a"))
        b = _write_yaml(tmp_path / "b.yaml", _valid_config_yaml("b"))
        set_profile_registry(register_profiles([f"a={a}"]))
        assert "a" in get_profile_registry()
        set_profile_registry(register_profiles([f"b={b}"]))
        retrieved = get_profile_registry()
        assert "b" in retrieved
        assert "a" not in retrieved

    def test_clear_empties_registry(self, tmp_path: Path) -> None:
        cfg = _write_yaml(tmp_path / "x.yaml", _valid_config_yaml("x"))
        set_profile_registry(register_profiles([f"x={cfg}"]))
        assert get_profile_registry() != {}
        clear_profile_registry()
        assert get_profile_registry() == {}

    def test_register_profiles_does_not_install_until_set(
        self, tmp_path: Path
    ) -> None:
        # ``register_profiles`` is pure — the caller decides when to flip
        # the singleton via ``set_profile_registry``. This separation lets
        # ``mcp_command`` keep "validation" and "install" distinct, so a
        # validation failure can't leak partial state.
        cfg = _write_yaml(tmp_path / "x.yaml", _valid_config_yaml("x"))
        registry = register_profiles([f"x={cfg}"])
        assert "x" in registry
        assert get_profile_registry() == {}


class TestPathSha256IsPathOnly:
    def test_sha256_changes_when_path_differs_but_content_same(
        self, tmp_path: Path
    ) -> None:
        body = _valid_config_yaml("same-content")
        a = _write_yaml(tmp_path / "a.yaml", body)
        b = _write_yaml(tmp_path / "b.yaml", body)
        ra = register_profiles([f"a={a}"])["a"]
        rb = register_profiles([f"b={b}"])["b"]
        # Same content, different absolute paths → different hashes.
        assert ra.path_sha256 != rb.path_sha256
