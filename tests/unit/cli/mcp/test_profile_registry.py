# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MCP config-profile registry (Track 10.3).

These cover the *startup-time* surface only — parsing CLI specs, loading the
files via :meth:`AshConfig.from_file`, rejecting duplicate / missing /
malformed inputs, and seeding the process-local registry singleton. The
per-session bind path (``mcp_select_profile``) lives in a sibling test file.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    SESSION_CONFIG_FILENAME,
    ProfileEntry,
    ProfileRegistryError,
    clear_profile_registry,
    get_profile_registry,
    parse_profile_spec,
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.cli.mcp.sandbox import CONFIG_DIR_NAME
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


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

    @pytest.mark.parametrize("name", ["p.json", "p.JSON"])
    def test_a_json_profile_is_read_as_json(self, tmp_path: Path, name) -> None:
        """Both loads (the model's and the top-level key gate) read it as JSON,
        whatever the suffix's case. JSON indented with a tab is not YAML."""
        cfg = _write_yaml(tmp_path / name, '{\n\t"project_name": "p-json"\n}\n')
        registry = register_profiles([f"default={cfg}"])
        assert registry["default"].config.project_name == "p-json"

    @pytest.mark.parametrize("name", ["p.toml", "P.TOML"])
    def test_a_toml_profile_registers(self, tmp_path: Path, name) -> None:
        """The top-level key gate read every profile as YAML or JSON, so a TOML
        profile's lines were refused as unknown fields."""
        cfg = _write_yaml(tmp_path / name, 'project_name = "p-toml"\n')
        registry = register_profiles([f"default={cfg}"])
        assert registry["default"].config.project_name == "p-toml"

    def test_a_toml_profile_with_an_unknown_field_is_refused(
        self, tmp_path: Path
    ) -> None:
        cfg = _write_yaml(tmp_path / "p.toml", 'project_name = "x"\nbogus_key = 1\n')
        with pytest.raises(ProfileRegistryError, match="bogus_key"):
            register_profiles([f"default={cfg}"])

    def test_multiple_profiles_register_independently(self, tmp_path: Path) -> None:
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
        # The refusal names the profile; the parse error is given by its type
        # and place only (config_sources.unparsed_config_reason).
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

    def test_a_profile_using_tagged_env_registers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The top-level key check reads the file as from_file does, so a tag the
        # loader resolves is not refused by a plain YAML parser first.
        monkeypatch.setenv("ASH_PROFILE_NAME_PROBE", "from-env")
        cfg = _write_yaml(
            tmp_path / "env.yaml",
            "project_name: !ENV ${ASH_PROFILE_NAME_PROBE:unset}\n",
        )
        registry = register_profiles([f"env={cfg}"])
        assert registry["env"].config.project_name == "from-env"

    def test_a_toml_profile_registers_and_is_still_checked(
        self, tmp_path: Path
    ) -> None:
        good = _write_yaml(tmp_path / "good.ashrc.toml", 'project_name = "toml"\n')
        bad = _write_yaml(tmp_path / "bad.ashrc.toml", "not_a_field = 1\n")

        registry = register_profiles([f"toml={good}"])
        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"bad={bad}"])

        assert registry["toml"].config.project_name == "toml"
        assert "not_a_field" in str(exc.value)

    def test_atomic_failure_does_not_partially_install(self, tmp_path: Path) -> None:
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

    def test_register_profiles_does_not_install_until_set(self, tmp_path: Path) -> None:
        # ``register_profiles`` is pure — the caller decides when to flip
        # the singleton via ``set_profile_registry``. This separation lets
        # ``mcp_command`` keep "validation" and "install" distinct, so a
        # validation failure can't leak partial state.
        cfg = _write_yaml(tmp_path / "x.yaml", _valid_config_yaml("x"))
        registry = register_profiles([f"x={cfg}"])
        assert "x" in registry
        assert get_profile_registry() == {}


class TestProfilesThatExtend:
    """A profile loads through AshConfig.from_file, which follows `extends`
    and applies `patch`, so the check of its top-level keys must not refuse
    either directive as an unknown field. Each file of the chain is checked,
    so a base's typo fails at boot too."""

    def test_a_profile_that_extends_a_base_registers(self, tmp_path: Path) -> None:
        _write_yaml(tmp_path / "base.yaml", "project_name: from-base\n")
        cfg = _write_yaml(
            tmp_path / "p.yaml",
            "extends: base.yaml\nfail_on_findings: false\n",
        )

        registry = register_profiles([f"default={cfg}"])

        assert registry["default"].config.project_name == "from-base"
        assert registry["default"].config.fail_on_findings is False

    def test_a_profile_that_patches_its_base_registers(self, tmp_path: Path) -> None:
        _write_yaml(tmp_path / "base.yaml", "project_name: from-base\n")
        cfg = _write_yaml(
            tmp_path / "p.yaml",
            "extends: base.yaml\npatch:\n"
            "  - {op: replace, path: /project_name, value: patched}\n",
        )

        registry = register_profiles([f"default={cfg}"])

        assert registry["default"].config.project_name == "patched"

    def test_an_unknown_field_in_a_base_is_refused(self, tmp_path: Path) -> None:
        base = _write_yaml(
            tmp_path / "base.yaml", "project_name: b\nbogus_base_key: 1\n"
        )
        cfg = _write_yaml(tmp_path / "p.yaml", "extends: base.yaml\n")

        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"default={cfg}"])

        assert "bogus_base_key" in str(exc.value)
        assert base.name in str(exc.value)

    def test_a_base_outside_the_profiles_directory_is_refused(
        self, tmp_path: Path
    ) -> None:
        _write_yaml(tmp_path / "outside.yaml", "project_name: out\n")
        (tmp_path / "profiles").mkdir()
        cfg = _write_yaml(
            tmp_path / "profiles" / "p.yaml", "extends: ../outside.yaml\n"
        )

        with pytest.raises(ProfileRegistryError):
            register_profiles([f"default={cfg}"])

    def test_a_base_named_by_a_variable_registers_and_hides_its_value(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("ASH_TEST_PROBE", "SECRETDIRZQ.yaml")
        _write_yaml(tmp_path / "SECRETDIRZQ.yaml", "project_name: env-base\n")
        cfg = _write_yaml(
            tmp_path / "p.yaml", "extends: ${ASH_TEST_PROBE:missing.yaml}\n"
        )

        registry = register_profiles([f"default={cfg}"])
        assert registry["default"].config.project_name == "env-base"

        (tmp_path / "SECRETDIRZQ.yaml").unlink()
        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"default={cfg}"])
        assert "SECRETDIRZQ" not in str(exc.value), exc.value


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


class TestAProfileKeptWhereAScanMayRewriteIt:
    """A profile is the operator's trusted base, so one kept where a client's
    delivery or a scanned checkout's owner can rewrite it is refused when it is
    registered, before its content is read: a file under a session workspace
    below the MCP workspace root (by the scan's own classifier, which admits the
    profile files the server writes in a session's ``config/`` directory), and a
    file under a granted scan root with a git checkout among its ancestors,
    below the root or holding it. The bases a profile extends are judged the
    same way once the load has named them (a checkout nested under the
    profile's directory holds a base the walk up from the profile never meets).
    A plain file under a granted root with no checkout above it, and a checkout
    outside every granted root, register as before."""

    @pytest.fixture(autouse=True)
    def _roots(self, tmp_path: Path, monkeypatch) -> None:
        self.allowed = tmp_path / "allowed"
        self.workspaces = tmp_path / "workspaces"
        self.allowed.mkdir()
        self.workspaces.mkdir()
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(self.allowed))
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(self.workspaces))

    def test_a_profile_under_a_sessions_delivered_source_is_refused(self) -> None:
        delivered = self.workspaces / "some-session" / "source"
        delivered.mkdir(parents=True)
        profile = _write_yaml(delivered / "ash.yaml", _valid_config_yaml())

        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"default={profile}"])

        message = str(exc.value)
        assert "'default'" in message
        assert str(profile) in message
        assert "workspace root" in message

    def test_a_sessions_own_config_profile_still_registers(self) -> None:
        # The file select_profile materializes for a session: written by the
        # server, so the classifier does not count it as the client's.
        config_dir = self.workspaces / "some-session" / CONFIG_DIR_NAME
        config_dir.mkdir(parents=True)
        profile = _write_yaml(
            config_dir / SESSION_CONFIG_FILENAME, _valid_config_yaml("own")
        )

        registry = register_profiles([f"own={profile}"])

        assert registry["own"].config.project_name == "own"

    def test_a_profile_inside_a_git_checkout_under_a_scan_root_is_refused(
        self,
    ) -> None:
        checkout = self.allowed / "checkout"
        (checkout / ".git").mkdir(parents=True)
        (checkout / ".ash").mkdir()
        profile = _write_yaml(checkout / ".ash" / "ash.yaml", _valid_config_yaml())

        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"default={profile}"])

        message = str(exc.value)
        assert str(profile) in message
        assert str(checkout.resolve()) in message
        assert "ASH_MCP_ALLOWED_ROOTS" in message

    def test_a_checkout_that_holds_the_scan_root_is_refused(
        self, tmp_path: Path
    ) -> None:
        """The granted root is a directory of a larger checkout: its ``.git``
        sits above the root. The tree the server scans is that checkout, and
        its owner can rewrite a profile kept anywhere under the root.

        Red at the base: the walk stopped at the granted root and never saw
        the ``.git`` above it, so the profile registered."""
        (tmp_path / ".git").mkdir()
        team = self.allowed / "team"
        team.mkdir()
        profile = _write_yaml(team / "ash.yaml", _valid_config_yaml("held"))

        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"default={profile}"])

        message = str(exc.value)
        assert str(profile) in message
        assert str(tmp_path.resolve()) in message
        assert "holds the scan root" in message
        assert "ASH_MCP_ALLOWED_ROOTS" in message

    def test_the_same_profile_under_a_root_with_no_checkout_registers(self) -> None:
        plain = self.allowed / "plain" / ".ash"
        plain.mkdir(parents=True)
        profile = _write_yaml(plain / "ash.yaml", _valid_config_yaml("plain"))

        registry = register_profiles([f"default={profile}"])

        assert registry["default"].config.project_name == "plain"

    def test_a_checkout_outside_every_scan_root_is_not_judged_here(
        self, tmp_path: Path
    ) -> None:
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / ".git").mkdir(parents=True)
        profile = _write_yaml(elsewhere / "ash.yaml", _valid_config_yaml("outside"))

        registry = register_profiles([f"default={profile}"])

        assert registry["default"].config.project_name == "outside"

    def test_a_base_inside_a_nested_checkout_is_refused(self) -> None:
        """Red at the base: only the profile's own file was judged, so a base in
        a checkout under the profile's directory was read as the operator's."""
        vendored = self.allowed / "vendor"
        (vendored / ".git").mkdir(parents=True)
        base = _write_yaml(vendored / "base.yaml", "project_name: from-vendor\n")
        profile = _write_yaml(self.allowed / "p.yaml", "extends: vendor/base.yaml\n")

        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"default={profile}"])

        message = str(exc.value)
        assert "extends" in message
        assert base.name in message
        assert str(vendored.resolve()) in message
        assert "ASH_MCP_ALLOWED_ROOTS" in message

    def test_a_base_beside_the_profile_under_a_plain_root_registers(self) -> None:
        plain = self.allowed / "plain"
        plain.mkdir()
        _write_yaml(plain / "base.yaml", "project_name: from-base\n")
        profile = _write_yaml(plain / "p.yaml", "extends: base.yaml\n")

        registry = register_profiles([f"default={profile}"])

        assert registry["default"].config.project_name == "from-base"

    @pytest.mark.skipif(os.name != "posix", reason="symbolic links need a posix host")
    def test_a_link_into_a_scanned_checkout_is_judged_by_where_it_leads(
        self, tmp_path: Path
    ) -> None:
        checkout = self.allowed / "checkout"
        (checkout / ".git").mkdir(parents=True)
        inside = _write_yaml(checkout / "ash.yaml", _valid_config_yaml())
        link = tmp_path / "etc" / "linked.yaml"
        link.parent.mkdir()
        os.symlink(inside, link)

        with pytest.raises(ProfileRegistryError) as exc:
            register_profiles([f"default={link}"])

        assert "ASH_MCP_ALLOWED_ROOTS" in str(exc.value)
