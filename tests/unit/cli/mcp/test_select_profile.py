# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``mcp_select_profile`` (Track 10.3).

Covers the three selection modes (static, inherit-and-patch, full-override),
mutual exclusion of ``patch_ops`` vs. ``override_yaml``, unknown profile
handling, and that the bind path stores the resolved config in the per-
session state slot ``mcp_select_profile`` is required to populate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    ProfileEntry,
    bind_session_config,  # noqa: F401 — imported for symmetry with binding tests
    clear_profile_registry,
    clear_session_state,
    get_profile_registry,
    get_session_state,
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import (
    mcp_list_profiles,
    mcp_select_profile,
)
from automated_security_helper.config.ash_config import (
    AshConfig,
    AshMcpConfig,
    RuntimeOverridesConfig,
)


@pytest.fixture(autouse=True)
def _isolate_state() -> None:
    """Each test starts with empty registry + empty session state."""
    clear_profile_registry()
    clear_session_state()
    yield
    clear_profile_registry()
    clear_session_state()


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _profile_with_runtime_overrides(
    *, project_name: str, allowed_paths: list[str]
) -> AshConfig:
    """Build an AshConfig whose runtime allowlist permits the given paths.

    The fixture flips ``enabled=True`` so ``apply_runtime_patch`` will not
    short-circuit on the master switch; ``denied_paths=[]`` removes the
    schema defaults that would otherwise block legitimate test ops.
    """
    return AshConfig(
        project_name=project_name,
        global_settings={
            "mcp": AshMcpConfig(
                runtime_overrides=RuntimeOverridesConfig(
                    enabled=True,
                    allowed_paths=allowed_paths,
                    denied_paths=[],
                )
            )
        },
    )


def _install_profile(name: str, cfg: AshConfig, tmp_path: Path) -> ProfileEntry:
    """Drop ``cfg`` to disk, register it under ``name``, install the registry.

    Returns the resulting :class:`ProfileEntry`.
    """
    import yaml

    file = _write(tmp_path / f"{name}.yaml", yaml.safe_dump(cfg.model_dump(by_alias=True)))
    registry = register_profiles([f"{name}={file}"])
    set_profile_registry(registry)
    return get_profile_registry()[name]


# ---------------------------------------------------------------------------
# Static select
# ---------------------------------------------------------------------------


class TestStaticSelect:
    def test_static_select_returns_success(self, tmp_path: Path) -> None:
        cfg = _profile_with_runtime_overrides(
            project_name="static-fixture",
            allowed_paths=["/project_name"],
        )
        _install_profile("default", cfg, tmp_path)
        result = mcp_select_profile("default")
        assert result["success"] is True
        assert result["mode"] == "static"
        assert result["profile_name"] == "default"
        assert result["session_id"] == DEFAULT_SESSION_ID

    def test_static_select_binds_profile_config_unchanged(
        self, tmp_path: Path
    ) -> None:
        cfg = _profile_with_runtime_overrides(
            project_name="static-fixture",
            allowed_paths=["/project_name"],
        )
        _install_profile("default", cfg, tmp_path)
        mcp_select_profile("default")
        state = get_session_state()
        assert state.bound_config is not None
        assert state.bound_config.project_name == "static-fixture"
        assert state.profile_name == "default"
        assert state.patch_ops is None
        assert state.override_yaml is None


# ---------------------------------------------------------------------------
# Inherit-and-patch
# ---------------------------------------------------------------------------


class TestInheritAndPatch:
    def test_patch_applied_via_runtime_patch(self, tmp_path: Path) -> None:
        cfg = _profile_with_runtime_overrides(
            project_name="patch-fixture",
            allowed_paths=["/project_name"],
        )
        _install_profile("default", cfg, tmp_path)
        ops = [
            {"op": "replace", "path": "/project_name", "value": "patched-name"}
        ]
        result = mcp_select_profile("default", patch_ops=ops)
        assert result["success"] is True
        assert result["mode"] == "inherit_and_patch"

        state = get_session_state()
        assert state.bound_config is not None
        assert state.bound_config.project_name == "patched-name"
        assert state.patch_ops == ops

    def test_patch_targeting_disallowed_path_is_denied(
        self, tmp_path: Path
    ) -> None:
        # Allowlist only permits /project_name. A patch on /fail_on_findings
        # must hit ``apply_runtime_patch``'s "not in allowed_paths" rule.
        cfg = _profile_with_runtime_overrides(
            project_name="fixture",
            allowed_paths=["/project_name"],
        )
        _install_profile("default", cfg, tmp_path)
        ops = [
            {"op": "replace", "path": "/fail_on_findings", "value": False}
        ]
        result = mcp_select_profile("default", patch_ops=ops)
        assert result["success"] is False
        assert "denied" in result["error"]
        # No partial bind on rejection.
        assert get_session_state().bound_config is None

    def test_patch_with_disabled_allowlist_is_denied(
        self, tmp_path: Path
    ) -> None:
        # The Track 10.4 master switch defaults to False — even an
        # otherwise-allowed path must be rejected.
        cfg = AshConfig(project_name="disabled-fixture")
        _install_profile("default", cfg, tmp_path)
        ops = [
            {"op": "replace", "path": "/project_name", "value": "x"}
        ]
        result = mcp_select_profile("default", patch_ops=ops)
        assert result["success"] is False
        assert "denied" in result["error"]


# ---------------------------------------------------------------------------
# Full override
# ---------------------------------------------------------------------------


class TestFullOverride:
    def test_override_replaces_resolved_config(self, tmp_path: Path) -> None:
        cfg = _profile_with_runtime_overrides(
            project_name="profile-name",
            allowed_paths=["/project_name"],
        )
        _install_profile("default", cfg, tmp_path)
        override = "project_name: override-name\n"
        result = mcp_select_profile("default", override_yaml=override)
        assert result["success"] is True
        assert result["mode"] == "override"

        state = get_session_state()
        assert state.bound_config is not None
        assert state.bound_config.project_name == "override-name"
        assert state.override_yaml == override

    def test_override_validated_against_ashconfig(self, tmp_path: Path) -> None:
        cfg = AshConfig(project_name="profile-name")
        _install_profile("default", cfg, tmp_path)
        # ``definitely_not_a_real_field`` is rejected by the strict validator.
        result = mcp_select_profile(
            "default",
            override_yaml="definitely_not_a_real_field: 1\n",
        )
        assert result["success"] is False
        assert "validation error" in result["error"].lower()
        assert get_session_state().bound_config is None

    def test_override_yaml_parse_error(self, tmp_path: Path) -> None:
        cfg = AshConfig(project_name="profile-name")
        _install_profile("default", cfg, tmp_path)
        result = mcp_select_profile(
            "default",
            override_yaml="project_name: {unclosed\n",
        )
        assert result["success"] is False
        assert "parse error" in result["error"].lower()


# ---------------------------------------------------------------------------
# Mutual exclusion + bad-name handling
# ---------------------------------------------------------------------------


class TestMutualExclusion:
    def test_patch_ops_and_override_yaml_together_is_error(
        self, tmp_path: Path
    ) -> None:
        cfg = AshConfig(project_name="profile-name")
        _install_profile("default", cfg, tmp_path)
        result = mcp_select_profile(
            "default",
            patch_ops=[{"op": "replace", "path": "/project_name", "value": "x"}],
            override_yaml="project_name: y\n",
        )
        assert result["success"] is False
        assert "mutually exclusive" in result["error"]
        # Neither mode bound anything.
        assert get_session_state().bound_config is None


class TestBadProfileName:
    def test_unknown_name_returns_error(self, tmp_path: Path) -> None:
        cfg = AshConfig(project_name="profile-name")
        _install_profile("only", cfg, tmp_path)
        result = mcp_select_profile("does-not-exist")
        assert result["success"] is False
        assert "unknown profile" in result["error"]
        assert "only" in result["error"]  # known names listed for context

    def test_unknown_name_with_empty_registry_lists_none(self) -> None:
        result = mcp_select_profile("anything")
        assert result["success"] is False
        assert "none registered" in result["error"]


# ---------------------------------------------------------------------------
# list_profiles surface
# ---------------------------------------------------------------------------


class TestListProfiles:
    def test_empty_registry_returns_zero(self) -> None:
        result = mcp_list_profiles()
        assert result == {"profiles": [], "count": 0}

    def test_registered_profiles_listed_with_path_hash_only(
        self, tmp_path: Path
    ) -> None:
        cfg_a = AshConfig(project_name="alpha")
        cfg_b = AshConfig(project_name="beta")
        _install_profile("alpha", cfg_a, tmp_path)
        # Register a second profile WITHOUT clobbering the first.
        import yaml

        file_b = _write(
            tmp_path / "beta.yaml",
            yaml.safe_dump(cfg_b.model_dump(by_alias=True)),
        )
        existing = get_profile_registry()
        more = register_profiles([f"beta={file_b}"])
        existing.update(more)
        set_profile_registry(existing)

        result = mcp_list_profiles()
        assert result["count"] == 2
        names = [e["name"] for e in result["profiles"]]
        assert names == sorted(names) == ["alpha", "beta"]
        # No path or content leaks — only the SHA hash is exposed.
        for entry in result["profiles"]:
            assert set(entry) == {"name", "path_sha256"}
            assert len(entry["path_sha256"]) == 64


# ---------------------------------------------------------------------------
# Per-session isolation
# ---------------------------------------------------------------------------


class TestSessionIsolation:
    def test_distinct_session_ids_get_distinct_states(
        self, tmp_path: Path
    ) -> None:
        cfg = _profile_with_runtime_overrides(
            project_name="multi-session",
            allowed_paths=["/project_name"],
        )
        _install_profile("default", cfg, tmp_path)

        mcp_select_profile("default", session_id="session-1")
        mcp_select_profile(
            "default",
            patch_ops=[
                {"op": "replace", "path": "/project_name", "value": "session-2-name"}
            ],
            session_id="session-2",
        )

        s1 = get_session_state("session-1")
        s2 = get_session_state("session-2")
        assert s1.bound_config is not None
        assert s2.bound_config is not None
        assert s1.bound_config.project_name == "multi-session"
        assert s2.bound_config.project_name == "session-2-name"
