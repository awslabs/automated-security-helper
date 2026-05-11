"""Tests for the runtime override allowlist + JSON-Patch enforcement (Track 10.4)."""

from __future__ import annotations

import json

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_patch,
)


def _base_config() -> AshConfig:
    return AshConfig()


class TestAllowlistDisabled:
    def test_disabled_allowlist_denies_all_patches(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(enabled=False, allowed_paths=["/project_name"])
        ops = [{"op": "replace", "path": "/project_name", "value": "new"}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "disabled" in excinfo.value.rule.lower()

    def test_disabled_allowlist_denies_even_empty_patch(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(enabled=False)
        with pytest.raises(RuntimePatchDeniedError):
            apply_runtime_patch(base, [], allowlist=allowlist)


class TestAllowedPaths:
    def test_allowed_path_replace_applied(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/project_name"],
            denied_paths=[],
        )
        ops = [{"op": "replace", "path": "/project_name", "value": "renamed"}]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert isinstance(result, AshConfig)
        assert result.project_name == "renamed"

    def test_allowed_path_add_applied(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/external_reports_to_include/-"],
            denied_paths=[],
        )
        ops = [
            {
                "op": "add",
                "path": "/external_reports_to_include/-",
                "value": "/tmp/report.sarif",
            }
        ]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "/tmp/report.sarif" in result.external_reports_to_include

    def test_allowed_glob_segment_match(self) -> None:
        base = _base_config()
        # /global_settings/* matches /global_settings/severity_threshold
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/*"],
            denied_paths=[],
        )
        ops = [
            {"op": "replace", "path": "/global_settings/severity_threshold", "value": "HIGH"}
        ]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.global_settings.severity_threshold == "HIGH"

    def test_allowed_subtree_glob(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/**"],
            denied_paths=[],
        )
        ops = [
            {"op": "replace", "path": "/global_settings/severity_threshold", "value": "HIGH"}
        ]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.global_settings.severity_threshold == "HIGH"

    def test_path_not_in_allowed_paths_is_denied(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/project_name"],
            denied_paths=[],
        )
        ops = [{"op": "replace", "path": "/fail_on_findings", "value": False}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "not in allowed_paths" in excinfo.value.rule


class TestDeniedPaths:
    def test_denied_path_overlapping_allowed_is_denied(self) -> None:
        """Denied wins when a path is both allowed and denied."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/**"],
            denied_paths=["/global_settings/fail_fast"],
        )
        ops = [{"op": "add", "path": "/global_settings/fail_fast", "value": True}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "denied_paths" in excinfo.value.rule

    def test_denied_partial_segment_glob(self) -> None:
        """Default denylist uses partial-segment globs like aws_*."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/scanners/**"],
            denied_paths=["/scanners/bedrock_summary/options/aws_*"],
        )
        ops = [
            {
                "op": "add",
                "path": "/scanners/bedrock_summary/options/aws_region",
                "value": "us-east-1",
            }
        ]
        with pytest.raises(RuntimePatchDeniedError):
            apply_runtime_patch(base, ops, allowlist=allowlist)

    def test_denied_subtree_glob(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/reporters/**"],
            denied_paths=["/reporters/bedrock_summary/**"],
        )
        ops = [
            {
                "op": "add",
                "path": "/reporters/bedrock_summary/options/model",
                "value": "claude",
            }
        ]
        with pytest.raises(RuntimePatchDeniedError):
            apply_runtime_patch(base, ops, allowlist=allowlist)


class TestForbiddenOps:
    def test_move_op_denied(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[],
        )
        ops = [{"op": "move", "from": "/project_name", "path": "/external_reports_to_include"}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "move" in excinfo.value.rule.lower()

    def test_copy_op_denied(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[],
        )
        ops = [{"op": "copy", "from": "/project_name", "path": "/some/other/path"}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "copy" in excinfo.value.rule.lower()


class TestSizeLimit:
    def test_patch_over_64kib_denied(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[],
        )
        # Build a patch whose serialized JSON exceeds 64 KiB.
        big_value = "x" * (70 * 1024)
        ops = [{"op": "replace", "path": "/project_name", "value": big_value}]
        assert len(json.dumps(ops).encode("utf-8")) > 64 * 1024
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "size" in excinfo.value.rule.lower() or "64" in excinfo.value.rule

    def test_patch_at_64kib_boundary_allowed(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/project_name"],
            denied_paths=[],
        )
        ops = [{"op": "replace", "path": "/project_name", "value": "ok"}]
        # Sanity check size
        assert len(json.dumps(ops).encode("utf-8")) < 64 * 1024
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.project_name == "ok"


class TestDeniedValuePatterns:
    def test_value_pattern_match_denies(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/project_name"],
            denied_paths=[],
            denied_value_patterns={"/project_name": r"^secret-.*$"},
        )
        ops = [{"op": "replace", "path": "/project_name", "value": "secret-leak"}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "denied_value_patterns" in excinfo.value.rule

    def test_value_pattern_no_match_allowed(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/project_name"],
            denied_paths=[],
            denied_value_patterns={"/project_name": r"^secret-.*$"},
        )
        ops = [{"op": "replace", "path": "/project_name", "value": "fine-name"}]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.project_name == "fine-name"


class TestValidationAfterApply:
    def test_invalid_resulting_config_rejected(self) -> None:
        """Patches that produce an invalid AshConfig must be rejected."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/severity_threshold"],
            denied_paths=[],
        )
        ops = [
            {
                "op": "replace",
                "path": "/global_settings/severity_threshold",
                "value": "BOGUS_LEVEL",
            }
        ]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "validation" in excinfo.value.rule.lower()


class TestAtomicMultiOp:
    def test_one_denied_op_fails_entire_patch(self) -> None:
        """Atomicity: a single denied op aborts the whole patch."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=["/fail_on_findings"],
        )
        ops = [
            {"op": "replace", "path": "/project_name", "value": "applied"},
            {"op": "replace", "path": "/fail_on_findings", "value": False},
        ]
        with pytest.raises(RuntimePatchDeniedError):
            apply_runtime_patch(base, ops, allowlist=allowlist)
        # Base must remain untouched (atomicity).
        assert base.project_name != "applied"

    def test_multi_op_all_allowed_applies(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/project_name", "/external_reports_to_include/-"],
            denied_paths=[],
        )
        ops = [
            {"op": "replace", "path": "/project_name", "value": "renamed"},
            {
                "op": "add",
                "path": "/external_reports_to_include/-",
                "value": "/tmp/r.sarif",
            },
        ]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.project_name == "renamed"
        assert "/tmp/r.sarif" in result.external_reports_to_include


class TestDefaults:
    def test_default_runtime_overrides_disabled(self) -> None:
        cfg = AshConfig()
        assert cfg.global_settings.mcp.runtime_overrides.enabled is False

    def test_default_runtime_overrides_includes_critical_denied_paths(self) -> None:
        cfg = AshConfig()
        denied = cfg.global_settings.mcp.runtime_overrides.denied_paths
        assert "/global_settings/fail_fast" in denied
        assert "/global_settings/ignore_paths" in denied
