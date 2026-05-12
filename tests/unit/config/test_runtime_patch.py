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
        """Atomicity: a single denied op aborts the whole patch and leaves the
        base config object byte-for-byte identical to what it was before the
        call (snapshot via model_dump, since `_base_config` returns a fresh
        instance each time and equality on that would be tautological)."""
        base = _base_config()
        before = base.model_dump(by_alias=True)
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
        assert base.model_dump(by_alias=True) == before

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
        # These are the schema-real fields the default denylist must cover.
        assert "/fail_on_findings" in denied
        assert "/global_settings/ignore_paths" in denied
        assert "/global_settings/suppressions" in denied
        assert "/reporters/bedrock-summary-reporter/options/aws_*" in denied
        assert "/reporters/cloudwatch-logs/**" in denied

    def test_every_default_denied_path_is_reachable_in_schema(self) -> None:
        """Every default denied_paths entry must point at a real AshConfig
        location so the denylist isn't quietly a no-op (regression for DA #73,
        which called out the previous `/global_settings/fail_fast` etc. as
        fictional schema paths). For glob-bearing entries we resolve the prefix
        up to (but not including) the first wildcard segment.

        Plugin-provided reporters (`bedrock-summary-reporter`, `cloudwatch-logs`)
        are NOT present on a default `AshConfig`; we materialize them here via
        model_validate so the schema check covers extras that real plugins add.
        """
        cfg = AshConfig.model_validate(
            {
                "reporters": {
                    "bedrock-summary-reporter": {"options": {"aws_region": "us-east-1"}},
                    "cloudwatch-logs": {"options": {"aws_region": "us-east-1"}},
                }
            }
        )
        dumped = cfg.model_dump(by_alias=True)
        denied = cfg.global_settings.mcp.runtime_overrides.denied_paths

        def _resolve_prefix(path: str) -> bool:
            # Walk segments up to the first wildcard. If the prefix exists in
            # the dumped dict, the denylist entry is anchored to a real path.
            assert path.startswith("/"), f"non-pointer denied path: {path!r}"
            node: object = dumped
            for seg in path[1:].split("/"):
                if "*" in seg or seg == "-":
                    return True  # wildcard prefix reached — anchor verified
                if isinstance(node, dict) and seg in node:
                    node = node[seg]
                    continue
                return False
            return True

        unreachable = [p for p in denied if not _resolve_prefix(p)]
        assert unreachable == [], (
            f"default denied_paths contains unreachable entries: {unreachable}"
        )


class TestRecursiveValuePattern:
    def test_value_pattern_matches_string_leaf_in_list(self) -> None:
        """#72 regression: a forbidden token hidden in a list value must be
        rejected. The previous json.dumps-and-search implementation would
        catch this by accident (because dumps emitted the substring), but the
        recursive walker should catch it deterministically."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/external_reports_to_include"],
            denied_paths=[],
            denied_value_patterns={"/external_reports_to_include": r"DROP TABLE"},
        )
        ops = [
            {
                "op": "replace",
                "path": "/external_reports_to_include",
                "value": ["/tmp/a.sarif", "DROP TABLE users", "/tmp/b.sarif"],
            }
        ]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "denied_value_patterns" in excinfo.value.rule

    def test_value_pattern_matches_string_leaf_in_nested_dict(self) -> None:
        """#72 regression: forbidden token nested inside a dict value."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/converters"],
            denied_paths=[],
            denied_value_patterns={"/converters": r"\$\(.*\)"},
        )
        ops = [
            {
                "op": "replace",
                "path": "/converters",
                "value": {"jupyter": {"options": {"foo": "bar $(whoami)"}}},
            }
        ]
        with pytest.raises(RuntimePatchDeniedError):
            apply_runtime_patch(base, ops, allowlist=allowlist)

    def test_value_pattern_no_match_in_safe_nested_value(self) -> None:
        """Safe nested values must pass; we only reject on real leaf matches."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/external_reports_to_include"],
            denied_paths=[],
            denied_value_patterns={"/external_reports_to_include": r"DROP TABLE"},
        )
        ops = [
            {
                "op": "replace",
                "path": "/external_reports_to_include",
                "value": ["/tmp/a.sarif", "/tmp/b.sarif"],
            }
        ]
        # Should apply cleanly.
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.external_reports_to_include == ["/tmp/a.sarif", "/tmp/b.sarif"]

    def test_value_key_missing_distinguished_from_explicit_null(self) -> None:
        """#72 regression: an op with no `value` key must be treated as
        'no value to check' and pass the value-pattern guard, while a
        `value: None` for a non-string field must also be benign (None is not
        a string leaf). Both should reach jsonpatch (which will then reject
        the missing-value form on its own)."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/project_name"],
            denied_paths=[],
            denied_value_patterns={"/project_name": r"^secret-.*$"},
        )
        # Missing `value` key — value-pattern guard returns early; jsonpatch
        # then raises because `add` requires a value.
        ops_missing = [{"op": "add", "path": "/project_name"}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops_missing, allowlist=allowlist)
        # Should be a jsonpatch failure, NOT a value-pattern denial.
        assert "denied_value_patterns" not in excinfo.value.rule

    def test_test_op_is_exempt_from_value_pattern(self) -> None:
        """#75 cleanup: `test` ops are read-only and must not be subjected to
        the value-pattern guard. They still go through allowed/denied path
        checks via _check_op_paths."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/project_name"],
            denied_paths=[],
            denied_value_patterns={"/project_name": r"^.*$"},  # would deny everything
        )
        ops = [{"op": "test", "path": "/project_name", "value": base.project_name}]
        # Should not raise on the value pattern; jsonpatch will succeed since
        # the test matches the actual project_name.
        apply_runtime_patch(base, ops, allowlist=allowlist)


class TestRfc6901Escapes:
    def test_path_with_escaped_slash_matches_pattern(self) -> None:
        """#74 regression: `~1` decodes to `/` in pointer segments. A patch
        targeting a key that literally contains `/` must round-trip through
        unescape on both sides of the matcher."""
        base = _base_config()
        # An allowlist whose pattern contains the literal segment "a/b" (encoded as "a~1b").
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/converters/a~1b"],
            denied_paths=[],
        )
        # Op path uses the same encoding; both must decode to the same segments.
        ops = [{"op": "test", "path": "/converters/a~1b", "value": None}]
        # We expect jsonpatch to reject (no such key) — but NOT the path check.
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "not in allowed_paths" not in excinfo.value.rule

    def test_path_with_escaped_tilde_decodes_correctly(self) -> None:
        """#74 regression: `~0` decodes to `~`, and order matters — `~01`
        must become `~1`, not `/`."""
        from automated_security_helper.config.runtime_patch import _path_segments

        # `~01` in a pointer segment → `~1` (literal ~ followed by 1), NOT `/`.
        assert _path_segments("/foo/~01") == ["foo", "~1"]
        # `~10` → `/0`
        assert _path_segments("/foo/~10") == ["foo", "/0"]
        # `~0~1` → `~/`
        assert _path_segments("/foo/~0~1") == ["foo", "~/"]
        # `~1~0` → `/~`
        assert _path_segments("/foo/~1~0") == ["foo", "/~"]

    def test_pattern_segment_unescape_symmetric_with_path(self) -> None:
        """Pattern and path must unescape symmetrically: a pattern segment
        of `~1foo` (literal `/foo`) must match a path segment of `~1foo`."""
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/x~1y"],  # one allowed key whose name is literally "x/y"
            denied_paths=[],
        )
        # Different path — should be denied because allowed_paths doesn't include it.
        ops = [{"op": "test", "path": "/x~1z", "value": None}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "not in allowed_paths" in excinfo.value.rule
