"""Tests for the runtime override allowlist + JSON-Patch enforcement (Track 10.4)."""

from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_override,
    apply_runtime_patch,
    check_runtime_ops,
    json_patch_between,
)


def _base_config() -> AshConfig:
    return AshConfig()


def _shipped_denied_paths() -> list[str]:
    """The denylist a default `AshConfig` ships.

    Read from the model instead of duplicated here, so a change to the shipped
    defaults cannot leave these regressions passing against a denylist nobody
    ships any more.
    """
    return list(AshConfig().global_settings.mcp.runtime_overrides.denied_paths)


# A suppression that silences every finding: `rule_id` defaults to None, which
# `AshSuppression.matches` reads as "every rule", and `path` "**" matches every
# file. `reason` is not decoration -- it is a required field on
# `IgnorePathWithReason`, so a payload without it is rejected by model
# validation after the patch applies. A test built on such a payload sees a
# denial and proves nothing about the denylist.
_BLANKET_SUPPRESSION = {"path": "**", "reason": "silence everything"}


class TestAllowlistDisabled:
    def test_disabled_allowlist_denies_all_patches(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=False, allowed_paths=["/project_name"]
        )
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
                "value": "/work/report.sarif",
            }
        ]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "/work/report.sarif" in result.external_reports_to_include

    def test_allowed_glob_segment_match(self) -> None:
        base = _base_config()
        # /global_settings/* matches /global_settings/severity_threshold
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/*"],
            denied_paths=[],
        )
        ops = [
            {
                "op": "replace",
                "path": "/global_settings/severity_threshold",
                "value": "HIGH",
            }
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
            {
                "op": "replace",
                "path": "/global_settings/severity_threshold",
                "value": "HIGH",
            }
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
        ops = [
            {
                "op": "move",
                "from": "/project_name",
                "path": "/external_reports_to_include",
            }
        ]
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
                "value": "/work/r.sarif",
            },
        ]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.project_name == "renamed"
        assert "/work/r.sarif" in result.external_reports_to_include


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
                    "bedrock-summary-reporter": {
                        "options": {"aws_region": "us-east-1"}
                    },
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
                "value": ["/work/a.sarif", "DROP TABLE users", "/work/b.sarif"],
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
                "value": ["/work/a.sarif", "/work/b.sarif"],
            }
        ]
        # Should apply cleanly.
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.external_reports_to_include == ["/work/a.sarif", "/work/b.sarif"]

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


class TestRootPointerRefused:
    """A write at the root pointer replaces the whole document, so no
    per-field `denied_paths` entry can constrain what it sets. The allowlist
    does not keep it out on its own: `**` matches zero segments, so the
    conventional `/**` entry matches the empty root path.
    """

    def test_root_replace_refused_even_with_subtree_allowlist(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[],
        )
        ops = [{"op": "replace", "path": "", "value": {"project_name": "swapped"}}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "root pointer" in excinfo.value.rule

    def test_root_add_refused(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[],
        )
        ops = [{"op": "add", "path": "", "value": {"project_name": "swapped"}}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "root pointer" in excinfo.value.rule

    def test_op_with_no_path_key_refused_as_root(self) -> None:
        """`path` is mandatory on every RFC 6902 op this module accepts. A
        missing key resolves to the root pointer, so it is refused rather than
        silently treated as an empty path that some allowlist glob matches.
        """
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[],
        )
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(
                base, [{"op": "replace", "value": 1}], allowlist=allowlist
            )
        assert "root pointer" in excinfo.value.rule

    def test_root_replace_allowed_when_allowlist_names_root_explicitly(self) -> None:
        """The refusal is an escape-hatch, not a wall: an operator who writes
        the root pointer into `allowed_paths` has asked for a whole-config
        swap, and with an empty denylist there is nothing left to constrain.
        """
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=[""],
            denied_paths=[],
        )
        swapped = base.model_dump(mode="json", by_alias=False)
        swapped["project_name"] = "swapped"
        result = apply_runtime_patch(
            base, [{"op": "replace", "path": "", "value": swapped}], allowlist=allowlist
        )
        assert result.project_name == "swapped"

    def test_root_replace_still_denied_by_denylist_when_root_is_allowed(self) -> None:
        """Naming the root in `allowed_paths` clears the structural refusal but
        not the denylist: the root write carries every denied descendant.
        """
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=[""],
            denied_paths=_shipped_denied_paths(),
        )
        swapped = base.model_dump(mode="json", by_alias=False)
        swapped["fail_on_findings"] = False
        ops = [{"op": "replace", "path": "", "value": swapped}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "denied_paths entry" in excinfo.value.rule


class TestDenyListIsSubtreeClosed:
    """Each `denied_paths` entry names a subtree, not one pointer.

    The matcher used to answer only "does this entry match the op's own
    pointer", which leaves two holes. A write *below* a denied leaf (`/-`,
    `/0`, a nested key) did not match it, because the pattern still had
    segments when the path ran out. A write *above* it did not match either,
    and that one is worse: the op's value supplies the denied descendant, so
    the three leaf entries can all be set from an ancestor while each of them
    correctly denies a direct write.
    """

    def test_ancestor_write_cannot_install_a_blanket_suppression(self) -> None:
        """The measured bypass. `/global_settings/suppressions` is denied and
        denies a direct write, yet a write at `/global_settings` supplied the
        suppression list wholesale.

        The assertion is on the effect, not just on the exception, so a
        regression reports what the patch installed.
        """
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/**"],
            denied_paths=_shipped_denied_paths(),
        )
        global_settings = base.global_settings.model_dump(mode="json", by_alias=False)
        global_settings["suppressions"] = [_BLANKET_SUPPRESSION]
        ops = [{"op": "replace", "path": "/global_settings", "value": global_settings}]

        try:
            result = apply_runtime_patch(base, ops, allowlist=allowlist)
        except RuntimePatchDeniedError as exc:
            # The operator has to be able to act on this, which means the
            # message names the denied descendant that caused the refusal.
            assert "denied_paths entry '/global_settings/" in exc.rule, exc.rule
        else:
            pytest.fail(
                "write at /global_settings was permitted; it installed "
                f"suppressions={result.global_settings.suppressions!r}"
            )

    def test_root_swap_cannot_flip_fail_on_findings(self) -> None:
        """Same mechanism at the top: a whole-config swap sets `fail_on_findings`
        and the suppression list in one op, and `/**` reaches the root because
        `**` matches zero segments.
        """
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=_shipped_denied_paths(),
        )
        swapped = base.model_dump(mode="json", by_alias=False)
        swapped["fail_on_findings"] = False
        swapped["global_settings"]["suppressions"] = [_BLANKET_SUPPRESSION]
        ops = [{"op": "replace", "path": "", "value": swapped}]

        try:
            result = apply_runtime_patch(base, ops, allowlist=allowlist)
        except RuntimePatchDeniedError:
            pass
        else:
            pytest.fail(
                "root swap was permitted: it set "
                f"fail_on_findings={result.fail_on_findings!r} and "
                f"suppressions={result.global_settings.suppressions!r}"
            )

    @pytest.mark.parametrize(
        "op_path,denied_entry",
        [
            # Array-append and array-index writes under a denied list field.
            ("/global_settings/suppressions/-", "/global_settings/suppressions"),
            ("/global_settings/suppressions/0", "/global_settings/suppressions"),
            ("/global_settings/ignore_paths/-", "/global_settings/ignore_paths"),
            ("/global_settings/ignore_paths/0", "/global_settings/ignore_paths"),
            # A nested key under a denied scalar. Nonsense against the schema,
            # but the guard must refuse it on the pointer alone rather than
            # leaning on validation to catch it later.
            ("/fail_on_findings/nested", "/fail_on_findings"),
            (
                "/fail_on_incomplete_scanners/nested",
                "/fail_on_incomplete_scanners",
            ),
            # Under a partial-segment glob entry.
            (
                "/reporters/bedrock-summary-reporter/options/aws_region/nested",
                "/reporters/bedrock-summary-reporter/options/aws_*",
            ),
            # Control: an entry that already ends in `/**` covered its own
            # subtree before this change, and must keep doing so.
            (
                "/reporters/cloudwatch-logs/options/log_group_name",
                "/reporters/cloudwatch-logs/**",
            ),
        ],
    )
    def test_write_below_a_denied_entry_is_denied(
        self, op_path: str, denied_entry: str
    ) -> None:
        assert denied_entry in _shipped_denied_paths(), (
            f"{denied_entry!r} is no longer a shipped default, so this case "
            "covers nothing"
        )
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=_shipped_denied_paths(),
        )
        ops = [{"op": "add", "path": op_path, "value": _BLANKET_SUPPRESSION}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert denied_entry in excinfo.value.rule, excinfo.value.rule

    @pytest.mark.parametrize(
        "op_path",
        [
            "/global_settings",
            "/reporters",
            "/reporters/bedrock-summary-reporter",
            "/reporters/bedrock-summary-reporter/options",
            # Control: `/reporters/cloudwatch-logs/**` already denied its own
            # parent segment before this change.
            "/reporters/cloudwatch-logs",
        ],
    )
    def test_write_above_a_denied_entry_is_denied(self, op_path: str) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=_shipped_denied_paths(),
        )
        ops = [{"op": "add", "path": op_path, "value": {}}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "denied_paths entry" in excinfo.value.rule, excinfo.value.rule

    def test_remove_at_an_ancestor_is_denied(self) -> None:
        """`remove` carries no value, so a predicate that inspects the value to
        decide whether the op supplies a denied descendant cannot see this one.
        Removing an ancestor deletes the denied subtree with it.
        """
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=_shipped_denied_paths(),
        )
        ops = [{"op": "remove", "path": "/global_settings"}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "denied_paths entry" in excinfo.value.rule

    def test_sibling_of_a_denied_entry_still_applies(self) -> None:
        """Subtree closure must not swallow the legitimate case: a sibling of a
        denied field is neither above nor below it.
        """
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/**"],
            denied_paths=_shipped_denied_paths(),
        )
        ops = [
            {
                "op": "replace",
                "path": "/global_settings/severity_threshold",
                "value": "HIGH",
            }
        ]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.global_settings.severity_threshold == "HIGH"

    def test_unrelated_top_level_field_still_applies(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/project_name"],
            denied_paths=_shipped_denied_paths(),
        )
        ops = [{"op": "replace", "path": "/project_name", "value": "renamed"}]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.project_name == "renamed"


class TestDeniedValuePatternsAreSubtreeClosed:
    """`denied_value_patterns` keys are pointer patterns, so they bind to a
    subtree the same way `denied_paths` entries do. An exact dict lookup on the
    op's own pointer covered neither a child write nor a parent write.
    """

    def test_pattern_on_parent_applies_to_child_write(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/**"],
            denied_paths=[],
            denied_value_patterns={"/global_settings": r"DROP TABLE"},
        )
        ops = [
            {
                "op": "add",
                "path": "/global_settings/suppressions/-",
                "value": {"path": "DROP TABLE users", "reason": "r"},
            }
        ]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "denied_value_patterns" in excinfo.value.rule

    def test_pattern_on_child_applies_to_parent_write(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings"],
            denied_paths=[],
            denied_value_patterns={
                "/global_settings/severity_threshold": r"^CRITICAL$"
            },
        )
        global_settings = base.global_settings.model_dump(mode="json", by_alias=False)
        global_settings["severity_threshold"] = "CRITICAL"
        ops = [{"op": "replace", "path": "/global_settings", "value": global_settings}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "denied_value_patterns" in excinfo.value.rule

    def test_pattern_on_glob_key_applies_to_matching_write(self) -> None:
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/**"],
            denied_paths=[],
            denied_value_patterns={"/global_settings/*": r"^CRITICAL$"},
        )
        ops = [
            {
                "op": "replace",
                "path": "/global_settings/severity_threshold",
                "value": "CRITICAL",
            }
        ]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(base, ops, allowlist=allowlist)
        assert "denied_value_patterns" in excinfo.value.rule

    def test_unrelated_pattern_key_does_not_fire(self) -> None:
        """Subtree closure must not make every registered regex apply to every
        op: a key on a disjoint pointer stays out of the way.
        """
        base = _base_config()
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/global_settings/severity_threshold"],
            denied_paths=[],
            denied_value_patterns={"/project_name": r"^HIGH$"},
        )
        ops = [
            {
                "op": "replace",
                "path": "/global_settings/severity_threshold",
                "value": "HIGH",
            }
        ]
        result = apply_runtime_patch(base, ops, allowlist=allowlist)
        assert result.global_settings.severity_threshold == "HIGH"


class TestOverrideAsPatch:
    """A whole-document override is gated as the patch that produces it.

    `select_profile(override_yaml=...)` binds a client-supplied config in place
    of the profile. These tests pin the two halves of holding that to the
    runtime-override rules: `json_patch_between` turns the difference into
    add/remove/replace ops, and `apply_runtime_override` runs those ops through
    `apply_runtime_patch`, so the rules live in one place.
    """

    def test_identical_documents_need_no_ops(self) -> None:
        doc = {"a": {"b": [1, 2]}, "c": "x"}
        assert json_patch_between(doc, json.loads(json.dumps(doc))) == []

    def test_a_nested_scalar_change_is_one_replace_at_the_leaf(self) -> None:
        before = {"global_settings": {"severity_threshold": "LOW", "x": 1}}
        after = {"global_settings": {"severity_threshold": "HIGH", "x": 1}}
        assert json_patch_between(before, after) == [
            {
                "op": "replace",
                "path": "/global_settings/severity_threshold",
                "value": "HIGH",
            }
        ]

    def test_a_list_change_replaces_the_whole_list(self) -> None:
        """Lists are values: an element-wise diff would emit index pointers that
        an allowlist written for the list (or for `/-`) does not name."""
        before = {"paths": ["a", "b"]}
        after = {"paths": ["a", "b", "c"]}
        assert json_patch_between(before, after) == [
            {"op": "replace", "path": "/paths", "value": ["a", "b", "c"]}
        ]

    def test_added_and_removed_keys(self) -> None:
        before = {"reporters": {"old": {"enabled": True}}}
        after = {"reporters": {"new": {"enabled": False}}}
        assert json_patch_between(before, after) == [
            {"op": "remove", "path": "/reporters/old"},
            {"op": "add", "path": "/reporters/new", "value": {"enabled": False}},
        ]

    def test_keys_are_escaped_per_rfc_6901(self) -> None:
        import jsonpatch

        before = {"m": {"a/b": 1, "c~d": 1}}
        after = {"m": {"a/b": 2, "c~d": 3}}
        ops = json_patch_between(before, after)
        assert [op["path"] for op in ops] == ["/m/a~1b", "/m/c~0d"]
        assert jsonpatch.apply_patch(before, ops) == after

    @pytest.mark.parametrize(
        "before, after",
        [(True, 1), (1, 1.0), (False, 0), ([True], [1]), ({"k": 1}, {"k": True})],
    )
    def test_values_python_calls_equal_are_still_different(
        self, before: object, after: object
    ) -> None:
        """`True == 1` and `1 == 1.0` in Python; they are distinct JSON values,
        and a change between them must reach the gate."""
        assert json_patch_between({"v": before}, {"v": after}) != []

    def test_override_is_refused_when_the_allowlist_is_disabled(self) -> None:
        base = AshConfig(project_name="base")
        override = AshConfig(project_name="changed")
        allowlist = RuntimeOverridesConfig(
            enabled=False, allowed_paths=["/project_name"]
        )
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_override(base, override, allowlist=allowlist)
        assert "disabled" in excinfo.value.rule

    def test_override_is_refused_by_a_shipped_denied_path(self) -> None:
        base = AshConfig(project_name="base", sandbox={"mode": "bwrap"})
        override = AshConfig(project_name="base", sandbox={"mode": "off"})
        allowlist = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_override(base, override, allowlist=allowlist)
        assert excinfo.value.op == {
            "op": "replace",
            "path": "/sandbox/mode",
            "value": "off",
        }
        assert "denied_paths entry '/sandbox'" in excinfo.value.rule

    def test_permitted_override_returns_the_override(self) -> None:
        base = AshConfig(project_name="base", sandbox={"mode": "bwrap"})
        override = AshConfig(project_name="changed", sandbox={"mode": "bwrap"})
        allowlist = RuntimeOverridesConfig(
            enabled=True, allowed_paths=["/project_name"]
        )
        result = apply_runtime_override(base, override, allowlist=allowlist)
        assert result.model_dump(mode="json") == override.model_dump(mode="json")
        assert base.project_name == "base"

    def test_a_difference_the_ops_miss_is_refused_not_bound(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """What is returned is what the gate checked. If the ops ever failed to
        express part of the override, that part would be unchecked; the call
        refuses instead of returning either config."""
        from automated_security_helper.config import runtime_patch

        base = AshConfig(project_name="base", sandbox={"mode": "bwrap"})
        override = AshConfig(project_name="changed", sandbox={"mode": "off"})
        allowlist = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])
        monkeypatch.setattr(
            runtime_patch,
            "json_patch_between",
            lambda before, after: [
                {"op": "replace", "path": "/project_name", "value": "changed"}
            ],
        )
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_override(base, override, allowlist=allowlist)
        assert "does not reproduce the override" in excinfo.value.rule


class TestDenialsMatchEitherSeparator:
    """Config merging treats '-' and '_' in a key as one key, per segment, so a
    denial written with one has to refuse a write spelled with the other, in any
    mix across segments.
    """

    def test_default_denial_refuses_the_underscore_spelling(self) -> None:
        allowlist = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])
        ops = [
            {
                "op": "add",
                "path": "/reporters/bedrock_summary_reporter/options/aws_region",
                "value": "us-east-1",
            }
        ]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(_base_config(), ops, allowlist=allowlist)
        assert "denied_paths" in excinfo.value.rule

    @pytest.mark.parametrize(
        "path",
        [
            "/scanners/trivy_repo/options/ignore_file",
            "/scanners/trivy-repo/options/ignore-file",
            "/scanners/trivy_repo/options/ignore-file",
        ],
    )
    def test_operator_denial_mixing_separators_refuses_every_mix(
        self, path: str
    ) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=["/scanners/trivy-repo/options/ignore_file"],
        )
        ops = [{"op": "add", "path": path, "value": "x"}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(_base_config(), ops, allowlist=allowlist)
        assert "denied_paths" in excinfo.value.rule

    def test_value_pattern_binds_to_either_spelling(self) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[],
            denied_value_patterns={
                "/reporters/bedrock-summary-reporter/options/aws_region": r"^us-east-1$"
            },
        )
        ops = [
            {
                "op": "add",
                "path": "/reporters/bedrock_summary_reporter/options/aws_region",
                "value": "us-east-1",
            }
        ]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(_base_config(), ops, allowlist=allowlist)
        assert "denied_value_patterns" in excinfo.value.rule

    def test_a_character_class_keeps_its_meaning(self) -> None:
        # Folding '-' would turn [a-z] into [a_z]; the pattern as written still
        # applies, so the folded form only adds refusals.
        allowlist = RuntimeOverridesConfig(
            enabled=True, allowed_paths=["/**"], denied_paths=["/project_[a-z]ame"]
        )
        ops = [{"op": "replace", "path": "/project_name", "value": "renamed"}]
        with pytest.raises(RuntimePatchDeniedError):
            apply_runtime_patch(_base_config(), ops, allowlist=allowlist)

    def test_an_unrelated_path_is_still_allowed(self) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=["/scanners/trivy-repo/options/ignore_file"],
        )
        ops = [{"op": "replace", "path": "/project_name", "value": "renamed"}]
        patched = apply_runtime_patch(_base_config(), ops, allowlist=allowlist)
        assert patched.project_name == "renamed"


# Spellings of the bedrock-summary-reporter section that AshConfig.get_plugin_config
# resolves for that plugin when no section uses its exact name.
_BEDROCK_SPELLINGS = [
    "BedrockSummary",
    "BedrockSummaryReporter",
    "bedrocksummaryreporter",
    "bedrocksummary",
    "Bedrock.Summary",
]


class TestDenialsMatchEveryPluginSpelling:
    """A plugin's config section is looked up ignoring case, punctuation and the
    Scanner/Reporter/Converter word (AshConfig.get_plugin_config), so a denial on
    that section has to refuse every spelling the lookup would read as it.
    """

    @pytest.mark.parametrize("spelling", _BEDROCK_SPELLINGS)
    def test_the_lookup_reads_each_spelling_as_the_plugin(self, spelling: str) -> None:
        # Without this the denial tests below could be refusing names nothing reads.
        config = AshConfig.model_validate(
            {"reporters": {spelling: {"options": {"aws_region": "us-east-1"}}}}
        )
        found = config.get_plugin_config("reporter", "bedrock-summary-reporter")
        assert found is not None
        assert found["options"]["aws_region"] == "us-east-1"

    @pytest.mark.parametrize("spelling", _BEDROCK_SPELLINGS)
    @pytest.mark.parametrize("suffix", ["/options/aws_region", ""])
    def test_default_denial_refuses_every_spelling(
        self, spelling: str, suffix: str
    ) -> None:
        allowlist = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])
        value = "us-east-1" if suffix else {"options": {"aws_region": "us-east-1"}}
        ops = [{"op": "add", "path": f"/reporters/{spelling}{suffix}", "value": value}]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            check_runtime_ops(ops, allowlist=allowlist)
        assert "denied_paths" in excinfo.value.rule

    @pytest.mark.parametrize("spelling", ["TrivyRepo", "trivyrepo", "TrivyRepoScanner"])
    def test_operator_denial_refuses_every_spelling(self, spelling: str) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=["/scanners/trivy-repo/options/ignore_file"],
        )
        ops = [
            {
                "op": "add",
                "path": f"/scanners/{spelling}/options/ignore_file",
                "value": "x",
            }
        ]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            check_runtime_ops(ops, allowlist=allowlist)
        assert "denied_paths" in excinfo.value.rule

    def test_value_pattern_binds_to_every_spelling(self) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[],
            denied_value_patterns={
                "/reporters/bedrock-summary-reporter/options/aws_region": r"^us-east-1$"
            },
        )
        ops = [
            {
                "op": "add",
                "path": "/reporters/BedrockSummary",
                "value": {"options": {"aws_region": "us-east-1"}},
            }
        ]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            check_runtime_ops(ops, allowlist=allowlist)
        assert "denied_value_patterns" in excinfo.value.rule

    @pytest.mark.parametrize(
        "path",
        ["/scanners/TrivyImage/options/ignore_file", "/reporters/TrivyRepo/options/x"],
    )
    def test_another_plugin_or_section_is_not_refused(self, path: str) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=["/scanners/trivy-repo/options/ignore_file"],
        )
        check_runtime_ops(
            [{"op": "add", "path": path, "value": "x"}], allowlist=allowlist
        )


def _lookup_reads(section: str, written: str, plugin_key: str) -> bool:
    """Whether get_plugin_config reads a section keyed ``written`` as ``plugin_key``'s."""
    plugin_type = {"scanners": "scanner", "reporters": "reporter"}[section]
    config = AshConfig.model_validate({section: {written: {"options": {}}}})
    return config.get_plugin_config(plugin_type, plugin_key) is not None


def _spellings(key: str) -> List[str]:
    """Spellings of a kebab-case plugin key that the lookup may read as it."""
    words = key.split("-")
    camel = "".join(word.capitalize() for word in words)
    return [
        camel,
        camel.lower(),
        key.upper(),
        "--".join(words),
        " ".join(words),
        "/".join(words),
        "~".join(words),
        camel + "Scanner",
        camel + "Reporter",
        camel + "ReporterConfig",
        "_".join(word.upper() for word in words),
    ]


# (denial, section, field written below the plugin's section, plugin keys the
# glob covers, plugin keys it does not)
_GLOB_DENIALS = [
    (
        "/scanners/trivy-*/options/ignore_file",
        "scanners",
        "options/ignore_file",
        ["trivy-repo"],
        ["bandit", "ferret-scan", "detect-secrets"],
    ),
    (
        "/scanners/trivy?repo/options/ignore_file",
        "scanners",
        "options/ignore_file",
        ["trivy-repo"],
        ["grype", "bandit"],
    ),
    (
        "/reporters/bedrock-*/**",
        "reporters",
        "options/aws_region",
        ["bedrock-summary-reporter"],
        ["csv", "cloudwatch-logs", "sarif"],
    ),
    (
        "/reporters/bedrock*/options/aws_*",
        "reporters",
        "options/aws_region",
        ["bedrock-summary-reporter"],
        ["csv", "cloudwatch-logs"],
    ),
]


def _write(section: str, written: str, field: str) -> Dict[str, Any]:
    plugin = written.replace("~", "~0").replace("/", "~1")
    return {"op": "add", "path": f"/{section}/{plugin}/{field}", "value": "x"}


class TestGlobPluginDenials:
    """A denial whose plugin segment is a glob covers every plugin key the glob
    matches, so it has to refuse every spelling get_plugin_config reads as one of
    those keys, not only spellings the glob matches as written.
    """

    @pytest.mark.parametrize(
        "denial,section,field,covered,_",
        _GLOB_DENIALS,
        ids=[case[0] for case in _GLOB_DENIALS],
    )
    def test_every_spelling_the_lookup_reads_is_refused(
        self,
        denial: str,
        section: str,
        field: str,
        covered: List[str],
        _: List[str],
    ) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True, allowed_paths=["/**"], denied_paths=[denial]
        )
        checked = 0
        for key in covered:
            for written in [key, *_spellings(key)]:
                if not _lookup_reads(section, written, key):
                    continue
                checked += 1
                with pytest.raises(RuntimePatchDeniedError) as excinfo:
                    check_runtime_ops(
                        [_write(section, written, field)], allowlist=allowlist
                    )
                assert "denied_paths" in excinfo.value.rule, written
        # The lookup reads most of the generated spellings; a run that checked
        # only the canonical keys would not exercise the glob at all.
        assert checked >= 5 * len(covered)

    @pytest.mark.parametrize(
        "denial,section,field,_,uncovered",
        _GLOB_DENIALS,
        ids=[case[0] for case in _GLOB_DENIALS],
    )
    def test_another_plugins_spellings_are_not_refused(
        self,
        denial: str,
        section: str,
        field: str,
        _: List[str],
        uncovered: List[str],
    ) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True, allowed_paths=["/**"], denied_paths=[denial]
        )
        for key in uncovered:
            for written in [key, *_spellings(key)]:
                check_runtime_ops(
                    [_write(section, written, field)], allowlist=allowlist
                )

    def test_a_value_pattern_bound_through_a_glob_covers_every_spelling(self) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[],
            denied_value_patterns={"/scanners/trivy-*/options/ignore_file": r"."},
        )
        ops = [
            {
                "op": "add",
                "path": "/scanners/TrivyRepo",
                "value": {"options": {"ignore_file": "standin.txt"}},
            }
        ]
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            check_runtime_ops(ops, allowlist=allowlist)
        assert "denied_value_patterns" in excinfo.value.rule


class TestGlobDenialsNameKnownPlugins:
    """A glob plugin segment is matched against the keys of known plugins, so it
    refuses another spelling only of a plugin whose key it matches."""

    @pytest.mark.parametrize(
        "section,glob",
        [
            ("scanners", "c*"),
            ("scanners", "[a-c]*"),
            ("scanners", "*-scan*"),
            ("reporters", "s*"),
            ("reporters", "*-reporter"),
            ("reporters", "*json*"),
        ],
    )
    def test_only_keys_the_glob_matches_are_refused(
        self, section: str, glob: str
    ) -> None:
        import fnmatch

        from automated_security_helper.config.runtime_patch import known_plugin_keys

        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=[f"/{section}/{glob}/options/field"],
        )
        keys = sorted(known_plugin_keys()[section])
        assert keys
        for key in keys:
            ops = [_write(section, key, "options/field")]
            folded = key.replace("-", "_")
            if fnmatch.fnmatchcase(key, glob) or fnmatch.fnmatchcase(
                folded, glob.replace("-", "_")
            ):
                with pytest.raises(RuntimePatchDeniedError):
                    check_runtime_ops(ops, allowlist=allowlist)
            else:
                check_runtime_ops(ops, allowlist=allowlist)

    @pytest.mark.parametrize(
        "denial",
        [
            "/*/trivy-repo/options/ignore_file",
            "/scanner?/trivy-*/options/ignore_file",
            "/[s]canners/trivy-repo/options/ignore_file",
        ],
    )
    def test_a_glob_section_segment_is_respelled_too(self, denial: str) -> None:
        allowlist = RuntimeOverridesConfig(
            enabled=True, allowed_paths=["/**"], denied_paths=[denial]
        )
        with pytest.raises(RuntimePatchDeniedError):
            check_runtime_ops(
                [_write("scanners", "TrivyRepo", "options/ignore_file")],
                allowlist=allowlist,
            )

    def test_a_section_the_config_already_has_is_a_known_key(self) -> None:
        base = AshConfig.model_validate({"scanners": {"acme-scan": {"enabled": False}}})
        allowlist = RuntimeOverridesConfig(
            enabled=True,
            allowed_paths=["/**"],
            denied_paths=["/scanners/acme-*/options/ignore_file"],
        )
        with pytest.raises(RuntimePatchDeniedError) as excinfo:
            apply_runtime_patch(
                base,
                [
                    {
                        "op": "add",
                        "path": "/scanners/AcmeScan",
                        "value": {"options": {"ignore_file": "standin.txt"}},
                    }
                ],
                allowlist=allowlist,
            )
        assert "denied_paths" in excinfo.value.rule

    def test_the_shipped_table_matches_the_plugin_packages(self, tmp_path) -> None:
        """The table stands in for importing the packages; this imports them, apart.

        Compared with the plugins the manager resolves after loading every module
        under ``plugin_modules``, which is the set a scan iterates, so a plugin
        its decorator registers but its package's ``ASH_*`` list leaves out is
        caught too.
        """
        import json as json_module
        import subprocess
        import sys

        from automated_security_helper.config.runtime_patch import (
            _SHIPPED_PLUGIN_KEYS,
        )

        code = (
            "import json, pkgutil\n"
            "from automated_security_helper.base.plugin_config import plugin_config_key\n"
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "from automated_security_helper.plugins.loader import (\n"
            "    load_additional_plugin_modules, load_internal_plugins)\n"
            "import automated_security_helper.plugin_modules as pm\n"
            "load_internal_plugins()\n"
            "load_additional_plugin_modules(\n"
            "    [pm.__name__ + '.' + info.name for info in pkgutil.iter_modules(pm.__path__)])\n"
            "print(json.dumps({\n"
            "    section: sorted({plugin_config_key(c)\n"
            "                     for c in ash_plugin_manager.plugin_modules(kind)})\n"
            "    for section, kind in (('scanners', 'scanner'), ('reporters', 'reporter'),\n"
            "                          ('converters', 'converter'))}))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=True,
        )
        resolved = json_module.loads(result.stdout.strip().splitlines()[-1])
        assert resolved == {
            section: sorted(keys) for section, keys in _SHIPPED_PLUGIN_KEYS.items()
        }

    def test_building_the_keys_imports_no_plugin_module(self, tmp_path) -> None:
        """Importing a plugin module registers its plugins, and a scan runs them all."""
        import subprocess
        import sys

        code = (
            "import sys\n"
            "from automated_security_helper.plugins.loader import load_internal_plugins\n"
            "from automated_security_helper.config.ash_config import AshConfig\n"
            "from automated_security_helper.config.runtime_patch import known_plugin_keys\n"
            "load_internal_plugins()\n"
            "def loaded():\n"
            "    return sorted(m for m in sys.modules if 'plugin_modules.ash_' in m)\n"
            "before = loaded()\n"
            "config = AshConfig.model_validate(\n"
            "    {'ash_plugin_modules': ['standin_not_imported']})\n"
            "known_plugin_keys(config)\n"
            "assert loaded() == before, sorted(set(loaded()) - set(before))\n"
            "assert 'standin_not_imported' not in sys.modules\n"
            "print('unchanged')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        assert result.stdout.strip().endswith("unchanged")
